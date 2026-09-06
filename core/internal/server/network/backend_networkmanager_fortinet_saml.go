package network

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/AvengeMedia/DankMaterialShell/core/internal/log"
)

const (
	// FortiGate redirects the browser back to this loopback port after SAML
	// login; 8020 is the openfortivpn default and what gateways are configured
	// with. Overridden per profile with the "saml-port" data key.
	fortinetSAMLDefaultListenPort = 8020
	fortinetDefaultGatewayPort    = 443
	fortinetUserAgent             = "Mozilla/5.0 SV1"
)

var errFortinetSAMLNoCookie = errors.New("gateway did not return an SVPNCOOKIE")

type fortinetSAMLRequest struct {
	Gateway    string
	Realm      string
	ListenPort int
	// CertPin is the openconnect-style "pin-sha256:" hash the gateway
	// connection is pinned to for the token exchange.
	CertPin string
}

type fortinetGatewayCert struct {
	// Pin is the openconnect --servercert form: sha256 of the public key.
	Pin string
	// Digest is the sha256 of the whole certificate, matching the hex digest
	// openfortivpn stores as "trusted-cert".
	Digest   string
	Verified bool
}

func (b *NetworkManagerBackend) runFortinetSAMLAuth(ctx context.Context, req fortinetSAMLRequest) (*openConnectAuthResult, error) {
	host, port, err := splitGatewayHostPort(req.Gateway)
	if err != nil {
		return nil, err
	}

	listenPort := req.ListenPort
	if listenPort == 0 {
		listenPort = fortinetSAMLDefaultListenPort
	}

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
	if err != nil {
		return nil, fmt.Errorf("cannot listen for the SAML redirect on port %d: %w", listenPort, err)
	}
	defer listener.Close()

	authURL := fortinetSAMLStartURL(host, port, req.Realm)
	log.Infof("[Fortinet-SAML] Listening on 127.0.0.1:%d, authenticate at %s", listenPort, authURL)

	if err := openInBrowser(authURL); err != nil {
		return nil, fmt.Errorf("cannot open a browser for SAML login, authenticate at %s: %w", authURL, err)
	}

	sessionID, err := waitForFortinetSAMLSession(ctx, listener)
	if err != nil {
		return nil, err
	}

	cookie, err := exchangeFortinetSAMLSession(ctx, host, port, sessionID, req.CertPin)
	if err != nil {
		return nil, err
	}

	log.Infof("[Fortinet-SAML] Authentication successful for %s", req.Gateway)

	return &openConnectAuthResult{
		Cookie:      "SVPNCOOKIE=" + cookie,
		Host:        net.JoinHostPort(host, strconv.Itoa(port)),
		Fingerprint: req.CertPin,
	}, nil
}

type fortinetAuthTarget struct {
	ConnName       string
	ConnUUID       string
	ConnectionPath string
	VpnService     string
	Data           map[string]string
}

// authenticateFortinetSAML establishes gateway trust, runs the browser SAML
// login and returns the cookie NetworkManager hands to openconnect.
func (b *NetworkManagerBackend) authenticateFortinetSAML(ctx context.Context, target fortinetAuthTarget) (*openConnectAuthResult, error) {
	gateway := target.Data["gateway"]
	host, port, err := splitGatewayHostPort(gateway)
	if err != nil {
		return nil, err
	}

	cert, err := probeGatewayCert(ctx, host, port)
	if err != nil {
		return nil, err
	}

	newlyTrusted, err := b.resolveFortinetCertTrust(ctx, target, cert)
	if err != nil {
		return nil, err
	}

	auth, err := b.runFortinetSAMLAuth(ctx, fortinetSAMLRequest{
		Gateway:    gateway,
		Realm:      target.Data["usergroup"],
		ListenPort: fortinetSAMLListenPort(target.Data),
		CertPin:    cert.Pin,
	})
	if err != nil {
		return nil, err
	}

	if newlyTrusted {
		b.pendingVPNSaveMu.Lock()
		b.pendingVPNSave = &pendingVPNCredentials{
			ConnectionPath: target.ConnectionPath,
			PersistentData: map[string]string{"trusted-cert": cert.Digest},
		}
		b.pendingVPNSaveMu.Unlock()
	}

	return auth, nil
}

// resolveFortinetCertTrust reports whether the user just approved a certificate
// that should be remembered. Trust is stored as the whole-certificate digest
// under the "trusted-cert" data key, the same value openfortivpn configs use.
func (b *NetworkManagerBackend) resolveFortinetCertTrust(
	ctx context.Context,
	target fortinetAuthTarget,
	cert *fortinetGatewayCert,
) (bool, error) {
	if cert.Verified {
		return false, nil
	}

	trusted := target.Data["trusted-cert"]
	if certDigestTrusted(trusted, cert.Digest) {
		return false, nil
	}

	if b.promptBroker == nil {
		return false, fmt.Errorf("VPN server certificate is untrusted: %s", cert.Pin)
	}

	reason := "server-certificate"
	if trusted != "" {
		reason = "server-certificate-changed"
	}

	token, err := b.promptBroker.Ask(ctx, PromptRequest{
		Name:           target.ConnName,
		ConnType:       "vpn",
		VpnService:     target.VpnService,
		SettingName:    "vpn",
		Hints:          []string{cert.Pin},
		Reason:         reason,
		ConnectionId:   target.ConnName,
		ConnectionUuid: target.ConnUUID,
		ConnectionPath: target.ConnectionPath,
	})
	if err != nil {
		return false, fmt.Errorf("failed to request certificate confirmation: %w", err)
	}
	if _, err := b.promptBroker.Wait(ctx, token); err != nil {
		return false, fmt.Errorf("certificate confirmation failed: %w", err)
	}

	return true, nil
}

// certDigestTrusted matches a certificate digest against the trusted list,
// which openfortivpn configs may carry as several entries.
func certDigestTrusted(trusted, digest string) bool {
	if trusted == "" || digest == "" {
		return false
	}
	for entry := range strings.SplitSeq(trusted, ",") {
		if strings.EqualFold(strings.TrimSpace(entry), digest) {
			return true
		}
	}
	return false
}

func fortinetSAMLListenPort(data map[string]string) int {
	port, err := strconv.Atoi(data["saml-port"])
	if err != nil || port < 1 || port > 65535 {
		return fortinetSAMLDefaultListenPort
	}
	return port
}

func splitGatewayHostPort(gateway string) (string, int, error) {
	trimmed := strings.TrimSpace(gateway)
	if trimmed == "" {
		return "", 0, errors.New("VPN gateway is empty")
	}

	if idx := strings.Index(trimmed, "://"); idx >= 0 {
		trimmed = trimmed[idx+3:]
	}
	trimmed = strings.TrimSuffix(trimmed, "/")
	if idx := strings.IndexAny(trimmed, "/?"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if trimmed == "" {
		return "", 0, fmt.Errorf("invalid VPN gateway: %s", gateway)
	}

	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		return trimmed, fortinetDefaultGatewayPort, nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid VPN gateway port: %s", portStr)
	}
	return host, port, nil
}

func fortinetSAMLStartURL(host string, port int, realm string) string {
	base := fmt.Sprintf("https://%s/remote/saml/start?redirect=1",
		net.JoinHostPort(host, strconv.Itoa(port)))
	if realm == "" {
		return base
	}
	return base + "&realm=" + url.QueryEscape(realm)
}

// waitForFortinetSAMLSession serves the loopback redirect target the gateway
// sends the browser to once SAML login succeeds, and returns the session id.
func waitForFortinetSAMLSession(ctx context.Context, listener net.Listener) (string, error) {
	type result struct {
		id  string
		err error
	}
	results := make(chan result, 1)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The gateway redirects to "/?id=..."; anything else is the browser
		// asking for extras like a favicon and must not abort the login.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		id := r.URL.Query().Get("id")
		if id == "" {
			writeFortinetSAMLPage(w, "VPN login failed: the gateway redirect did not include a session id.")
			select {
			case results <- result{err: errors.New("SAML redirect did not include a session id")}:
			default:
			}
			return
		}

		writeFortinetSAMLPage(w, "VPN login complete. You can close this tab.")
		select {
		case results <- result{id: id}:
		default:
		}
	})

	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go server.Serve(listener)
	defer server.Close()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("SAML login was not completed: %w", ctx.Err())
	case res := <-results:
		return res.id, res.err
	}
}

func writeFortinetSAMLPage(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!DOCTYPE html><html><body>%s</body></html>", message)
}

// exchangeFortinetSAMLSession trades the SAML session id for the SVPNCOOKIE
// that openconnect uses as its Fortinet cookie.
func exchangeFortinetSAMLSession(ctx context.Context, host string, port int, sessionID, certPin string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create cookie jar: %w", err)
	}

	client := &http.Client{
		Jar:       jar,
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: pinnedTLSConfig(host, certPin)},
	}
	defer client.CloseIdleConnections()

	endpoint := fmt.Sprintf("https://%s/remote/saml/auth_id?id=%s",
		net.JoinHostPort(host, strconv.Itoa(port)), url.QueryEscape(sessionID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build token request: %w", err)
	}
	req.Header.Set("User-Agent", fortinetUserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to exchange SAML session for a cookie: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gateway rejected the SAML session (HTTP %d)", resp.StatusCode)
	}

	if cookie := findSVPNCookie(resp.Cookies()); cookie != "" {
		return cookie, nil
	}
	if cookie := findSVPNCookie(jar.Cookies(req.URL)); cookie != "" {
		return cookie, nil
	}
	return "", errFortinetSAMLNoCookie
}

func findSVPNCookie(cookies []*http.Cookie) string {
	for _, cookie := range cookies {
		if cookie.Name == "SVPNCOOKIE" && cookie.Value != "" {
			return cookie.Value
		}
	}
	return ""
}

// probeGatewayCert reads the gateway's leaf certificate and reports both the
// openconnect pin and the whole-certificate digest, along with whether the
// chain validates against the system trust store.
func probeGatewayCert(ctx context.Context, host string, port int) (*fortinetGatewayCert, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: host},
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("cannot reach VPN gateway %s: %w", host, err)
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("VPN gateway %s presented no certificate", host)
	}

	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates})

	return &fortinetGatewayCert{
		Pin:      certificatePin(leaf),
		Digest:   certificateDigest(leaf),
		Verified: verifyErr == nil,
	}, nil
}

// certificatePin hashes the public key, matching openconnect's --servercert.
func certificatePin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// certificateDigest hashes the whole certificate, matching the hex digest
// openfortivpn stores as "trusted-cert".
func certificateDigest(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func pinnedTLSConfig(host, pin string) *tls.Config {
	if pin == "" {
		return &tls.Config{ServerName: host}
	}

	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("VPN gateway presented no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse gateway certificate: %w", err)
			}
			if certificatePin(cert) != pin {
				return errors.New("VPN gateway certificate does not match the trusted fingerprint")
			}
			return nil
		},
	}
}

func openInBrowser(target string) error {
	cmd := exec.Command("xdg-open", target)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}
