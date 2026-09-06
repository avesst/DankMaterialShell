package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOpenfortivpnConfig(t *testing.T) {
	const digest = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899"

	t.Run("reads the fields that map onto a profile", func(t *testing.T) {
		cfg, err := parseOpenfortivpnConfig(strings.NewReader(`
# work VPN
host = vpn.example.com
port = 10443
username = jdoe
realm = contractors
trusted-cert = ` + digest + `
saml-login = 9000
set-dns = 0
pppd-use-peerdns = 1
`))
		require.NoError(t, err)
		assert.Equal(t, "vpn.example.com", cfg.Host)
		assert.Equal(t, 10443, cfg.Port)
		assert.Equal(t, "jdoe", cfg.Username)
		assert.Equal(t, "contractors", cfg.Realm)
		assert.Equal(t, []string{digest}, cfg.TrustedCerts)
		assert.Equal(t, 9000, cfg.SAMLPort)
	})

	t.Run("defaults the gateway port", func(t *testing.T) {
		cfg, err := parseOpenfortivpnConfig(strings.NewReader("host=vpn.example.com\n"))
		require.NoError(t, err)
		assert.Equal(t, fortinetDefaultGatewayPort, cfg.Port)
		assert.Zero(t, cfg.SAMLPort)
	})

	t.Run("collects several trusted certs and lowercases them", func(t *testing.T) {
		other := strings.Repeat("bb", 32)
		cfg, err := parseOpenfortivpnConfig(strings.NewReader(
			"host = vpn.example.com\ntrusted-cert = " + strings.ToUpper(digest) + "\ntrusted-cert = " + other + "\n"))
		require.NoError(t, err)
		assert.Equal(t, []string{digest, other}, cfg.TrustedCerts)
	})

	t.Run("skips a malformed trusted cert", func(t *testing.T) {
		cfg, err := parseOpenfortivpnConfig(strings.NewReader("host = vpn.example.com\ntrusted-cert = nope\n"))
		require.NoError(t, err)
		assert.Empty(t, cfg.TrustedCerts)
	})

	t.Run("rejects files that are not openfortivpn configs", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
		}{
			{name: "wireguard", input: "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n"},
			{name: "openvpn", input: "client\ndev tun\nremote vpn.example.com 1194\n"},
			{name: "no host", input: "port = 443\nusername = jdoe\n"},
			{name: "empty", input: ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := parseOpenfortivpnConfig(strings.NewReader(tt.input))
				assert.Error(t, err)
			})
		}
	})

	t.Run("rejects out of range ports", func(t *testing.T) {
		_, err := parseOpenfortivpnConfig(strings.NewReader("host = vpn.example.com\nport = 70000\n"))
		assert.ErrorContains(t, err, "invalid port")

		_, err = parseOpenfortivpnConfig(strings.NewReader("host = vpn.example.com\nsaml-login = 0\n"))
		assert.ErrorContains(t, err, "invalid saml-login port")
	})
}

func TestBuildOpenfortivpnSettings(t *testing.T) {
	const service = "org.freedesktop.NetworkManager.openconnect"

	t.Run("builds a fortinet SAML openconnect profile", func(t *testing.T) {
		settings := buildOpenfortivpnSettings(&openfortivpnConfig{
			Host:         "vpn.example.com",
			Port:         10443,
			Username:     "jdoe",
			Realm:        "contractors",
			TrustedCerts: []string{"aa", "bb"},
			SAMLPort:     9000,
		}, "Work VPN", service)

		assert.Equal(t, "Work VPN", settings["connection"]["id"])
		assert.Equal(t, "vpn", settings["connection"]["type"])
		assert.Equal(t, false, settings["connection"]["autoconnect"])
		assert.Equal(t, service, settings["vpn"]["service-type"])

		data, ok := settings["vpn"]["data"].(map[string]string)
		require.True(t, ok)
		assert.Equal(t, "vpn.example.com:10443", data["gateway"])
		assert.Equal(t, "fortinet", data["protocol"])
		assert.Equal(t, "saml", data["authtype"])
		assert.Equal(t, "jdoe", data["username"])
		assert.Equal(t, "contractors", data["usergroup"])
		assert.Equal(t, "9000", data["saml-port"])
		assert.Equal(t, "aa,bb", data["trusted-cert"])

		// The secret agent supplies these at connect time, so NM must not store them.
		assert.Equal(t, "2", data["cookie-flags"])
		assert.Equal(t, "2", data["gateway-flags"])
		assert.Equal(t, "2", data["gwcert-flags"])
	})

	t.Run("routes the profile through the SAML auth path", func(t *testing.T) {
		settings := buildOpenfortivpnSettings(&openfortivpnConfig{
			Host: "vpn.example.com",
			Port: 443,
		}, "Work VPN", service)

		data := settings["vpn"]["data"].(map[string]string)
		assert.Equal(t, "fortinet_saml", detectVPNAuthAction(service, data))
	})

	t.Run("omits optional fields", func(t *testing.T) {
		settings := buildOpenfortivpnSettings(&openfortivpnConfig{
			Host: "vpn.example.com",
			Port: 443,
		}, "Work VPN", service)

		data := settings["vpn"]["data"].(map[string]string)
		assert.NotContains(t, data, "username")
		assert.NotContains(t, data, "usergroup")
		assert.NotContains(t, data, "saml-port")
		assert.NotContains(t, data, "trusted-cert")
		assert.Equal(t, fortinetSAMLDefaultListenPort, fortinetSAMLListenPort(data))
	})
}

func TestReadOpenfortivpnConfig(t *testing.T) {
	dir := t.TempDir()

	fortinet := filepath.Join(dir, "myvpn")
	require.NoError(t, os.WriteFile(fortinet, []byte("host = vpn.example.com\nport = 10443\n"), 0o600))

	wireguard := filepath.Join(dir, "wg0.conf")
	require.NoError(t, os.WriteFile(wireguard, []byte("[Interface]\nPrivateKey = abc\n"), 0o600))

	cfg := readOpenfortivpnConfig(fortinet)
	require.NotNil(t, cfg)
	assert.Equal(t, "vpn.example.com", cfg.Host)

	assert.Nil(t, readOpenfortivpnConfig(wireguard))
	assert.Nil(t, readOpenfortivpnConfig(filepath.Join(dir, "missing")))
}

func TestVPNNameFromPath(t *testing.T) {
	assert.Equal(t, "myvpn", vpnNameFromPath("/home/user/.config/openfortivpn/myvpn"))
	assert.Equal(t, "work", vpnNameFromPath("/home/user/work.conf"))
}
