package utils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateRedirectURI(t *testing.T) {
	allowedURIs := []string{
		"https://example.com/callback",
		"https://app.example.com/oauth/callback",
		"myapp://callback",
	}

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{
			name:     "exact match",
			uri:      "https://example.com/callback",
			expected: true,
		},
		{
			name:     "subdomain exact match",
			uri:      "https://app.example.com/oauth/callback",
			expected: true,
		},
		{
			name:     "custom scheme exact match",
			uri:      "myapp://callback",
			expected: true,
		},
		{
			name:     "not in allowed list",
			uri:      "https://evil.com/callback",
			expected: false,
		},
		{
			name:     "partial match should fail",
			uri:      "https://example.com/callback/extra",
			expected: false,
		},
		{
			name:     "case sensitive",
			uri:      "https://Example.com/callback",
			expected: false,
		},
		{
			name:     "empty string",
			uri:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRedirectURI(tt.uri, allowedURIs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateRedirectURIFormat(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		expectErr bool
	}{
		{
			name:      "valid https uri",
			uri:       "https://example.com/callback",
			expectErr: false,
		},
		{
			name:      "valid http uri",
			uri:       "http://localhost:8080/callback",
			expectErr: false,
		},
		{
			name:      "valid custom scheme",
			uri:       "myapp://callback",
			expectErr: false,
		},
		{
			name:      "missing scheme",
			uri:       "example.com/callback",
			expectErr: true,
		},
		{
			name:      "contains fragment",
			uri:       "https://example.com/callback#fragment",
			expectErr: true,
		},
		{
			name:      "invalid uri",
			uri:       "://invalid",
			expectErr: true,
		},
		{
			name:      "empty string",
			uri:       "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURIFormat(tt.uri)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	allowedScopes := []string{"openid", "profile", "email", "address"}

	tests := []struct {
		name      string
		requested []string
		expected  bool
	}{
		{
			name:      "single valid scope",
			requested: []string{"openid"},
			expected:  true,
		},
		{
			name:      "multiple valid scopes",
			requested: []string{"openid", "profile", "email"},
			expected:  true,
		},
		{
			name:      "all allowed scopes",
			requested: []string{"openid", "profile", "email", "address"},
			expected:  true,
		},
		{
			name:      "single invalid scope",
			requested: []string{"admin"},
			expected:  false,
		},
		{
			name:      "mix of valid and invalid",
			requested: []string{"openid", "admin"},
			expected:  false,
		},
		{
			name:      "empty requested scopes",
			requested: []string{},
			expected:  true,
		},
		{
			name:      "case sensitive",
			requested: []string{"OpenID"},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateScopes(tt.requested, allowedScopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidatePKCE(t *testing.T) {
	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		expectErr           bool
	}{
		{
			name:                "valid S256 PKCE",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			expectErr:           false,
		},
		{
			name:                "valid plain PKCE",
			codeVerifier:        "my-code-verifier",
			codeChallenge:       "my-code-verifier",
			codeChallengeMethod: "plain",
			expectErr:           false,
		},
		{
			name:                "no PKCE used",
			codeVerifier:        "",
			codeChallenge:       "",
			codeChallengeMethod: "",
			expectErr:           false,
		},
		{
			name:                "invalid S256 verification",
			codeVerifier:        "wrong-verifier",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			expectErr:           true,
		},
		{
			name:                "missing verifier when challenge present",
			codeVerifier:        "",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			expectErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePKCE(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHTTPSURI(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		fieldName string
		expectErr bool
	}{
		{
			name:      "valid https uri",
			uri:       "https://example.com/logo.png",
			fieldName: "logo_uri",
			expectErr: false,
		},
		{
			name:      "valid https with path",
			uri:       "https://example.com/legal/privacy",
			fieldName: "policy_uri",
			expectErr: false,
		},
		{
			name:      "http instead of https",
			uri:       "http://example.com/logo.png",
			fieldName: "logo_uri",
			expectErr: true,
		},
		{
			name:      "contains fragment",
			uri:       "https://example.com/logo.png#section",
			fieldName: "logo_uri",
			expectErr: true,
		},
		{
			name:      "missing host",
			uri:       "https:///path",
			fieldName: "client_uri",
			expectErr: true,
		},
		{
			name:      "invalid url",
			uri:       "not-a-url",
			fieldName: "tos_uri",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHTTPSURI(tt.uri, tt.fieldName)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateURI_SSRFPrevention(t *testing.T) {
	tests := []struct {
		name         string
		uri          string
		requireHTTPS bool
		expectErr    bool
		errContains  string
	}{
		{
			name:         "valid public https url",
			uri:          "https://example.com/api",
			requireHTTPS: true,
			expectErr:    false,
		},
		{
			name:         "valid public http url when https not required",
			uri:          "http://example.com/api",
			requireHTTPS: false,
			expectErr:    false,
		},
		{
			name:         "http url when https required",
			uri:          "http://example.com/api",
			requireHTTPS: true,
			expectErr:    true,
			errContains:  "https scheme",
		},
		{
			name:         "localhost hostname",
			uri:          "https://localhost:8080/api",
			requireHTTPS: true,
			expectErr:    true,
			errContains:  "localhost",
		},
		{
			name:         "loopback ip 127.0.0.1",
			uri:          "https://127.0.0.1/api",
			requireHTTPS: true,
			expectErr:    true,
			errContains:  "loopback",
		},
		{
			name:         "loopback ip 127.1.2.3",
			uri:          "https://127.1.2.3/api",
			requireHTTPS: true,
			expectErr:    true,
			errContains:  "loopback",
		},
		{
			name:         "private ip 10.0.0.1",
			uri:          "https://10.0.0.1/api",
			requireHTTPS: true,
			expectErr:    true,
			errContains:  "private IP",
		},
		{
			name:         "private ip 172.16.0.1",
			uri:          "https://172.16.0.1/api",
			requireHTTPS: true,
			expectErr:    true,
			errContains:  "private IP",
		},
		{
			name:         "private ip 192.168.1.1",
			uri:          "https://192.168.1.1/api",
			requireHTTPS: true,
			expectErr:    true,
			errContains:  "private IP",
		},
		{
			name:         "link-local ip 169.254.1.1",
			uri:          "https://169.254.1.1/api",
			requireHTTPS: true,
			expectErr:    true,
			errContains:  "link-local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURI(tt.uri, tt.requireHTTPS)
			if tt.expectErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		expectErr   bool
		errContains string
	}{
		{
			name:      "public ipv4",
			ip:        "8.8.8.8",
			expectErr: false,
		},
		{
			name:        "loopback 127.0.0.1",
			ip:          "127.0.0.1",
			expectErr:   true,
			errContains: "loopback",
		},
		{
			name:        "loopback ipv6",
			ip:          "::1",
			expectErr:   true,
			errContains: "loopback",
		},
		{
			name:        "private 10.x.x.x",
			ip:          "10.0.0.1",
			expectErr:   true,
			errContains: "private IP",
		},
		{
			name:        "private 172.16.x.x",
			ip:          "172.16.0.1",
			expectErr:   true,
			errContains: "private IP",
		},
		{
			name:        "private 192.168.x.x",
			ip:          "192.168.1.1",
			expectErr:   true,
			errContains: "private IP",
		},
		{
			name:        "link-local 169.254.x.x",
			ip:          "169.254.1.1",
			expectErr:   true,
			errContains: "link-local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := parseIP(tt.ip)
			err := validateIPAddress(ip)
			if tt.expectErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "public ip",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "10.0.0.0/8 start",
			ip:       "10.0.0.0",
			expected: true,
		},
		{
			name:     "10.0.0.0/8 end",
			ip:       "10.255.255.255",
			expected: true,
		},
		{
			name:     "172.16.0.0/12 start",
			ip:       "172.16.0.0",
			expected: true,
		},
		{
			name:     "172.16.0.0/12 end",
			ip:       "172.31.255.255",
			expected: true,
		},
		{
			name:     "172.15.x.x not in range",
			ip:       "172.15.0.1",
			expected: false,
		},
		{
			name:     "172.32.x.x not in range",
			ip:       "172.32.0.1",
			expected: false,
		},
		{
			name:     "192.168.0.0/16 start",
			ip:       "192.168.0.0",
			expected: true,
		},
		{
			name:     "192.168.0.0/16 end",
			ip:       "192.168.255.255",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := parseIP(tt.ip)
			result := isPrivateIP(ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContains(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	tests := []struct {
		name     string
		item     string
		expected bool
	}{
		{
			name:     "item exists",
			item:     "banana",
			expected: true,
		},
		{
			name:     "item does not exist",
			item:     "grape",
			expected: false,
		},
		{
			name:     "empty string",
			item:     "",
			expected: false,
		},
		{
			name:     "case sensitive",
			item:     "Banana",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(slice, tt.item)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to parse IP for tests
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}
