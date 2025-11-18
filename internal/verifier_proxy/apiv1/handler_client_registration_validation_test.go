package apiv1

import (
	"testing"
	"vc/internal/verifier_proxy/apiv1/utils"

	"github.com/stretchr/testify/assert"
)

func TestValidateLogoURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid https logo uri",
			uri:     "https://example.com/logo.png",
			wantErr: false,
		},
		{
			name:    "valid https logo uri with path",
			uri:     "https://client.example.com/assets/images/logo.png",
			wantErr: false,
		},
		{
			name:    "valid https logo uri with query",
			uri:     "https://example.com/logo.png?size=large",
			wantErr: false,
		},
		{
			name:    "http scheme not allowed",
			uri:     "http://example.com/logo.png",
			wantErr: true,
			errMsg:  "must use https scheme",
		},
		{
			name:    "fragment not allowed",
			uri:     "https://example.com/logo.png#top",
			wantErr: true,
			errMsg:  "must not contain a fragment",
		},
		{
			name:    "invalid url",
			uri:     "://invalid",
			wantErr: true,
			errMsg:  "invalid logo_uri URL",
		},
		{
			name:    "missing host",
			uri:     "https:///logo.png",
			wantErr: true,
			errMsg:  "must have a host",
		},
		{
			name:    "relative url not allowed",
			uri:     "/logo.png",
			wantErr: true,
			errMsg:  "must use https scheme",
		},
		{
			name:    "data uri not allowed",
			uri:     "data:image/png;base64,iVBORw0KGgo=",
			wantErr: true,
			errMsg:  "must use https scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidateHTTPSURI(tt.uri, "logo_uri")
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateClientMetadataURI(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		fieldName string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid https client_uri",
			uri:       "https://example.com",
			fieldName: "client_uri",
			wantErr:   false,
		},
		{
			name:      "valid https policy_uri with path",
			uri:       "https://example.com/privacy-policy",
			fieldName: "policy_uri",
			wantErr:   false,
		},
		{
			name:      "valid https tos_uri with query",
			uri:       "https://example.com/terms?lang=en",
			fieldName: "tos_uri",
			wantErr:   false,
		},
		{
			name:      "http scheme not allowed",
			uri:       "http://example.com",
			fieldName: "client_uri",
			wantErr:   true,
			errMsg:    "must use https scheme",
		},
		{
			name:      "fragment not allowed in policy_uri",
			uri:       "https://example.com/policy#section1",
			fieldName: "policy_uri",
			wantErr:   true,
			errMsg:    "must not contain a fragment",
		},
		{
			name:      "invalid url",
			uri:       "not a url",
			fieldName: "tos_uri",
			wantErr:   true,
			errMsg:    "must use https scheme",
		},
		{
			name:      "missing host",
			uri:       "https://",
			fieldName: "client_uri",
			wantErr:   true,
			errMsg:    "must have a host",
		},
		{
			name:      "ftp scheme not allowed",
			uri:       "ftp://example.com",
			fieldName: "client_uri",
			wantErr:   true,
			errMsg:    "must use https scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidateHTTPSURI(tt.uri, tt.fieldName)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRegistrationRequest_WithLogoURI(t *testing.T) {
	client := createTestClient(t)

	tests := []struct {
		name    string
		req     *ClientRegistrationRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid logo_uri",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				LogoURI:      "https://client.example.com/logo.png",
			},
			wantErr: false,
		},
		{
			name: "invalid logo_uri - http scheme",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				LogoURI:      "http://client.example.com/logo.png",
			},
			wantErr: true,
			errMsg:  "invalid logo_uri",
		},
		{
			name: "invalid logo_uri - has fragment",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				LogoURI:      "https://client.example.com/logo.png#main",
			},
			wantErr: true,
			errMsg:  "must not contain a fragment",
		},
		{
			name: "valid client_uri",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				ClientURI:    "https://client.example.com",
			},
			wantErr: false,
		},
		{
			name: "invalid client_uri - http scheme",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				ClientURI:    "http://client.example.com",
			},
			wantErr: true,
			errMsg:  "must use https scheme",
		},
		{
			name: "valid policy_uri",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				PolicyURI:    "https://client.example.com/privacy",
			},
			wantErr: false,
		},
		{
			name: "invalid policy_uri - has fragment",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				PolicyURI:    "https://client.example.com/privacy#data",
			},
			wantErr: true,
			errMsg:  "must not contain a fragment",
		},
		{
			name: "valid tos_uri",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				TosURI:       "https://client.example.com/terms",
			},
			wantErr: false,
		},
		{
			name: "invalid tos_uri - http scheme",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				TosURI:       "http://client.example.com/terms",
			},
			wantErr: true,
			errMsg:  "must use https scheme",
		},
		{
			name: "all metadata URIs valid",
			req: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://client.example.com/callback"},
				LogoURI:      "https://client.example.com/logo.png",
				ClientURI:    "https://client.example.com",
				PolicyURI:    "https://client.example.com/privacy",
				TosURI:       "https://client.example.com/terms",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateRegistrationRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
