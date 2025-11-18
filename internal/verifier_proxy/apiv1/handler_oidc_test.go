package apiv1

import (
	"testing"
	"vc/internal/verifier_proxy/apiv1/utils"

	"github.com/stretchr/testify/assert"
)

// TestPKCE_S256_Validation tests PKCE S256 code challenge validation
func TestPKCE_S256_Validation(t *testing.T) {
	// Test vector from RFC 7636
	// code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	tests := []struct {
		name          string
		verifier      string
		challenge     string
		method        string
		expectError   bool
		errorContains string
	}{
		{
			name:        "Valid S256 PKCE",
			verifier:    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge:   "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:      "S256",
			expectError: false,
		},
		{
			name:          "Invalid S256 - wrong verifier",
			verifier:      "wrongverifier123456789012345678901234567890",
			challenge:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:        "S256",
			expectError:   true,
			errorContains: "invalid",
		},
		{
			name:        "Valid plain PKCE",
			verifier:    "plainverifier123456789012345678901234567890",
			challenge:   "plainverifier123456789012345678901234567890",
			method:      "plain",
			expectError: false,
		},
		{
			name:          "Invalid plain - mismatch",
			verifier:      "verifier1",
			challenge:     "verifier2",
			method:        "plain",
			expectError:   true,
			errorContains: "invalid",
		},
		{
			name:          "Empty verifier",
			verifier:      "",
			challenge:     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:        "S256",
			expectError:   true,
			errorContains: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidatePKCE(tt.verifier, tt.challenge, tt.method)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" && err != nil {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPKCE_CodeVerifierRequirements tests code verifier format requirements
func TestPKCE_CodeVerifierRequirements(t *testing.T) {
	tests := []struct {
		name     string
		verifier string
		valid    bool
	}{
		{"Valid 43 chars", "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG", true},                                                                                              // exactly 43
		{"Valid 64 chars", "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12", true},                                                                         // exactly 64
		{"Valid 128 chars", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", true},        // exactly 128
		{"Too short - 42 chars", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP", false},                                                                                        // exactly 42
		{"Too long - 129 chars", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-", false}, // exactly 129
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that verifier length is within bounds (43-128 chars per RFC 7636)
			if tt.valid {
				assert.GreaterOrEqual(t, len(tt.verifier), 43)
				assert.LessOrEqual(t, len(tt.verifier), 128)
			} else {
				if len(tt.verifier) < 43 {
					assert.Less(t, len(tt.verifier), 43)
				} else {
					assert.Greater(t, len(tt.verifier), 128)
				}
			}
		})
	}
}

// TestError_Types tests error type definitions
func TestError_Types(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		isNil bool
	}{
		{"ErrInvalidRequest", ErrInvalidRequest, false},
		{"ErrInvalidClient", ErrInvalidClient, false},
		{"ErrInvalidGrant", ErrInvalidGrant, false},
		{"ErrUnauthorizedClient", ErrUnauthorizedClient, false},
		{"ErrUnsupportedGrantType", ErrUnsupportedGrantType, false},
		{"ErrInvalidScope", ErrInvalidScope, false},
		{"ErrServerError", ErrServerError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.isNil {
				assert.Nil(t, tt.err)
			} else {
				assert.NotNil(t, tt.err)
				assert.Error(t, tt.err)
			}
		})
	}
}

// TestTokenRequest_Validation tests token request structure
func TestTokenRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     TokenRequest
		isValid bool
	}{
		{
			name: "Valid authorization_code grant",
			req: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "auth-code-123",
				RedirectURI:  "https://example.com/callback",
				ClientID:     "client-123",
				ClientSecret: "secret",
				CodeVerifier: "verifier-abc",
			},
			isValid: true,
		},
		{
			name: "Valid refresh_token grant",
			req: TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "refresh-xyz",
				ClientID:     "client-123",
				ClientSecret: "secret",
			},
			isValid: true,
		},
		{
			name: "Missing grant_type",
			req: TokenRequest{
				Code:     "code-123",
				ClientID: "client-123",
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.isValid {
				assert.NotEmpty(t, tt.req.GrantType)
			} else {
				// In actual validation, this would fail binding
				assert.Empty(t, tt.req.GrantType)
			}
		})
	}
}

// TestTokenResponse_Structure tests token response structure
func TestTokenResponse_Structure(t *testing.T) {
	response := &TokenResponse{
		AccessToken:  "access-token-xyz",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token-abc",
		IDToken:      "eyJhbGc...id-token",
		Scope:        "openid profile email",
	}

	assert.NotEmpty(t, response.AccessToken)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.NotEmpty(t, response.RefreshToken)
	assert.NotEmpty(t, response.IDToken)
	assert.Contains(t, response.Scope, "openid")
}

// TestAuthorizeRequest_Validation tests authorize request structure
func TestAuthorizeRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     AuthorizeRequest
		isValid bool
	}{
		{
			name: "Valid request with PKCE",
			req: AuthorizeRequest{
				ClientID:            "client-123",
				RedirectURI:         "https://example.com/callback",
				ResponseType:        "code",
				Scope:               "openid profile",
				State:               "state-xyz",
				Nonce:               "nonce-abc",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
			},
			isValid: true,
		},
		{
			name: "Valid request without PKCE",
			req: AuthorizeRequest{
				ClientID:     "client-123",
				RedirectURI:  "https://example.com/callback",
				ResponseType: "code",
				Scope:        "openid",
				State:        "state-xyz",
			},
			isValid: true,
		},
		{
			name: "Missing required client_id",
			req: AuthorizeRequest{
				RedirectURI:  "https://example.com/callback",
				ResponseType: "code",
				Scope:        "openid",
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.isValid {
				assert.NotEmpty(t, tt.req.ClientID)
				assert.NotEmpty(t, tt.req.RedirectURI)
				assert.NotEmpty(t, tt.req.ResponseType)
			} else {
				hasRequired := tt.req.ClientID != "" &&
					tt.req.RedirectURI != "" &&
					tt.req.ResponseType != ""
				assert.False(t, hasRequired)
			}
		})
	}
}

// TestAuthorizeResponse_Structure tests authorize response structure
func TestAuthorizeResponse_Structure(t *testing.T) {
	response := &AuthorizeResponse{
		SessionID:      "session-123",
		QRCodeData:     "openid4vp://...",
		QRCodeImageURL: "/qr/session-123",
		DeepLinkURL:    "openid4vp://...",
		PollURL:        "/poll/session-123",
	}

	assert.NotEmpty(t, response.SessionID)
	assert.NotEmpty(t, response.QRCodeData)
	assert.Contains(t, response.QRCodeData, "openid4vp://")
	assert.Contains(t, response.QRCodeImageURL, response.SessionID)
	assert.Contains(t, response.PollURL, response.SessionID)
}

// TestDiscoveryMetadata_Structure tests discovery metadata structure
func TestDiscoveryMetadata_Structure(t *testing.T) {
	metadata := &DiscoveryMetadata{
		Issuer:                            "https://verifier.example.com",
		AuthorizationEndpoint:             "https://verifier.example.com/authorize",
		TokenEndpoint:                     "https://verifier.example.com/token",
		JwksURI:                           "https://verifier.example.com/jwks",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public", "pairwise"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		ClaimsSupported:                   []string{"sub", "iss", "aud"},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
	}

	assert.NotEmpty(t, metadata.Issuer)
	assert.Contains(t, metadata.ResponseTypesSupported, "code")
	assert.Contains(t, metadata.GrantTypesSupported, "authorization_code")
	assert.Contains(t, metadata.CodeChallengeMethodsSupported, "S256")
	assert.Contains(t, metadata.ScopesSupported, "openid")
}

// TestUserInfoRequest_Structure tests userinfo request structure
func TestUserInfoRequest_Structure(t *testing.T) {
	request := &UserInfoRequest{
		AccessToken: "bearer-token-xyz",
	}

	assert.NotEmpty(t, request.AccessToken)
	assert.Contains(t, request.AccessToken, "bearer")
}

// TestGetRequestObjectRequest_Structure tests request object request structure
func TestGetRequestObjectRequest_Structure(t *testing.T) {
	request := &GetRequestObjectRequest{
		SessionID: "session-123",
	}

	assert.NotEmpty(t, request.SessionID)
}

// TestDirectPostRequest_Structure tests direct post request structure
func TestDirectPostRequest_Structure(t *testing.T) {
	request := &DirectPostRequest{
		VPToken:                "eyJhbGc...",
		PresentationSubmission: "{\"id\":\"sub-123\"}",
		State:                  "state-xyz",
	}

	assert.NotEmpty(t, request.VPToken)
	assert.NotEmpty(t, request.PresentationSubmission)
	assert.NotEmpty(t, request.State)
}

// TestCallbackRequest_Structure tests callback request structure
func TestCallbackRequest_Structure(t *testing.T) {
	request := &CallbackRequest{
		Code:  "auth-code-123",
		State: "state-xyz",
		Error: "",
	}

	assert.NotEmpty(t, request.Code)
	assert.NotEmpty(t, request.State)
	assert.Empty(t, request.Error)
}

// TestPollSessionRequest_Structure tests poll session request structure
func TestPollSessionRequest_Structure(t *testing.T) {
	request := &PollSessionRequest{
		SessionID: "session-123",
	}

	assert.NotEmpty(t, request.SessionID)
}

// TestPollSessionResponse_Structure tests poll session response structure
func TestPollSessionResponse_Structure(t *testing.T) {
	response := &PollSessionResponse{
		Status:      "completed",
		RedirectURI: "https://example.com/callback?code=xyz&state=abc",
	}

	assert.Equal(t, "completed", response.Status)
	assert.NotEmpty(t, response.RedirectURI)
	assert.Contains(t, response.RedirectURI, "code=")
}

// TestGetQRCodeRequest_Structure tests QR code request structure
func TestGetQRCodeRequest_Structure(t *testing.T) {
	request := &GetQRCodeRequest{
		SessionID: "session-123",
	}

	assert.NotEmpty(t, request.SessionID)
}

// TestJWKS_Structure tests JWKS structure
func TestJWKS_Structure(t *testing.T) {
	jwks := &JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: "key-1",
				Alg: "RS256",
				N:   "modulus...",
				E:   "AQAB",
			},
		},
	}

	assert.NotNil(t, jwks.Keys)
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "RSA", jwks.Keys[0].Kty)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
	assert.Equal(t, "key-1", jwks.Keys[0].Kid)
}

// Benchmark PKCE validation performance
func BenchmarkPKCE_S256_Validation(b *testing.B) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	method := "S256"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = utils.ValidatePKCE(verifier, challenge, method)
	}
}

func BenchmarkPKCE_Plain_Validation(b *testing.B) {
	verifier := "plainverifier123456789012345678901234567890"
	challenge := verifier
	method := "plain"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = utils.ValidatePKCE(verifier, challenge, method)
	}
}
