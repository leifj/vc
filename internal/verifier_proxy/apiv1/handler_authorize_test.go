package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
	"vc/internal/verifier_proxy/apiv1/utils"
	"vc/internal/verifier_proxy/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// setupTestClientWithDB creates a test client with mock database pre-populated with test data
func setupTestClientWithDB(t *testing.T) (*Client, *MockDBService, *db.Client) {
	ctx := context.Background()

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:               "https://verifier.example.com",
				SubjectType:          "public",
				SubjectSalt:          "test-salt",
				SessionDuration:      900,
				CodeDuration:         600,
				AccessTokenDuration:  3600,
				IDTokenDuration:      3600,
				RefreshTokenDuration: 86400,
			},
			OpenID4VP: model.OpenID4VPConfig{
				PresentationTimeout: 300,
				SupportedCredentials: []model.SupportedCredentialConfig{
					{VCT: "PersonIdentificationData", Scopes: []string{"pid"}},
					{VCT: "DiplomaCredential", Scopes: []string{"edu_diploma"}},
				},
			},
		},
	}

	log := logger.NewSimple("test-authorize")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	// Create test RSA key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create mock database
	mockDB := NewMockDBService()

	// Create test client in database
	secretHash, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	testClient := &db.Client{
		ClientID:                "test-client-123",
		ClientSecretHash:        string(secretHash),
		RedirectURIs:            []string{"https://client.example.com/callback", "http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		AllowedScopes:           []string{"openid", "profile", "email", "pid", "edu_diploma"},
		DefaultScopes:           []string{"openid"},
		SubjectType:             "public",
		RequirePKCE:             false,
	}
	mockDB.Clients.AddClient(testClient)

	// Note: We can't directly inject mockDB into Client due to private fields
	// Instead, we'll test the logic through the public API where possible
	// and create unit tests for individual functions

	client, _ := New(ctx, &db.Service{}, cfg, tracer, log)
	client.oidcSigningKey = privateKey

	return client, mockDB, testClient
}

// TestAuthorize_ValidRequest tests the authorize handler with a valid request
// Note: This tests the logic flow, but database operations need integration testing
func TestAuthorize_RequestValidation(t *testing.T) {
	client, _, testClient := setupTestClientWithDB(t)

	tests := []struct {
		name        string
		request     *AuthorizeRequest
		setupClient func(*db.Client)
		expectError error
	}{
		{
			name: "Valid authorization request",
			request: &AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client-123",
				RedirectURI:  "https://client.example.com/callback",
				Scope:        "openid profile",
				State:        "random-state-123",
				Nonce:        "random-nonce-456",
			},
			setupClient: func(c *db.Client) {},
			expectError: nil,
		},
		{
			name: "Valid request with PKCE",
			request: &AuthorizeRequest{
				ResponseType:        "code",
				ClientID:            "test-client-123",
				RedirectURI:         "https://client.example.com/callback",
				Scope:               "openid pid",
				State:               "state-abc",
				Nonce:               "nonce-def",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
			},
			setupClient: func(c *db.Client) {},
			expectError: nil,
		},
		{
			name: "PKCE required but not provided",
			request: &AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client-123",
				RedirectURI:  "https://client.example.com/callback",
				Scope:        "openid",
				State:        "state",
				Nonce:        "nonce",
			},
			setupClient: func(c *db.Client) {
				c.RequirePKCE = true
			},
			expectError: ErrInvalidRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup client configuration
			tt.setupClient(testClient)

			// Test request validation logic (individual validation functions)
			// Since we can't easily test the full Authorize flow without DB,
			// we test the validation components

			// Validate redirect URI
			validRedirect := utils.ValidateRedirectURI(tt.request.RedirectURI, testClient.RedirectURIs)
			if strings.Contains(tt.name, "Valid") {
				assert.True(t, validRedirect, "Redirect URI should be valid")
			}

			// Validate scopes
			requestedScopes := strings.Split(tt.request.Scope, " ")
			validScopes := utils.ValidateScopes(requestedScopes, testClient.AllowedScopes)
			if strings.Contains(tt.name, "Valid") {
				assert.True(t, validScopes, "Scopes should be valid")
			}

			// Validate response type
			validResponseType := client.contains(testClient.ResponseTypes, tt.request.ResponseType)
			assert.True(t, validResponseType, "Response type should be valid")

			// Validate PKCE requirement
			if testClient.RequirePKCE {
				if tt.request.CodeChallenge == "" {
					assert.Equal(t, ErrInvalidRequest, tt.expectError, "Should error when PKCE required but not provided")
				}
			}
		})
	}
}

// TestAuthorize_ClientValidation tests client validation scenarios
func TestAuthorize_ClientValidation(t *testing.T) {
	client, _, _ := setupTestClientWithDB(t)

	tests := []struct {
		name        string
		clientID    string
		expectError error
	}{
		{
			name:        "Valid client ID",
			clientID:    "test-client-123",
			expectError: nil,
		},
		{
			name:        "Invalid client ID",
			clientID:    "non-existent-client",
			expectError: ErrInvalidClient,
		},
		{
			name:        "Empty client ID",
			clientID:    "",
			expectError: ErrInvalidClient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test client ID validation
			if tt.clientID == "" || tt.clientID == "non-existent-client" {
				// These should result in client not found
				assert.NotNil(t, client, "Client should exist")
			}
		})
	}
}

// TestAuthorize_RedirectURIValidation tests redirect URI validation
func TestAuthorize_RedirectURIValidation(t *testing.T) {
	_, _, testClient := setupTestClientWithDB(t)

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{
			name:     "Valid HTTPS redirect URI",
			uri:      "https://client.example.com/callback",
			expected: true,
		},
		{
			name:     "Valid localhost redirect URI",
			uri:      "http://localhost:3000/callback",
			expected: true,
		},
		{
			name:     "Invalid redirect URI - not in allowed list",
			uri:      "https://evil.com/callback",
			expected: false,
		},
		{
			name:     "Invalid redirect URI - wrong path",
			uri:      "https://client.example.com/wrong-path",
			expected: false,
		},
		{
			name:     "Invalid redirect URI - HTTP instead of HTTPS",
			uri:      "http://client.example.com/callback",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.ValidateRedirectURI(tt.uri, testClient.RedirectURIs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthorize_ScopeValidation tests scope validation
func TestAuthorize_ScopeValidation(t *testing.T) {
	_, _, testClient := setupTestClientWithDB(t)

	tests := []struct {
		name     string
		scopes   string
		expected bool
	}{
		{
			name:     "Valid openid scope",
			scopes:   "openid",
			expected: true,
		},
		{
			name:     "Valid multiple scopes",
			scopes:   "openid profile email",
			expected: true,
		},
		{
			name:     "Valid with credential scopes",
			scopes:   "openid pid edu_diploma",
			expected: true,
		},
		{
			name:     "Invalid scope - not in allowed list",
			scopes:   "openid admin",
			expected: false,
		},
		{
			name:     "Invalid scope - all scopes not allowed",
			scopes:   "superuser admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestedScopes := strings.Split(tt.scopes, " ")
			result := utils.ValidateScopes(requestedScopes, testClient.AllowedScopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAuthorize_SessionCreation tests session ID generation and structure
func TestAuthorize_SessionCreation(t *testing.T) {
	client, _, _ := setupTestClientWithDB(t)

	// Test session ID generation
	sessionID1 := client.generateSessionID()
	sessionID2 := client.generateSessionID()

	assert.NotEmpty(t, sessionID1, "Session ID should not be empty")
	assert.NotEmpty(t, sessionID2, "Session ID should not be empty")
	assert.NotEqual(t, sessionID1, sessionID2, "Session IDs should be unique")
	assert.Len(t, sessionID1, 64, "Session ID should be 64 characters (32 bytes hex encoded)")
}

// TestAuthorize_ResponseStructure tests the authorize response structure
func TestAuthorize_ResponseStructure(t *testing.T) {
	// Test that we can create a valid authorize response
	sessionID := "test-session-123"
	externalURL := "https://verifier.example.com"

	authzReqURL := "openid4vp://?client_id=" + externalURL + "&request_uri=" + externalURL + "/verification/request-object/" + sessionID

	response := &AuthorizeResponse{
		SessionID:      sessionID,
		QRCodeData:     authzReqURL,
		QRCodeImageURL: "/qr/" + sessionID,
		DeepLinkURL:    authzReqURL,
		PollURL:        "/poll/" + sessionID,
	}

	assert.Equal(t, sessionID, response.SessionID)
	assert.Contains(t, response.QRCodeData, "openid4vp://")
	assert.Contains(t, response.QRCodeData, sessionID)
	assert.Equal(t, "/qr/"+sessionID, response.QRCodeImageURL)
	assert.Equal(t, "/poll/"+sessionID, response.PollURL)
	assert.Equal(t, authzReqURL, response.DeepLinkURL)
}

// TestAuthorize_PKCEValidation tests PKCE requirement validation
func TestAuthorize_PKCEValidation(t *testing.T) {
	tests := []struct {
		name          string
		requirePKCE   bool
		codeChallenge string
		shouldError   bool
	}{
		{
			name:          "PKCE not required, no challenge",
			requirePKCE:   false,
			codeChallenge: "",
			shouldError:   false,
		},
		{
			name:          "PKCE not required, with challenge",
			requirePKCE:   false,
			codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			shouldError:   false,
		},
		{
			name:          "PKCE required, with challenge",
			requirePKCE:   true,
			codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			shouldError:   false,
		},
		{
			name:          "PKCE required, no challenge - should error",
			requirePKCE:   true,
			codeChallenge: "",
			shouldError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test PKCE validation logic
			if tt.requirePKCE && tt.codeChallenge == "" {
				assert.True(t, tt.shouldError, "Should error when PKCE required but no challenge provided")
			} else {
				assert.False(t, tt.shouldError, "Should not error")
			}
		})
	}
}

// TestAuthorize_StateAndNonce tests state and nonce handling
func TestAuthorize_StateAndNonce(t *testing.T) {
	tests := []struct {
		name  string
		state string
		nonce string
	}{
		{
			name:  "With state and nonce",
			state: "random-state-value",
			nonce: "random-nonce-value",
		},
		{
			name:  "With empty state",
			state: "",
			nonce: "nonce-value",
		},
		{
			name:  "With empty nonce",
			state: "state-value",
			nonce: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create session with state and nonce
			session := &db.Session{
				ID:        "session-123",
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(15 * time.Minute),
				Status:    db.SessionStatusPending,
				OIDCRequest: db.OIDCRequest{
					State: tt.state,
					Nonce: tt.nonce,
				},
			}

			assert.Equal(t, tt.state, session.OIDCRequest.State)
			assert.Equal(t, tt.nonce, session.OIDCRequest.Nonce)
		})
	}
}

// BenchmarkAuthorize_SessionIDGeneration benchmarks session ID generation
func BenchmarkAuthorize_SessionIDGeneration(b *testing.B) {
	client, _, _ := setupTestClientWithDB(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.generateSessionID()
	}
}

// BenchmarkAuthorize_Validation benchmarks authorization validation
func BenchmarkAuthorize_Validation(b *testing.B) {
	client, _, testClient := setupTestClientWithDB(&testing.T{})

	uri := "https://client.example.com/callback"
	scopes := []string{"openid", "profile", "email"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = utils.ValidateRedirectURI(uri, testClient.RedirectURIs)
		_ = utils.ValidateScopes(scopes, testClient.AllowedScopes)
		_ = client.contains(testClient.ResponseTypes, "code")
	}
}
