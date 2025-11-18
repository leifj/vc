package apiv1

import (
	"testing"
	"vc/internal/verifier_proxy/apiv1/utils"
	"vc/internal/verifier_proxy/db"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// TestGenerateSessionID tests that session IDs are generated correctly
func TestGenerateSessionID(t *testing.T) {
	client := createTestClient(t)

	id1 := client.generateSessionID()
	id2 := client.generateSessionID()

	// Should generate non-empty IDs
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)

	// Should be 64 characters (32 bytes hex encoded)
	assert.Len(t, id1, 64)
	assert.Len(t, id2, 64)

	// Should be unique
	assert.NotEqual(t, id1, id2)
}

// TestGenerateAuthorizationCode tests authorization code generation
func TestGenerateAuthorizationCode(t *testing.T) {
	client := createTestClient(t)

	code1 := client.generateAuthorizationCode()
	code2 := client.generateAuthorizationCode()

	// Should generate non-empty codes
	assert.NotEmpty(t, code1)
	assert.NotEmpty(t, code2)

	// Should be 32 characters (fixed length)
	assert.Len(t, code1, 32)
	assert.Len(t, code2, 32)

	// Should be unique
	assert.NotEqual(t, code1, code2)
}

// TestGenerateAccessToken tests access token generation
func TestGenerateAccessToken(t *testing.T) {
	client := createTestClient(t)

	token1 := client.generateAccessToken()
	token2 := client.generateAccessToken()

	// Should generate non-empty tokens
	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)

	// Should be 32 characters
	assert.Len(t, token1, 32)
	assert.Len(t, token2, 32)

	// Should be unique
	assert.NotEqual(t, token1, token2)
}

// TestGenerateRefreshToken tests refresh token generation
func TestGenerateRefreshToken(t *testing.T) {
	client := createTestClient(t)

	token1 := client.generateRefreshToken()
	token2 := client.generateRefreshToken()

	// Should generate non-empty tokens
	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)

	// Should be 32 characters
	assert.Len(t, token1, 32)
	assert.Len(t, token2, 32)

	// Should be unique
	assert.NotEqual(t, token1, token2)
}

// TestGenerateSubjectIdentifier_Public tests public subject identifier generation
func TestGenerateSubjectIdentifier_Public(t *testing.T) {
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				SubjectType: "public",
				SubjectSalt: "test-salt-123",
			},
		},
	}

	client := createTestClientWithConfig(t, cfg)

	walletID := "wallet-123"
	clientID1 := "client-1"
	clientID2 := "client-2"

	// Public subject should be same for same wallet across different clients
	sub1 := client.generateSubjectIdentifier(walletID, clientID1)
	sub2 := client.generateSubjectIdentifier(walletID, clientID2)

	assert.NotEmpty(t, sub1)
	assert.NotEmpty(t, sub2)
	assert.Equal(t, sub1, sub2, "Public subject identifiers should be same across clients")

	// Verify it's deterministic
	sub3 := client.generateSubjectIdentifier(walletID, clientID1)
	assert.Equal(t, sub1, sub3)

	// Different wallet should produce different subject
	sub4 := client.generateSubjectIdentifier("wallet-456", clientID1)
	assert.NotEqual(t, sub1, sub4)
}

// TestGenerateSubjectIdentifier_Pairwise tests pairwise subject identifier generation
func TestGenerateSubjectIdentifier_Pairwise(t *testing.T) {
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				SubjectType: "pairwise",
				SubjectSalt: "test-salt-456",
			},
		},
	}

	client := createTestClientWithConfig(t, cfg)

	walletID := "wallet-789"
	clientID1 := "client-1"
	clientID2 := "client-2"

	// Pairwise subject should be different for same wallet across different clients
	sub1 := client.generateSubjectIdentifier(walletID, clientID1)
	sub2 := client.generateSubjectIdentifier(walletID, clientID2)

	assert.NotEmpty(t, sub1)
	assert.NotEmpty(t, sub2)
	assert.NotEqual(t, sub1, sub2, "Pairwise subject identifiers should differ across clients")

	// Verify it's deterministic for same wallet+client pair
	sub3 := client.generateSubjectIdentifier(walletID, clientID1)
	assert.Equal(t, sub1, sub3)

	// Different wallet should produce different subject
	sub4 := client.generateSubjectIdentifier("wallet-999", clientID1)
	assert.NotEqual(t, sub1, sub4)
}

// TestGenerateSubjectIdentifier_DifferentSalts tests that salt affects subject
func TestGenerateSubjectIdentifier_DifferentSalts(t *testing.T) {
	cfg1 := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				SubjectType: "public",
				SubjectSalt: "salt-1",
			},
		},
	}

	cfg2 := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				SubjectType: "public",
				SubjectSalt: "salt-2",
			},
		},
	}

	client1 := createTestClientWithConfig(t, cfg1)
	client2 := createTestClientWithConfig(t, cfg2)

	walletID := "wallet-123"
	clientID := "client-1"

	sub1 := client1.generateSubjectIdentifier(walletID, clientID)
	sub2 := client2.generateSubjectIdentifier(walletID, clientID)

	assert.NotEqual(t, sub1, sub2, "Different salts should produce different subjects")
}

// TestValidateRedirectURI tests redirect URI validation
func TestValidateRedirectURI(t *testing.T) {
	allowedURIs := []string{
		"https://example.com/callback",
		"https://app.example.com/auth",
		"http://localhost:8080/callback",
	}

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{"Valid exact match", "https://example.com/callback", true},
		{"Valid second URI", "https://app.example.com/auth", true},
		{"Valid localhost", "http://localhost:8080/callback", true},
		{"Invalid - not in list", "https://evil.com/callback", false},
		{"Invalid - different path", "https://example.com/different", false},
		{"Invalid - different port", "http://localhost:9090/callback", false},
		{"Invalid - empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.ValidateRedirectURI(tt.uri, allowedURIs)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidateScopes tests scope validation
func TestValidateScopes(t *testing.T) {
	allowedScopes := []string{"openid", "profile", "email", "pid"}

	tests := []struct {
		name      string
		requested []string
		expected  bool
	}{
		{"Valid single scope", []string{"openid"}, true},
		{"Valid multiple scopes", []string{"openid", "profile"}, true},
		{"Valid all allowed scopes", []string{"openid", "profile", "email", "pid"}, true},
		{"Invalid scope", []string{"admin"}, false},
		{"Valid and invalid mixed", []string{"openid", "admin"}, false},
		{"Empty requested", []string{}, true},
		{"Nil requested", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.ValidateScopes(tt.requested, allowedScopes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestContains tests the contains helper function
func TestContains(t *testing.T) {
	client := createTestClient(t)

	slice := []string{"apple", "banana", "cherry"}

	tests := []struct {
		name     string
		item     string
		expected bool
	}{
		{"Contains first", "apple", true},
		{"Contains middle", "banana", true},
		{"Contains last", "cherry", true},
		{"Does not contain", "orange", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.contains(slice, tt.item)
			assert.Equal(t, tt.expected, result)
		})
	}

	// Test with empty slice
	assert.False(t, client.contains([]string{}, "anything"))

	// Test with nil slice
	assert.False(t, client.contains(nil, "anything"))
}

// TestAuthenticateClient tests client authentication
func TestAuthenticateClient(t *testing.T) {
	client := createTestClient(t)

	// Create a client with a hashed secret
	secret := "my-secret-password"
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	assert.NoError(t, err)

	dbClient := &db.Client{
		ClientID:         "test-client",
		ClientSecretHash: string(hashedSecret),
	}

	tests := []struct {
		name        string
		secret      string
		expectError bool
	}{
		{"Valid secret", secret, false},
		{"Invalid secret", "wrong-password", true},
		{"Empty secret", "", true},
		{"Similar but wrong secret", "my-secret-passwor", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.authenticateClient(dbClient, tt.secret)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAuthenticateClient_EmptyHash tests authentication with no client secret set
func TestAuthenticateClient_EmptyHash(t *testing.T) {
	client := createTestClient(t)

	dbClient := &db.Client{
		ClientID:         "public-client",
		ClientSecretHash: "", // Public client - no secret
	}

	// Should fail when secret hash is empty but secret is provided
	err := client.authenticateClient(dbClient, "any-secret")
	assert.Error(t, err)
}

// Helper functions for creating test clients

func createTestClient(t *testing.T) *Client {
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
		},
	}
	return createTestClientWithConfig(t, cfg)
}

func createTestClientWithConfig(t *testing.T, cfg *model.Cfg) *Client {
	log := logger.NewSimple("test")

	client := &Client{
		cfg:    cfg,
		db:     nil, // Not needed for these unit tests
		log:    log.New("apiv1"),
		tracer: nil, // Not needed for these unit tests
	}

	return client
}

// TestGenerateNonce tests nonce generation from handler_openid4vp.go
func TestGenerateNonce(t *testing.T) {
	client := createTestClient(t)

	nonce1 := client.generateNonce()
	nonce2 := client.generateNonce()

	// Should generate non-empty nonces
	assert.NotEmpty(t, nonce1)
	assert.NotEmpty(t, nonce2)

	// Should be unique
	assert.NotEqual(t, nonce1, nonce2)

	// Should be at least 16 characters (cryptographically secure)
	assert.GreaterOrEqual(t, len(nonce1), 16)
	assert.GreaterOrEqual(t, len(nonce2), 16)
}

// TestCreateAuthorizationRequestURI tests request URI generation
func TestCreateAuthorizationRequestURI(t *testing.T) {
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "https://verifier.example.com",
		},
	}

	client := createTestClientWithConfig(t, cfg)
	client.cfg.VerifierProxy.OIDC.Issuer = "https://verifier.example.com"
	sessionID := "test-session-123"

	uri, err := client.createAuthorizationRequestURI(sessionID)
	assert.NoError(t, err)

	// Should return OpenID4VP URL with request_uri parameter
	assert.Contains(t, uri, "openid4vp://")
	assert.Contains(t, uri, "request_uri=")
	assert.Contains(t, uri, "test-session-123")
}

// TestCreateAuthorizationRequestURI_EmptyBaseURL tests handling of missing base URL
func TestCreateAuthorizationRequestURI_EmptyBaseURL(t *testing.T) {
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "",
		},
	}

	client := createTestClientWithConfig(t, cfg)
	sessionID := "test-session-123"

	uri, err := client.createAuthorizationRequestURI(sessionID)
	assert.NoError(t, err)

	// Should include request_uri parameter even without base URL
	assert.Contains(t, uri, "openid4vp://")
	assert.Contains(t, uri, "request_uri=")
	assert.Contains(t, uri, "test-session-123")
}

// Benchmark tests for performance-critical functions

func BenchmarkGenerateSessionID(b *testing.B) {
	log := logger.NewSimple("bench")
	client := &Client{log: log.New("apiv1")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.generateSessionID()
	}
}

func BenchmarkGenerateAuthorizationCode(b *testing.B) {
	log := logger.NewSimple("bench")
	client := &Client{log: log.New("apiv1")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.generateAuthorizationCode()
	}
}

func BenchmarkGenerateSubjectIdentifier_Public(b *testing.B) {
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				SubjectType: "public",
				SubjectSalt: "benchmark-salt",
			},
		},
	}
	log := logger.NewSimple("bench")
	client := &Client{
		cfg: cfg,
		log: log.New("apiv1"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.generateSubjectIdentifier("wallet-123", "client-456")
	}
}

func BenchmarkGenerateSubjectIdentifier_Pairwise(b *testing.B) {
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				SubjectType: "pairwise",
				SubjectSalt: "benchmark-salt",
			},
		},
	}
	log := logger.NewSimple("bench")
	client := &Client{
		cfg: cfg,
		log: log.New("apiv1"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.generateSubjectIdentifier("wallet-123", "client-456")
	}
}

func BenchmarkAuthenticateClient(b *testing.B) {
	log := logger.NewSimple("bench")
	client := &Client{log: log.New("apiv1")}

	secret := "benchmark-password"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	dbClient := &db.Client{
		ClientID:         "bench-client",
		ClientSecretHash: string(hashedSecret),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.authenticateClient(dbClient, secret)
	}
}
