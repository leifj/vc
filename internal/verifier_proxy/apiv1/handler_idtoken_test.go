package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
	"vc/internal/verifier_proxy/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// generateTestRSAKey generates an RSA key pair for testing
func generateTestRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// TestGenerateIDToken tests ID token generation with various claims
func TestGenerateIDToken(t *testing.T) {
	ctx := context.Background()

	// Generate test RSA key
	privateKey, err := generateTestRSAKey()
	if err != nil {
		t.Fatalf("Failed to generate test RSA key: %v", err)
	}

	// Create test client with signing key
	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:          "https://verifier.example.com",
				SigningAlg:      "RS256",
				IDTokenDuration: 3600, // 1 hour
				SubjectType:     "public",
				SubjectSalt:     "test-salt-12345",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, err := New(ctx, nil, cfg, tracer, log)
	assert.NoError(t, err)

	// Set the signing key
	client.oidcSigningKey = privateKey
	client.oidcSigningAlg = "RS256"

	// Create test session with minimal claims
	session := &db.Session{
		OIDCRequest: db.OIDCRequest{
			Nonce: "test-nonce-123",
		},
		OpenID4VP: db.OpenID4VPSession{
			WalletID: "test-wallet-id",
		},
		VerifiedClaims: map[string]any{
			"given_name":  "John",
			"family_name": "Doe",
			"email":       "john.doe@example.com",
		},
	}

	testClient := &db.Client{
		ClientID: "test-client-123",
	}

	// Test ID token generation
	tokenString, err := client.generateIDToken(session, testClient)
	assert.NoError(t, err, "generateIDToken should not error")
	assert.NotEmpty(t, tokenString, "Token string should not be empty")

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &privateKey.PublicKey, nil
	})

	assert.NoError(t, err, "Token should parse successfully")
	assert.True(t, token.Valid, "Token should be valid")

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok, "Claims should be MapClaims")

	// Verify standard claims
	assert.Equal(t, "https://verifier.example.com", claims["iss"], "Issuer should match")
	assert.Equal(t, "test-client-123", claims["aud"], "Audience should match client ID")
	assert.Equal(t, "test-nonce-123", claims["nonce"], "Nonce should match")
	assert.NotEmpty(t, claims["sub"], "Subject should be present")
	assert.NotEmpty(t, claims["iat"], "Issued at should be present")
	assert.NotEmpty(t, claims["exp"], "Expiration should be present")

	// Verify custom claims from verified data
	assert.Equal(t, "John", claims["given_name"], "Given name should be in claims")
	assert.Equal(t, "Doe", claims["family_name"], "Family name should be in claims")
	assert.Equal(t, "john.doe@example.com", claims["email"], "Email should be in claims")

	// Verify expiration is in the future
	exp, ok := claims["exp"].(float64)
	assert.True(t, ok, "Expiration should be a number")
	assert.Greater(t, exp, float64(time.Now().Unix()), "Expiration should be in the future")
}

// TestGenerateIDToken_PairwiseSubject tests pairwise subject identifier
func TestGenerateIDToken_PairwiseSubject(t *testing.T) {
	ctx := context.Background()

	privateKey, err := generateTestRSAKey()
	assert.NoError(t, err)

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:          "https://verifier.example.com",
				SigningAlg:      "RS256",
				IDTokenDuration: 3600,
				SubjectType:     "pairwise",
				SubjectSalt:     "test-salt-pairwise",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, err := New(ctx, nil, cfg, tracer, log)
	assert.NoError(t, err)

	client.oidcSigningKey = privateKey

	session := &db.Session{
		OIDCRequest: db.OIDCRequest{
			Nonce: "nonce-1",
		},
		OpenID4VP: db.OpenID4VPSession{
			WalletID: "wallet-123",
		},
		VerifiedClaims: map[string]any{},
	}

	client1 := &db.Client{ClientID: "client-1"}
	client2 := &db.Client{ClientID: "client-2"}

	// Generate tokens for same wallet, different clients
	token1, err := client.generateIDToken(session, client1)
	assert.NoError(t, err)

	token2, err := client.generateIDToken(session, client2)
	assert.NoError(t, err)

	// Parse both tokens
	parsedToken1, _ := jwt.Parse(token1, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	parsedToken2, _ := jwt.Parse(token2, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	claims1 := parsedToken1.Claims.(jwt.MapClaims)
	claims2 := parsedToken2.Claims.(jwt.MapClaims)

	// For pairwise, subjects should be different for different clients
	sub1 := claims1["sub"].(string)
	sub2 := claims2["sub"].(string)
	assert.NotEqual(t, sub1, sub2, "Pairwise subjects should differ for different clients")
}

// TestGenerateIDToken_EmptyVerifiedClaims tests with no verified claims
func TestGenerateIDToken_EmptyVerifiedClaims(t *testing.T) {
	ctx := context.Background()

	privateKey, err := generateTestRSAKey()
	assert.NoError(t, err)

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:          "https://example.com",
				SigningAlg:      "RS256",
				IDTokenDuration: 3600,
				SubjectType:     "public",
				SubjectSalt:     "salt",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, _ := New(ctx, nil, cfg, tracer, log)
	client.oidcSigningKey = privateKey

	session := &db.Session{
		OIDCRequest: db.OIDCRequest{
			Nonce: "test-nonce",
		},
		OpenID4VP: db.OpenID4VPSession{
			WalletID: "wallet-1",
		},
		VerifiedClaims: map[string]any{}, // Empty claims
	}

	testClient := &db.Client{ClientID: "client-1"}

	tokenString, err := client.generateIDToken(session, testClient)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Parse token
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	claims := token.Claims.(jwt.MapClaims)

	// Should only have standard OIDC claims
	assert.Contains(t, claims, "iss")
	assert.Contains(t, claims, "sub")
	assert.Contains(t, claims, "aud")
	assert.Contains(t, claims, "exp")
	assert.Contains(t, claims, "iat")
	assert.Contains(t, claims, "nonce")

	// Should not have custom claims
	assert.NotContains(t, claims, "given_name")
	assert.NotContains(t, claims, "email")
}

// TestGenerateIDToken_ComplexClaims tests with various claim types
func TestGenerateIDToken_ComplexClaims(t *testing.T) {
	ctx := context.Background()

	privateKey, err := generateTestRSAKey()
	assert.NoError(t, err)

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:          "https://example.com",
				SigningAlg:      "RS256",
				IDTokenDuration: 3600,
				SubjectType:     "public",
				SubjectSalt:     "salt",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, _ := New(ctx, nil, cfg, tracer, log)
	client.oidcSigningKey = privateKey

	session := &db.Session{
		OIDCRequest: db.OIDCRequest{
			Nonce: "test-nonce",
		},
		OpenID4VP: db.OpenID4VPSession{
			WalletID: "wallet-1",
		},
		VerifiedClaims: map[string]any{
			"name":           "John Doe",
			"email":          "john@example.com",
			"email_verified": true,
			"age":            30,
			"address": map[string]any{
				"street":  "123 Main St",
				"city":    "Springfield",
				"country": "US",
			},
			"roles": []string{"user", "admin"},
		},
	}

	testClient := &db.Client{ClientID: "client-1"}

	tokenString, err := client.generateIDToken(session, testClient)
	assert.NoError(t, err)

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	claims := token.Claims.(jwt.MapClaims)

	// Verify complex claims are preserved
	assert.Equal(t, "John Doe", claims["name"])
	assert.Equal(t, "john@example.com", claims["email"])
	assert.Equal(t, true, claims["email_verified"])
	assert.Equal(t, float64(30), claims["age"]) // JSON numbers become float64

	// Verify nested object
	address, ok := claims["address"].(map[string]any)
	assert.True(t, ok, "Address should be a map")
	assert.Equal(t, "123 Main St", address["street"])
	assert.Equal(t, "Springfield", address["city"])

	// Verify array
	roles, ok := claims["roles"].([]any)
	assert.True(t, ok, "Roles should be an array")
	assert.Len(t, roles, 2)
}

// BenchmarkGenerateIDToken benchmarks ID token generation
func BenchmarkGenerateIDToken(b *testing.B) {
	ctx := context.Background()
	privateKey, _ := generateTestRSAKey()

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:          "https://example.com",
				SigningAlg:      "RS256",
				IDTokenDuration: 3600,
				SubjectType:     "public",
				SubjectSalt:     "salt",
			},
		},
	}

	log := logger.NewSimple("test-idtoken")
	tracer, _ := trace.NewForTesting(ctx, "test", log)

	client, _ := New(ctx, nil, cfg, tracer, log)
	client.oidcSigningKey = privateKey

	session := &db.Session{
		OIDCRequest: db.OIDCRequest{Nonce: "nonce"},
		OpenID4VP:   db.OpenID4VPSession{WalletID: "wallet"},
		VerifiedClaims: map[string]any{
			"name":  "John Doe",
			"email": "john@example.com",
		},
	}

	testClient := &db.Client{ClientID: "client-1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.generateIDToken(session, testClient)
	}
}

// TestConfigurableTokenExpiration tests that ID token expiration is configurable
func TestConfigurableTokenExpiration(t *testing.T) {
	ctx := context.Background()

	privateKey, err := generateTestRSAKey()
	assert.NoError(t, err)

	tests := []struct {
		name            string
		idTokenDuration int // in seconds
		expectedTTL     time.Duration
	}{
		{
			name:            "1 hour expiration",
			idTokenDuration: 3600,
			expectedTTL:     time.Hour,
		},
		{
			name:            "30 minute expiration",
			idTokenDuration: 1800,
			expectedTTL:     30 * time.Minute,
		},
		{
			name:            "5 minute expiration",
			idTokenDuration: 300,
			expectedTTL:     5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				VerifierProxy: model.VerifierProxy{
					OIDC: model.OIDCConfig{
						Issuer:          "https://verifier.example.com",
						IDTokenDuration: tt.idTokenDuration,
						SubjectType:     "public",
						SubjectSalt:     "test-salt",
					},
				},
			}

			log := logger.NewSimple("test")
			tracer, _ := trace.NewForTesting(ctx, "test", log)
			client, _ := New(ctx, nil, cfg, tracer, log)
			client.oidcSigningKey = privateKey

			session := &db.Session{
				OIDCRequest:    db.OIDCRequest{Nonce: "nonce"},
				OpenID4VP:      db.OpenID4VPSession{WalletID: "wallet"},
				VerifiedClaims: map[string]any{},
			}
			testClient := &db.Client{ClientID: "client"}

			before := time.Now()
			tokenString, err := client.generateIDToken(session, testClient)
			assert.NoError(t, err)

			// Parse token to check expiration
			token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return &privateKey.PublicKey, nil
			})

			claims := token.Claims.(jwt.MapClaims)
			exp := int64(claims["exp"].(float64))
			iat := int64(claims["iat"].(float64))

			actualTTL := time.Duration(exp-iat) * time.Second
			assert.Equal(t, tt.expectedTTL, actualTTL, "Token expiration should match configured duration")

			// Verify expiration is in the future
			expirationTime := time.Unix(exp, 0)
			assert.True(t, expirationTime.After(before), "Token should not be expired")
		})
	}
}

// TestConfigurableSigningAlgorithm tests that signing algorithm is configurable
func TestConfigurableSigningAlgorithm(t *testing.T) {
	ctx := context.Background()

	privateKey, err := generateTestRSAKey()
	assert.NoError(t, err)

	tests := []struct {
		name            string
		signingAlg      string
		expectedMethod  jwt.SigningMethod
		expectedAlgName string
	}{
		{
			name:            "RS256 algorithm",
			signingAlg:      "RS256",
			expectedMethod:  jwt.SigningMethodRS256,
			expectedAlgName: "RS256",
		},
		{
			name:            "RS384 algorithm",
			signingAlg:      "RS384",
			expectedMethod:  jwt.SigningMethodRS384,
			expectedAlgName: "RS384",
		},
		{
			name:            "RS512 algorithm",
			signingAlg:      "RS512",
			expectedMethod:  jwt.SigningMethodRS512,
			expectedAlgName: "RS512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				VerifierProxy: model.VerifierProxy{
					OIDC: model.OIDCConfig{
						Issuer:          "https://verifier.example.com",
						SigningAlg:      tt.signingAlg,
						IDTokenDuration: 3600,
						SubjectType:     "public",
						SubjectSalt:     "test-salt",
					},
				},
			}

			log := logger.NewSimple("test")
			tracer, _ := trace.NewForTesting(ctx, "test", log)
			client, _ := New(ctx, nil, cfg, tracer, log)
			client.oidcSigningKey = privateKey

			// Test getSigningMethod returns correct algorithm
			signingMethod := client.getSigningMethod()
			assert.Equal(t, tt.expectedMethod, signingMethod, "Signing method should match configured algorithm")

			// Generate token and verify algorithm in header
			session := &db.Session{
				OIDCRequest:    db.OIDCRequest{Nonce: "nonce"},
				OpenID4VP:      db.OpenID4VPSession{WalletID: "wallet"},
				VerifiedClaims: map[string]any{},
			}
			testClient := &db.Client{ClientID: "client"}

			tokenString, err := client.generateIDToken(session, testClient)
			assert.NoError(t, err)

			// Parse token to check algorithm in header
			token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return &privateKey.PublicKey, nil
			})

			assert.Equal(t, tt.expectedAlgName, token.Header["alg"], "Token header should contain correct algorithm")
		})
	}
}

// TestGetSigningMethod_UnknownAlgorithm tests fallback to RS256 for unknown algorithms
func TestGetSigningMethod_UnknownAlgorithm(t *testing.T) {
	ctx := context.Background()

	cfg := &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			OIDC: model.OIDCConfig{
				Issuer:          "https://verifier.example.com",
				SigningAlg:      "UNKNOWN_ALG",
				IDTokenDuration: 3600,
				SubjectType:     "public",
				SubjectSalt:     "test-salt",
			},
		},
	}

	log := logger.NewSimple("test")
	tracer, _ := trace.NewForTesting(ctx, "test", log)
	client, _ := New(ctx, nil, cfg, tracer, log)

	// Should default to RS256 for unknown algorithm
	signingMethod := client.getSigningMethod()
	assert.Equal(t, jwt.SigningMethodRS256, signingMethod, "Unknown algorithm should default to RS256")
}
