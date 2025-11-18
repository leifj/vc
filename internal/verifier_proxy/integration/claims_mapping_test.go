package integration

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"vc/internal/verifier_proxy/apiv1"
	"vc/internal/verifier_proxy/db"
	"vc/pkg/configuration"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// TestIntegration_ClaimMapping_PID_Basic tests claim mapping for PID basic profile
func TestIntegration_ClaimMapping_PID_Basic(t *testing.T) {
	suite := NewIntegrationSuite(t)
	defer suite.Cleanup()

	// Create a presentation template with claim mappings for PID
	template := &configuration.PresentationRequestTemplate{
		ID:          "eudi_pid_basic",
		Name:        "PID Basic",
		Description: "EU Digital Identity PID - Basic Profile",
		OIDCScopes:  []string{"openid", "profile", "pid"},
		DCQLQuery: &openid4vp.DCQL{
			Credentials: []openid4vp.CredentialQuery{
				{
					ID:     "pid",
					Format: "vc+sd-jwt",
					Meta: openid4vp.MetaQuery{
						VCTValues: []string{"eu.europa.ec.eudi.pid.1"},
					},
				},
			},
		},
		ClaimMappings: map[string]string{
			"given_name":  "given_name",
			"family_name": "family_name",
			"birthdate":   "birthdate",
			"sub":         "sub", // Map sub to preserve it
		},
		ClaimTransforms: map[string]configuration.ClaimTransform{
			"birthdate": {
				Type: "date_format",
				Params: map[string]string{
					"from": "2006-01-02",
					"to":   "02/01/2006",
				},
			},
		},
		Enabled: true,
	}

	// Add template to presentation builder
	suite.apiv1.AddPresentationTemplateForTesting(template)

	// Get test client
	client := suite.testClients["confidential"]
	if !assert.NotNil(t, client, "Confidential client should exist") {
		return
	}

	// Generate PKCE pair
	pkce := GeneratePKCEPair()

	// Step 1: Start authorization flow
	authReq := &apiv1.AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            client.ClientID,
		RedirectURI:         client.RedirectURIs[0],
		Scope:               "openid profile pid",
		State:               "test-state-claims",
		Nonce:               "test-nonce-claims",
		CodeChallenge:       pkce.Challenge,
		CodeChallengeMethod: pkce.Method,
	}

	authResp, err := suite.apiv1.Authorize(suite.ctx, authReq)
	if !assert.NoError(t, err, "Authorization should succeed") {
		return
	}

	sessionID := authResp.SessionID
	t.Logf("Created session: %s", sessionID)

	// Step 2: Create VP token with PID claims
	session, _ := suite.db.Sessions.GetByID(suite.ctx, sessionID)

	// Create VP token with specific claims
	vpToken, err := createVPTokenWithClaims(t, map[string]any{
		"given_name":  "Jane",
		"family_name": "Doe",
		"birthdate":   "1985-06-15", // ISO format
		"sub":         "test-subject-123",
	})
	if !assert.NoError(t, err, "Should create VP token") {
		return
	}

	t.Logf("VP Token created with PID claims")

	// Step 3: Submit VP token
	directPostReq := &apiv1.DirectPostRequest{
		VPToken:                vpToken,
		State:                  sessionID,
		PresentationSubmission: `{"id":"submission-1","definition_id":"pd-1"}`,
	}

	directPostResp, err := suite.apiv1.ProcessDirectPost(suite.ctx, directPostReq)
	if !assert.NoError(t, err, "Should process direct post") {
		return
	}
	if !assert.NotNil(t, directPostResp, "Direct post response should not be nil") {
		return
	}

	// Step 4: Verify mapped claims in session
	session, err = suite.db.Sessions.GetByID(suite.ctx, sessionID)
	if !assert.NoError(t, err, "Should retrieve updated session") {
		return
	}

	assert.Equal(t, db.SessionStatusCodeIssued, session.Status)
	assert.NotEmpty(t, session.VerifiedClaims, "Verified claims should be stored")

	// Check specific mapped claims
	claims := session.VerifiedClaims
	assert.Equal(t, "Jane", claims["given_name"], "given_name should be mapped")
	assert.Equal(t, "Doe", claims["family_name"], "family_name should be mapped")

	// Birthdate should be transformed from ISO to DD/MM/YYYY
	assert.Equal(t, "15/06/1985", claims["birthdate"], "birthdate should be transformed")

	assert.Equal(t, "test-subject-123", claims["sub"], "sub should be preserved")

	t.Logf("Verified claims: %+v", claims)

	// Step 5: Exchange for tokens and verify ID token contains mapped claims
	tokenReq := &apiv1.TokenRequest{
		GrantType:    "authorization_code",
		Code:         session.Tokens.AuthorizationCode,
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ClientID,
		ClientSecret: "secret",
		CodeVerifier: pkce.Verifier,
	}

	tokenResp, err := suite.apiv1.Token(suite.ctx, tokenReq)
	if !assert.NoError(t, err, "Token exchange should succeed") {
		return
	}

	// Parse ID token
	idTokenClaims, err := ParseIDToken(tokenResp.IDToken)
	if !assert.NoError(t, err, "Should parse ID token") {
		return
	}

	// Verify ID token contains mapped claims with transformations applied
	assert.Equal(t, "Jane", idTokenClaims["given_name"])
	assert.Equal(t, "Doe", idTokenClaims["family_name"])
	assert.Equal(t, "15/06/1985", idTokenClaims["birthdate"], "ID token should contain transformed birthdate")

	t.Logf("ID token claims verified: %+v", idTokenClaims)
}

// Helper function to create VP token with specific claims
func createVPTokenWithClaims(t *testing.T, userClaims map[string]any) (string, error) {
	// Create SD-JWT header
	claims := map[string]any{
		"vct": "eu.europa.ec.eudi.pid.1",
		"_sd": []string{"hash1", "hash2"}, // Dummy hashes
	}

	// Merge user claims
	for k, v := range userClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		return "", err
	}

	// Create disclosures for each user claim (except sub which is in main JWT)
	var disclosures []string
	for claimName, claimValue := range userClaims {
		if claimName == "sub" || claimName == "vct" {
			continue // These are in the main JWT
		}

		disclosure := []any{
			generateRandomString(16), // salt
			claimName,
			claimValue,
		}
		disclosureJSON, _ := json.Marshal(disclosure)
		disclosureB64 := base64.RawURLEncoding.EncodeToString(disclosureJSON)
		disclosures = append(disclosures, disclosureB64)
	}

	// Format as SD-JWT: <jwt>~<disclosure1>~<disclosure2>~...~<key_binding>
	sdJWT := tokenString
	for _, disc := range disclosures {
		sdJWT += "~" + disc
	}
	sdJWT += "~" // Empty key binding

	return sdJWT, nil
}
