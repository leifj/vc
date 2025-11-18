package apiv1

import (
	"context"
	"testing"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
)

// TestCreatePresentationDefinition_PID tests presentation definition for PID scope
func TestCreatePresentationDefinition_PID(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{"openid", "pid"}

	pd, err := client.createPresentationDefinition(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, pd)

	// Should return a PresentationDefinitionParameter struct
	pdParam, ok := pd.(*openid4vp.PresentationDefinitionParameter)
	assert.True(t, ok, "Should return PresentationDefinitionParameter")
	assert.NotEmpty(t, pdParam.ID, "Should have an ID")
	assert.NotEmpty(t, pdParam.InputDescriptors, "Should have at least one input descriptor for PID")
}

// TestCreatePresentationDefinition_MultipleScopes tests presentation definition for multiple scopes
func TestCreatePresentationDefinition_MultipleScopes(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{"openid", "pid", "email"}

	pd, err := client.createPresentationDefinition(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, pd)

	pdParam, ok := pd.(*openid4vp.PresentationDefinitionParameter)
	assert.True(t, ok)

	// Should have multiple input descriptors (one for PID, one for email)
	assert.GreaterOrEqual(t, len(pdParam.InputDescriptors), 1)
}

// TestCreatePresentationDefinition_OnlyOpenID tests with only openid scope
func TestCreatePresentationDefinition_OnlyOpenID(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{"openid"}

	pd, err := client.createPresentationDefinition(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, pd)

	pdParam, ok := pd.(*openid4vp.PresentationDefinitionParameter)
	assert.True(t, ok)
	assert.NotEmpty(t, pdParam.ID)

	// Should have a generic input descriptor when no specific credentials
	assert.NotEmpty(t, pdParam.InputDescriptors)
}

// TestCreatePresentationDefinition_EmptyScopes tests with empty scopes
func TestCreatePresentationDefinition_EmptyScopes(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{}

	pd, err := client.createPresentationDefinition(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, pd)

	pdParam, ok := pd.(*openid4vp.PresentationDefinitionParameter)
	assert.True(t, ok)

	// Should create a generic presentation definition
	assert.NotEmpty(t, pdParam.InputDescriptors)
}

// TestCreatePresentationDefinition_UnsupportedScope tests with unsupported scope
func TestCreatePresentationDefinition_UnsupportedScope(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	scopes := []string{"openid", "unsupported_scope"}

	pd, err := client.createPresentationDefinition(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, pd)

	pdParam, ok := pd.(*openid4vp.PresentationDefinitionParameter)
	assert.True(t, ok)
	assert.NotEmpty(t, pdParam.ID)

	// Should still create a presentation definition with generic descriptor
	assert.NotEmpty(t, pdParam.InputDescriptors)
}

// TestCreateRequestObject tests request object creation
func TestCreateRequestObject(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	sessionID := "test-session-123"
	nonce := "test-nonce-456"
	presentationDefinition := &openid4vp.PresentationDefinitionParameter{
		ID:               "test-pd",
		InputDescriptors: []openid4vp.InputDescriptor{},
	}

	// This will fail without proper signing key, but we can test the structure
	requestObject, err := client.CreateRequestObject(nil, sessionID, presentationDefinition, nonce)

	// Expect error because no signing key is configured
	assert.Error(t, err)
	assert.Empty(t, requestObject)
}

// TestGenerateNonce tests nonce generation (already in client_test.go but good to have here too)
func TestGenerateNonce_Uniqueness(t *testing.T) {
	cfg := createTestConfig()
	client := createTestClientWithConfig(t, cfg)

	nonces := make(map[string]bool)
	iterations := 1000

	// Generate many nonces and ensure they're all unique
	for i := 0; i < iterations; i++ {
		nonce := client.generateNonce()
		assert.NotEmpty(t, nonce)
		assert.False(t, nonces[nonce], "Nonce should be unique")
		nonces[nonce] = true
	}

	assert.Len(t, nonces, iterations, "All nonces should be unique")
}

// Helper function to create test configuration with supported credentials
func createTestConfig() *model.Cfg {
	return &model.Cfg{
		VerifierProxy: model.VerifierProxy{
			ExternalURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
			OpenID4VP: model.OpenID4VPConfig{
				PresentationTimeout: 300,
				SupportedCredentials: []model.SupportedCredentialConfig{
					{
						VCT:    "urn:eu:pid:1",
						Scopes: []string{"pid"},
					},
					{
						VCT:    "urn:eu:ehic:1",
						Scopes: []string{"ehic"},
					},
					{
						VCT:    "urn:eu:email:1",
						Scopes: []string{"email"},
					},
				},
			},
		},
	}
}

// Benchmark presentation definition creation
func BenchmarkCreatePresentationDefinition(b *testing.B) {
	cfg := createTestConfig()
	log := logger.NewSimple("bench")
	client := &Client{
		cfg: cfg,
		log: log.New("apiv1"),
	}

	scopes := []string{"openid", "pid", "email"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.createPresentationDefinition(scopes)
	}
}

// Benchmark nonce generation
func BenchmarkGenerateNonce(b *testing.B) {
	log := logger.NewSimple("bench")
	client := &Client{log: log.New("apiv1")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = client.generateNonce()
	}
}

// TestCreatePresentationDefinition_WithTemplates tests template-based presentation definition
func TestCreatePresentationDefinition_WithTemplates(t *testing.T) {
	ctx := context.Background()

	// Load test templates
	templatesDir := "testdata/presentation_requests"
	config, err := configuration.LoadPresentationRequests(ctx, templatesDir)
	assert.NoError(t, err, "Should load test templates")

	// Create test client with templates
	cfg := createTestConfig()
	log := logger.NewSimple("test")
	client := &Client{
		cfg:                 cfg,
		log:                 log.New("apiv1"),
		presentationBuilder: openid4vp.NewPresentationBuilder(config.GetEnabledTemplates()),
	}

	// Test with PID scope
	scopes := []string{"openid", "pid"}
	pd, err := client.createPresentationDefinition(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, pd)

	pdParam, ok := pd.(*openid4vp.PresentationDefinitionParameter)
	assert.True(t, ok, "Should return PresentationDefinitionParameter")
	assert.NotEmpty(t, pdParam.ID, "Should have an ID")
	assert.NotEmpty(t, pdParam.InputDescriptors, "Should have input descriptors")

	// Verify the descriptor was created from template
	if len(pdParam.InputDescriptors) > 0 {
		descriptor := pdParam.InputDescriptors[0]
		assert.NotEmpty(t, descriptor.ID)
		assert.NotEmpty(t, descriptor.Constraints.Fields)

		// Check for VCT constraint
		hasVCT := false
		for _, field := range descriptor.Constraints.Fields {
			if len(field.Path) > 0 && field.Path[0] == "$.vct" {
				hasVCT = true
				break
			}
		}
		assert.True(t, hasVCT, "Should have VCT constraint")
	}
}

// TestCreatePresentationDefinition_TemplatesFallback tests fallback to legacy when template fails
func TestCreatePresentationDefinition_TemplatesFallback(t *testing.T) {
	ctx := context.Background()

	// Load test templates
	templatesDir := "testdata/presentation_requests"
	config, err := configuration.LoadPresentationRequests(ctx, templatesDir)
	assert.NoError(t, err)

	// Create client with templates
	cfg := createTestConfig()
	log := logger.NewSimple("test")
	client := &Client{
		cfg:                 cfg,
		log:                 log.New("apiv1"),
		presentationBuilder: openid4vp.NewPresentationBuilder(config.GetEnabledTemplates()),
	}

	// Test with scope not in templates (should fall back to legacy config)
	scopes := []string{"openid", "ehic"}
	pd, err := client.createPresentationDefinition(scopes)
	assert.NoError(t, err)
	assert.NotNil(t, pd)

	pdParam, ok := pd.(*openid4vp.PresentationDefinitionParameter)
	assert.True(t, ok)
	assert.NotEmpty(t, pdParam.InputDescriptors, "Should have descriptors from legacy config")
}
