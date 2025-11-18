//go:build saml

package saml

import (
	"testing"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: These tests cover the DEPRECATED AttributeMapper
// For new code, use ClaimTransformer and transformer_test.go

func TestAttributeMapper_MapAttributes_PID(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			SAMLType:       "pid",
			CredentialType: "pid",
			Attributes: map[string]model.SAMLAttributeConfig{
				"urn:oid:2.5.4.42":                  {Claim: "given_name", Required: true},
				"urn:oid:2.5.4.4":                   {Claim: "family_name", Required: true},
				"urn:oid:0.9.2342.19200300.100.1.3": {Claim: "email", Required: false},
				"urn:oid:1.2.752.29.4.13":           {Claim: "personal_identity_number", Required: false},
				"urn:oid:2.16.840.1.113730.3.1.241": {Claim: "display_name", Required: false},
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	samlAttrs := map[string][]string{
		"urn:oid:2.5.4.42":                  {"John"},
		"urn:oid:2.5.4.4":                   {"Doe"},
		"urn:oid:0.9.2342.19200300.100.1.3": {"john.doe@example.com"},
		"urn:oid:1.2.752.29.4.13":           {"197001011234"},
		"urn:oid:2.16.840.1.113730.3.1.241": {"John Doe"},
	}

	claims, err := mapper.MapAttributes(samlAttrs, "pid")
	require.NoError(t, err)

	assert.Equal(t, "John", claims["given_name"])
	assert.Equal(t, "Doe", claims["family_name"])
	assert.Equal(t, "john.doe@example.com", claims["email"])
	assert.Equal(t, "197001011234", claims["personal_identity_number"])
	assert.Equal(t, "John Doe", claims["display_name"])
}

func TestAttributeMapper_MapAttributes_MissingOptional(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			SAMLType:       "pid",
			CredentialType: "pid",
			Attributes: map[string]model.SAMLAttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
				"urn:oid:2.5.4.4":  {Claim: "family_name", Required: true},
				"urn:oid:2.5.4.10": {Claim: "organization", Required: false},
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	samlAttrs := map[string][]string{
		"urn:oid:2.5.4.42": {"John"},
		"urn:oid:2.5.4.4":  {"Doe"},
		// Missing optional organization
	}

	claims, err := mapper.MapAttributes(samlAttrs, "pid")
	require.NoError(t, err)

	assert.Equal(t, "John", claims["given_name"])
	assert.Equal(t, "Doe", claims["family_name"])
	assert.NotContains(t, claims, "organization")
}

func TestAttributeMapper_MapAttributes_MissingRequired(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			SAMLType:       "pid",
			CredentialType: "pid",
			Attributes: map[string]model.SAMLAttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
				"urn:oid:2.5.4.4":  {Claim: "family_name", Required: true},
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	samlAttrs := map[string][]string{
		"urn:oid:2.5.4.42": {"John"},
		// Missing required family_name
	}

	_, err = mapper.MapAttributes(samlAttrs, "pid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required attribute missing")
}

func TestAttributeMapper_MapAttributes_MultipleValues(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			SAMLType:       "diploma",
			CredentialType: "diploma",
			Attributes: map[string]model.SAMLAttributeConfig{
				"urn:oid:1.3.6.1.4.1.5923.1.1.1.1": {Claim: "affiliation", Required: false},
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	samlAttrs := map[string][]string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.1": {"student", "member"},
	}

	claims, err := mapper.MapAttributes(samlAttrs, "diploma")
	require.NoError(t, err)

	affiliation, ok := claims["affiliation"].([]string)
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"student", "member"}, affiliation)
}

func TestAttributeMapper_GetDefaultIdP(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			SAMLType:       "pid",
			CredentialType: "pid",
			DefaultIdP:     "https://idp.example.com",
			Attributes:     map[string]model.SAMLAttributeConfig{},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	idp, ok := mapper.GetDefaultIdP("pid")
	assert.True(t, ok)
	assert.Equal(t, "https://idp.example.com", idp)

	_, ok = mapper.GetDefaultIdP("unknown")
	assert.False(t, ok)
}

func TestAttributeMapper_IsValidCredentialType(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			SAMLType:       "pid",
			CredentialType: "pid",
			Attributes:     map[string]model.SAMLAttributeConfig{},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	assert.True(t, mapper.IsValidCredentialType("pid"))
	assert.False(t, mapper.IsValidCredentialType("unknown"))
}

func TestAttributeMapper_WithDefaults(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			SAMLType:       "pid",
			CredentialType: "pid",
			Attributes: map[string]model.SAMLAttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
				"urn:oid:2.5.4.6":  {Claim: "country", Required: false, Default: "SE"},
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	samlAttrs := map[string][]string{
		"urn:oid:2.5.4.42": {"John"},
		// country missing - should use default
	}

	claims, err := mapper.MapAttributes(samlAttrs, "pid")
	require.NoError(t, err)

	assert.Equal(t, "John", claims["given_name"])
	assert.Equal(t, "SE", claims["country"])
}

func TestAttributeMapper_WithTransform(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			SAMLType:       "pid",
			CredentialType: "pid",
			Attributes: map[string]model.SAMLAttributeConfig{
				"urn:oid:0.9.2342.19200300.100.1.3": {Claim: "email", Required: true, Transform: "lowercase"},
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	samlAttrs := map[string][]string{
		"urn:oid:0.9.2342.19200300.100.1.3": {"JOHN.DOE@EXAMPLE.COM"},
	}

	claims, err := mapper.MapAttributes(samlAttrs, "pid")
	require.NoError(t, err)

	assert.Equal(t, "john.doe@example.com", claims["email"])
}
