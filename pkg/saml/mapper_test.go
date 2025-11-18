//go:build saml

package saml

import (
	"testing"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttributeMapper_MapAttributes_PID(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			CredentialType: "pid",
			Attributes: map[string]string{
				"urn:oid:2.5.4.42":                  "given_name",
				"urn:oid:2.5.4.4":                   "family_name",
				"urn:oid:0.9.2342.19200300.100.1.3": "email",
				"urn:oid:1.2.752.29.4.13":           "personal_identity_number",
				"urn:oid:2.16.840.1.113730.3.1.241": "display_name",
			},
			RequiredAttributes: []string{
				"urn:oid:2.5.4.42",
				"urn:oid:2.5.4.4",
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

func TestAttributeMapper_MapAttributes_MultiValue(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			CredentialType: "diploma",
			Attributes: map[string]string{
				"urn:oid:1.3.6.1.4.1.5923.1.1.1.1": "affiliation",
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	// eduPersonAffiliation can have multiple values
	samlAttrs := map[string][]string{
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.1": {"student", "member", "staff"},
	}

	claims, err := mapper.MapAttributes(samlAttrs, "diploma")
	require.NoError(t, err)

	// Multi-valued attributes should be stored as arrays
	affiliation, ok := claims["affiliation"]
	require.True(t, ok)

	affiliationSlice, ok := affiliation.([]string)
	require.True(t, ok)
	assert.Len(t, affiliationSlice, 3)
	assert.Contains(t, affiliationSlice, "student")
	assert.Contains(t, affiliationSlice, "member")
	assert.Contains(t, affiliationSlice, "staff")
}

func TestAttributeMapper_MissingRequiredAttributes(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			CredentialType: "pid",
			Attributes: map[string]string{
				"urn:oid:2.5.4.42": "given_name",
				"urn:oid:2.5.4.4":  "family_name",
			},
			RequiredAttributes: []string{
				"urn:oid:2.5.4.42",
				"urn:oid:2.5.4.4",
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	// Missing family_name
	samlAttrs := map[string][]string{
		"urn:oid:2.5.4.42": {"John"},
	}

	_, err = mapper.MapAttributes(samlAttrs, "pid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required attribute missing")
}

func TestAttributeMapper_InvalidCredentialType(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			CredentialType: "pid",
			Attributes: map[string]string{
				"urn:oid:2.5.4.42": "given_name",
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	samlAttrs := map[string][]string{
		"urn:oid:2.5.4.42": {"John"},
	}

	_, err = mapper.MapAttributes(samlAttrs, "invalid_credential_type")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no attribute mapping found")
}

func TestAttributeMapper_IsValidCredentialType(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{CredentialType: "pid"},
		{CredentialType: "diploma"},
		{CredentialType: "ehic"},
	}

	mapper := NewAttributeMapper(mappings, log)

	assert.True(t, mapper.IsValidCredentialType("pid"))
	assert.True(t, mapper.IsValidCredentialType("diploma"))
	assert.True(t, mapper.IsValidCredentialType("ehic"))
	assert.False(t, mapper.IsValidCredentialType("invalid"))
	assert.False(t, mapper.IsValidCredentialType(""))
}

func TestAttributeMapper_UnmappedAttributesIgnored(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	mappings := []model.SAMLAttributeMapping{
		{
			CredentialType: "pid",
			Attributes: map[string]string{
				"urn:oid:2.5.4.42": "given_name",
			},
		},
	}

	mapper := NewAttributeMapper(mappings, log)

	samlAttrs := map[string][]string{
		"urn:oid:2.5.4.42": {"John"},
		"urn:oid:2.5.4.4":  {"Doe"},   // Not in mapping, should be ignored
		"urn:oid:9.9.9.9":  {"Extra"}, // Not in mapping, should be ignored
	}

	claims, err := mapper.MapAttributes(samlAttrs, "pid")
	require.NoError(t, err)

	// Only mapped attribute should be present
	assert.Equal(t, "John", claims["given_name"])
	assert.NotContains(t, claims, "family_name")
	assert.Len(t, claims, 1)
}
