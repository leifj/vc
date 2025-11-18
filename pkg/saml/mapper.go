//go:build saml

package saml

import (
	"fmt"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// AttributeMapper handles mapping between SAML attributes and credential claims
type AttributeMapper struct {
	mappings map[string]model.SAMLAttributeMapping
	log      *logger.Log
}

// NewAttributeMapper creates a new attribute mapper
func NewAttributeMapper(mappings []model.SAMLAttributeMapping, log *logger.Log) *AttributeMapper {
	mappingMap := make(map[string]model.SAMLAttributeMapping)
	for _, mapping := range mappings {
		mappingMap[mapping.CredentialType] = mapping
	}

	return &AttributeMapper{
		mappings: mappingMap,
		log:      log.New("mapper"),
	}
}

// MapAttributes maps SAML attributes to credential claims
func (m *AttributeMapper) MapAttributes(samlAttrs map[string][]string, credentialType string) (map[string]interface{}, error) {
	mapping, ok := m.mappings[credentialType]
	if !ok {
		return nil, fmt.Errorf("no attribute mapping found for credential type: %s", credentialType)
	}

	claims := make(map[string]interface{})

	for samlAttr, claimName := range mapping.Attributes {
		values, exists := samlAttrs[samlAttr]
		if !exists {
			m.log.Debug("SAML attribute not present",
				"saml_attr", samlAttr,
				"claim_name", claimName,
				"credential_type", credentialType)
			continue
		}

		if len(values) == 1 {
			claims[claimName] = values[0]
		} else if len(values) > 1 {
			claims[claimName] = values
		}
	}

	if len(mapping.RequiredAttributes) > 0 {
		for _, requiredAttr := range mapping.RequiredAttributes {
			claimName, ok := mapping.Attributes[requiredAttr]
			if !ok {
				continue
			}

			if _, exists := claims[claimName]; !exists {
				return nil, fmt.Errorf("required attribute missing: %s (claim: %s)", requiredAttr, claimName)
			}
		}
	}

	m.log.Debug("mapped SAML attributes",
		"credential_type", credentialType,
		"saml_attrs_count", len(samlAttrs),
		"mapped_claims_count", len(claims))

	return claims, nil
}

// IsValidCredentialType checks if a credential type has a mapping configured
func (m *AttributeMapper) IsValidCredentialType(credentialType string) bool {
	_, ok := m.mappings[credentialType]
	return ok
}

// GetDefaultIdP returns the default IdP for a credential type, if configured
func (m *AttributeMapper) GetDefaultIdP(credentialType string) (string, bool) {
	mapping, ok := m.mappings[credentialType]
	if !ok {
		return "", false
	}
	return mapping.DefaultIdP, mapping.DefaultIdP != ""
}

// GetSupportedCredentialTypes returns all configured credential types
func (m *AttributeMapper) GetSupportedCredentialTypes() []string {
	types := make([]string, 0, len(m.mappings))
	for credType := range m.mappings {
		types = append(types, credType)
	}
	return types
}
