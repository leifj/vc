//go:build saml

package saml

import (
	"fmt"
	"strings"
)

// AttributeMapping defines how a SAML attribute maps to a credential claim
type AttributeMapping struct {
	Claim     string // Dot-notation path: "identity.family_name" or simple "family_name"
	Required  bool   // Whether this attribute is required
	Transform string // Optional transformation: "lowercase", "uppercase", "trim"
	Default   string // Optional default value if attribute is missing
}

// CredentialMapping defines how a SAML credential type maps to a credential constructor
type CredentialMapping struct {
	SAMLType           string                       // SAML credential type identifier (e.g., "pid")
	CredentialType     string                       // Key in credential_constructor config
	CredentialConfigID string                       // OpenID4VCI credential configuration ID
	Attributes         map[string]*AttributeMapping // OID → AttributeMapping
}

// ClaimTransformer transforms SAML attributes into credential claims
type ClaimTransformer struct {
	mappings map[string]*CredentialMapping
}

// NewClaimTransformer creates a new claim transformer
func NewClaimTransformer(mappings []*CredentialMapping) *ClaimTransformer {
	m := make(map[string]*CredentialMapping)
	for _, mapping := range mappings {
		m[mapping.SAMLType] = mapping
	}
	return &ClaimTransformer{
		mappings: m,
	}
}

// GetMapping returns the credential mapping for a SAML type
func (t *ClaimTransformer) GetMapping(samlType string) (*CredentialMapping, error) {
	mapping, exists := t.mappings[samlType]
	if !exists {
		return nil, fmt.Errorf("unknown SAML credential type: %s", samlType)
	}
	return mapping, nil
}

// TransformClaims converts SAML attributes to a generic document structure
func (t *ClaimTransformer) TransformClaims(
	samlType string,
	attributes map[string]interface{},
) (map[string]interface{}, error) {
	mapping, err := t.GetMapping(samlType)
	if err != nil {
		return nil, err
	}

	// Build nested document structure using dot notation
	doc := make(map[string]interface{})

	for oid, attrMapping := range mapping.Attributes {
		value, exists := attributes[oid]

		if !exists {
			if attrMapping.Required {
				return nil, fmt.Errorf("missing required attribute: %s (claim: %s)", oid, attrMapping.Claim)
			}
			if attrMapping.Default != "" {
				value = attrMapping.Default
			} else {
				continue
			}
		}

		// Apply transformations
		value = applyTransform(value, attrMapping.Transform)

		// Set value in document using dot-notation path
		if err := setNestedValue(doc, attrMapping.Claim, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", attrMapping.Claim, err)
		}
	}

	return doc, nil
}

// applyTransform applies a transformation to a value
func applyTransform(value interface{}, transform string) interface{} {
	if transform == "" {
		return value
	}

	// Only apply transformations to strings
	str, ok := value.(string)
	if !ok {
		return value
	}

	switch transform {
	case "lowercase":
		return strings.ToLower(str)
	case "uppercase":
		return strings.ToUpper(str)
	case "trim":
		return strings.TrimSpace(str)
	default:
		return value
	}
}

// setNestedValue sets a value in a map using dot-notation path
// Example: "identity.family_name" creates map[identity][family_name] = value
func setNestedValue(doc map[string]interface{}, path string, value interface{}) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}

	// Split path by dots
	parts := strings.Split(path, ".")

	// Simple case: no nesting
	if len(parts) == 1 {
		doc[path] = value
		return nil
	}

	// Navigate/create nested structure
	current := doc
	for i := 0; i < len(parts)-1; i++ {
		key := parts[i]

		// Check if key exists
		next, exists := current[key]
		if !exists {
			// Create new map
			newMap := make(map[string]interface{})
			current[key] = newMap
			current = newMap
		} else {
			// Key exists - ensure it's a map
			nextMap, ok := next.(map[string]interface{})
			if !ok {
				return fmt.Errorf("path conflict: %s is not a map", strings.Join(parts[:i+1], "."))
			}
			current = nextMap
		}
	}

	// Set final value
	finalKey := parts[len(parts)-1]
	current[finalKey] = value
	return nil
}

// getNestedValue retrieves a value from a map using dot-notation path
// Used for validation/testing
func getNestedValue(doc map[string]interface{}, path string) (interface{}, bool) {
	if path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")

	// Simple case: no nesting
	if len(parts) == 1 {
		val, exists := doc[path]
		return val, exists
	}

	// Navigate nested structure
	current := doc
	for i := 0; i < len(parts)-1; i++ {
		key := parts[i]
		next, exists := current[key]
		if !exists {
			return nil, false
		}

		nextMap, ok := next.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current = nextMap
	}

	// Get final value
	finalKey := parts[len(parts)-1]
	val, exists := current[finalKey]
	return val, exists
}
