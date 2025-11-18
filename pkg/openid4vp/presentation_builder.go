package openid4vp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// PresentationRequestTemplate represents a template for creating presentation requests.
// This is a minimal interface to avoid import cycles with pkg/configuration.
type PresentationRequestTemplate interface {
	GetID() string
	GetOIDCScopes() []string
	GetDCQLQuery() *DCQL
}

// PresentationBuilder builds OpenID4VP presentation requests from templates
type PresentationBuilder struct {
	templates  map[string]PresentationRequestTemplate // ID -> template
	scopeIndex map[string]string                      // scope -> template ID
}

// NewPresentationBuilder creates a new PresentationBuilder with the given templates
// The templates parameter accepts any slice of types that implement PresentationRequestTemplate
func NewPresentationBuilder[T PresentationRequestTemplate](templates []T) *PresentationBuilder {
	builder := &PresentationBuilder{
		templates:  make(map[string]PresentationRequestTemplate),
		scopeIndex: make(map[string]string),
	}

	// Index templates by ID and scopes
	for _, template := range templates {
		id := template.GetID()
		builder.templates[id] = template

		// Index by each scope
		for _, scope := range template.GetOIDCScopes() {
			builder.scopeIndex[scope] = id
		}
	}

	return builder
}

// BuildFromScopes creates a DCQL query from OIDC scopes using configured templates
// Returns the DCQL query and the template that was used
func (pb *PresentationBuilder) BuildFromScopes(ctx context.Context, scopes []string) (*DCQL, PresentationRequestTemplate, error) {
	if len(scopes) == 0 {
		return nil, nil, fmt.Errorf("no scopes provided")
	}

	// Find first matching template by scope
	var templateID string
	for _, scope := range scopes {
		if id, ok := pb.scopeIndex[scope]; ok {
			templateID = id
			break
		}
	}

	if templateID == "" {
		return nil, nil, fmt.Errorf("no template found for scopes %v", scopes)
	}

	template := pb.templates[templateID]
	dcql := template.GetDCQLQuery()
	if dcql == nil {
		return nil, nil, fmt.Errorf("template %s has no DCQL query", template.GetID())
	}

	return dcql, template, nil
}

// BuildFromTemplate creates a DCQL query from a specific template ID
func (pb *PresentationBuilder) BuildFromTemplate(ctx context.Context, templateID string) (*DCQL, PresentationRequestTemplate, error) {
	template, ok := pb.templates[templateID]
	if !ok {
		return nil, nil, fmt.Errorf("template %s not found", templateID)
	}

	dcql := template.GetDCQLQuery()
	if dcql == nil {
		return nil, nil, fmt.Errorf("template %s has no DCQL query", template.GetID())
	}

	return dcql, template, nil
}

// BuildPresentationDefinition creates a PresentationDefinitionParameter from scopes
// This is for backward compatibility with the existing Presentation Exchange format
func (pb *PresentationBuilder) BuildPresentationDefinition(ctx context.Context, scopes []string) (*PresentationDefinitionParameter, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("no scopes provided")
	}

	// Filter out standard OIDC scopes
	credentialScopes := filterStandardScopes(scopes)
	if len(credentialScopes) == 0 {
		// No credential-specific scopes, return a generic presentation definition
		return pb.createGenericPresentationDefinition(), nil
	}

	// Try to find templates for the scopes
	var inputDescriptors []InputDescriptor
	usedScopes := make(map[string]bool)

	for _, scope := range credentialScopes {
		if usedScopes[scope] {
			continue
		}

		templateID, ok := pb.scopeIndex[scope]
		if !ok {
			// No template for this scope, skip it
			continue
		}

		template := pb.templates[templateID]

		// Convert DCQL to InputDescriptor
		dcql := template.GetDCQLQuery()
		if dcql != nil && len(dcql.Credentials) > 0 {
			for _, credQuery := range dcql.Credentials {
				descriptor := pb.dcqlCredentialToInputDescriptor(credQuery, scope)
				inputDescriptors = append(inputDescriptors, descriptor)
				usedScopes[scope] = true
			}
		}
	}

	// If no descriptors were created from templates, create a generic one
	if len(inputDescriptors) == 0 {
		return pb.createGenericPresentationDefinition(), nil
	}

	pd := &PresentationDefinitionParameter{
		ID:               generateRandomID(),
		Name:             "Verifier Proxy Presentation Request",
		Purpose:          "To verify your identity",
		InputDescriptors: inputDescriptors,
	}

	return pd, nil
}

// dcqlCredentialToInputDescriptor converts a DCQL CredentialQuery to a Presentation Exchange InputDescriptor
func (pb *PresentationBuilder) dcqlCredentialToInputDescriptor(credQuery CredentialQuery, scope string) InputDescriptor {
	descriptor := InputDescriptor{
		ID:      fmt.Sprintf("input_%s", credQuery.ID),
		Name:    fmt.Sprintf("Credential: %s", credQuery.ID),
		Purpose: fmt.Sprintf("Required for scope: %s", scope),
		Constraints: Constraints{
			LimitDisclosure: "required",
			Fields:          []Field{},
		},
	}

	// Add VCT constraint
	if len(credQuery.Meta.VCTValues) > 0 {
		vctField := Field{
			Path: []string{"$.vct"},
		}

		// If single VCT, use const filter
		if len(credQuery.Meta.VCTValues) == 1 {
			vctField.Filter = &Filter{
				Type:  "string",
				Const: credQuery.Meta.VCTValues[0],
			}
		} else {
			// Multiple VCTs, use enum filter
			vctField.Filter = &Filter{
				Type: "string",
				Enum: credQuery.Meta.VCTValues,
			}
		}

		descriptor.Constraints.Fields = append(descriptor.Constraints.Fields, vctField)
	}

	// Add claim constraints if specified
	if len(credQuery.Claims) > 0 {
		for _, claim := range credQuery.Claims {
			if len(claim.Path) > 0 {
				// Convert DCQL claim path to JSONPath
				jsonPath := dcqlPathToJSONPath(claim.Path)
				field := Field{
					Path: []string{jsonPath},
				}
				descriptor.Constraints.Fields = append(descriptor.Constraints.Fields, field)
			}
		}
	}

	return descriptor
}

// dcqlPathToJSONPath converts a DCQL claim path to JSONPath format
func dcqlPathToJSONPath(path []string) string {
	if len(path) == 0 {
		return "$"
	}

	result := "$"
	for _, segment := range path {
		result += "." + segment
	}
	return result
}

// createGenericPresentationDefinition creates a generic presentation definition
// when no specific templates match
func (pb *PresentationBuilder) createGenericPresentationDefinition() *PresentationDefinitionParameter {
	return &PresentationDefinitionParameter{
		ID:      generateRandomID(),
		Name:    "Verifier Proxy Presentation Request",
		Purpose: "To verify your identity",
		InputDescriptors: []InputDescriptor{
			{
				ID:      "input_generic",
				Name:    "Any Verifiable Credential",
				Purpose: "User identity verification",
				Constraints: Constraints{
					LimitDisclosure: "required",
					Fields: []Field{
						{
							Path: []string{"$.vct"},
						},
					},
				},
			},
		},
	}
}

// filterStandardScopes removes standard OIDC scopes from the list
func filterStandardScopes(scopes []string) []string {
	standardScopes := map[string]bool{
		"openid":         true,
		"profile":        true,
		"email":          true,
		"address":        true,
		"phone":          true,
		"offline_access": true,
	}

	filtered := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !standardScopes[scope] {
			filtered = append(filtered, scope)
		}
	}
	return filtered
}

// generateRandomID generates a random ID for presentation definitions
func generateRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// FindTemplateByScopes finds a template that matches the given OIDC scopes
// Returns the first template where all requested scopes are present in the template's scopes
func (pb *PresentationBuilder) FindTemplateByScopes(scopes []string) PresentationRequestTemplate {
	if len(scopes) == 0 {
		return nil
	}

	// Try to find a template where all requested scopes match
	for _, template := range pb.templates {
		templateScopes := template.GetOIDCScopes()
		if scopesMatch(scopes, templateScopes) {
			return template
		}
	}

	return nil
}

// scopesMatch checks if the requested scopes match the template scopes
// A template matches if it contains at least one of the requested scopes
// (excluding standard OIDC scopes like "openid", "profile", "email")
func scopesMatch(requestedScopes []string, templateScopes []string) bool {
	// Filter out standard OIDC scopes from requested scopes
	credentialScopes := make([]string, 0)
	for _, scope := range requestedScopes {
		if scope != "openid" && scope != "profile" && scope != "email" {
			credentialScopes = append(credentialScopes, scope)
		}
	}

	if len(credentialScopes) == 0 {
		return false
	}

	// Check if template contains any of the credential scopes
	for _, requestedScope := range credentialScopes {
		for _, templateScope := range templateScopes {
			if requestedScope == templateScope {
				return true // Match found
			}
		}
	}

	return false
}

// GetClaimMappings is a helper to extract claim mappings from a template
// Returns nil if the template doesn't implement this method
func GetClaimMappings(template PresentationRequestTemplate) map[string]string {
	if t, ok := template.(interface {
		GetClaimMappings() map[string]string
	}); ok {
		return t.GetClaimMappings()
	}
	return nil
}

// ListTemplates returns all templates
func (pb *PresentationBuilder) ListTemplates() []PresentationRequestTemplate {
	templates := make([]PresentationRequestTemplate, 0, len(pb.templates))
	for _, template := range pb.templates {
		templates = append(templates, template)
	}
	return templates
}

// GetTemplate returns a specific template by ID
func (pb *PresentationBuilder) GetTemplate(templateID string) (PresentationRequestTemplate, error) {
	template, ok := pb.templates[templateID]
	if !ok {
		return nil, fmt.Errorf("template %s not found", templateID)
	}
	return template, nil
}
