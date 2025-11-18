package apiv1

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
)

// CreateRequestObject creates and signs an OpenID4VP request object
func (c *Client) CreateRequestObject(ctx context.Context, sessionID string, presentationDefinition any, nonce string) (string, error) {
	// Create request object
	requestObject := &openid4vp.RequestObject{
		ISS:                    c.cfg.VerifierProxy.OIDC.Issuer,
		AUD:                    "https://self-issued.me/v2",
		IAT:                    time.Now().Unix(),
		ResponseType:           "vp_token",
		ClientID:               c.cfg.VerifierProxy.OIDC.Issuer,
		Nonce:                  nonce,
		ResponseMode:           "direct_post",
		ResponseURI:            c.cfg.VerifierProxy.ExternalURL + "/verification/direct_post",
		State:                  sessionID,
		PresentationDefinition: presentationDefinitionToPresentationDefinitionParameter(presentationDefinition),
	}

	// Sign the request object
	signedJWT, err := requestObject.Sign(jwt.SigningMethodRS256, c.oidcSigningKey, nil)
	if err != nil {
		c.log.Error(err, "Failed to sign request object")
		return "", err
	}

	// Cache the request object
	c.requestObjectCache.Set(sessionID, requestObject, 5*time.Minute)

	return signedJWT, nil
}

// createPresentationDefinition maps OIDC scopes to OpenID4VP presentation definition
func (c *Client) createPresentationDefinition(scopes []string) (any, error) {
	// If presentation builder is configured, use template-based approach
	if c.presentationBuilder != nil {
		pd, err := c.presentationBuilder.BuildPresentationDefinition(context.Background(), scopes)
		if err != nil {
			c.log.Info("Failed to build presentation definition from templates, falling back to legacy mapping", "error", err)
			// Fall through to legacy behavior
		} else {
			return pd, nil
		}
	}

	// Legacy behavior: use hard-coded scope mapping from config
	inputDescriptors := []openid4vp.InputDescriptor{}

	for _, scope := range scopes {
		// Skip standard OIDC scopes
		if scope == "openid" || scope == "profile" || scope == "email" {
			continue
		}

		// Check if this scope maps to a configured credential
		for _, credConfig := range c.cfg.VerifierProxy.OpenID4VP.SupportedCredentials {
			for _, credScope := range credConfig.Scopes {
				if credScope == scope {
					// Create input descriptor for this credential
					inputDescriptor := openid4vp.InputDescriptor{
						ID:      fmt.Sprintf("input_%s", credConfig.VCT),
						Name:    fmt.Sprintf("Verifiable Credential: %s", credConfig.VCT),
						Purpose: fmt.Sprintf("Required for scope: %s", scope),
						Constraints: openid4vp.Constraints{
							LimitDisclosure: "required",
							Fields: []openid4vp.Field{
								{
									Path: []string{"$.vct"},
									Filter: &openid4vp.Filter{
										Type:  "string",
										Const: credConfig.VCT,
									},
								},
							},
						},
					}
					inputDescriptors = append(inputDescriptors, inputDescriptor)
				}
			}
		}
	}

	// If no specific credentials found, create a generic one
	if len(inputDescriptors) == 0 {
		inputDescriptors = append(inputDescriptors, openid4vp.InputDescriptor{
			ID:      "input_generic",
			Name:    "Any Verifiable Credential",
			Purpose: "User identity verification",
			Constraints: openid4vp.Constraints{
				LimitDisclosure: "required",
				Fields: []openid4vp.Field{
					{
						Path: []string{"$.vct"},
					},
				},
			},
		})
	}

	presentationDef := &openid4vp.PresentationDefinitionParameter{
		ID:               generateRandomID(),
		Name:             "Verifier Proxy Presentation Request",
		Purpose:          "To verify your identity",
		InputDescriptors: inputDescriptors,
	}

	return presentationDef, nil
}

// presentationDefinitionToPresentationDefinitionParameter converts any type to PresentationDefinitionParameter
func presentationDefinitionToPresentationDefinitionParameter(pd any) *openid4vp.PresentationDefinitionParameter {
	if pd == nil {
		return nil
	}

	if pdParam, ok := pd.(*openid4vp.PresentationDefinitionParameter); ok {
		return pdParam
	}

	// If it's already stored in session, it should be the right type
	// Otherwise return nil and let the caller handle it
	return nil
}

// generateRandomID generates a random ID for presentation definitions
func generateRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateNonce creates a cryptographically random nonce
func (c *Client) generateNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
