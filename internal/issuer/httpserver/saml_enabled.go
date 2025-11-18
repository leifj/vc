//go:build saml

package httpserver

import (
	"vc/pkg/saml"
)

// SAMLService is the actual SAML service when SAML is enabled
type SAMLService = *saml.Service
