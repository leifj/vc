package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
	"vc/internal/verifier_proxy/db"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vp"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Client holds the verifier proxy API implementation
type Client struct {
	cfg                         *model.Cfg
	db                          *db.Service
	log                         *logger.Log
	tracer                      *trace.Tracer
	oidcSigningKey              any
	oidcSigningAlg              string
	ephemeralEncryptionKeyCache *ttlcache.Cache[string, jwk.Key]
	requestObjectCache          *ttlcache.Cache[string, *openid4vp.RequestObject]
	presentationBuilder         *openid4vp.PresentationBuilder // Template-based presentation request builder
	claimsExtractor             *openid4vp.ClaimsExtractor     // Claims extraction and mapping
}

// New creates a new instance of the verifier proxy API
func New(ctx context.Context, db *db.Service, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:                         cfg,
		db:                          db,
		log:                         log.New("apiv1"),
		tracer:                      tracer,
		ephemeralEncryptionKeyCache: ttlcache.New(ttlcache.WithTTL[string, jwk.Key](10 * time.Minute)),
		requestObjectCache:          ttlcache.New(ttlcache.WithTTL[string, *openid4vp.RequestObject](5 * time.Minute)),
	}

	// Start caches
	go c.ephemeralEncryptionKeyCache.Start()
	go c.requestObjectCache.Start()

	// Load OIDC signing key
	if err := c.loadSigningKey(); err != nil {
		// Allow empty key path for testing (key will be set via SetSigningKeyForTesting)
		c.log.Info("Failed to load signing key from config - must be set for testing", "error", err)
	}
	// Default to RS256 even if key isn't loaded yet (can be overridden)
	c.oidcSigningAlg = "RS256"

	// Load presentation request templates if configured
	if err := c.loadPresentationTemplates(ctx); err != nil {
		return nil, fmt.Errorf("failed to load presentation templates: %w", err)
	}

	// Initialize claims extractor
	c.claimsExtractor = openid4vp.NewClaimsExtractor()

	c.log.Info("Started")

	return c, nil
}

// loadSigningKey loads the RSA private key from the configured path
func (c *Client) loadSigningKey() error {
	keyPath := c.cfg.VerifierProxy.OIDC.SigningKeyPath
	if keyPath == "" {
		return fmt.Errorf("signing_key_path not configured")
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return fmt.Errorf("failed to parse private key (tried PKCS1 and PKCS8): %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("key is not RSA private key")
		}
	}

	c.oidcSigningKey = privateKey
	return nil
}

// loadPresentationTemplates loads presentation request templates from configured directory
func (c *Client) loadPresentationTemplates(ctx context.Context) error {
	// Check if templates directory is configured
	templatesDir := c.cfg.VerifierProxy.OpenID4VP.PresentationRequestsDir
	if templatesDir == "" {
		c.log.Info("Presentation requests directory not configured, using legacy scope mapping")
		return nil
	}

	// Load templates from directory
	config, err := configuration.LoadPresentationRequests(ctx, templatesDir)
	if err != nil {
		// Log error but don't fail startup - fall back to legacy behavior
		c.log.Info("Failed to load presentation request templates, falling back to legacy scope mapping", "error", err, "dir", templatesDir)
		return nil
	}

	// Create presentation builder
	c.presentationBuilder = openid4vp.NewPresentationBuilder(config.GetEnabledTemplates())

	templateCount := len(config.Templates)
	enabledCount := len(config.GetEnabledTemplates())
	c.log.Info("Loaded presentation request templates",
		"total", templateCount,
		"enabled", enabledCount,
		"dir", templatesDir)

	return nil
}

// generateSessionID creates a cryptographically random session identifier
func (c *Client) generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to time-based ID if random fails
		return oauth2.GenerateCryptographicNonceFixedLength(32)
	}
	return hex.EncodeToString(b)
}

// generateAuthorizationCode creates a cryptographically random authorization code
func (c *Client) generateAuthorizationCode() string {
	return oauth2.GenerateCryptographicNonceFixedLength(32)
}

// generateAccessToken creates a cryptographically random access token
func (c *Client) generateAccessToken() string {
	return oauth2.GenerateCryptographicNonceFixedLength(32)
}

// generateRefreshToken creates a cryptographically random refresh token
func (c *Client) generateRefreshToken() string {
	return oauth2.GenerateCryptographicNonceFixedLength(32)
}

// extractAndMapClaims extracts claims from a VP token and maps them to OIDC claims
// using the template that matches the requested scopes
func (c *Client) extractAndMapClaims(ctx context.Context, vpToken string, scopeStr string) (map[string]any, error) {
	// If no claims extractor, fall back to basic extraction
	if c.claimsExtractor == nil {
		c.log.Debug("No claims extractor configured, using basic claim extraction")
		// Use sdjwt3 directly for basic claim extraction
		return c.claimsExtractor.ExtractClaimsFromVPToken(ctx, vpToken)
	}

	// If no presentation builder, use basic extraction without mapping
	if c.presentationBuilder == nil {
		c.log.Debug("No presentation builder configured, using basic extraction without mapping")
		return c.claimsExtractor.ExtractClaimsFromVPToken(ctx, vpToken)
	}

	// Parse scopes
	scopes := parseScopes(scopeStr)

	// Find the template that was used for this request
	template := c.presentationBuilder.FindTemplateByScopes(scopes)
	if template == nil {
		c.log.Debug("No template found for scopes, using basic claim extraction", "scopes", scopes)
		return c.claimsExtractor.ExtractClaimsFromVPToken(ctx, vpToken)
	}

	c.log.Debug("Using template for claim extraction", "template_id", template.GetID(), "scopes", scopes)

	// Get claim mappings from template
	claimMappings := openid4vp.GetClaimMappings(template)
	if claimMappings == nil {
		c.log.Debug("Template has no claim mappings, using basic extraction")
		return c.claimsExtractor.ExtractClaimsFromVPToken(ctx, vpToken)
	}

	// Convert ClaimTransform to ClaimTransformDef for the extractor
	transformDefs := make(map[string]openid4vp.ClaimTransformDef)
	if templateWithTransforms, ok := template.(interface {
		GetClaimTransforms() map[string]configuration.ClaimTransform
	}); ok {
		for claimName, transform := range templateWithTransforms.GetClaimTransforms() {
			transformDefs[claimName] = openid4vp.ClaimTransformDef{
				Type:   transform.Type,
				Params: transform.Params,
			}
		}
	}

	// Extract, map, and transform claims
	oidcClaims, err := c.claimsExtractor.ExtractAndMapClaims(ctx, vpToken, claimMappings, transformDefs)
	if err != nil {
		return nil, fmt.Errorf("failed to extract and map claims: %w", err)
	}

	return oidcClaims, nil
}

// parseScopes splits a scope string into individual scopes
func parseScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}
	return strings.Split(scopeStr, " ")
}

// generateSubjectIdentifier creates a subject identifier for the user
// This can be either public (same across all RPs) or pairwise (different per RP)
func (c *Client) generateSubjectIdentifier(walletID string, clientID string) string {
	subjectType := c.cfg.VerifierProxy.OIDC.SubjectType

	switch subjectType {
	case "pairwise":
		// Generate pairwise pseudonymous identifier
		hash := sha256.New()
		hash.Write([]byte(walletID))
		hash.Write([]byte(clientID))
		hash.Write([]byte(c.cfg.VerifierProxy.OIDC.SubjectSalt))
		return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	default:
		// Public subject identifier (same across all RPs)
		hash := sha256.New()
		hash.Write([]byte(walletID))
		hash.Write([]byte(c.cfg.VerifierProxy.OIDC.SubjectSalt))
		return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	}
}

// EphemeralEncryptionKey generates or retrieves an ephemeral encryption key
// TODO: Implement when needed for encrypted responses
/* func (c *Client) EphemeralEncryptionKey(kid string) (jwk.Key, jwk.Key, error) {
	// Check cache first
	if item := c.ephemeralEncryptionKeyCache.Get(kid); item != nil {
		privateKey := item.Value()
		publicKey, err := privateKey.PublicKey()
		if err != nil {
			return nil, nil, err
		}
		return privateKey, publicKey, nil
	}

	// Generate new key pair
	privateKey, err := jwk.GenerateKey(jwk.EC, jwk.P256, jwk.WithKeyID(kid))
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return nil, nil, err
	}

	// Cache the key
	c.ephemeralEncryptionKeyCache.Set(kid, privateKey, ttlcache.DefaultTTL)

	return privateKey, publicKey, nil
}
*/

// getSigningMethod returns the JWT signing method based on the configured algorithm
func (c *Client) getSigningMethod() jwt.SigningMethod {
	switch c.cfg.VerifierProxy.OIDC.SigningAlg {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	default:
		// Default to RS256 for backward compatibility
		c.log.Info("Unknown signing algorithm in config, defaulting to RS256", "algorithm", c.cfg.VerifierProxy.OIDC.SigningAlg)
		return jwt.SigningMethodRS256
	}
}
