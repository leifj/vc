package httpserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"vc/pkg/httphelpers"
)

// setupOIDCRateLimitedEndpoints registers OIDC endpoints that require rate limiting.
// These endpoints use manual registration instead of RegEndpoint() because they need
// to apply rate limiting middleware before the handler wrapper.
func (s *Service) setupOIDCRateLimitedEndpoints(ctx context.Context, rgRoot *gin.RouterGroup) {
	// OAuth 2.0 / OIDC Authorization Endpoint (RFC 6749 §3.1)
	// Rate limited to prevent authorization code enumeration attacks
	rgRoot.GET("/authorize", s.authorizeLimiter.Middleware(),
		s.wrapHandler(ctx, "authorize", http.StatusOK, s.endpointAuthorize))

	// OAuth 2.0 / OIDC Token Endpoint (RFC 6749 §3.2)
	// Rate limited to prevent token brute-force attacks
	rgRoot.POST("/token", s.tokenLimiter.Middleware(),
		s.wrapHandler(ctx, "token", http.StatusOK, s.endpointToken))

	// Dynamic Client Registration Endpoint (RFC 7591)
	// Rate limited to prevent DoS via client registration spam
	rgRoot.POST("/register", s.registerLimiter.Middleware(),
		s.wrapHandler(ctx, "register", http.StatusCreated, s.endpointRegisterClient))
}

// wrapHandler wraps an endpoint handler function with standard tracing, logging, and error handling.
// This maintains consistency with RegEndpoint() while allowing middleware composition.
func (s *Service) wrapHandler(
	ctx context.Context,
	name string,
	successStatus int,
	handler func(context.Context, *gin.Context) (any, error),
) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create trace span for this endpoint
		k := fmt.Sprintf("api_endpoint %s:%s", c.Request.Method, name)
		ctx, span := s.tracer.Start(ctx, k)
		defer span.End()

		// Execute the handler
		res, err := handler(ctx, c)
		if err != nil {
			// Log the error
			s.log.Debug(fmt.Sprintf("endpoint%s", name), "err", err)

			// Return error response with appropriate status code
			c.JSON(httphelpers.StatusCode(ctx, err), gin.H{"error": err.Error()})
			return
		}

		// Return success response
		c.JSON(successStatus, res)
	}
}
