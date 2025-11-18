package httpserver

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"vc/internal/verifier_proxy/apiv1"
)

// endpointRegisterClient handles OAuth 2.0 Dynamic Client Registration (RFC 7591)
func (s *Service) endpointRegisterClient(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointRegisterClient called")

	// Parse request body
	var req apiv1.ClientRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.log.Debug("Failed to parse registration request", "err", err)
		return nil, apiv1.NewInvalidRequestError("Invalid client metadata in request body")
	}

	// Delegate to apiv1 layer
	response, err := s.apiv1.RegisterClient(ctx, &req)
	if err != nil {
		s.log.Debug("Client registration failed", "err", err)
		return nil, err
	}

	return response, nil
}

// endpointGetClientConfiguration handles retrieving client configuration (RFC 7592)
func (s *Service) endpointGetClientConfiguration(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointGetClientConfiguration called")

	clientID := c.Param("client_id")
	if clientID == "" {
		return nil, apiv1.NewInvalidRequestError("Missing client_id parameter")
	}

	// Extract registration access token from Authorization header
	registrationAccessToken := extractBearerToken(c)
	if registrationAccessToken == "" {
		return nil, apiv1.ErrInvalidToken
	}

	// Delegate to apiv1 layer
	response, err := s.apiv1.GetClientInformation(ctx, clientID, registrationAccessToken)
	if err != nil {
		s.log.Debug("Get client configuration failed", "err", err)
		return nil, err
	}

	return response, nil
}

// endpointUpdateClient handles updating client configuration (RFC 7592)
func (s *Service) endpointUpdateClient(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointUpdateClient called")

	clientID := c.Param("client_id")
	if clientID == "" {
		return nil, apiv1.NewInvalidRequestError("Missing client_id parameter")
	}

	// Extract registration access token from Authorization header
	registrationAccessToken := extractBearerToken(c)
	if registrationAccessToken == "" {
		return nil, apiv1.ErrInvalidToken
	}

	// Parse request body
	var req apiv1.ClientRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.log.Debug("Failed to parse update request", "err", err)
		return nil, apiv1.NewInvalidRequestError("Invalid client metadata in request body")
	}

	// Delegate to apiv1 layer
	response, err := s.apiv1.UpdateClient(ctx, clientID, registrationAccessToken, &req)
	if err != nil {
		s.log.Debug("Client update failed", "err", err)
		return nil, err
	}

	return response, nil
}

// endpointDeleteClient handles deleting a client registration (RFC 7592)
func (s *Service) endpointDeleteClient(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointDeleteClient called")

	clientID := c.Param("client_id")
	if clientID == "" {
		return nil, apiv1.NewInvalidRequestError("Missing client_id parameter")
	}

	// Extract registration access token from Authorization header
	registrationAccessToken := extractBearerToken(c)
	if registrationAccessToken == "" {
		return nil, apiv1.ErrInvalidToken
	}

	// Delegate to apiv1 layer
	err := s.apiv1.DeleteClient(ctx, clientID, registrationAccessToken)
	if err != nil {
		s.log.Debug("Client deletion failed", "err", err)
		return nil, err
	}

	// RFC 7592 specifies 204 No Content for successful deletion
	c.Status(204)
	return nil, nil
}

// extractBearerToken extracts the bearer token from the Authorization header
func extractBearerToken(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}
