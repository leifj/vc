package apiv1

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOAuthError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *OAuthError
		expected string
	}{
		{
			name: "with description",
			err: &OAuthError{
				ErrorCode:        "invalid_request",
				ErrorDescription: "Missing parameter",
			},
			expected: "invalid_request: Missing parameter",
		},
		{
			name: "without description",
			err: &OAuthError{
				ErrorCode: "invalid_request",
			},
			expected: "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestOAuthError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &OAuthError{
		ErrorCode: "server_error",
		Cause:     cause,
	}

	assert.Equal(t, cause, err.Unwrap())
	assert.True(t, errors.Is(err, cause))
}

func TestPredefinedErrors(t *testing.T) {
	tests := []struct {
		name           string
		err            *OAuthError
		expectedCode   string
		expectedStatus int
	}{
		{
			name:           "ErrInvalidRequest",
			err:            ErrInvalidRequest,
			expectedCode:   ErrCodeInvalidRequest,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrInvalidClient",
			err:            ErrInvalidClient,
			expectedCode:   ErrCodeInvalidClient,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ErrInvalidGrant",
			err:            ErrInvalidGrant,
			expectedCode:   ErrCodeInvalidGrant,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrUnauthorizedClient",
			err:            ErrUnauthorizedClient,
			expectedCode:   ErrCodeUnauthorizedClient,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ErrUnsupportedGrantType",
			err:            ErrUnsupportedGrantType,
			expectedCode:   ErrCodeUnsupportedGrantType,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrInvalidScope",
			err:            ErrInvalidScope,
			expectedCode:   ErrCodeInvalidScope,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrAccessDenied",
			err:            ErrAccessDenied,
			expectedCode:   ErrCodeAccessDenied,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "ErrUnsupportedResponseType",
			err:            ErrUnsupportedResponseType,
			expectedCode:   ErrCodeUnsupportedResponseType,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrServerError",
			err:            ErrServerError,
			expectedCode:   ErrCodeServerError,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "ErrTemporarilyUnavailable",
			err:            ErrTemporarilyUnavailable,
			expectedCode:   ErrCodeTemporarilyUnavailable,
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "ErrInvalidToken",
			err:            ErrInvalidToken,
			expectedCode:   ErrCodeInvalidToken,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ErrExpiredToken",
			err:            ErrExpiredToken,
			expectedCode:   ErrCodeExpiredToken,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ErrSessionNotFound",
			err:            ErrSessionNotFound,
			expectedCode:   ErrCodeInvalidGrant,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrSessionExpired",
			err:            ErrSessionExpired,
			expectedCode:   ErrCodeSessionExpired,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrInvalidVP",
			err:            ErrInvalidVP,
			expectedCode:   ErrCodeInvalidRequest,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedCode, tt.err.ErrorCode)
			assert.Equal(t, tt.expectedStatus, tt.err.HTTPStatus)
			assert.NotEmpty(t, tt.err.ErrorDescription, "Error description should not be empty")
		})
	}
}

func TestNewOAuthError(t *testing.T) {
	err := NewOAuthError("custom_error", "Custom description", http.StatusTeapot)

	assert.Equal(t, "custom_error", err.ErrorCode)
	assert.Equal(t, "Custom description", err.ErrorDescription)
	assert.Equal(t, http.StatusTeapot, err.HTTPStatus)
}

func TestNewInvalidRequestError(t *testing.T) {
	description := "Missing client_id parameter"
	err := NewInvalidRequestError(description)

	assert.Equal(t, ErrCodeInvalidRequest, err.ErrorCode)
	assert.Equal(t, description, err.ErrorDescription)
	assert.Equal(t, http.StatusBadRequest, err.HTTPStatus)
}

func TestNewInvalidClientError(t *testing.T) {
	description := "Client not found"
	err := NewInvalidClientError(description)

	assert.Equal(t, ErrCodeInvalidClient, err.ErrorCode)
	assert.Equal(t, description, err.ErrorDescription)
	assert.Equal(t, http.StatusUnauthorized, err.HTTPStatus)
}

func TestNewInvalidGrantError(t *testing.T) {
	description := "Authorization code expired"
	err := NewInvalidGrantError(description)

	assert.Equal(t, ErrCodeInvalidGrant, err.ErrorCode)
	assert.Equal(t, description, err.ErrorDescription)
	assert.Equal(t, http.StatusBadRequest, err.HTTPStatus)
}

func TestNewInvalidScopeError(t *testing.T) {
	description := "Scope 'admin' is not allowed"
	err := NewInvalidScopeError(description)

	assert.Equal(t, ErrCodeInvalidScope, err.ErrorCode)
	assert.Equal(t, description, err.ErrorDescription)
	assert.Equal(t, http.StatusBadRequest, err.HTTPStatus)
}

func TestNewServerError(t *testing.T) {
	cause := errors.New("database connection failed")
	description := "Unable to process request"
	err := NewServerError(description, cause)

	assert.Equal(t, ErrCodeServerError, err.ErrorCode)
	assert.Equal(t, description, err.ErrorDescription)
	assert.Equal(t, http.StatusInternalServerError, err.HTTPStatus)
	assert.Equal(t, cause, err.Cause)
	assert.True(t, errors.Is(err, cause))
}

func TestGetHTTPStatus(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "OAuthError - BadRequest",
			err:      ErrInvalidRequest,
			expected: http.StatusBadRequest,
		},
		{
			name:     "OAuthError - Unauthorized",
			err:      ErrInvalidClient,
			expected: http.StatusUnauthorized,
		},
		{
			name:     "OAuthError - Forbidden",
			err:      ErrAccessDenied,
			expected: http.StatusForbidden,
		},
		{
			name:     "OAuthError - ServiceUnavailable",
			err:      ErrTemporarilyUnavailable,
			expected: http.StatusServiceUnavailable,
		},
		{
			name:     "Regular error - defaults to 500",
			err:      errors.New("some error"),
			expected: http.StatusInternalServerError,
		},
		{
			name:     "Wrapped OAuthError",
			err:      NewServerError("Wrapped", errors.New("underlying")),
			expected: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := GetHTTPStatus(tt.err)
			assert.Equal(t, tt.expected, status)
		})
	}
}

func TestIsOAuthError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "OAuthError",
			err:      ErrInvalidRequest,
			expected: true,
		},
		{
			name:     "Custom OAuthError",
			err:      NewInvalidRequestError("test"),
			expected: true,
		},
		{
			name:     "Regular error",
			err:      errors.New("not oauth"),
			expected: false,
		},
		{
			name:     "Wrapped OAuthError",
			err:      NewServerError("test", errors.New("cause")),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsOAuthError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAsOAuthError(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		expectedCode    string
		expectedStatus  int
		shouldHaveCause bool
	}{
		{
			name:            "Already OAuthError",
			err:             ErrInvalidRequest,
			expectedCode:    ErrCodeInvalidRequest,
			expectedStatus:  http.StatusBadRequest,
			shouldHaveCause: false,
		},
		{
			name:            "Regular error wrapped as ServerError",
			err:             errors.New("something went wrong"),
			expectedCode:    ErrCodeServerError,
			expectedStatus:  http.StatusInternalServerError,
			shouldHaveCause: true,
		},
		{
			name:            "Custom OAuthError preserved",
			err:             NewInvalidScopeError("custom"),
			expectedCode:    ErrCodeInvalidScope,
			expectedStatus:  http.StatusBadRequest,
			shouldHaveCause: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AsOAuthError(tt.err)
			assert.Equal(t, tt.expectedCode, result.ErrorCode)
			assert.Equal(t, tt.expectedStatus, result.HTTPStatus)
			if tt.shouldHaveCause {
				assert.NotNil(t, result.Cause)
				assert.True(t, errors.Is(result, tt.err))
			}
		})
	}
}

func TestHTTPStatusMapping(t *testing.T) {
	tests := []struct {
		errorCode      string
		expectedStatus int
	}{
		{ErrCodeInvalidRequest, http.StatusBadRequest},                 // 400
		{ErrCodeInvalidClient, http.StatusUnauthorized},                // 401
		{ErrCodeAccessDenied, http.StatusForbidden},                    // 403
		{ErrCodeInvalidGrant, http.StatusBadRequest},                   // 400
		{ErrCodeUnauthorizedClient, http.StatusUnauthorized},           // 401
		{ErrCodeUnsupportedGrantType, http.StatusBadRequest},           // 400
		{ErrCodeInvalidScope, http.StatusBadRequest},                   // 400
		{ErrCodeServerError, http.StatusInternalServerError},           // 500
		{ErrCodeTemporarilyUnavailable, http.StatusServiceUnavailable}, // 503
	}

	for _, tt := range tests {
		t.Run(tt.errorCode, func(t *testing.T) {
			err := NewOAuthError(tt.errorCode, "test", tt.expectedStatus)
			assert.Equal(t, tt.expectedStatus, err.HTTPStatus)
			assert.Equal(t, tt.expectedStatus, GetHTTPStatus(err))
		})
	}
}

func TestErrorConstants(t *testing.T) {
	// Verify all error code constants are defined correctly
	assert.Equal(t, "invalid_request", ErrCodeInvalidRequest)
	assert.Equal(t, "invalid_client", ErrCodeInvalidClient)
	assert.Equal(t, "invalid_grant", ErrCodeInvalidGrant)
	assert.Equal(t, "unauthorized_client", ErrCodeUnauthorizedClient)
	assert.Equal(t, "unsupported_grant_type", ErrCodeUnsupportedGrantType)
	assert.Equal(t, "invalid_scope", ErrCodeInvalidScope)
	assert.Equal(t, "access_denied", ErrCodeAccessDenied)
	assert.Equal(t, "unsupported_response_type", ErrCodeUnsupportedResponseType)
	assert.Equal(t, "server_error", ErrCodeServerError)
	assert.Equal(t, "temporarily_unavailable", ErrCodeTemporarilyUnavailable)
	assert.Equal(t, "invalid_token", ErrCodeInvalidToken)
	assert.Equal(t, "expired_token", ErrCodeExpiredToken)
	assert.Equal(t, "session_expired", ErrCodeSessionExpired)
}
