package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_Allow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter: 10 requests per minute, burst of 2
	rl := NewRateLimiter(10, 2)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// First request should succeed
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request should succeed (within burst)
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiter_Exceed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create very restrictive rate limiter: 1 request per minute, burst of 1
	rl := NewRateLimiter(1, 1)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// First request should succeed
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second immediate request should be rate limited
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Check error response
	assert.Contains(t, w.Body.String(), "rate_limit_exceeded")
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter: 1 request per minute, burst of 1
	rl := NewRateLimiter(1, 1)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Request from IP 1
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Request from IP 2 should still succeed (different IP)
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.2")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimiter_Recovery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter: 60 requests per minute (1 per second), burst of 1
	rl := NewRateLimiter(60, 1)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// First request succeeds
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second immediate request is blocked
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Wait for token bucket to refill (slightly over 1 second)
	time.Sleep(1100 * time.Millisecond)

	// Third request should succeed after waiting
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	require.NotNil(t, config)
	assert.Greater(t, config.TokenRequestsPerMinute, 0)
	assert.Greater(t, config.TokenBurst, 0)
	assert.Greater(t, config.AuthorizeRequestsPerMinute, 0)
	assert.Greater(t, config.AuthorizeBurst, 0)
	assert.Greater(t, config.RegisterRequestsPerMinute, 0)
	assert.Greater(t, config.RegisterBurst, 0)

	// Token endpoint should be more restrictive than authorize
	assert.Less(t, config.TokenRequestsPerMinute, config.AuthorizeRequestsPerMinute)

	// Register should be most restrictive
	assert.Less(t, config.RegisterRequestsPerMinute, config.TokenRequestsPerMinute)
}

func BenchmarkRateLimiter(b *testing.B) {
	gin.SetMode(gin.TestMode)

	rl := NewRateLimiter(1000, 100)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
