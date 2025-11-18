package utils

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"vc/pkg/oauth2"
)

// Package utils provides validation utilities for the verifier-proxy API.
// URL validation leverages Go's net/url package for parsing and standard checks,
// with additional security features (SSRF prevention) layered on top.

// ValidateRedirectURI validates a redirect URI against a list of allowed URIs.
// Returns true if the URI is in the allowed list (exact match required).
func ValidateRedirectURI(uri string, allowedURIs []string) bool {
	for _, allowedURI := range allowedURIs {
		if uri == allowedURI {
			return true
		}
	}
	return false
}

// urlValidationOptions configures URL validation behavior
type urlValidationOptions struct {
	requireHTTPS  bool
	requireHost   bool
	allowFragment bool
	blockSSRF     bool
}

// parseAndValidateURL is the core validation function that parses and validates URLs.
// It leverages net/url.Parse() and url.URL struct methods for all standard validations,
// with additional security checks (SSRF prevention) layered on top.
func parseAndValidateURL(rawURL, fieldName string, opts urlValidationOptions) (*url.URL, error) {
	// Let net/url do the parsing and basic validation
	u, err := url.Parse(rawURL)
	if err != nil {
		if fieldName == "redirect_uri" {
			return nil, fmt.Errorf("invalid %s: %w", fieldName, err)
		}
		return nil, fmt.Errorf("invalid %s URL: %w", fieldName, err)
	}

	// Use url.URL.Scheme for scheme validation
	// If HTTPS is required and there's no scheme or wrong scheme, prioritize that error
	if opts.requireHTTPS {
		if u.Scheme == "" || u.Scheme != "https" {
			return nil, fmt.Errorf("%s must use https scheme", fieldName)
		}
	} else if u.Scheme == "" {
		return nil, fmt.Errorf("%s must have a scheme", fieldName)
	}

	// Use url.URL.Fragment for fragment validation
	if !opts.allowFragment && u.Fragment != "" {
		return nil, fmt.Errorf("%s must not contain a fragment", fieldName)
	}

	// Use url.URL.Host for host validation
	if opts.requireHost && u.Host == "" {
		return nil, fmt.Errorf("%s must have a host", fieldName)
	}

	// Add SSRF prevention on top of stdlib validation
	if opts.blockSSRF {
		// Use url.URL.Hostname() to extract hostname without port
		if err := checkSSRF(u.Hostname()); err != nil {
			return nil, err
		}
	}

	return u, nil
}

// checkSSRF performs SSRF (Server-Side Request Forgery) prevention checks
func checkSSRF(hostname string) error {
	// Check for localhost
	if strings.ToLower(hostname) == "localhost" {
		return fmt.Errorf("localhost URLs are not allowed")
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname: %w", err)
	}

	// Check each resolved IP address using net.IP methods
	for _, ip := range ips {
		if err := validateIPAddress(ip); err != nil {
			return err
		}
	}

	return nil
}

// ValidateRedirectURIFormat validates that a redirect URI conforms to OAuth 2.0 requirements.
// Per RFC 6749:
// - Must have a scheme
// - Must not contain a fragment
//
// Uses net/url.Parse() for parsing and url.URL struct methods for validation.
func ValidateRedirectURIFormat(uri string) error {
	_, err := parseAndValidateURL(uri, "redirect_uri", urlValidationOptions{
		requireHTTPS:  false,
		requireHost:   false,
		allowFragment: false,
		blockSSRF:     false,
	})
	return err
}

// ValidateScopes validates that all requested scopes are in the allowed list.
// Returns true if all requested scopes are allowed.
func ValidateScopes(requestedScopes, allowedScopes []string) bool {
	for _, scope := range requestedScopes {
		if !contains(allowedScopes, scope) {
			return false
		}
	}
	return true
}

// ValidatePKCE validates the code verifier against the code challenge.
// Wraps the oauth2.ValidatePKCE function for consistency.
func ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	return oauth2.ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod)
}

// ValidateHTTPSURI validates that a URI uses HTTPS scheme and has proper format.
// Used for client metadata URIs (logo_uri, client_uri, policy_uri, tos_uri).
// Per RFC 7591 Section 2:
// - Must use HTTPS scheme
// - Must not contain a fragment
// - Must have a host
//
// Uses net/url.Parse() for parsing and url.URL struct methods for validation.
func ValidateHTTPSURI(uri, fieldName string) error {
	_, err := parseAndValidateURL(uri, fieldName, urlValidationOptions{
		requireHTTPS:  true,
		requireHost:   true,
		allowFragment: false,
		blockSSRF:     false,
	})
	return err
}

// ValidateURI validates a URI with SSRF (Server-Side Request Forgery) prevention.
// Blocks requests to:
// - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
// - Loopback addresses (127.0.0.0/8, ::1)
// - Link-local addresses (169.254.0.0/16, fe80::/10)
// - localhost hostname
//
// When requireHTTPS is true, also enforces HTTPS scheme.
//
// Uses net/url.Parse() for parsing, url.URL struct methods for standard validation,
// and net.IP methods (IsLoopback, IsLinkLocalUnicast, etc.) for security checks.
func ValidateURI(uri string, requireHTTPS bool) error {
	_, err := parseAndValidateURL(uri, "URL", urlValidationOptions{
		requireHTTPS:  requireHTTPS,
		requireHost:   false,
		allowFragment: false,
		blockSSRF:     true,
	})
	return err
}

// validateIPAddress checks if an IP address is in a blocked range.
// Uses net.IP methods from the standard library for IP validation.
func validateIPAddress(ip net.IP) error {
	// Check for loopback (127.0.0.0/8, ::1) using net.IP.IsLoopback()
	if ip.IsLoopback() {
		return fmt.Errorf("loopback addresses are not allowed")
	}

	// Check for link-local (169.254.0.0/16, fe80::/10) using net.IP methods
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("link-local addresses are not allowed")
	}

	// Check for private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
	if isPrivateIP(ip) {
		return fmt.Errorf("private IP addresses are not allowed")
	}

	return nil
}

// isPrivateIP checks if an IP is in a private range using net.ParseCIDR and net.IPNet.Contains
func isPrivateIP(ip net.IP) bool {
	// Private IPv4 ranges
	privateRanges := []string{
		"10.0.0.0/8",     // Class A private network
		"172.16.0.0/12",  // Class B private networks
		"192.168.0.0/16", // Class C private networks
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// contains checks if a slice contains a specific item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
