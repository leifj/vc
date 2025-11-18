//go:build saml

package saml

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"vc/pkg/logger"

	"github.com/crewjam/saml"
	"github.com/patrickmn/go-cache"
)

// MDQClient handles Metadata Query Protocol (MDQ) requests
type MDQClient struct {
	serverURL string
	cache     *cache.Cache
	client    *http.Client
	log       *logger.Log
}

// NewMDQClient creates a new MDQ client
func NewMDQClient(serverURL string, cacheTTL int, log *logger.Log) *MDQClient {
	if cacheTTL == 0 {
		cacheTTL = 3600
	}

	if !strings.HasSuffix(serverURL, "/") {
		serverURL += "/"
	}

	return &MDQClient{
		serverURL: serverURL,
		cache:     cache.New(time.Duration(cacheTTL)*time.Second, time.Duration(cacheTTL*2)*time.Second),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		log: log.New("mdq"),
	}
}

// GetIDPMetadata retrieves IdP metadata from MDQ server
func (m *MDQClient) GetIDPMetadata(ctx context.Context, entityID string) (*saml.EntityDescriptor, error) {
	m.log.Debug("fetching IdP metadata", "entity_id", entityID)

	if cached, found := m.cache.Get(entityID); found {
		m.log.Debug("IdP metadata found in cache", "entity_id", entityID)
		return cached.(*saml.EntityDescriptor), nil
	}

	encodedEntityID := url.QueryEscape(entityID)
	mdqURL := m.serverURL + encodedEntityID

	m.log.Debug("querying MDQ server", "url", mdqURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mdqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create MDQ request: %w", err)
	}

	req.Header.Set("Accept", "application/samlmetadata+xml")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MDQ request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MDQ server returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read MDQ response: %w", err)
	}

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse IdP metadata XML: %w", err)
	}

	if len(metadata.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("metadata does not contain IdP SSO descriptor")
	}

	if len(metadata.IDPSSODescriptors[0].SingleSignOnServices) == 0 {
		return nil, fmt.Errorf("IdP metadata does not contain SSO service endpoint")
	}

	m.cache.Set(entityID, &metadata, cache.DefaultExpiration)

	m.log.Info("IdP metadata fetched and cached",
		"entity_id", entityID,
		"sso_location", metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location)

	return &metadata, nil
}

// ClearCache clears all cached metadata
func (m *MDQClient) ClearCache() {
	m.cache.Flush()
	m.log.Debug("MDQ cache cleared")
}

// CacheStats returns cache statistics
func (m *MDQClient) CacheStats() (itemCount int) {
	return m.cache.ItemCount()
}
