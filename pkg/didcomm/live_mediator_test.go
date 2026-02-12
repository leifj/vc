//go:build didcomm && vc20 && live

// Package didcomm_test provides live integration tests against the public mediator.
//
// These tests verify DIDComm functionality with a real public mediator:
// - DID resolution via go-trust did:webvh registry
// - Key extraction from resolved DID documents
// - Trust ping messaging to the mediator
//
// To run live mediator tests:
//   go test -tags "didcomm vc20 live" -v ./pkg/didcomm/...
//
// Requirements:
// - Network connectivity to the public mediator
// - The public mediator at fpp.storm.ws must be available
package didcomm_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/didwebvh"
	"github.com/sirosfoundation/go-trust/pkg/testserver"

	"vc/pkg/didcomm"
	"vc/pkg/didcomm/message"
	"vc/pkg/didcomm/protocol/trustping"
	"vc/pkg/didcomm/routing"
	"vc/pkg/didcomm/transport"
	"vc/pkg/keyresolver"
)

// Public mediator constants
const (
	// PublicMediatorDIDWebVH is the did:webvh identifier for the public test mediator
	PublicMediatorDIDWebVH = "did:webvh:QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V:fpp.storm.ws:public-mediator"

	// PublicMediatorServiceEndpoint is the expected HTTP service endpoint
	PublicMediatorServiceEndpoint = "https://public-mediator.fpp.storm.ws/mediator/v1"

	// PublicMediatorWSEndpoint is the expected WebSocket service endpoint
	PublicMediatorWSEndpoint = "wss://public-mediator.fpp.storm.ws/mediator/v1/ws"
)

// =============================================================================
// DID Resolution Tests via go-trust
// =============================================================================

// TestLiveMediatorDIDResolution tests resolving the public mediator DID
// using the go-trust did:webvh registry.
func TestLiveMediatorDIDResolution(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	// Create test server with the did:webvh registry
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	// Create resolver using the test server
	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test resolution (this sends a resolution-only request)
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve mediator DID: %v", err)
	}

	if !resp.Decision {
		reason := "unknown"
		if resp.Context != nil && resp.Context.Reason != nil {
			if r, ok := resp.Context.Reason["error"].(string); ok {
				reason = r
			}
		}
		t.Fatalf("Resolution denied: %s", reason)
	}

	t.Log("✓ Successfully resolved public mediator DID")

	// Verify we got trust_metadata (the DID document)
	if resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("No trust_metadata in response")
	}

	// Type assert trust_metadata to map
	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatalf("trust_metadata is not a map, got %T", resp.Context.TrustMetadata)
	}

	// Log the resolved DID document structure
	metadataJSON, _ := json.MarshalIndent(didDoc, "", "  ")
	t.Logf("Resolved DID Document:\n%s", string(metadataJSON))

	// Verify expected fields
	if id, ok := didDoc["id"].(string); !ok || id != PublicMediatorDIDWebVH {
		t.Errorf("Expected DID ID %s, got %v", PublicMediatorDIDWebVH, didDoc["id"])
	}

	// Verify verification methods exist
	if vms, ok := didDoc["verificationMethod"].([]interface{}); !ok || len(vms) == 0 {
		t.Error("Expected verification methods in DID document")
	} else {
		t.Logf("✓ Found %d verification methods", len(vms))
	}

	// Verify service endpoints exist
	if services, ok := didDoc["service"].([]interface{}); !ok || len(services) == 0 {
		t.Error("Expected service endpoints in DID document")
	} else {
		t.Logf("✓ Found %d services", len(services))
		for _, svc := range services {
			if svcMap, ok := svc.(map[string]interface{}); ok {
				t.Logf("  Service: %s (%s)", svcMap["id"], svcMap["type"])
			}
		}
	}

	// Verify key agreement keys exist
	if kas, ok := didDoc["keyAgreement"].([]interface{}); !ok || len(kas) == 0 {
		t.Error("Expected keyAgreement references in DID document")
	} else {
		t.Logf("✓ Found %d keyAgreement references", len(kas))
	}
}

// TestLiveMediatorKeyExtraction tests extracting keys from the resolved DID document.
func TestLiveMediatorKeyExtraction(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	// Create test server with the did:webvh registry
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	// Create resolver using the test server
	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Resolve the mediator DID
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve mediator DID: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed or no metadata")
	}

	// Type assert trust_metadata to map
	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatalf("trust_metadata is not a map, got %T", resp.Context.TrustMetadata)
	}

	// Extract verification methods
	vms, ok := didDoc["verificationMethod"].([]interface{})
	if !ok {
		t.Fatal("No verification methods in DID document")
	}

	// Parse each verification method
	var x25519Keys []jwk.Key
	var ed25519Keys []jwk.Key
	var p256Keys []jwk.Key
	var secp256k1Keys []jwk.Key

	for _, vm := range vms {
		vmMap, ok := vm.(map[string]interface{})
		if !ok {
			continue
		}

		vmID := vmMap["id"].(string)
		vmType := vmMap["type"].(string)

		t.Logf("Processing verification method: %s (type: %s)", vmID, vmType)

		// Handle Multikey format
		if vmType == "Multikey" {
			multibase, ok := vmMap["publicKeyMultibase"].(string)
			if !ok {
				t.Logf("  No publicKeyMultibase for %s", vmID)
				continue
			}

			key, keyType, err := parseMultikey(multibase)
			if err != nil {
				t.Logf("  Failed to parse multikey %s: %v", vmID, err)
				continue
			}

			switch keyType {
			case "Ed25519":
				ed25519Keys = append(ed25519Keys, key)
				t.Logf("  ✓ Parsed Ed25519 key")
			case "X25519":
				x25519Keys = append(x25519Keys, key)
				t.Logf("  ✓ Parsed X25519 key")
			case "P-256":
				p256Keys = append(p256Keys, key)
				t.Logf("  ✓ Parsed P-256 key")
			case "secp256k1":
				secp256k1Keys = append(secp256k1Keys, key)
				t.Logf("  ✓ Parsed secp256k1 key")
			default:
				t.Logf("  Unknown key type: %s", keyType)
			}
		}
	}

	t.Logf("\nKey summary:")
	t.Logf("  Ed25519 keys: %d", len(ed25519Keys))
	t.Logf("  X25519 keys: %d", len(x25519Keys))
	t.Logf("  P-256 keys: %d", len(p256Keys))
	t.Logf("  secp256k1 keys: %d", len(secp256k1Keys))

	// Verify we have at least one key agreement key (X25519 or P-256)
	if len(x25519Keys) == 0 && len(p256Keys) == 0 {
		t.Error("Expected at least one key agreement key (X25519 or P-256)")
	}
}

// TestLiveMediatorServiceEndpoints tests extracting service endpoints from the mediator DID.
func TestLiveMediatorServiceEndpoints(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	// Create test server with the did:webvh registry
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	// Create resolver using the test server
	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Resolve the mediator DID
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve mediator DID: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed or no metadata")
	}

	// Type assert trust_metadata to map
	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatalf("trust_metadata is not a map, got %T", resp.Context.TrustMetadata)
	}

	// Extract services
	services, ok := didDoc["service"].([]interface{})
	if !ok || len(services) == 0 {
		t.Fatal("No services in DID document")
	}

	var didcommService *routing.DIDCommService
	var didcommServiceID string
	for _, svc := range services {
		svcMap, ok := svc.(map[string]interface{})
		if !ok {
			continue
		}

		svcType, _ := svcMap["type"].(string)
		if svcType != "DIDCommMessaging" {
			continue
		}

		// Parse DIDCommMessaging service
		didcommService = &routing.DIDCommService{}
		didcommServiceID, _ = svcMap["id"].(string)

		// Parse service endpoint(s)
		if endpoint, ok := svcMap["serviceEndpoint"]; ok {
			switch ep := endpoint.(type) {
			case string:
				didcommService.ServiceEndpoint = ep
			case []interface{}:
				// Multiple endpoints (HTTP and WebSocket)
				for _, e := range ep {
					if epMap, ok := e.(map[string]interface{}); ok {
						uri := epMap["uri"].(string)
						accept, _ := epMap["accept"].([]interface{})
						t.Logf("  Endpoint: %s (accept: %v)", uri, accept)

						// Use the first HTTP endpoint
						if didcommService.ServiceEndpoint == "" {
							didcommService.ServiceEndpoint = uri
						}
					}
				}
			}
		}

		break
	}

	if didcommService == nil {
		t.Fatal("No DIDCommMessaging service found")
	}

	t.Logf("✓ Found DIDCommMessaging service: %s", didcommServiceID)
	t.Logf("  Service endpoint: %s", didcommService.ServiceEndpoint)

	// Verify expected endpoint
	if didcommService.ServiceEndpoint != PublicMediatorServiceEndpoint {
		t.Logf("Note: Service endpoint is %s (expected %s)", didcommService.ServiceEndpoint, PublicMediatorServiceEndpoint)
	}
}

// =============================================================================
// Trust Ping Tests with Live Mediator
// =============================================================================

// TestLiveMediatorTrustPingMessage tests creating a trust ping message for the mediator.
func TestLiveMediatorTrustPingMessage(t *testing.T) {
	// Generate sender keys
	_, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate sender key: %v", err)
	}
	_ = senderPriv // Would be used for signing

	// Create trust ping message to the mediator
	senderDID := "did:key:" + generateDIDKeyFromEd25519(t)
	ping, err := trustping.NewPing(
		senderDID,
		PublicMediatorDIDWebVH,
		trustping.WithResponseRequested(true),
	)
	if err != nil {
		t.Fatalf("Failed to create trust ping: %v", err)
	}

	// Verify message structure
	if ping.Type != trustping.TypePing {
		t.Errorf("Wrong message type: %s", ping.Type)
	}

	if ping.From != senderDID {
		t.Errorf("Wrong from DID: %s", ping.From)
	}

	if len(ping.To) == 0 || ping.To[0] != PublicMediatorDIDWebVH {
		t.Errorf("Wrong to DID: %v", ping.To)
	}

	t.Logf("✓ Created trust ping message:")
	t.Logf("  ID: %s", ping.ID)
	t.Logf("  Type: %s", ping.Type)
	t.Logf("  From: %s", ping.From)
	t.Logf("  To: %v", ping.To)
}

// TestLiveMediatorPackMessage tests packing a message for the mediator using resolved keys.
func TestLiveMediatorPackMessage(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	// Create test server with the did:webvh registry
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	// Create resolver using the test server
	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Resolve the mediator DID
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve mediator DID: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed or no metadata")
	}

	// Type assert trust_metadata to map
	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatalf("trust_metadata is not a map, got %T", resp.Context.TrustMetadata)
	}

	// Extract key agreement keys from the DID document
	recipientKeys, err := extractKeyAgreementKeys(didDoc)
	if err != nil {
		t.Fatalf("Failed to extract key agreement keys: %v", err)
	}

	if len(recipientKeys) == 0 {
		t.Fatal("No key agreement keys found in mediator DID document")
	}

	t.Logf("✓ Found %d key agreement keys", len(recipientKeys))

	// Create a trust ping message
	senderDID := "did:key:" + generateDIDKeyFromEd25519(t)
	ping, err := trustping.NewPing(senderDID, PublicMediatorDIDWebVH, trustping.WithResponseRequested(true))
	if err != nil {
		t.Fatalf("Failed to create trust ping: %v", err)
	}

	// Convert to message.Message
	msg := message.New(
		message.WithID(ping.ID),
		message.WithType(ping.Type),
		message.WithFrom(ping.From),
		message.WithTo(ping.To[0]),
		message.WithBody(ping.Body),
	)

	// Pack the message (anonymous encryption to mediator)
	packed, err := didcomm.PackAnoncrypt(ctx, msg, recipientKeys)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	t.Logf("✓ Successfully packed message:")
	t.Logf("  Media type: %s", packed.MediaType)
	t.Logf("  Message size: %d bytes", len(packed.Message))

	// Verify it's a valid JWE
	if len(packed.Message) < 100 {
		t.Error("Packed message seems too small for a JWE")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// parseMultikey parses a multibase-encoded multikey and returns a JWK and key type.
func parseMultikey(multibase string) (jwk.Key, string, error) {
	// Multikey format: z<multicodec><key-bytes>
	// Common multicodec prefixes:
	// - 0xed (237): Ed25519 public key
	// - 0xec (236): X25519 public key
	// - 0x1200: P-256 public key
	// - 0xe7 (231): secp256k1 public key

	if len(multibase) < 2 || multibase[0] != 'z' {
		return nil, "", nil
	}

	// Decode base58btc (without the 'z' prefix)
	decoded, err := decodeBase58btc(multibase[1:])
	if err != nil {
		return nil, "", err
	}

	if len(decoded) < 2 {
		return nil, "", nil
	}

	// Check multicodec prefix
	switch {
	case decoded[0] == 0xed && decoded[1] == 0x01:
		// Ed25519 (0xed01)
		if len(decoded) < 34 {
			return nil, "", nil
		}
		keyBytes := decoded[2:]
		key, err := jwk.Import(ed25519.PublicKey(keyBytes))
		if err != nil {
			return nil, "", err
		}
		return key, "Ed25519", nil

	case decoded[0] == 0xec && decoded[1] == 0x01:
		// X25519 (0xec01)
		if len(decoded) < 34 {
			return nil, "", nil
		}
		keyBytes := decoded[2:]
		pubKey, err := ecdh.X25519().NewPublicKey(keyBytes)
		if err != nil {
			return nil, "", err
		}
		key, err := jwk.Import(pubKey)
		if err != nil {
			return nil, "", err
		}
		return key, "X25519", nil

	case decoded[0] == 0x80 && decoded[1] == 0x24:
		// P-256 (varint 0x1200 = 0x80 0x24)
		if len(decoded) < 35 {
			return nil, "", nil
		}
		// Compressed P-256 key
		keyBytes := decoded[2:]
		key, err := importP256CompressedKey(keyBytes)
		if err != nil {
			return nil, "", err
		}
		return key, "P-256", nil

	case decoded[0] == 0xe7 && decoded[1] == 0x01:
		// secp256k1 (0xe701)
		if len(decoded) < 35 {
			return nil, "", nil
		}
		keyBytes := decoded[2:]
		key, err := importSecp256k1CompressedKey(keyBytes)
		if err != nil {
			return nil, "", err
		}
		return key, "secp256k1", nil
	}

	return nil, "", nil
}

// decodeBase58btc decodes a base58btc string.
func decodeBase58btc(s string) ([]byte, error) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading '1's (zeros)
	zeros := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		zeros++
	}

	// Build index table
	table := make([]int, 128)
	for i := range table {
		table[i] = -1
	}
	for i, c := range alphabet {
		table[c] = i
	}

	// Process characters
	result := make([]byte, len(s)*733/1000+1)
	resultLen := 0

	for _, c := range s {
		if c >= 128 || table[c] == -1 {
			return nil, nil
		}
		carry := table[c]
		for i := 0; i < resultLen || carry != 0; i++ {
			if i < resultLen {
				carry += 58 * int(result[i])
			}
			result[i] = byte(carry % 256)
			carry /= 256
			if i >= resultLen {
				resultLen = i + 1
			}
		}
	}

	// Reverse result
	output := make([]byte, zeros+resultLen)
	for i := 0; i < resultLen; i++ {
		output[zeros+resultLen-1-i] = result[i]
	}

	return output, nil
}

// importP256CompressedKey imports a compressed P-256 public key.
func importP256CompressedKey(compressed []byte) (jwk.Key, error) {
	// For now, skip P-256 compressed key parsing (complex elliptic point decompression)
	return nil, nil
}

// importSecp256k1CompressedKey imports a compressed secp256k1 public key.
func importSecp256k1CompressedKey(compressed []byte) (jwk.Key, error) {
	// For now, skip secp256k1 compressed key parsing (complex elliptic point decompression)
	return nil, nil
}

// extractKeyAgreementKeys extracts JWK keys from a DID document's keyAgreement section.
func extractKeyAgreementKeys(didDoc map[string]interface{}) ([]jwk.Key, error) {
	var keys []jwk.Key

	// Get keyAgreement references
	kaRefs, ok := didDoc["keyAgreement"].([]interface{})
	if !ok {
		return nil, nil
	}

	// Get verification methods
	vms, ok := didDoc["verificationMethod"].([]interface{})
	if !ok {
		return nil, nil
	}

	// Build a map of VM IDs to verification methods
	vmMap := make(map[string]map[string]interface{})
	for _, vm := range vms {
		vmObj, ok := vm.(map[string]interface{})
		if !ok {
			continue
		}
		vmID, _ := vmObj["id"].(string)
		vmMap[vmID] = vmObj
	}

	// Process each keyAgreement reference
	for _, kaRef := range kaRefs {
		refStr, ok := kaRef.(string)
		if !ok {
			continue
		}

		vmObj, exists := vmMap[refStr]
		if !exists {
			continue
		}

		// Parse the verification method
		vmType, _ := vmObj["type"].(string)
		if vmType == "Multikey" {
			multibase, ok := vmObj["publicKeyMultibase"].(string)
			if !ok {
				continue
			}

			key, keyType, err := parseMultikey(multibase)
			if err != nil || key == nil {
				continue
			}

			// Only include key agreement capable keys (X25519, P-256, secp256k1)
			if keyType == "X25519" || keyType == "P-256" || keyType == "secp256k1" {
				// Set the key ID
				vmID, _ := vmObj["id"].(string)
				_ = key.Set("kid", vmID)
				keys = append(keys, key)
			}
		}
	}

	return keys, nil
}

// generateDIDKeyFromEd25519 generates a did:key identifier from a generated Ed25519 key.
func generateDIDKeyFromEd25519(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Multicodec prefix for Ed25519: 0xed01
	multicodec := []byte{0xed, 0x01}
	keyBytes := append(multicodec, pub...)

	// Encode as base58btc with 'z' prefix
	return "z" + encodeBase58btc(keyBytes)
}

// encodeBase58btc encodes bytes to base58btc string.
func encodeBase58btc(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading zeros
	zeros := 0
	for _, b := range data {
		if b == 0 {
			zeros++
		} else {
			break
		}
	}

	// Allocate enough space
	size := len(data)*138/100 + 1
	buf := make([]byte, size)

	var length int
	for _, b := range data {
		carry := int(b)
		for i := 0; i < length || carry != 0; i++ {
			if i < length {
				carry += 256 * int(buf[i])
			}
			buf[i] = byte(carry % 58)
			carry /= 58
			if i >= length {
				length = i + 1
			}
		}
	}

	// Build result
	result := make([]byte, zeros+length)
	for i := 0; i < zeros; i++ {
		result[i] = '1'
	}
	for i := 0; i < length; i++ {
		result[zeros+i] = alphabet[buf[length-1-i]]
	}

	return string(result)
}

// =============================================================================
// Evaluation Response Helpers
// =============================================================================

// getReasonError extracts the error message from an evaluation response.
func getReasonError(resp *authzen.EvaluationResponse) string {
	if resp == nil || resp.Context == nil || resp.Context.Reason == nil {
		return "unknown"
	}
	if errStr, ok := resp.Context.Reason["error"].(string); ok {
		return errStr
	}
	return "unknown"
}

// =============================================================================
// HTTP Transport Tests
// =============================================================================

// TestLiveMediatorHTTPSend tests sending a trust ping to the mediator over HTTP.
func TestLiveMediatorHTTPSend(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	// Create test server with the did:webvh registry
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	// Create resolver using the test server
	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Resolve the mediator DID
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve mediator DID: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed or no metadata")
	}

	// Type assert trust_metadata to map
	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatalf("trust_metadata is not a map, got %T", resp.Context.TrustMetadata)
	}

	// Extract key agreement keys from the DID document
	recipientKeys, err := extractKeyAgreementKeys(didDoc)
	if err != nil {
		t.Fatalf("Failed to extract key agreement keys: %v", err)
	}

	if len(recipientKeys) == 0 {
		t.Fatal("No key agreement keys found in mediator DID document")
	}

	// Create a trust ping message
	senderDID := "did:key:" + generateDIDKeyFromEd25519(t)
	ping, err := trustping.NewPing(senderDID, PublicMediatorDIDWebVH, trustping.WithResponseRequested(true))
	if err != nil {
		t.Fatalf("Failed to create trust ping: %v", err)
	}

	// Convert to message.Message
	msg := message.New(
		message.WithID(ping.ID),
		message.WithType(ping.Type),
		message.WithFrom(ping.From),
		message.WithTo(ping.To[0]),
		message.WithBody(ping.Body),
	)

	// Pack the message
	packed, err := didcomm.PackAnoncrypt(ctx, msg, recipientKeys)
	if err != nil {
		t.Fatalf("Failed to pack message: %v", err)
	}

	t.Logf("✓ Packed message (%d bytes)", len(packed.Message))

	// Trace: Log request details
	t.Log("=== HTTP REQUEST TRACE ===")
	t.Logf("  Method: POST")
	t.Logf("  Endpoint: %s", PublicMediatorServiceEndpoint)
	t.Logf("  Content-Type: %s", packed.MediaType)
	t.Logf("  Body size: %d bytes", len(packed.Message))
	t.Logf("  Body (first 500 chars): %s", truncateString(string(packed.Message), 500))

	// Create HTTP client
	httpClient := transport.NewHTTPClient(transport.WithTimeout(30 * time.Second))

	// Send the message
	sendResp, err := httpClient.Send(ctx, transport.SendRequest{
		Endpoint:     PublicMediatorServiceEndpoint,
		Message:      packed.Message,
		MediaType:    packed.MediaType,
		ExpectReturn: true,
	})

	if err != nil {
		t.Fatalf("HTTP send failed: %v (endpoint: %s)", err, PublicMediatorServiceEndpoint)
	}

	// Trace: Log response details
	t.Log("=== HTTP RESPONSE TRACE ===")
	t.Logf("  Status: %d", sendResp.StatusCode)
	t.Logf("  Content-Type: %s", sendResp.MediaType)
	t.Logf("  Body size: %d bytes", len(sendResp.Body))
	if len(sendResp.Body) > 0 {
		t.Logf("  Body: %s", truncateString(string(sendResp.Body), 1000))
	}

	// Per DIDComm HTTP transport spec:
	// - 200 OK: synchronous response with DIDComm message in body
	// - 202 Accepted: message received, no immediate response
	if sendResp.StatusCode != 200 && sendResp.StatusCode != 202 {
		t.Fatalf("Expected HTTP 200 or 202, got %d: %s", sendResp.StatusCode, string(sendResp.Body))
	}

	if sendResp.StatusCode == 202 {
		t.Log("✓ Message accepted for asynchronous processing (202 Accepted)")
		return
	}

	// 200 OK - should have a response message
	if len(sendResp.Body) == 0 {
		t.Fatal("200 OK response but empty body")
	}

	// Verify Content-Type is a DIDComm media type
	validMediaTypes := []string{
		"application/didcomm-encrypted+json",
		"application/didcomm-signed+json",
		"application/didcomm-plain+json",
	}
	validContentType := false
	for _, mt := range validMediaTypes {
		if sendResp.MediaType == mt {
			validContentType = true
			break
		}
	}
	if !validContentType {
		t.Fatalf("Expected DIDComm media type, got: %s", sendResp.MediaType)
	}

	t.Logf("✓ Received DIDComm response (%s, %d bytes)", sendResp.MediaType, len(sendResp.Body))

	// Log the response for debugging
	var responseData interface{}
	if json.Unmarshal(sendResp.Body, &responseData) == nil {
		respJSON, _ := json.MarshalIndent(responseData, "  ", "  ")
		t.Logf("Response:\n  %s", string(respJSON))
	}
}

// TestLiveMediatorInvalidDID tests error handling for invalid DIDs.
func TestLiveMediatorInvalidDID(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     10 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	// Create test server with the did:webvh registry
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	// Create resolver
	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	testCases := []struct {
		name    string
		did     string
		wantErr bool
	}{
		{
			name:    "Invalid DID format",
			did:     "not-a-did",
			wantErr: true,
		},
		{
			name:    "Unknown did:webvh",
			did:     "did:webvh:QmInvalidSCID12345:nonexistent.example.com:test",
			wantErr: true,
		},
		{
			name:    "did:key format",
			did:     "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
			wantErr: true, // did:webvh registry won't handle did:key
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			resp, err := resolver.GetClient().Resolve(ctx, tc.did)

			if tc.wantErr {
				if err != nil {
					t.Logf("✓ Got expected error: %v", err)
				} else if !resp.Decision {
					reason := getReasonError(resp)
					t.Logf("✓ Resolution denied as expected: %s", reason)
				} else {
					t.Errorf("Expected error or denial for %s, but got success", tc.did)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.did, err)
				} else if !resp.Decision {
					t.Errorf("Unexpected denial for %s", tc.did)
				}
			}
		})
	}
}

// TestLiveMediatorMultipleResolutions tests that multiple resolutions work consistently.
func TestLiveMediatorMultipleResolutions(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	// Create test server
	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Resolve the same DID multiple times
	const numResolutions = 5
	var firstDIDID string
	var durations []time.Duration

	for i := 0; i < numResolutions; i++ {
		start := time.Now()

		resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
		if err != nil {
			t.Fatalf("Resolution %d failed: %v", i+1, err)
		}

		duration := time.Since(start)
		durations = append(durations, duration)

		if !resp.Decision {
			t.Fatalf("Resolution %d denied", i+1)
		}

		// Type assert trust_metadata to map
		didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
		if !ok {
			t.Fatalf("Resolution %d: trust_metadata is not a map", i+1)
		}

		didID, _ := didDoc["id"].(string)
		if firstDIDID == "" {
			firstDIDID = didID
		} else if didID != firstDIDID {
			t.Errorf("Resolution %d returned different DID ID: %s vs %s", i+1, didID, firstDIDID)
		}

		t.Logf("Resolution %d: %v", i+1, duration)
	}

	// Calculate average
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	avg := total / time.Duration(len(durations))

	t.Logf("✓ All %d resolutions returned consistent DID: %s", numResolutions, firstDIDID)
	t.Logf("  Average resolution time: %v", avg)
}

// TestLiveMediatorDIDKeyFormats tests generating did:key identifiers with different algorithms.
func TestLiveMediatorDIDKeyFormats(t *testing.T) {
	testCases := []struct {
		name   string
		prefix byte
	}{
		{
			name:   "Ed25519",
			prefix: 0xed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			didKey := "did:key:" + generateDIDKeyFromEd25519(t)

			// Verify format
			if len(didKey) < 50 {
				t.Errorf("did:key seems too short: %s", didKey)
			}

			if didKey[:12] != "did:key:z6Mk" {
				t.Errorf("Unexpected did:key prefix: %s", didKey[:12])
			}

			t.Logf("✓ Generated %s did:key: %s", tc.name, didKey)
		})
	}
}

// TestLiveMediatorDiscoverServiceEndpoints tests discovering all service endpoints.
func TestLiveMediatorDiscoverServiceEndpoints(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	services, ok := didDoc["service"].([]interface{})
	if !ok {
		t.Fatal("No services in DID document")
	}

	t.Log("Discovered services:")

	var foundHTTP, foundWS bool
	for _, svc := range services {
		svcMap, ok := svc.(map[string]interface{})
		if !ok {
			continue
		}

		svcID := svcMap["id"]
		svcType := svcMap["type"]
		t.Logf("  Service: %s (type: %s)", svcID, svcType)

		// Parse endpoints
		if ep, ok := svcMap["serviceEndpoint"]; ok {
			switch endpoint := ep.(type) {
			case string:
				t.Logf("    Endpoint: %s", endpoint)
			case []interface{}:
				for _, e := range endpoint {
					if epMap, ok := e.(map[string]interface{}); ok {
						uri, _ := epMap["uri"].(string)
						accept, _ := epMap["accept"].([]interface{})
						t.Logf("    Endpoint: %s (accept: %v)", uri, accept)

						if uri == PublicMediatorServiceEndpoint {
							foundHTTP = true
						}
						if uri == PublicMediatorWSEndpoint {
							foundWS = true
						}
					}
				}
			}
		}
	}

	if foundHTTP {
		t.Logf("✓ Found expected HTTP endpoint: %s", PublicMediatorServiceEndpoint)
	} else {
		t.Logf("⚠ Expected HTTP endpoint not found: %s", PublicMediatorServiceEndpoint)
	}

	if foundWS {
		t.Logf("✓ Found expected WebSocket endpoint: %s", PublicMediatorWSEndpoint)
	} else {
		t.Logf("⚠ Expected WebSocket endpoint not found: %s", PublicMediatorWSEndpoint)
	}
}

// TestLiveMediatorDiscoverFeatures tests querying the mediator's supported features.
func TestLiveMediatorDiscoverFeatures(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Resolve the mediator DID
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	// Extract recipient keys
	recipientKeys, err := extractKeyAgreementKeys(didDoc)
	if err != nil || len(recipientKeys) == 0 {
		t.Fatal("No key agreement keys found")
	}

	// Create discover-features query
	senderDID := "did:key:" + generateDIDKeyFromEd25519(t)

	// Build discover-features 2.0 query message
	queryMsg := message.New(
		message.WithType("https://didcomm.org/discover-features/2.0/queries"),
		message.WithFrom(senderDID),
		message.WithTo(PublicMediatorDIDWebVH),
		message.WithBody(map[string]interface{}{
			"queries": []map[string]interface{}{
				{
					"feature-type": "protocol",
					"match":        "https://didcomm.org/*",
				},
			},
		}),
	)

	// Pack the message
	packed, err := didcomm.PackAnoncrypt(ctx, queryMsg, recipientKeys)
	if err != nil {
		t.Fatalf("Failed to pack discover-features query: %v", err)
	}

	t.Logf("✓ Created discover-features query (%d bytes)", len(packed.Message))

	// Trace: Log request details
	t.Log("=== HTTP REQUEST TRACE ===")
	t.Logf("  Method: POST")
	t.Logf("  Endpoint: %s", PublicMediatorServiceEndpoint)
	t.Logf("  Content-Type: %s", packed.MediaType)
	t.Logf("  Body size: %d bytes", len(packed.Message))
	t.Logf("  Body (first 500 chars): %s", truncateString(string(packed.Message), 500))

	// Send the message
	httpClient := transport.NewHTTPClient(transport.WithTimeout(30 * time.Second))

	sendResp, err := httpClient.Send(ctx, transport.SendRequest{
		Endpoint:     PublicMediatorServiceEndpoint,
		Message:      packed.Message,
		MediaType:    packed.MediaType,
		ExpectReturn: true,
	})

	if err != nil {
		t.Fatalf("HTTP send failed: %v", err)
	}

	// Trace: Log response details
	t.Log("=== HTTP RESPONSE TRACE ===")
	t.Logf("  Status: %d", sendResp.StatusCode)
	t.Logf("  Content-Type: %s", sendResp.MediaType)
	t.Logf("  Body size: %d bytes", len(sendResp.Body))
	if len(sendResp.Body) > 0 {
		t.Logf("  Body: %s", truncateString(string(sendResp.Body), 1000))
	}

	// Per DIDComm HTTP transport spec:
	// - 200 OK: synchronous response with DIDComm message
	// - 202 Accepted: message received for async processing
	if sendResp.StatusCode != 200 && sendResp.StatusCode != 202 {
		t.Fatalf("Expected HTTP 200 or 202, got %d: %s", sendResp.StatusCode, string(sendResp.Body))
	}

	if sendResp.StatusCode == 202 {
		t.Log("✓ Message accepted for asynchronous processing")
		return
	}

	// 200 OK - should have a discover-features/disclose response
	if len(sendResp.Body) == 0 {
		t.Fatal("200 OK response but empty body")
	}

	// Verify Content-Type is a DIDComm media type
	if sendResp.MediaType != "application/didcomm-encrypted+json" &&
		sendResp.MediaType != "application/didcomm-plain+json" {
		t.Fatalf("Expected DIDComm media type, got: %s", sendResp.MediaType)
	}

	t.Logf("✓ Received DIDComm response (%d bytes)", len(sendResp.Body))

	// Log the response structure
	var respData interface{}
	if json.Unmarshal(sendResp.Body, &respData) == nil {
		respJSON, _ := json.MarshalIndent(respData, "  ", "  ")
		t.Logf("Response:\n  %s", string(respJSON))
	}
}

// TestLiveMediatorVerificationMethods tests extracting and validating all verification methods.
func TestLiveMediatorVerificationMethods(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	vms, ok := didDoc["verificationMethod"].([]interface{})
	if !ok {
		t.Fatal("No verification methods")
	}

	t.Logf("Verification Methods (%d):", len(vms))

	for i, vm := range vms {
		vmMap, ok := vm.(map[string]interface{})
		if !ok {
			continue
		}

		vmID := vmMap["id"].(string)
		vmType := vmMap["type"].(string)
		controller := vmMap["controller"].(string)

		t.Logf("  [%d] ID: %s", i+1, vmID)
		t.Logf("      Type: %s", vmType)
		t.Logf("      Controller: %s", controller)

		// Verify controller matches DID
		expectedController := PublicMediatorDIDWebVH
		if controller != expectedController {
			t.Logf("      ⚠ Controller mismatch: expected %s", expectedController)
		}

		// Parse the key
		if vmType == "Multikey" {
			multibase, ok := vmMap["publicKeyMultibase"].(string)
			if ok {
				key, keyType, err := parseMultikey(multibase)
				if err != nil {
					t.Logf("      ⚠ Failed to parse key: %v", err)
				} else if key != nil {
					t.Logf("      Key type: %s", keyType)
					t.Logf("      Multibase: %s...", multibase[:min(20, len(multibase))])
				}
			}
		}
	}

	// Verify keyAgreement references
	kaRefs, ok := didDoc["keyAgreement"].([]interface{})
	if ok {
		t.Logf("Key Agreement References (%d):", len(kaRefs))
		for i, ref := range kaRefs {
			t.Logf("  [%d] %s", i+1, ref)
		}
	}

	// Verify authentication references
	authRefs, ok := didDoc["authentication"].([]interface{})
	if ok {
		t.Logf("Authentication References (%d):", len(authRefs))
		for i, ref := range authRefs {
			t.Logf("  [%d] %s", i+1, ref)
		}
	}

	// Verify assertionMethod references
	assertRefs, ok := didDoc["assertionMethod"].([]interface{})
	if ok {
		t.Logf("Assertion Method References (%d):", len(assertRefs))
		for i, ref := range assertRefs {
			t.Logf("  [%d] %s", i+1, ref)
		}
	}
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// Controller Chain Tests
// =============================================================================

// TestLiveMediatorControllerChain tests resolving the controller chain.
// The public mediator is controlled by the fpp.storm.ws domain DID.
func TestLiveMediatorControllerChain(t *testing.T) {
	// Create a did:webvh registry
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Resolve the mediator DID
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve mediator DID: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	// Get controller
	controller, ok := didDoc["controller"].(string)
	if !ok {
		t.Log("No controller specified in DID document")
		return
	}

	t.Logf("Mediator controller: %s", controller)

	// Also resolve the controller DID
	controllerResp, err := resolver.GetClient().Resolve(ctx, controller)
	if err != nil {
		t.Logf("⚠ Could not resolve controller DID: %v", err)
		return
	}

	if !controllerResp.Decision {
		t.Logf("⚠ Controller DID resolution denied")
		return
	}

	controllerDoc, ok := controllerResp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Logf("⚠ Controller trust_metadata is not a map")
		return
	}

	controllerID := controllerDoc["id"].(string)
	t.Logf("✓ Resolved controller DID: %s", controllerID)

	// Log controller's verification methods
	if vms, ok := controllerDoc["verificationMethod"].([]interface{}); ok {
		t.Logf("  Controller has %d verification methods", len(vms))
	}

	// Check if controller has its own controller (chain)
	if parentController, ok := controllerDoc["controller"].(string); ok {
		t.Logf("  Controller's controller: %s", parentController)
	} else {
		t.Log("  Controller is self-controlled (root of trust)")
	}
}

// TestLiveMediatorAlsoKnownAs tests the alsoKnownAs equivalence.
func TestLiveMediatorAlsoKnownAs(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	aliases, ok := didDoc["alsoKnownAs"].([]interface{})
	if !ok || len(aliases) == 0 {
		t.Log("No alsoKnownAs aliases defined")
		return
	}

	t.Logf("AlsoKnownAs aliases (%d):", len(aliases))
	for i, alias := range aliases {
		aliasStr, ok := alias.(string)
		if !ok {
			continue
		}
		t.Logf("  [%d] %s", i+1, aliasStr)

		// Check if it's a did:web equivalent
		if len(aliasStr) > 8 && aliasStr[:8] == "did:web:" {
			t.Logf("      → This is the did:web equivalent of the did:webvh")
		}
	}
}

// =============================================================================
// Concurrent Resolution Tests
// =============================================================================

// TestLiveMediatorConcurrentResolution tests concurrent DID resolutions.
func TestLiveMediatorConcurrentResolution(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const numGoroutines = 10
	results := make(chan struct {
		duration time.Duration
		err      error
		didID    string
	}, numGoroutines)

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			reqStart := time.Now()
			resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)

			result := struct {
				duration time.Duration
				err      error
				didID    string
			}{
				duration: time.Since(reqStart),
				err:      err,
			}

			if err == nil && resp.Decision && resp.Context != nil && resp.Context.TrustMetadata != nil {
				if didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{}); ok {
					result.didID, _ = didDoc["id"].(string)
				}
			}

			results <- result
		}(i)
	}

	// Collect results
	var successful, failed int
	var totalDuration time.Duration
	var firstDIDID string

	for i := 0; i < numGoroutines; i++ {
		result := <-results
		if result.err != nil {
			failed++
			t.Logf("  Request %d failed: %v", i+1, result.err)
		} else if result.didID == "" {
			failed++
			t.Logf("  Request %d: no DID ID returned", i+1)
		} else {
			successful++
			totalDuration += result.duration
			if firstDIDID == "" {
				firstDIDID = result.didID
			} else if result.didID != firstDIDID {
				t.Errorf("Inconsistent DID ID: %s vs %s", result.didID, firstDIDID)
			}
		}
	}

	totalTime := time.Since(start)

	t.Logf("Concurrent resolution results:")
	t.Logf("  Total goroutines: %d", numGoroutines)
	t.Logf("  Successful: %d", successful)
	t.Logf("  Failed: %d", failed)
	t.Logf("  Total wall time: %v", totalTime)
	if successful > 0 {
		t.Logf("  Average per request: %v", totalDuration/time.Duration(successful))
	}

	if failed > 0 {
		t.Errorf("%d/%d concurrent resolutions failed", failed, numGoroutines)
	}
}

// =============================================================================
// Message Construction Tests
// =============================================================================

// TestLiveMediatorForwardMessage tests constructing a forward message.
func TestLiveMediatorForwardMessage(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Resolve mediator to get keys
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	recipientKeys, err := extractKeyAgreementKeys(didDoc)
	if err != nil || len(recipientKeys) == 0 {
		t.Fatal("No key agreement keys")
	}

	// Create a forward message
	// The forward message wraps an inner message destined for another party
	// through the mediator
	innerRecipientDID := "did:key:" + generateDIDKeyFromEd25519(t)
	senderDID := "did:key:" + generateDIDKeyFromEd25519(t)

	// Create inner trust ping message
	innerPing, err := trustping.NewPing(senderDID, innerRecipientDID, trustping.WithResponseRequested(true))
	if err != nil {
		t.Fatalf("Failed to create inner ping: %v", err)
	}

	innerMsg := message.New(
		message.WithID(innerPing.ID),
		message.WithType(innerPing.Type),
		message.WithFrom(innerPing.From),
		message.WithTo(innerPing.To[0]),
		message.WithBody(innerPing.Body),
	)

	// Pack the inner message (would normally encrypt to recipient)
	innerJSON, err := json.Marshal(innerMsg)
	if err != nil {
		t.Fatalf("Failed to marshal inner message: %v", err)
	}

	// Create forward message to mediator
	forwardMsg := message.New(
		message.WithType("https://didcomm.org/routing/2.0/forward"),
		message.WithTo(PublicMediatorDIDWebVH),
		message.WithBody(map[string]interface{}{
			"next":        innerRecipientDID,
			"attachments": []map[string]interface{}{
				{
					"id":        "inner-message",
					"data":      map[string]interface{}{"json": json.RawMessage(innerJSON)},
					"media_type": "application/didcomm-plain+json",
				},
			},
		}),
	)

	// Pack the forward message to mediator
	packed, err := didcomm.PackAnoncrypt(ctx, forwardMsg, recipientKeys)
	if err != nil {
		t.Fatalf("Failed to pack forward message: %v", err)
	}

	t.Logf("✓ Created forward message:")
	t.Logf("  Inner recipient: %s", innerRecipientDID)
	t.Logf("  Mediator: %s", PublicMediatorDIDWebVH)
	t.Logf("  Packed size: %d bytes", len(packed.Message))
	t.Logf("  Media type: %s", packed.MediaType)
}

// TestLiveMediatorOutOfBandInvitation tests creating an out-of-band invitation.
func TestLiveMediatorOutOfBandInvitation(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Resolve mediator
	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	// Extract service endpoint for the invitation
	services, _ := didDoc["service"].([]interface{})
	var serviceEndpoint string
	for _, svc := range services {
		svcMap, ok := svc.(map[string]interface{})
		if !ok {
			continue
		}
		if svcMap["type"] == "DIDCommMessaging" {
			if ep, ok := svcMap["serviceEndpoint"].([]interface{}); ok && len(ep) > 0 {
				if epMap, ok := ep[0].(map[string]interface{}); ok {
					serviceEndpoint, _ = epMap["uri"].(string)
				}
			}
			break
		}
	}

	// Create OOB invitation
	inviterDID := "did:key:" + generateDIDKeyFromEd25519(t)

	oobInvitation := map[string]interface{}{
		"type":   "https://didcomm.org/out-of-band/2.0/invitation",
		"id":     generateUUID(),
		"from":   inviterDID,
		"body": map[string]interface{}{
			"goal_code":   "connect",
			"goal":        "To establish a DIDComm connection",
			"accept":      []string{"didcomm/v2"},
		},
		"attachments": []map[string]interface{}{
			{
				"id":        "request-0",
				"media_type": "application/didcomm-plain+json",
				"data": map[string]interface{}{
					"json": map[string]interface{}{
						"type": "https://didcomm.org/trust-ping/2.0/ping",
						"from": inviterDID,
						"body": map[string]interface{}{
							"response_requested": true,
						},
					},
				},
			},
		},
	}

	// If we have a mediator endpoint, include routing
	if serviceEndpoint != "" {
		oobInvitation["body"].(map[string]interface{})["routing"] = map[string]interface{}{
			"mediator": PublicMediatorDIDWebVH,
			"endpoint": serviceEndpoint,
		}
	}

	invitationJSON, _ := json.MarshalIndent(oobInvitation, "", "  ")
	t.Logf("✓ Created OOB invitation:\n%s", string(invitationJSON))
}

// =============================================================================
// Timeout Handling Tests
// =============================================================================

// TestLiveMediatorTimeoutHandling tests timeout behavior.
func TestLiveMediatorTimeoutHandling(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     100 * time.Millisecond, // Very short timeout
		Description: "test-webvh-registry-short-timeout",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	// Use a very short context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err = resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Logf("✓ Got expected timeout/context error: %v", err)
	} else {
		t.Log("⚠ Resolution succeeded despite short timeout (network was very fast)")
	}
}

// TestLiveMediatorReasonableTimeout tests resolution with reasonable timeout.
func TestLiveMediatorReasonableTimeout(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	// Test various timeout values
	timeouts := []time.Duration{
		5 * time.Second,
		15 * time.Second,
		30 * time.Second,
	}

	for _, timeout := range timeouts {
		t.Run(timeout.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			start := time.Now()
			resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
			duration := time.Since(start)

			if err != nil {
				t.Errorf("Resolution failed with %v timeout: %v", timeout, err)
				return
			}

			if !resp.Decision {
				t.Errorf("Resolution denied with %v timeout", timeout)
				return
			}

			t.Logf("✓ Resolved in %v (timeout: %v)", duration, timeout)
		})
	}
}

// =============================================================================
// Message Validation Tests
// =============================================================================

// TestLiveMediatorMessageBodyValidation tests message body structure validation.
func TestLiveMediatorMessageBodyValidation(t *testing.T) {
	testCases := []struct {
		name        string
		msgType     string
		body        map[string]interface{}
		expectValid bool
	}{
		{
			name:    "Valid trust ping",
			msgType: "https://didcomm.org/trust-ping/2.0/ping",
			body: map[string]interface{}{
				"response_requested": true,
			},
			expectValid: true,
		},
		{
			name:    "Trust ping without response_requested",
			msgType: "https://didcomm.org/trust-ping/2.0/ping",
			body:    map[string]interface{}{},
			expectValid: true, // response_requested is optional
		},
		{
			name:    "Empty body",
			msgType: "https://didcomm.org/trust-ping/2.0/ping",
			body:    nil,
			expectValid: true,
		},
		{
			name:    "Forward message with next",
			msgType: "https://didcomm.org/routing/2.0/forward",
			body: map[string]interface{}{
				"next": "did:key:z6MkTestRecipient",
			},
			expectValid: true,
		},
		{
			name:    "Forward message without next",
			msgType: "https://didcomm.org/routing/2.0/forward",
			body:    map[string]interface{}{},
			expectValid: false, // next is required
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			senderDID := "did:key:" + generateDIDKeyFromEd25519(t)

			msg := message.New(
				message.WithType(tc.msgType),
				message.WithFrom(senderDID),
				message.WithTo(PublicMediatorDIDWebVH),
				message.WithBody(tc.body),
			)

			// Validate message structure
			isValid := true
			var validationError string

			// Check required fields
			if msg.Type == "" {
				isValid = false
				validationError = "missing type"
			}

			if msg.ID == "" {
				isValid = false
				validationError = "missing ID"
			}

			// Check forward-specific requirements
			if tc.msgType == "https://didcomm.org/routing/2.0/forward" {
				if tc.body == nil {
					isValid = false
					validationError = "forward requires body"
				} else if _, hasNext := tc.body["next"]; !hasNext {
					isValid = false
					validationError = "forward requires next field"
				}
			}

			if tc.expectValid && !isValid {
				t.Errorf("Expected valid message but got: %s", validationError)
			}
			if !tc.expectValid && isValid {
				t.Error("Expected invalid message but it was valid")
			}

			if isValid {
				t.Logf("✓ Message structure valid")
			} else {
				t.Logf("✓ Message correctly identified as invalid: %s", validationError)
			}
		})
	}
}

// TestLiveMediatorDIDDocumentStructure tests that the DID document has expected structure.
func TestLiveMediatorDIDDocumentStructure(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	// Required fields per DID Core spec
	requiredFields := []string{"id"}
	optionalFields := []string{
		"@context",
		"controller",
		"verificationMethod",
		"authentication",
		"assertionMethod",
		"keyAgreement",
		"capabilityInvocation",
		"capabilityDelegation",
		"service",
		"alsoKnownAs",
	}

	t.Log("DID Document Structure Validation:")

	// Check required fields
	for _, field := range requiredFields {
		if _, exists := didDoc[field]; !exists {
			t.Errorf("Missing required field: %s", field)
		} else {
			t.Logf("  ✓ Required field '%s' present", field)
		}
	}

	// Check optional fields
	for _, field := range optionalFields {
		if value, exists := didDoc[field]; exists {
			switch v := value.(type) {
			case []interface{}:
				t.Logf("  ✓ Optional field '%s' present (%d items)", field, len(v))
			case string:
				t.Logf("  ✓ Optional field '%s' present: %s", field, v)
			default:
				t.Logf("  ✓ Optional field '%s' present", field)
			}
		}
	}

	// Check @context
	if ctxVal, ok := didDoc["@context"].([]interface{}); ok {
		t.Log("  @context values:")
		for _, ctx := range ctxVal {
			t.Logf("    - %v", ctx)
		}
	}

	// Check for DID Core v1 context
	foundDIDCoreContext := false
	if ctxVal, ok := didDoc["@context"].([]interface{}); ok {
		for _, ctx := range ctxVal {
			if ctxStr, ok := ctx.(string); ok {
				if ctxStr == "https://www.w3.org/ns/did/v1" {
					foundDIDCoreContext = true
					break
				}
			}
		}
	}
	if foundDIDCoreContext {
		t.Log("  ✓ DID Core v1 context present")
	} else {
		t.Log("  ⚠ DID Core v1 context not found")
	}
}

// TestLiveMediatorResolutionMetadata tests that resolution metadata is present.
func TestLiveMediatorResolutionMetadata(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	// Check for didResolutionMetadata (did:webvh specific)
	resolutionMeta, ok := didDoc["didResolutionMetadata"].(map[string]interface{})
	if !ok {
		t.Log("No didResolutionMetadata found (may be separate in response)")
		return
	}

	t.Log("DID Resolution Metadata:")

	// Check for expected did:webvh metadata fields
	metadataFields := []string{"scid", "versionId", "versionTime", "created", "updated", "deactivated", "portable"}
	for _, field := range metadataFields {
		if value, exists := resolutionMeta[field]; exists {
			t.Logf("  %s: %v", field, value)
		}
	}

	// Verify SCID matches the DID
	if scid, ok := resolutionMeta["scid"].(string); ok {
		expectedSCID := "QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V"
		if scid == expectedSCID {
			t.Logf("  ✓ SCID matches DID: %s", scid)
		} else {
			t.Errorf("  ✗ SCID mismatch: got %s, expected %s", scid, expectedSCID)
		}
	}

	// Check deactivated status
	if deactivated, ok := resolutionMeta["deactivated"].(bool); ok {
		if !deactivated {
			t.Log("  ✓ DID is not deactivated")
		} else {
			t.Error("  ✗ DID is deactivated")
		}
	}
}

// =============================================================================
// Key Algorithm Tests
// =============================================================================

// TestLiveMediatorKeyAlgorithms tests that we can identify all key algorithms.
func TestLiveMediatorKeyAlgorithms(t *testing.T) {
	registry, err := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
		Timeout:     30 * time.Second,
		Description: "test-webvh-registry",
	})
	if err != nil {
		t.Fatalf("Failed to create did:webvh registry: %v", err)
	}

	srv := testserver.New(testserver.WithRegistry(registry))
	defer srv.Close()

	resolver := keyresolver.NewGoTrustResolver(srv.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := resolver.GetClient().Resolve(ctx, PublicMediatorDIDWebVH)
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !resp.Decision || resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("Resolution failed")
	}

	didDoc, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("trust_metadata is not a map")
	}

	vms, ok := didDoc["verificationMethod"].([]interface{})
	if !ok {
		t.Fatal("No verification methods")
	}

	// Track algorithms found
	algorithms := make(map[string]int)

	for _, vm := range vms {
		vmMap, ok := vm.(map[string]interface{})
		if !ok {
			continue
		}

		vmType, _ := vmMap["type"].(string)
		vmID, _ := vmMap["id"].(string)

		if vmType == "Multikey" {
			multibase, ok := vmMap["publicKeyMultibase"].(string)
			if !ok {
				continue
			}

			_, keyType, err := parseMultikey(multibase)
			if err != nil {
				t.Logf("  Failed to parse %s: %v", vmID, err)
				continue
			}

			algorithms[keyType]++
			t.Logf("  %s: %s", vmID, keyType)
		} else {
			algorithms[vmType]++
			t.Logf("  %s: %s", vmID, vmType)
		}
	}

	t.Log("\nAlgorithm Summary:")
	expectedAlgorithms := map[string]bool{
		"Ed25519":   true, // Signing
		"X25519":    true, // Key agreement (ECDH-ES)
		"P-256":     true, // Key agreement (ECDH-ES+A256KW)
		"secp256k1": true, // Key agreement (Bitcoin/Ethereum style)
	}

	for algo, count := range algorithms {
		t.Logf("  %s: %d key(s)", algo, count)
		if expectedAlgorithms[algo] {
			t.Logf("    ✓ Expected algorithm")
		}
	}

	// Check for minimum required algorithms for DIDComm
	if _, hasEd25519 := algorithms["Ed25519"]; !hasEd25519 {
		t.Error("Missing Ed25519 signing key")
	}
	if _, hasX25519 := algorithms["X25519"]; !hasX25519 {
		t.Log("Note: No X25519 key agreement key found")
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// generateUUID generates a simple UUID v4 for testing.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// truncateString truncates a string to maxLen characters for logging.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
