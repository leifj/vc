# Affinidi DIDComm Mediator Protocol Analysis

**Date:** February 2026  
**Status:** Analysis / Interoperability Assessment  
**Mediator Under Test:** `did:webvh:QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V:fpp.storm.ws:public-mediator`

## Executive Summary

This document analyzes the Affinidi Messaging Mediator protocol suite and compares it to standard DIDComm 2.1 mediator specifications. The Affinidi mediator implements a **custom profile** that deviates significantly from the standard `coordinate-mediation/3.0` protocol, instead using an account-based model with fine-grained ACL controls.

**Key Finding:** The Affinidi mediator does NOT implement the standard DIDComm mediation negotiation protocol. Clients must use the Affinidi-specific account management protocol to register with the mediator.

---

## Table of Contents

1. [Protocol Comparison Matrix](#protocol-comparison-matrix)
2. [Standard DIDComm 2.1 Mediator Protocols](#standard-didcomm-21-mediator-protocols)
3. [Affinidi Custom Protocols](#affinidi-custom-protocols)
4. [Architectural Differences](#architectural-differences)
5. [Interoperability Analysis](#interoperability-analysis)
6. [Protocol Announcement: Recommended Approach](#protocol-announcement-recommended-approach)
7. [Implementation Recommendations](#implementation-recommendations)
8. [Test Strategy](#test-strategy)

---

## Protocol Comparison Matrix

| Protocol | Standard DIDComm 2.1 | Affinidi Profile | Compatible? |
|----------|---------------------|------------------|-------------|
| **Trust Ping 2.0** | ✅ Supported | ✅ Supported | ✅ Yes |
| **Routing/Forward 2.0** | ✅ Supported | ✅ Supported + extensions | ✅ Yes |
| **Message Pickup 3.0** | ✅ Supported | ✅ Supported | ✅ Yes |
| **Problem Report 2.0** | ✅ Supported | ✅ Supported (outbound only) | ✅ Yes |
| **Coordinate Mediation 3.0** | ✅ Supported | ❌ NOT Supported | ❌ No |
| **Account Management 1.0** | ❌ Not specified | ✅ Supported | N/A |
| **Admin Management 1.0** | ❌ Not specified | ✅ Supported | N/A |
| **ACL Management 1.0** | ❌ Not specified | ✅ Supported | N/A |

---

## Standard DIDComm 2.1 Mediator Protocols

### Coordinate Mediation 3.0 (NOT supported by Affinidi)

The standard mediation protocol uses a request/grant model:

```
Client                                  Mediator
   |                                       |
   |---- mediate-request ----------------->|
   |                                       |
   |<--- mediate-grant/mediate-deny -------|
   |                                       |
   |---- keylist-update ------------------>|
   |                                       |
   |<--- keylist-update-response ----------|
```

**Message Types:**
- `https://didcomm.org/coordinate-mediation/3.0/mediate-request`
- `https://didcomm.org/coordinate-mediation/3.0/mediate-grant`
- `https://didcomm.org/coordinate-mediation/3.0/mediate-deny`
- `https://didcomm.org/coordinate-mediation/3.0/keylist-update`
- `https://didcomm.org/coordinate-mediation/3.0/keylist-update-response`
- `https://didcomm.org/coordinate-mediation/3.0/keylist-query`
- `https://didcomm.org/coordinate-mediation/3.0/keylist`

### Trust Ping 2.0 (Compatible)

Used to verify connectivity. Both implementations are compatible.

| Property | Value |
|----------|-------|
| Type URI | `https://didcomm.org/trust-ping/2.0/ping` |
| Response Type | Same as request type |

```json
{
  "type": "https://didcomm.org/trust-ping/2.0/ping",
  "id": "unique-message-id",
  "from": "did:example:sender",
  "to": ["did:example:mediator"],
  "body": {
    "response_requested": true
  }
}
```

### Routing/Forward 2.0 (Compatible with extensions)

Routes encrypted messages through the mediator.

| Property | Value |
|----------|-------|
| Type URI | `https://didcomm.org/routing/2.0/forward` |

**Standard body:**
```json
{
  "next": "did:example:recipient"
}
```

**Affinidi extensions (optional headers):**
- `ephemeral`: `bool` - If true, message is not stored, only live-streamed
- `delay_milli`: `i64` - Delay before delivery (negative = random delay)

### Message Pickup 3.0 (Compatible)

Protocol for retrieving queued messages.

| Message Type | Direction |
|--------------|-----------|
| `status-request` | Client → Mediator |
| `status` | Mediator → Client |
| `live-delivery-change` | Client → Mediator |
| `delivery-request` | Client → Mediator |
| `delivery` | Mediator → Client |
| `messages-received` | Client → Mediator |

**Important:** Affinidi requires `"return_route": "all"` header on all Message Pickup 3.0 messages.

---

## Affinidi Custom Protocols

### Account Management 1.0

**Type URI:** `https://didcomm.org/mediator/1.0/account-management`

Replaces `coordinate-mediation/3.0` with an account-based model.

#### Operations

| Operation | Request Body | Description |
|-----------|--------------|-------------|
| `account_get` | `{"account_get": "sha256_did_hash"}` | Get account info |
| `account_list` | `{"account_list": {"cursor": 0, "limit": 100}}` | List accounts |
| `account_add` | `{"account_add": {"did_hash": "...", "acls": 505}}` | Create account |
| `account_remove` | `{"account_remove": "sha256_did_hash"}` | Remove account |
| `account_change_type` | `{"account_change_type": {"did_hash": "...", "type": "Admin"}}` | Change role |
| `account_change_queue_limits` | `{"account_change_queue_limits": {...}}` | Set queue limits |

#### Account Types

| Type | Value | Description |
|------|-------|-------------|
| Standard | `"0"` | Regular user |
| Admin | `"1"` | Can manage accounts |
| RootAdmin | `"2"` | Full access |
| Mediator | `"3"` | Mediator service account |
| Unknown | `"-1"` | Invalid |

### Admin Management 1.0

**Type URI:** `https://didcomm.org/mediator/1.0/admin-management`

**Required header:** `created_time` must be present.

| Operation | Description |
|-----------|-------------|
| `admin_add` | Promote DIDs to admin (max 100 per request) |
| `admin_strip` | Remove admin rights |
| `admin_list` | Paginated list of admins |
| `Configuration` | Get mediator configuration |

### ACL Management 1.0

**Type URIs:**
- Request: `https://didcomm.org/mediator/1.0/acl-management`
- Response: `https://affinidi.com/messaging/global-acl-management`

#### ACL Bitmask (Little Endian u64)

| Bit | Permission | Description |
|-----|------------|-------------|
| 0 | `access_list_mode` | 0 = ExplicitAllow, 1 = ExplicitDeny |
| 1 | `access_list_mode_self_change` | Can user change their own mode? |
| 2 | `did_blocked` | 0 = allowed, 1 = blocked |
| 3 | `did_local` | 0 = not local, 1 = can store messages |
| 4 | `send_messages` | Can send messages |
| 5 | `send_messages_self_change` | Can toggle send permission |
| 6 | `receive_messages` | Can receive messages |
| 7 | `receive_messages_self_change` | Can toggle receive permission |
| 8 | `send_forwarded` | Can forward messages |
| 9 | `send_forwarded_self_change` | Can toggle forward permission |
| 10 | `receive_forwarded` | Can receive forwarded messages |
| 11 | `receive_forwarded_self_change` | Can toggle forwarded receive |
| 12 | `create_invites` | Can create OOB invitations |
| 13 | `create_invites_self_change` | Can toggle invite creation |
| 14 | `anon_receive` | Can receive anonymous messages |
| 15 | `anon_receive_self_change` | Can toggle anonymous receive |
| 16 | `self_manage_list` | Can self-manage access list |
| 17 | `self_manage_send_queue_limit` | Can manage own send queue limit |
| 18 | `self_manage_receive_queue_limit` | Can manage own receive queue limit |

#### Common ACL Values

| Value | Binary | Meaning |
|-------|--------|---------|
| `505` | `0b111111001` | Standard permissions |

---

## Architectural Differences

### Message ID Handling

| Aspect | Standard DIDComm | Affinidi |
|--------|------------------|----------|
| **ID Generation** | Client-chosen UUIDs | SHA256(message content) |
| **ID Format** | Arbitrary string | Hex-encoded hash |
| **Acknowledgement** | Reference original ID | Reference content hash |

**Important:** When using Message Pickup 3.0 with Affinidi, all message IDs in `messages-received` must be SHA256 hashes.

### Authentication Model

| Aspect | Standard DIDComm | Affinidi |
|--------|------------------|----------|
| **Registration** | `mediate-request` | `account_add` |
| **Key Binding** | `keylist-update` | Implicit (account-based) |
| **Permissions** | Binary grant/deny | 18-bit ACL bitmask |
| **Self-Service** | Limited | Configurable per-permission |

### DID Document Structure

The Affinidi mediator's DID document includes:

```json
{
  "service": [
    {
      "type": "DIDCommMessaging",
      "serviceEndpoint": [
        {"uri": "https://...", "accept": ["didcomm/v2"]},
        {"uri": "wss://...", "accept": ["didcomm/v2"]}
      ]
    },
    {
      "type": "Authentication",
      "serviceEndpoint": "https://.../authenticate"
    },
    {
      "type": "LinkedVerifiablePresentation",
      "serviceEndpoint": ".../whois.vp"
    }
  ]
}
```

**Notable:** The `Authentication` service type is non-standard and specific to Affinidi.

---

## Interoperability Analysis

### What Works (Cross-Compatible)

1. **Trust Ping** - Standard ping/pong works
2. **Message Routing** - Forward messages can be sent
3. **Message Pickup** - Query status, delivery requests work
4. **Problem Reports** - Error handling is compatible

### What Doesn't Work

1. **Mediation Request** - `coordinate-mediation/3.0` not supported
2. **Key Registration** - No `keylist-update` equivalent
3. **Standard Onboarding** - Cannot use standard mediation flow

### Migration Path for Clients

A client working with both standard and Affinidi mediators checks the `protocols` field in the DID document:

```go
func selectMediationFlow(didDoc map[string]interface{}) {
    service := findDIDCommService(didDoc)
    protocols := service["protocols"].([]string)
    
    if contains(protocols, "coordinate-mediation/3.0") {
        // Standard DIDComm flow
        send(mediateRequest)
        await(mediateGrant)
        send(keylistUpdate)
    } else if contains(protocols, "mediator/1.0/account-management") {
        // Affinidi flow
        send(accountAdd)
        // No key registration needed
    } else if protocols == nil {
        // No protocols listed - assume standard
        send(mediateRequest)
        // ...
    }
}
```

---

## Protocol Announcement: Recommended Approach

The solution is simple: **list supported protocol URIs in the DID document's `DIDCommMessaging` service.**

The protocol type URIs themselves ARE the profile - no additional abstraction needed.

### Current vs Proposed: Key Differences

| Aspect | Current DIDComm | Proposed Extension |
|--------|----------------|-------------------|
| **What DID doc declares** | Transport only (`accept: ["didcomm/v2"]`) | Transport + Protocols |
| **Protocol discovery** | Discover Features 2.0 (requires message exchange) | Static in DID document |
| **When client knows capabilities** | After authenticated exchange | Before first message |
| **Round trips required** | Minimum 1 (often 2+) | Zero |
| **Failure mode** | Try → Problem Report → Retry | Know upfront, no failures |
| **Cacheability** | Not cacheable (dynamic) | Fully cacheable with DID doc |

#### Current Approach: Discover Features 2.0

```
Client                              Mediator
   |                                   |
   |  [Resolve DID document]           |
   |  (only learns: "accepts didcomm/v2")
   |                                   |
   |---- discover-features/queries --->|  (1st round trip)
   |<--- discover-features/disclose ---|
   |                                   |
   |  [Now knows: supports account-management, not coordinate-mediation]
   |                                   |
   |---- account_add ----------------->|  (2nd round trip)
   |<--- account response -------------|
```

**Problems:**
1. Must establish encrypted channel before learning capabilities
2. Extra round trip adds latency
3. Cannot pre-select flow without sending a message first4. If Discover Features isn't supported, must guess and fail

#### Proposed Approach: Static Protocol List

```
Client                              Mediator
   |                                   |
   |  [Resolve DID document]           |
   |  (learns: supports account-management, messagepickup, etc.)
   |                                   |
   |---- account_add ----------------->|  (1st round trip - correct flow!)
   |<--- account response -------------|
```

**Benefits:**
1. Zero-knowledge setup - client knows flow before any DIDComm exchange
2. One fewer round trip
3. Works even if mediator doesn't support Discover Features
4. DID document caching means essentially free capability lookup

### DID Document Service with Protocol List

```json
{
  "type": "DIDCommMessaging",
  "serviceEndpoint": [
    {"uri": "https://public-mediator.example.com/v1", "accept": ["didcomm/v2"]},
    {"uri": "wss://public-mediator.example.com/v1/ws", "accept": ["didcomm/v2"]}
  ],
  "protocols": [
    "https://didcomm.org/trust-ping/2.0",
    "https://didcomm.org/routing/2.0",
    "https://didcomm.org/messagepickup/3.0",
    "https://didcomm.org/mediator/1.0/account-management",
    "https://didcomm.org/mediator/1.0/acl-management"
  ]
}
```

### Client Detection Logic

```go
func detectMediationProtocol(service map[string]interface{}) string {
    protocols, ok := service["protocols"].([]interface{})
    if !ok {
        // No protocols listed - assume standard DIDComm mediation
        return "coordinate-mediation/3.0"
    }
    
    for _, p := range protocols {
        uri := p.(string)
        if strings.Contains(uri, "coordinate-mediation/3.0") {
            return "coordinate-mediation/3.0"
        }
        if strings.Contains(uri, "mediator/1.0/account-management") {
            return "affinidi-account-management/1.0"
        }
    }
    
    return "unknown"
}
```

### Why This Works

1. **No new abstraction** - Protocol URIs already uniquely identify capabilities
2. **Static & cacheable** - Part of the DID document, no round-trip needed
3. **Backward compatible** - Absence of `protocols` field = assume standard
4. **Self-describing** - Client can immediately determine which flow to use

### Specification Change Required

Add to DIDComm Messaging specification:

> A `DIDCommMessaging` service MAY include a `protocols` property containing an array of protocol type URIs that the service endpoint supports. If omitted, clients SHOULD assume standard DIDComm protocols are supported.

### Supporting Both Approaches (Recommended)

The static DID document approach and Discover Features 2.0 are **complementary, not mutually exclusive**. A mediator SHOULD support both:

| Approach | Use Case | Client Type |
|----------|----------|-------------|
| **Static (DID doc)** | Initial capability discovery | New clients, optimization |
| **Dynamic (Discover Features)** | Runtime verification, legacy | Existing DIDComm clients |

#### Why Support Both?

1. **Backward compatibility** - Existing clients using Discover Features 2.0 continue to work
2. **Optimization** - New clients can skip the round-trip when DID doc has protocols
3. **Verification** - Clients can verify DID doc claims via Discover Features
4. **Dynamic changes** - If capabilities change at runtime, Discover Features reflects current state

#### Mediator Implementation

```
Mediator Setup:
1. Publish DID document with "protocols" array (static advertisement)
2. Implement discover-features/2.0 handler (dynamic verification)
3. Keep both in sync

DID Document:
{
  "type": "DIDCommMessaging",
  "protocols": ["https://didcomm.org/mediator/1.0/account-management", ...]
}

Discover Features Handler:
- Respond to queries with same protocol list
- Can filter by "match" pattern in query
```

#### Client Implementation

```go
func connectToMediator(didDoc map[string]interface{}) error {
    service := findDIDCommService(didDoc)
    
    // Step 1: Check static protocol list (fast path)
    if protocols, ok := service["protocols"].([]interface{}); ok {
        flow := selectFlow(protocols)
        if flow != "unknown" {
            return executeFlow(flow)  // No Discover Features needed
        }
    }
    
    // Step 2: Fall back to Discover Features 2.0 (slow path)
    // Only if DID doc doesn't have protocols or client wants verification
    disclose, err := sendDiscoverFeatures(mediatorDID)
    if err != nil {
        return err
    }
    flow := selectFlowFromDisclose(disclose)
    return executeFlow(flow)
}
```

#### Sequence: Client with Both Options

```
Client                              Mediator
   |                                   |
   |  [Resolve DID document]           |
   |  protocols: [account-management]  |
   |                                   |
   |  [FAST PATH: Use static info]     |
   |---- account_add ----------------->|
   |<--- account response -------------|
   |                                   |
   
   -- OR if verification needed --
   
   |  [SLOW PATH: Verify via Discover Features]
   |---- discover-features/queries --->|
   |<--- discover-features/disclose ---|
   |  [Confirms: account-management]   |
   |---- account_add ----------------->|
   |<--- account response -------------|
```

#### Affinidi Could Add This Today

The Affinidi mediator could implement Discover Features 2.0 to expose the same capabilities:

```json
// Query
{
  "type": "https://didcomm.org/discover-features/2.0/queries",
  "body": {
    "queries": [{"feature-type": "protocol", "match": "*"}]
  }
}

// Response (Disclose)
{
  "type": "https://didcomm.org/discover-features/2.0/disclose",
  "body": {
    "disclosures": [
      {"feature-type": "protocol", "id": "https://didcomm.org/trust-ping/2.0"},
      {"feature-type": "protocol", "id": "https://didcomm.org/routing/2.0"},
      {"feature-type": "protocol", "id": "https://didcomm.org/messagepickup/3.0"},
      {"feature-type": "protocol", "id": "https://didcomm.org/mediator/1.0/account-management"},
      {"feature-type": "protocol", "id": "https://didcomm.org/mediator/1.0/acl-management"},
      {"feature-type": "protocol", "id": "https://didcomm.org/mediator/1.0/admin-management"}
    ]
  }
}
```

This would make Affinidi mediators fully interoperable with existing DIDComm clients that use Discover Features 2.0 for capability discovery.

---

## Implementation Recommendations

### Phase 1: Affinidi Protocol Support

Create `pkg/didcomm/protocol/affinidi/`:

```go
// account.go
package affinidi

const (
    TypeAccountManagement = "https://didcomm.org/mediator/1.0/account-management"
    TypeACLManagement     = "https://didcomm.org/mediator/1.0/acl-management"
    TypeAdminManagement   = "https://didcomm.org/mediator/1.0/admin-management"
)

type AccountAddRequest struct {
    AccountAdd struct {
        DIDHash string `json:"did_hash"`
        ACLs    uint64 `json:"acls,omitempty"`
    } `json:"account_add"`
}

type AccountGetRequest struct {
    AccountGet string `json:"account_get"`
}

type Account struct {
    DIDHash            string  `json:"did_hash"`
    ACLs               uint64  `json:"acls"`
    Type               string  `json:"type"`
    AccessListCount    uint32  `json:"access_list_count"`
    QueueSendLimit     *int32  `json:"queue_send_limit,omitempty"`
    QueueReceiveLimit  *int32  `json:"queue_receive_limit,omitempty"`
    SendQueueCount     uint32  `json:"send_queue_count"`
    SendQueueBytes     uint64  `json:"send_queue_bytes"`
    ReceiveQueueCount  uint32  `json:"receive_queue_count"`
    ReceiveQueueBytes  uint64  `json:"receive_queue_bytes"`
}
```

### Phase 2: Mediator Interface Abstraction

```go
// pkg/didcomm/mediator/mediator.go
package mediator

type Mediator interface {
    // Common operations
    Ping(ctx context.Context) error
    Forward(ctx context.Context, msg []byte, next string) error
    
    // Message pickup
    Status(ctx context.Context, recipientDID string) (*StatusResponse, error)
    RequestDelivery(ctx context.Context, recipientDID string, limit int) ([][]byte, error)
    AcknowledgeMessages(ctx context.Context, messageIDs []string) error
    
    // Registration (implementation-specific)
    Register(ctx context.Context) error
}

type StandardMediator struct { ... }  // coordinate-mediation/3.0
type AffinidiMediator struct { ... }  // account-management/1.0
```

### Phase 3: Profile Detection

```go
// pkg/didcomm/mediator/detect.go
func DetectProfile(didDoc map[string]interface{}) (MediatorProfile, error) {
    services := didDoc["service"].([]interface{})
    
    for _, svc := range services {
        svcMap := svc.(map[string]interface{})
        if svcMap["type"] == "DIDCommMessaging" {
            if protocols, ok := svcMap["protocols"].([]interface{}); ok {
                return analyzeProtocols(protocols)
            }
        }
    }
    
    // Fallback: assume standard
    return StandardProfile, nil
}
```

---

## Test Strategy

### Unit Tests

Test Affinidi protocol message construction and parsing:

```go
func TestAccountAddMessage(t *testing.T) {
    req := affinidi.AccountAddRequest{...}
    msg := message.New(
        message.WithType(affinidi.TypeAccountManagement),
        message.WithBody(req),
    )
    // Verify structure
}
```

### Integration Tests

Test against mock Affinidi mediator:

```go
func TestAffinidiMediatorRegistration(t *testing.T) {
    mediator := affinidi.NewMediator(PublicMediatorDIDWebVH)
    err := mediator.Register(ctx)
    require.NoError(t, err)
}
```

### Live Tests

Test against the actual public mediator:

```go
//go:build live

func TestLiveAffinidiAccountAdd(t *testing.T) {
    // Register with actual mediator
    // Verify account exists
    // Clean up
}
```

---

## References

1. [Affinidi DIDComm Protocols Documentation](https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/affinidi-messaging/affinidi-messaging-mediator/docs/didcomm-protocols.md)
2. [DIDComm Messaging v2.1 Specification](https://identity.foundation/didcomm-messaging/spec/v2.1/)
3. [Coordinate Mediation Protocol 3.0](https://didcomm.org/coordinate-mediation/3.0/)
4. [Message Pickup Protocol 3.0](https://didcomm.org/messagepickup/3.0/)
5. [Routing Protocol 2.0](https://didcomm.org/routing/2.0/)

---

## Appendix: Type URI Summary

### Standard DIDComm Protocols

| Protocol | Type URI |
|----------|----------|
| Trust Ping | `https://didcomm.org/trust-ping/2.0/ping` |
| Routing | `https://didcomm.org/routing/2.0/forward` |
| Pickup Status Req | `https://didcomm.org/messagepickup/3.0/status-request` |
| Pickup Status | `https://didcomm.org/messagepickup/3.0/status` |
| Pickup Delivery Change | `https://didcomm.org/messagepickup/3.0/live-delivery-change` |
| Pickup Delivery Req | `https://didcomm.org/messagepickup/3.0/delivery-request` |
| Pickup Delivery | `https://didcomm.org/messagepickup/3.0/delivery` |
| Pickup Received | `https://didcomm.org/messagepickup/3.0/messages-received` |
| Problem Report | `https://didcomm.org/report-problem/2.0/problem-report` |

### Affinidi Custom Protocols

| Protocol | Type URI |
|----------|----------|
| Account Management | `https://didcomm.org/mediator/1.0/account-management` |
| Admin Management | `https://didcomm.org/mediator/1.0/admin-management` |
| ACL Management (Req) | `https://didcomm.org/mediator/1.0/acl-management` |
| ACL Management (Resp) | `https://affinidi.com/messaging/global-acl-management` |

### Standard Protocols NOT Supported by Affinidi

| Protocol | Type URI |
|----------|----------|
| Mediate Request | `https://didcomm.org/coordinate-mediation/3.0/mediate-request` |
| Mediate Grant | `https://didcomm.org/coordinate-mediation/3.0/mediate-grant` |
| Mediate Deny | `https://didcomm.org/coordinate-mediation/3.0/mediate-deny` |
| Keylist Update | `https://didcomm.org/coordinate-mediation/3.0/keylist-update` |
| Keylist Query | `https://didcomm.org/coordinate-mediation/3.0/keylist-query` |
