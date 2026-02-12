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
6. [Profile Announcement Proposals](#profile-announcement-proposals)
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

A client wanting to work with both standard and Affinidi mediators needs:

```
if (mediator.supportsProtocol("coordinate-mediation/3.0")) {
    // Standard flow
    send(mediateRequest)
    await(mediateGrant)
    send(keylistUpdate)
} else if (mediator.supportsProtocol("mediator/1.0/account-management")) {
    // Affinidi flow
    send(accountAdd)
    // No key registration needed
}
```

---

## Profile Announcement Proposals

The core issue: **How does a client discover which mediation protocol a mediator supports?**

### Option A: DID Document Service Extension

Add protocol list to the DIDCommMessaging service:

```json
{
  "type": "DIDCommMessaging",
  "serviceEndpoint": [...],
  "protocols": [
    "https://didcomm.org/trust-ping/2.0",
    "https://didcomm.org/routing/2.0",
    "https://didcomm.org/messagepickup/3.0",
    "https://didcomm.org/mediator/1.0/account-management"
  ],
  "profile": "affinidi-mediator-1.0"
}
```

**Pros:** Static, cacheable, no extra round-trip  
**Cons:** Requires DID document update on protocol changes

### Option B: Discover Features 2.0

Use the standard DIDComm feature discovery protocol:

```json
{
  "type": "https://didcomm.org/discover-features/2.0/queries",
  "body": {
    "queries": [
      {"feature-type": "protocol", "match": "https://didcomm.org/*"}
    ]
  }
}
```

**Pros:** Dynamic, standard DIDComm protocol  
**Cons:** Requires authenticated message exchange

### Option C: Well-Known Endpoint

`GET /.well-known/didcomm-mediator`

```json
{
  "profile": "affinidi-mediator-1.0",
  "version": "0.7.0",
  "protocols": {
    "trust-ping": "2.0",
    "routing": "2.0",
    "messagepickup": "3.0",
    "account-management": "1.0",
    "acl-management": "1.0",
    "admin-management": "1.0"
  },
  "extensions": {
    "ephemeral_messages": true,
    "delayed_delivery": true,
    "live_delivery": true
  }
}
```

**Pros:** No DIDComm required, standard HTTP  
**Cons:** New convention, not part of DID spec

### Option D: Linked Verifiable Presentation

Use the existing `LinkedVerifiablePresentation` service to include capability attestations:

```json
{
  "type": "LinkedVerifiablePresentation",
  "serviceEndpoint": ".../capabilities.vp"
}
```

The VP contains claims about supported protocols.

**Pros:** Cryptographically verifiable, already in Affinidi DID doc  
**Cons:** Heavyweight for simple capability discovery

### Recommended Approach

**Hybrid: Option A + Option B**

1. List supported protocols in DID document (Option A)
2. Support Discover Features 2.0 for dynamic queries (Option B)
3. Use `profile` field to indicate the overall profile name

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
