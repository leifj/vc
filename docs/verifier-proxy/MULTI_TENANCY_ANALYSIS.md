# Verifier-Proxy Multi-Tenancy Analysis

**Status:** Architecture Analysis  
**Version:** 1.0  
**Date:** 2025-11-16  
**Goal:** Support multiple OP-RP configuration combinations

## Executive Summary

This document analyzes architectural approaches for implementing multi-tenancy in the verifier-proxy service to support multiple OpenID Provider (OP) and Relying Party (RP) configuration combinations.

**Key Finding:** Multiple deployment approach is recommended for initial implementation, with path to single-instance multi-tenancy for scaling.

---

## Current Architecture Analysis

### Configuration Model

The verifier-proxy currently operates with **single-tenant configuration**:

```yaml
verifier_proxy:
  external_url: "http://vc_dev_verifier_proxy:8080"
  oidc:
    issuer: "http://vc_dev_verifier_proxy:8080"  # Single issuer
    signing_key_path: "/private_rsa.pem"          # Single key
    subject_type: "pairwise"                       # Single policy
    subject_salt: "change-this-in-production"      # Single salt
```

### State Management

**Database Layer:**
- MongoDB with two collections: `sessions` and `clients`
- Database name: `verifier_proxy` (hardcoded in `db/db.go`)
- Clients registered per-instance
- Sessions scoped to client_id but no tenant isolation

**In-Memory State:**
- OIDC signing key (single key loaded at startup)
- Ephemeral encryption key cache (TTL-based, per-instance)
- Request object cache (session-scoped)
- Presentation builder templates (loaded from single directory)

### Component Dependencies

```
main.go
  ├─> db.Service (MongoDB connection, single database)
  ├─> apiv1.Client
  │     ├─> loadSigningKey() - single key
  │     ├─> loadPresentationTemplates() - single directory
  │     └─> generateIDToken() - uses c.cfg.VerifierProxy.OIDC.Issuer
  └─> httpserver.Service (single HTTP server)
```

### Tenant-Specific Configuration Points

1. **OIDC Issuer URI** (`oidc.issuer`)
   - Appears in ID tokens as `iss` claim
   - Used in discovery metadata
   - Must be unique per tenant

2. **Signing Keys** (`oidc.signing_key_path`)
   - Used to sign ID tokens and access tokens
   - Should be isolated per tenant for security

3. **Subject Identifiers** (`oidc.subject_type`, `oidc.subject_salt`)
   - Pairwise subjects use tenant-specific salt
   - Different tenants need different subject namespaces

4. **Presentation Templates** (`openid4vp.presentation_requests_dir`)
   - Tenant-specific DCQL requirements
   - Custom claim mappings per tenant

5. **External URL** (`external_url`)
   - Callback URLs for wallets
   - OAuth redirect URIs
   - Must be tenant-specific

6. **Client Registry**
   - Each tenant has different set of registered RPs
   - Client IDs must be scoped to tenant

---

## Approach 1: Multiple Deployments (Separate Instances)

### Architecture

Deploy separate verifier-proxy instances, one per tenant.

```
┌─────────────────────┐
│   Load Balancer /   │
│   Reverse Proxy     │
└──────┬──────┬───────┘
       │      │
       │      └──────────────────┐
       │                         │
┌──────▼─────────┐      ┌───────▼────────┐
│ Tenant A       │      │ Tenant B       │
│ verifier-proxy │      │ verifier-proxy │
├────────────────┤      ├────────────────┤
│ Config: A      │      │ Config: B      │
│ DB: tenant_a   │      │ DB: tenant_b   │
│ Keys: A        │      │ Keys: B        │
│ Templates: A   │      │ Templates: B   │
└────────────────┘      └────────────────┘
```

### Implementation

**Docker Compose:**
```yaml
services:
  verifier-proxy-tenant-a:
    image: docker.sunet.se/dc4eu/verifier-proxy:latest
    container_name: vc_verifier_proxy_tenant_a
    environment:
      - VC_CONFIG_YAML=/config/config-tenant-a.yaml
    volumes:
      - ./config/tenant-a:/config:ro
      - ./keys/tenant-a:/keys:ro
      - ./presentation_requests/tenant-a:/presentation_requests:ro
    ports:
      - "8081:8080"
    depends_on:
      - mongo

  verifier-proxy-tenant-b:
    image: docker.sunet.se/dc4eu/verifier-proxy:latest
    container_name: vc_verifier_proxy_tenant_b
    environment:
      - VC_CONFIG_YAML=/config/config-tenant-b.yaml
    volumes:
      - ./config/tenant-b:/config:ro
      - ./keys/tenant-b:/keys:ro
      - ./presentation_requests/tenant-b:/presentation_requests:ro
    ports:
      - "8082:8080"
    depends_on:
      - mongo

  mongo:
    # Shared MongoDB instance with separate databases
```

**Configuration per Tenant:**
```yaml
# config/tenant-a/config.yaml
verifier_proxy:
  external_url: "https://verifier-a.example.com"
  oidc:
    issuer: "https://verifier-a.example.com"
    signing_key_path: "/keys/tenant_a_rsa.pem"
    subject_salt: "tenant-a-salt-xyz"
  openid4vp:
    presentation_requests_dir: "/presentation_requests"

common:
  mongo:
    uri: "mongodb://mongo:27017"
    database: "verifier_proxy_tenant_a"  # Separate database
```

### Pros

✅ **Complete Isolation**
- Each tenant has isolated configuration, keys, and state
- No code changes required
- Security boundary at OS/container level

✅ **Simplicity**
- Use existing codebase without modifications
- Easy to understand and debug
- Deploy immediately with current code

✅ **Independent Scaling**
- Scale tenants independently based on load
- High-volume tenant doesn't affect others
- Can use different instance sizes per tenant

✅ **Independent Operations**
- Update/restart tenants independently
- Different versions per tenant if needed
- Tenant-specific monitoring and alerts

✅ **Failure Isolation**
- Tenant A crash doesn't affect Tenant B
- Blast radius limited to single tenant
- Easy rollback per tenant

✅ **Security & Compliance**
- Clear tenant boundaries for auditing
- Separate signing keys per tenant
- Database-level isolation
- Easier compliance demonstrations (GDPR, data residency)

✅ **Configuration Flexibility**
- Each tenant can have completely different settings
- No constraints from shared configuration schema
- Easy to add tenant-specific features

### Cons

❌ **Resource Overhead**
- Each instance consumes ~100-200MB memory
- Duplicate Go runtime, HTTP servers, caches
- Higher infrastructure costs at scale

❌ **Operational Complexity**
- More containers to manage
- N × deployment pipelines
- More monitoring endpoints

❌ **Configuration Management**
- Duplicate configuration files
- Need tooling to manage tenant configs
- Risk of configuration drift

❌ **Database Connection Pool**
- Each instance has separate MongoDB connection pool
- May exhaust MongoDB connection limits with many tenants
- Need to tune connection pool settings

❌ **Shared Dependency Updates**
- Need to update all tenant instances
- Coordination overhead for breaking changes
- Testing matrix grows with tenants

### Cost Analysis

**Per Tenant:**
- Memory: ~150MB per instance
- CPU: Minimal idle, scales with load
- Storage: Negligible (configs + keys < 1MB)

**Break-even Point:**
- Economical for: 1-50 tenants
- Consider alternatives at: 50+ tenants

---

## Approach 2: Single Instance Multi-Tenant

### Architecture

Single verifier-proxy instance with tenant discrimination.

```
┌─────────────────────────────────┐
│     Verifier-Proxy (Single)     │
├─────────────────────────────────┤
│  Tenant Router/Discriminator    │
│  ┌──────────┬──────────────┐    │
│  │ Tenant A │ Tenant B     │    │
│  │ Config   │ Config       │    │
│  │ Keys     │ Keys         │    │
│  │ Templates│ Templates    │    │
│  └──────────┴──────────────┘    │
├─────────────────────────────────┤
│    Database (Multi-tenant)      │
│  ┌────────────┬──────────────┐  │
│  │ tenant_a.* │ tenant_b.*   │  │
│  └────────────┴──────────────┘  │
└─────────────────────────────────┘
```

### Tenant Discrimination Strategies

#### Option 2A: Domain-Based Routing

Route based on hostname:
- `https://tenant-a.verifier.example.com` → Tenant A config
- `https://tenant-b.verifier.example.com` → Tenant B config

```go
func (c *Client) getTenantConfig(req *http.Request) (*TenantConfig, error) {
    hostname := req.Host
    tenant, ok := c.tenantConfigs[hostname]
    if !ok {
        return nil, ErrTenantNotFound
    }
    return tenant, nil
}
```

#### Option 2B: Path-Based Routing

Route based on URL path prefix:
- `https://verifier.example.com/tenant-a/authorize` → Tenant A
- `https://verifier.example.com/tenant-b/authorize` → Tenant B

```go
func (c *Client) getTenantFromPath(path string) (string, error) {
    parts := strings.Split(path, "/")
    if len(parts) < 2 {
        return "", ErrInvalidPath
    }
    return parts[1], nil // tenant-a or tenant-b
}
```

#### Option 2C: Client-ID Based

Embed tenant in client_id:
- `client_id: "tenant-a::keycloak-dev"`
- `client_id: "tenant-b::mobile-app"`

```go
func (c *Client) getTenantFromClientID(clientID string) (string, error) {
    parts := strings.Split(clientID, "::")
    if len(parts) != 2 {
        return "", ErrInvalidClientID
    }
    return parts[0], nil
}
```

### Implementation Changes Required

**1. Configuration Schema**

```yaml
verifier_proxy:
  tenants:
    - id: "tenant-a"
      external_url: "https://tenant-a.verifier.example.com"
      oidc:
        issuer: "https://tenant-a.verifier.example.com"
        signing_key_path: "/keys/tenant_a_rsa.pem"
        subject_salt: "tenant-a-salt"
      openid4vp:
        presentation_requests_dir: "/presentation_requests/tenant-a"
    
    - id: "tenant-b"
      external_url: "https://tenant-b.verifier.example.com"
      oidc:
        issuer: "https://tenant-b.verifier.example.com"
        signing_key_path: "/keys/tenant_b_rsa.pem"
        subject_salt: "tenant-b-salt"
      openid4vp:
        presentation_requests_dir: "/presentation_requests/tenant-b"
```

**2. Database Schema**

Add `tenant_id` to collections:

```javascript
// sessions collection
{
  _id: "session_id",
  tenant_id: "tenant-a",  // NEW
  created_at: ISODate(...),
  // ... rest of fields
}

// clients collection
{
  _id: "client_id",
  tenant_id: "tenant-a",  // NEW
  client_id: "keycloak-dev",
  // ... rest of fields
}

// Create compound indexes
db.sessions.createIndex({ tenant_id: 1, _id: 1 })
db.clients.createIndex({ tenant_id: 1, client_id: 1 }, { unique: true })
```

**3. Client Struct Refactoring**

```go
// apiv1/client.go
type Client struct {
    cfg                         *model.Cfg
    db                          *db.Service
    log                         *logger.Log
    tracer                      *trace.Tracer
    
    // Multi-tenant state
    tenants                     map[string]*TenantRuntime
    tenantDiscriminator         TenantDiscriminator
}

type TenantRuntime struct {
    Config              *model.TenantConfig
    SigningKey          any
    SigningAlg          string
    PresentationBuilder *openid4vp.PresentationBuilder
    // Per-tenant caches could go here
}

type TenantDiscriminator interface {
    GetTenantID(req *http.Request) (string, error)
}
```

**4. Handler Modifications**

Every handler needs tenant context:

```go
func (c *Client) Authorize(ctx context.Context, req *AuthorizeRequest, tenantID string) (*AuthorizeResponse, error) {
    // Get tenant runtime
    tenant, err := c.getTenant(tenantID)
    if err != nil {
        return nil, err
    }
    
    // Use tenant-specific config
    issuer := tenant.Config.OIDC.Issuer
    
    // Database operations include tenant_id
    session := &db.Session{
        TenantID: tenantID,
        // ...
    }
    
    // ...
}
```

**5. Database Layer Changes**

All queries include tenant_id:

```go
func (c *ClientCollection) GetByClientID(ctx context.Context, tenantID string, clientID string) (*Client, error) {
    var client Client
    err := c.collection.FindOne(ctx, bson.M{
        "tenant_id": tenantID,
        "client_id": clientID,
    }).Decode(&client)
    // ...
}
```

### Pros

✅ **Resource Efficiency**
- Single Go runtime and HTTP server
- Shared connection pools
- Lower memory footprint (~150MB total vs N × 150MB)

✅ **Centralized Operations**
- Single deployment
- One monitoring endpoint
- Unified logging

✅ **Easier Updates**
- Update all tenants simultaneously
- Single codebase to maintain
- Consistent versions across tenants

✅ **Dynamic Tenant Management**
- Add/remove tenants without deployment
- Runtime configuration updates possible
- API for tenant management

✅ **Database Connection Efficiency**
- Single connection pool shared across tenants
- Better connection utilization
- Lower MongoDB resource usage

### Cons

❌ **Significant Development Effort**
- Requires extensive refactoring
- ~40-50 files need changes
- Database schema migration required
- Estimated: 2-3 weeks development + testing

❌ **Complexity & Risk**
- Tenant isolation bugs could leak data
- More complex code paths
- Harder to debug tenant-specific issues
- Tenant routing adds latency

❌ **No Failure Isolation**
- Single instance crash affects all tenants
- Resource exhaustion (memory, connections) impacts all
- Blast radius is entire service

❌ **Scaling Limitations**
- Can't scale tenants independently
- High-load tenant affects all tenants
- All tenants share same instance resources

❌ **Security Concerns**
- Tenant isolation enforced in code, not infrastructure
- Single vulnerability affects all tenants
- Signing keys in same memory space
- Higher audit burden

❌ **Configuration Constraints**
- All tenants must use same software version
- Limited ability for tenant-specific customization
- Breaking changes affect all tenants simultaneously

❌ **Testing Complexity**
- Must test tenant isolation thoroughly
- More edge cases (tenant A affects tenant B)
- Regression testing across all tenants

### Development Estimate

**Files requiring changes:** ~40-50 files
- `pkg/model/config.go` - Tenant config schema
- `internal/verifier_proxy/db/*.go` - Add tenant_id everywhere
- `internal/verifier_proxy/apiv1/*.go` - All handlers
- `cmd/verifier-proxy/main.go` - Initialization

**Testing required:**
- Unit tests for tenant isolation
- Integration tests with multiple tenants
- Load tests for tenant interference
- Security audit for data leakage

**Migration path:**
- Database migration scripts
- Configuration migration tools
- Backward compatibility period

---

## Approach 3: Hybrid Approaches

### Option 3A: Tenant Pools (Middle Ground)

Deploy multiple instances, each serving a group of tenants.

```
┌─────────────────────────────────┐
│   Pool 1 (Tenants A, B, C)      │
│   Single Instance               │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│   Pool 2 (Tenants D, E, F)      │
│   Single Instance               │
└─────────────────────────────────┘
```

**Use Case:** 
- Start with separate instances (Approach 1)
- Migrate to pools as tenant count grows
- Group tenants by load characteristics or organization

**Pros:**
- Balance resource efficiency with isolation
- Failure isolation per pool
- Can scale pools independently

**Cons:**
- Complexity of both approaches
- Need tenant assignment logic

### Option 3B: Sidecar Pattern

Deploy tenant-specific sidecars alongside shared core.

```
┌──────────────────────────────────────┐
│  Core Verifier-Proxy (Shared)       │
│  - Common OIDC logic                 │
│  - Session management                │
└────────┬─────────────────────────────┘
         │
    ┌────┴────┬────────┬───────┐
    │         │        │       │
┌───▼───┐ ┌──▼───┐ ┌──▼───┐  ...
│Tenant │ │Tenant│ │Tenant│
│  A    │ │  B   │ │  C   │
│Sidecar│ │Sidecar│ │Sidecar│
└───────┘ └──────┘ └──────┘
```

**Use Case:**
- Tenant-specific extensions
- Different credential formats per tenant
- Custom integrations

**Pros:**
- Shared core logic
- Tenant-specific customization
- Plugin architecture

**Cons:**
- Complex inter-process communication
- Harder to reason about
- Not applicable to current needs

### Option 3C: Namespace Routing (Kubernetes)

Use Kubernetes namespaces with ingress routing.

```
Ingress:
  tenant-a.verifier.example.com → namespace: tenant-a
  tenant-b.verifier.example.com → namespace: tenant-b

Namespace: tenant-a
  └─> verifier-proxy deployment (tenant-a config)
  └─> mongodb (tenant-a database)

Namespace: tenant-b  
  └─> verifier-proxy deployment (tenant-b config)
  └─> mongodb (tenant-b database)
```

**Use Case:**
- Already using Kubernetes
- Need network-level isolation
- Compliance requirements

**Pros:**
- Kubernetes-native isolation
- Network policies per tenant
- Resource quotas per namespace
- GitOps friendly

**Cons:**
- Requires Kubernetes
- Overhead of K8s infrastructure
- More complex operations

---

## Decision Matrix

| Criterion | Approach 1: Multi-Deploy | Approach 2: Single-Instance | Approach 3A: Pools |
|-----------|--------------------------|-----------------------------|--------------------|
| **Development Effort** | ✅ None (ready now) | ❌ High (2-3 weeks) | ⚠️ Medium |
| **Resource Efficiency** | ❌ Low (N × 150MB) | ✅ High (~150MB total) | ⚠️ Medium |
| **Failure Isolation** | ✅ Complete | ❌ None | ⚠️ Per-pool |
| **Security Isolation** | ✅ OS/container level | ❌ Application level | ⚠️ Per-pool |
| **Operational Complexity** | ⚠️ Medium | ✅ Low | ❌ High |
| **Independent Scaling** | ✅ Yes | ❌ No | ⚠️ Per-pool |
| **Time to Market** | ✅ Immediate | ❌ 3-4 weeks | ⚠️ 2-3 weeks |
| **Maintenance Burden** | ⚠️ Medium | ✅ Low | ❌ High |
| **Cost (10 tenants)** | ~1.5GB RAM | ~150MB RAM | ~500MB RAM |
| **Cost (100 tenants)** | ~15GB RAM | ~150MB RAM | ~3GB RAM |

---

## Recommendations

### Immediate: Approach 1 (Multiple Deployments)

**For the current state:** Deploy separate instances per tenant.

**Rationale:**
1. **Zero development time** - Production ready immediately
2. **Security first** - Complete isolation at infrastructure level
3. **Proven pattern** - Standard multi-tenant architecture
4. **Manageable scale** - Feasible for 5-50 tenants
5. **Risk mitigation** - Tenant failures don't cascade

**Implementation Steps:**

1. **Create deployment template** (1 day)
   ```bash
   ./scripts/provision-tenant.sh tenant-id domain-name
   ```
   - Generates config files
   - Creates signing keys
   - Sets up Docker Compose entry
   - Initializes MongoDB database

2. **Document tenant onboarding** (1 day)
   - Template README
   - Configuration guide
   - Client registration procedures

3. **Setup monitoring** (1 day)
   - Per-tenant metrics
   - Aggregate dashboards
   - Alerting per tenant

4. **Automate with IaC** (2-3 days)
   - Terraform/Ansible for provisioning
   - CI/CD per tenant
   - Automated testing

### Future: Migration Path to Single-Instance

**When to consider migration:**
- Tenant count > 50
- Resource costs become significant
- Operational burden too high
- Need dynamic tenant provisioning

**Migration strategy:**
1. Implement Approach 2 (single-instance) in parallel
2. Run both systems during transition
3. Migrate tenants gradually (blue-green deployment)
4. Keep Approach 1 as fallback for high-security tenants

**Hybrid final state:**
- Most tenants on single-instance (Approach 2)
- High-security/high-load tenants on dedicated instances (Approach 1)
- Best of both worlds

---

## Security Considerations

### Approach 1 (Recommended)

**Strengths:**
- ✅ Tenant isolation at OS/container boundary
- ✅ Separate signing keys (different memory spaces)
- ✅ Separate databases (no query interference)
- ✅ Network isolation possible (firewalls, VPCs)
- ✅ Easier compliance audits (clear boundaries)

**Weaknesses:**
- ⚠️ Shared MongoDB instance (use separate instances if required)
- ⚠️ Configuration file management (use secrets management)

### Approach 2 (Future)

**Strengths:**
- ✅ Centralized security updates
- ✅ Single codebase to audit

**Weaknesses:**
- ❌ Tenant isolation enforced in application code
- ❌ Signing keys in same memory space
- ❌ Database isolation via logical queries (not physical)
- ❌ Tenant routing bugs could leak data
- ❌ Single point of compromise affects all tenants

**Mitigations for Approach 2:**
- Extensive security testing
- Code review focused on tenant isolation
- Runtime checks for tenant access
- Audit logging for cross-tenant access attempts
- Hardware Security Module (HSM) for key isolation

---

## Performance Considerations

### Approach 1

**Latency:**
- Base latency: ~50ms (same as single tenant)
- No tenant routing overhead
- Direct database access

**Throughput:**
- Limited by instance resources
- Independent scaling per tenant
- No tenant interference

**Resource Usage:**
```
10 tenants:
  Memory: 10 × 150MB = 1.5GB
  CPU: ~0.1 vCPU per tenant idle, scales with load
  Connections: 10 × connection_pool_size
```

### Approach 2

**Latency:**
- Base latency: ~50ms
- Tenant routing: +5-10ms
- Database tenant_id filtering: +5ms
- Total: ~60-70ms

**Throughput:**
- Shared resources across tenants
- High-load tenant affects all
- Need careful resource limits

**Resource Usage:**
```
10 tenants:
  Memory: ~150MB + (10 × 20MB overhead) = 350MB
  CPU: Shared, potential contention
  Connections: Single shared pool
```

---

## Migration & Deployment

### Approach 1: Deployment Automation

**Provision Script (`scripts/provision-tenant.sh`):**
```bash
#!/bin/bash
TENANT_ID=$1
DOMAIN=$2

# Generate directory structure
mkdir -p config/${TENANT_ID}
mkdir -p keys/${TENANT_ID}
mkdir -p presentation_requests/${TENANT_ID}

# Generate signing keys
./developer_tools/gen_rsa_sign_key.sh keys/${TENANT_ID}/rsa.pem

# Generate config from template
sed "s/TENANT_ID/${TENANT_ID}/g; s/DOMAIN/${DOMAIN}/g" \
    config/template.yaml > config/${TENANT_ID}/config.yaml

# Add to docker-compose
cat >> docker-compose.yaml <<EOF

  verifier-proxy-${TENANT_ID}:
    image: docker.sunet.se/dc4eu/verifier-proxy:latest
    container_name: vc_verifier_proxy_${TENANT_ID}
    environment:
      - VC_CONFIG_YAML=/config/config.yaml
    volumes:
      - ./config/${TENANT_ID}:/config:ro
      - ./keys/${TENANT_ID}:/keys:ro
      - ./presentation_requests/${TENANT_ID}:/presentation_requests:ro
    depends_on:
      - mongo
      - mongo-init-verifier-proxy-${TENANT_ID}
EOF

echo "✅ Tenant ${TENANT_ID} provisioned"
echo "   Domain: ${DOMAIN}"
echo "   Config: config/${TENANT_ID}/config.yaml"
```

### Approach 2: Migration Script

If migrating to single-instance later:

```bash
#!/bin/bash
# migrate-to-single-instance.sh

# 1. Backup all tenant databases
for tenant in tenant-a tenant-b; do
    mongodump --db=verifier_proxy_${tenant} --out=backup/${tenant}
done

# 2. Restore with tenant_id field
for tenant in tenant-a tenant-b; do
    mongorestore --db=verifier_proxy \
        --transformNamespace="verifier_proxy_${tenant}.*" \
        --nsInclude="verifier_proxy_${tenant}.*" \
        backup/${tenant}
    
    # Add tenant_id to all documents
    mongo verifier_proxy --eval "
        db.sessions.updateMany({}, {\$set: {tenant_id: '${tenant}'}});
        db.clients.updateMany({}, {\$set: {tenant_id: '${tenant}'}});
    "
done

# 3. Create compound indexes
mongo verifier_proxy --eval "
    db.sessions.createIndex({tenant_id: 1, _id: 1});
    db.clients.createIndex({tenant_id: 1, client_id: 1}, {unique: true});
"
```

---

## Testing Strategy

### Approach 1

**Per-Tenant Tests:**
- Standard integration tests per instance
- No special multi-tenant tests needed

**Infrastructure Tests:**
- Provisioning script
- Configuration templates
- Resource limits

### Approach 2

**Tenant Isolation Tests:**
```go
func TestTenantIsolation(t *testing.T) {
    // Create session for tenant-a
    sessionA := createSession("tenant-a", "client-a")
    
    // Try to access from tenant-b
    err := getSession("tenant-b", sessionA.ID)
    assert.Error(t, err, "Should not access tenant-a session from tenant-b")
}

func TestClientIDUniquenessPerTenant(t *testing.T) {
    // Same client_id should work in different tenants
    clientA := registerClient("tenant-a", "shared-client-id")
    clientB := registerClient("tenant-b", "shared-client-id")
    
    assert.NotEqual(t, clientA.InternalID, clientB.InternalID)
}
```

---

## Cost Analysis

### Infrastructure Costs (AWS Example)

**Approach 1 (10 tenants):**
```
Compute:
  10 × t3.small (2vCPU, 2GB RAM) = $0.0208/hour × 10 × 730 hours/month
  = $151.84/month

Database:
  1 × t3.medium MongoDB (2vCPU, 4GB RAM) = $0.0416/hour × 730
  = $30.37/month

Load Balancer:
  ALB = $22.50/month

Total: ~$205/month for 10 tenants ($20.50 per tenant)
```

**Approach 2 (10 tenants):**
```
Compute:
  1 × t3.small (2vCPU, 2GB RAM) = $0.0208/hour × 730
  = $15.18/month

Database:
  1 × t3.medium MongoDB = $30.37/month

Load Balancer:
  ALB = $22.50/month

Total: ~$68/month for 10 tenants ($6.80 per tenant)

Development Cost:
  Engineering time: 2-3 weeks × $10k/week = $20-30k
  Amortized over 12 months = $1,667-2,500/month

Effective Cost Year 1: ~$1,735-2,568/month
Break-even: Month 13
```

**Recommendation:** Use Approach 1 until proven cost burden, then migrate.

---

## Open Questions & Future Considerations

1. **Dynamic Client Registration per Tenant**
   - Should DCR be tenant-scoped?
   - How to handle registration access tokens across tenants?

2. **Presentation Template Sharing**
   - Can tenants share common templates?
   - Template inheritance/composition?

3. **Monitoring & Observability**
   - Per-tenant metrics vs. aggregate?
   - Tenant-specific dashboards?

4. **Backup & Recovery**
   - Per-tenant backups in Approach 1?
   - Tenant restoration procedures?

5. **Rate Limiting**
   - Per-tenant limits?
   - Global limits?

6. **Compliance & Data Residency**
   - Do tenants need geographic isolation?
   - GDPR requirements per tenant?

---

## Conclusion

**Recommended Path:**

1. **Immediate (Now):** Implement Approach 1 (Multiple Deployments)
   - Production ready in days, not weeks
   - Security and isolation guarantees
   - Manageable for 5-50 tenants
   - Provides experience with multi-tenant requirements

2. **Future (6-12 months):** Evaluate migration to Approach 2
   - After understanding real tenant patterns
   - When tenant count justifies development investment
   - With clear requirements for tenant isolation
   - Gradual migration with hybrid deployment

3. **Long Term:** Hybrid model
   - Most tenants on shared instance
   - High-security/compliance tenants on dedicated instances
   - Flexible scaling strategy

This approach minimizes risk, maximizes time-to-market, and provides a clear evolution path as requirements mature.

---

## Appendix A: Configuration Template

### Multi-Deployment Template (`config/template.yaml`)

```yaml
verifier_proxy:
  api_server:
    addr: :8080
    tls:
      enabled: true
      cert: /certs/TENANT_ID.crt
      key: /certs/TENANT_ID.key
  
  external_url: "https://DOMAIN"
  
  oidc:
    issuer: "https://DOMAIN"
    signing_key_path: "/keys/rsa.pem"
    signing_alg: "RS256"
    id_token_duration: 3600
    access_token_duration: 3600
    refresh_token_duration: 86400
    subject_type: "pairwise"
    subject_salt: "GENERATE_RANDOM_SALT"
  
  openid4vp:
    presentation_timeout: 300
    presentation_requests_dir: "/presentation_requests"
    supported_credentials:
      - vct: "urn:eudi:pid:1"
        scopes: ["profile", "pid"]

common:
  production: true
  mongo:
    uri: "mongodb://mongo:27017"
    database: "verifier_proxy_TENANT_ID"
  tracing:
    addr: "jaeger:4318"
    type: "jaeger"
    timeout: 10
  log:
    folder_path: "/logs/TENANT_ID"
```

---

## Appendix B: Code Modifications for Approach 2

### Required Changes Summary

**pkg/model/config.go:**
```go
type VerifierProxy struct {
    // Existing single-tenant fields (deprecated)
    APIServer   APIServer       `yaml:"api_server"`
    ExternalURL string          `yaml:"external_url"`
    OIDC        OIDCConfig      `yaml:"oidc"`
    OpenID4VP   OpenID4VPConfig `yaml:"openid4vp"`
    
    // New multi-tenant configuration
    Tenants     []TenantConfig  `yaml:"tenants"`
}

type TenantConfig struct {
    ID          string          `yaml:"id"`
    ExternalURL string          `yaml:"external_url"`
    OIDC        OIDCConfig      `yaml:"oidc"`
    OpenID4VP   OpenID4VPConfig `yaml:"openid4vp"`
}
```

**internal/verifier_proxy/db/client.go:**
```go
type Client struct {
    TenantID     string   `bson:"tenant_id" json:"tenant_id"`  // NEW
    ClientID     string   `bson:"client_id" json:"client_id"`
    // ... rest of fields
}
```

**internal/verifier_proxy/db/session.go:**
```go
type Session struct {
    TenantID   string    `bson:"tenant_id" json:"tenant_id"`  // NEW
    SessionID  string    `bson:"_id" json:"session_id"`
    // ... rest of fields
}
```

**Estimated LOC changes:** ~2,000-3,000 lines across 40-50 files

---

**Document Version History:**

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-11-16 | Initial analysis |
