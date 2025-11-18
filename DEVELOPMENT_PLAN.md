# Phased Development Plan

**Date:** November 16, 2025  
**Status:** Draft for Review

## Executive Summary

This document outlines a phased development plan for two major initiatives:

1. **DCQL-Based Configurable Presentation Requests** - Enable flexible, standards-compliant credential verification using DCQL (Digital Credentials Query Language)
2. **Code Organization Analysis** - Evaluate splitting verifier-proxy into a separate project

## Goal 1: Configurable DCQL Presentation Requests

### Overview

Implement configurable presentation requests that map arbitrary DCQL queries (per [OpenID4VP Section 6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6)) to claims returned to OpenID RPs. The base functionality should be integrated into the verifier code and made available to other implementations beyond verifier-proxy.

### Current State Analysis

**Existing DCQL Implementation:**
- ✅ DCQL types defined in `pkg/openid4vp/dcql.go` (77 lines)
- ✅ Comprehensive test coverage in `pkg/openid4vp/dcql_test.go`
- ✅ DCQL integrated into RequestObject structure
- ✅ UI supports DCQL query generation (presentation-definition.js)
- ✅ Used by both verifier and verifier-proxy services

**Current Limitations:**
1. **Hard-coded scope-to-credential mapping** in `verifier_proxy/apiv1/handler_openid4vp.go:createPresentationDefinition()`
   - Scopes like "pid", "ehic" mapped to specific VCT values
   - No runtime configuration
   - Tight coupling to specific credential types

2. **Limited claims selection**
   - UI allows manual claim selection per request
   - No persistent presentation request templates
   - No mapping of DCQL results to OIDC claims

3. **Split presentation logic**
   - Verifier service: Direct DCQL from UI
   - Verifier-proxy: OIDC scopes → Presentation Definition conversion
   - No shared abstraction layer

**Dependencies:**
- `pkg/openid4vp` - Core DCQL types ✅ Already reusable
- `pkg/sdjwt3` - SD-JWT verification (used in response processing)
- `pkg/vcclient` - Credential validation

### Phase 1: Foundation & Configuration (2-3 weeks)

**Goal:** Create configurable presentation request templates with DCQL support

#### 1.1 Design Configuration Schema

Create YAML/JSON configuration format for presentation requests:

```yaml
# config/presentation_requests.yaml
presentation_requests:
  - id: "basic_pid"
    name: "Basic PID Verification"
    oidc_scope: "pid"
    dcql:
      credentials:
        - id: "pid_credential"
          format: "vc+sd-jwt"
          meta:
            vct_values: ["urn:eu.europa.ec.eudi:pid:1"]
          claims:
            - path: ["given_name"]
            - path: ["family_name"]
            - path: ["birthdate"]
    claim_mappings:
      given_name: "given_name"
      family_name: "family_name"
      birthdate: "birthdate"
      
  - id: "full_pid"
    name: "Full PID Verification"
    oidc_scope: "pid:full"
    dcql:
      credentials:
        - id: "pid_credential"
          format: "vc+sd-jwt"
          meta:
            vct_values: ["urn:eu.europa.ec.eudi:pid:1"]
          # No claims array = request all claims
    claim_mappings:
      "*": "*"  # Map all claims through
```

**Deliverables:**
- [ ] Configuration schema definition (JSON Schema + Go structs)
- [ ] Configuration loader in `pkg/configuration/presentation_requests.go`
- [ ] Validation logic for presentation request configs
- [ ] Unit tests for configuration parsing

**Files to Create:**
- `pkg/configuration/presentation_requests.go`
- `pkg/configuration/presentation_requests_test.go`
- `pkg/configuration/testdata/presentation_requests.yaml`

#### 1.2 Refactor DCQL Generation

Extract presentation definition creation from verifier-proxy into reusable pkg:

```go
// pkg/openid4vp/presentation_builder.go
package openid4vp

type PresentationRequestTemplate struct {
    ID            string
    Name          string
    OIDCScope     string
    DCQLQuery     *DCQL
    ClaimMappings map[string]string
}

type PresentationBuilder struct {
    templates map[string]*PresentationRequestTemplate
}

func NewPresentationBuilder(templates []*PresentationRequestTemplate) *PresentationBuilder

func (pb *PresentationBuilder) BuildFromScope(scope string) (*DCQL, error)

func (pb *PresentationBuilder) BuildFromDCQL(dcql *DCQL) (*DCQL, error)

func (pb *PresentationBuilder) MapResponseClaims(
    response *ResponseParameters, 
    template *PresentationRequestTemplate,
) (map[string]any, error)
```

**Deliverables:**
- [ ] `pkg/openid4vp/presentation_builder.go` - Core builder logic
- [ ] `pkg/openid4vp/presentation_builder_test.go` - Comprehensive tests
- [ ] `pkg/openid4vp/claim_mapper.go` - Claims mapping logic
- [ ] Refactor `internal/verifier_proxy/apiv1/handler_openid4vp.go` to use builder

**Migration Path:**
1. Create new builder with backward compatibility
2. Update verifier-proxy to use builder (optional configuration)
3. Deprecate old `createPresentationDefinition()` method
4. Update verifier service to use builder

### Phase 2: Claims Mapping Engine (2-3 weeks)

**Goal:** Map VP token claims to OIDC UserInfo/ID token claims

#### 2.1 Claims Extraction

Enhance response processing to extract claims from VPs:

```go
// pkg/openid4vp/claims_extractor.go
package openid4vp

type ClaimsExtractor struct {
    // Extract claims from various VP formats
}

func (ce *ClaimsExtractor) ExtractClaims(
    vpToken string,
    dcqlQuery *DCQL,
) (map[string]any, error)

// Handles:
// - SD-JWT VPs (selective disclosure)
// - Nested claim paths (e.g., ["address", "street_address"])
// - Multiple credentials in response
// - Claim filtering per DCQL query
```

**Deliverables:**
- [ ] `pkg/openid4vp/claims_extractor.go`
- [ ] `pkg/openid4vp/claims_extractor_test.go`
- [ ] Support for SD-JWT claim extraction
- [ ] Support for nested claim paths
- [ ] Integration tests with real SD-JWT credentials

#### 2.2 OIDC Claims Mapping

Map extracted VP claims to OIDC standard claims:

```go
// pkg/openid4vp/oidc_mapper.go
package openid4vp

type OIDCClaimsMapper struct {
    mappings map[string]ClaimMapping
}

type ClaimMapping struct {
    VPClaimPath   []string  // Path in VP credential
    OIDCClaim     string    // OIDC claim name
    Transform     func(any) any  // Optional transformation
    Required      bool
}

func (m *OIDCClaimsMapper) MapToUserInfo(
    vpClaims map[string]any,
    requestedScopes []string,
) (map[string]any, error)

func (m *OIDCClaimsMapper) MapToIDToken(
    vpClaims map[string]any,
    requestedScopes []string,
) (map[string]any, error)
```

**Deliverables:**
- [ ] `pkg/openid4vp/oidc_mapper.go`
- [ ] `pkg/openid4vp/oidc_mapper_test.go`
- [ ] Configurable claim mappings
- [ ] Standard OIDC scope handling (profile, email, address, phone)
- [ ] Custom scope mapping support

### Phase 3: Integration & Testing (2 weeks)

**Goal:** Integrate into verifier-proxy and test end-to-end

#### 3.1 Verifier-Proxy Integration

Update verifier-proxy to use new DCQL pipeline:

**Files to Modify:**
- `internal/verifier_proxy/apiv1/handler_openid4vp.go`
  - Replace `createPresentationDefinition()` with PresentationBuilder
  - Add claims extraction in callback handling
  - Map VP claims to UserInfo response

- `internal/verifier_proxy/apiv1/handler_oidc.go`
  - Update UserInfo endpoint to use mapped claims
  - Update ID token generation to include mapped claims

- `internal/verifier_proxy/apiv1/client.go`
  - Add PresentationBuilder initialization
  - Load presentation request templates from config

**Deliverables:**
- [ ] Updated handlers using new abstractions
- [ ] Configuration loading in service startup
- [ ] Backward compatibility with existing scope-based flows
- [ ] Migration documentation

#### 3.2 Verifier Service Integration

Update standalone verifier service:

**Files to Modify:**
- `internal/verifier/apiv1/handlers_ui.go`
  - Use PresentationBuilder for UI-generated DCQL
  - Optional: Load presentation request templates

- `internal/verifier/apiv1/handlers_verification.go`
  - Use ClaimsExtractor for response processing

**Deliverables:**
- [ ] Verifier service using shared abstractions
- [ ] Code reuse validation
- [ ] UI remains functional

#### 3.3 End-to-End Testing

**Test Scenarios:**
1. **Basic scope mapping** - "pid" scope → PID credential request → UserInfo claims
2. **Custom DCQL** - UI-generated DCQL → VP response → claim extraction
3. **Multiple credentials** - Request multiple VCTs → combined claims response
4. **Selective disclosure** - Request specific claims → verify only requested claims in VP
5. **Claim transformation** - Date formats, name composition, etc.

**Deliverables:**
- [ ] Integration tests in `internal/verifier_proxy/integration/`
- [ ] E2E tests with real wallet interaction
- [ ] Performance benchmarks
- [ ] Documentation updates

### Phase 4: Advanced Features (3-4 weeks)

**Goal:** Add advanced DCQL capabilities

#### 4.1 Advanced DCQL Features

Implement full DCQL spec support:

- [ ] **Credential Sets** - Alternative credential options
- [ ] **Claim Sets** - Required claim combinations
- [ ] **Trusted Authorities** - Issuer constraints
- [ ] **Multiple Credentials** - Cross-credential queries
- [ ] **Claim Constraints** - Value filters, patterns

#### 4.2 Template Management API

Create API for managing presentation request templates:

```go
// pkg/openid4vp/template_manager.go
type TemplateManager interface {
    CreateTemplate(ctx context.Context, template *PresentationRequestTemplate) error
    GetTemplate(ctx context.Context, id string) (*PresentationRequestTemplate, error)
    ListTemplates(ctx context.Context) ([]*PresentationRequestTemplate, error)
    UpdateTemplate(ctx context.Context, template *PresentationRequestTemplate) error
    DeleteTemplate(ctx context.Context, id string) error
}
```

**Storage Options:**
- File-based (YAML/JSON files)
- Database-backed (MongoDB)
- Hybrid (file for defaults, DB for runtime)

**Deliverables:**
- [ ] Template manager interface
- [ ] File-based implementation
- [ ] MongoDB implementation (optional)
- [ ] REST API endpoints for template CRUD
- [ ] Admin UI for template management

### Success Criteria

- [ ] All DCQL features from Section 6 supported
- [ ] Configurable presentation requests work in both verifier and verifier-proxy
- [ ] Zero changes needed to wallet clients (backward compatible)
- [ ] Claims correctly mapped to OIDC UserInfo/ID token
- [ ] Performance: <100ms overhead for claims processing
- [ ] Test coverage: >80% for new pkg/openid4vp code
- [ ] Documentation: Complete examples for all DCQL features

### Dependencies & Risks

**Dependencies:**
- SD-JWT library (`pkg/sdjwt3`) for claim extraction
- MongoDB for template storage (optional)
- Conformance test suite for OIDC validation

**Risks:**
1. **Complexity of claims mapping** - Some credential structures may not map cleanly to OIDC
   - *Mitigation*: Define clear transformation rules, support custom mappers
   
2. **Performance** - Complex DCQL queries with nested claims
   - *Mitigation*: Benchmark early, optimize extraction logic, consider caching
   
3. **Breaking changes** - Existing scope-based flows may break
   - *Mitigation*: Maintain backward compatibility, gradual migration

---

## Goal 2: Code Organization Analysis - verifier-proxy Split

### Current State

**Repository Structure:**
```
vc/
├── cmd/
│   ├── verifier/          # Standalone verifier service
│   ├── verifier_proxy/    # OIDC proxy service
│   ├── issuer/            # VC issuer service
│   ├── apigw/             # API gateway
│   ├── registry/          # Credential registry
│   └── ...
├── internal/
│   ├── verifier/          # ~1,360 LOC
│   ├── verifier_proxy/    # ~7,872 LOC
│   ├── issuer/
│   ├── apigw/
│   └── ...
└── pkg/                   # ~13,616 LOC (shared libraries)
    ├── openid4vp/
    ├── openid4vci/
    ├── sdjwt3/
    ├── model/
    └── ...
```

**Code Metrics:**
- **verifier_proxy**: 29 Go files, ~7,872 lines
- **verifier**: 15 Go files, ~1,360 lines
- **pkg**: Shared libraries, ~13,616 lines
- **Total repository**: ~23K lines Go code across 7 services

**Current Dependencies:**
```
verifier_proxy → pkg/openid4vp (DCQL, RequestObject)
verifier_proxy → pkg/model (Config, DB types)
verifier_proxy → pkg/oauth2 (OIDC flows)
verifier_proxy → pkg/jose (JWT/JWK)
verifier_proxy → pkg/sdjwt3 (SD-JWT verification)

verifier → pkg/openid4vp (DCQL)
verifier → pkg/model (Config, DB types)
```

### Analysis: Monorepo vs Separate Repository

#### Option A: Keep Monorepo (Status Quo)

**Pros:**

1. **Shared Code Efficiency**
   - `pkg/openid4vp`, `pkg/sdjwt3`, `pkg/model` used by multiple services
   - Single source of truth for DCQL types, SD-JWT logic
   - Changes propagate immediately to all consumers
   - No version skew between services

2. **Simplified Development**
   - Single `go.mod` - unified dependency management
   - Cross-service refactoring in single PR
   - Easier to maintain consistency (linting, formatting, CI)
   - Simplified local development setup

3. **Atomic Changes**
   - Can update `pkg/openid4vp` + verifier_proxy + verifier in one commit
   - Breaking changes visible immediately across all services
   - Integration tests can cover multiple services
   - Git history shows complete context

4. **Reduced Overhead**
   - One CI/CD pipeline
   - One issue tracker
   - One PR review process
   - One release cadence (if desired)

5. **Current Investment**
   - Existing CI/CD already set up
   - PR strategy already defined (5 PRs organized)
   - Docker Compose for local dev
   - Shared test infrastructure

**Cons:**

1. **Size Concerns**
   - Repository could grow large over time
   - `git clone` time increases
   - IDE may slow down with large workspace

2. **Service Coupling**
   - Risk of tight coupling between services
   - Changes to pkg/ affect all services
   - Harder to enforce service boundaries

3. **Release Complexity**
   - If services need independent versioning
   - Tagging strategy becomes complex (e.g., `verifier-proxy/v1.2.3`)
   - Client consumers may not need all services

4. **Team Scaling**
   - Harder to assign ownership per service
   - All developers need access to entire repo
   - More complex CODEOWNERS file

#### Option B: Split verifier-proxy to Separate Repo

**Structure:**
```
vc-verifier-proxy/
├── cmd/verifier_proxy/
├── internal/verifier_proxy/
├── pkg/                    # Subset or vendored
│   ├── openid4vp/          # Could be duplicated or imported
│   ├── oauth2/
│   └── ...
├── go.mod
└── README.md

vc/  (original)
├── cmd/
│   ├── verifier/
│   ├── issuer/
│   └── ...
├── pkg/
│   ├── openid4vp/          # Shared library
│   └── ...
```

**Pros:**

1. **Clear Boundaries**
   - verifier-proxy is self-contained
   - Independent release cadence
   - Easier to enforce API contracts
   - Can be open-sourced separately if needed

2. **Independent Evolution**
   - verifier-proxy can evolve faster/slower than other services
   - Different teams can own different repos
   - Easier to deprecate if needed
   - Different security/compliance requirements

3. **Smaller Repos**
   - Faster clone times
   - Smaller IDE workspace
   - Focused issue tracking
   - Clearer git history per service

4. **Versioning Clarity**
   - Simple semantic versioning per service
   - Clear release notes per service
   - Easier for external consumers (if exposing as library)

**Cons:**

1. **Shared Code Duplication**
   - **Critical Issue**: `pkg/openid4vp`, `pkg/sdjwt3` used by both
   - Options:
     - **A) Duplicate code** - Maintenance nightmare, divergence risk
     - **B) Separate shared library repo** - `go-vc-libs` (adds complexity)
     - **C) Go module import** - `vc-verifier-proxy` imports `github.com/org/vc/pkg/openid4vp`
       - Still requires coordinating version updates
       - Breaking changes in `vc/pkg` breaks `vc-verifier-proxy`

2. **Development Friction**
   - Need to update multiple repos for cross-cutting changes
   - Example: Adding new DCQL field requires:
     1. Update `vc/pkg/openid4vp/dcql.go`
     2. Release new version of vc
     3. Update `vc-verifier-proxy/go.mod` to new version
     4. Update verifier-proxy code
     5. Test and release verifier-proxy
   - Multi-repo PRs are harder to review atomically

3. **Testing Complexity**
   - Integration tests spanning services become harder
   - Need to coordinate versions for E2E tests
   - CI/CD needs to know about dependencies between repos

4. **Initial Migration Cost**
   - Move code between repos
   - Set up new CI/CD
   - Update import paths
   - Migrate issues/PRs
   - Estimated: 1-2 weeks of work

5. **Version Skew**
   - verifier-proxy may use old version of pkg/openid4vp
   - Security fixes need to be propagated across repos
   - Dependency hell with transitive dependencies

### Recommended Approach: Hybrid (Monorepo with Better Structure)

**Keep monorepo but improve organization:**

```
vc/
├── services/
│   ├── verifier_proxy/      # Move from cmd/verifier_proxy
│   │   ├── cmd/
│   │   ├── internal/
│   │   ├── README.md        # Service-specific docs
│   │   ├── Makefile         # Service-specific build
│   │   └── docker-compose.yml
│   ├── verifier/
│   ├── issuer/
│   └── apigw/
├── libs/                    # Rename from pkg/
│   ├── openid4vp/
│   ├── sdjwt3/
│   └── ...
├── tools/                   # Shared dev tools
├── docs/                    # Cross-service docs
└── go.mod                   # Single module
```

**Benefits:**
- ✅ Keeps all benefits of monorepo
- ✅ Clear service boundaries via directory structure
- ✅ Service-specific docs/configs co-located
- ✅ Can still extract to separate repo later if needed
- ✅ Go workspaces could enable per-service `go.mod` if desired

**Implementation:**
1. Restructure directories (1 day)
2. Update import paths (automated via goimports)
3. Update CI/CD to support new structure (1 day)
4. Update documentation (1 day)

### Decision Matrix

| Criterion | Monorepo | Split Repo | Hybrid |
|-----------|----------|------------|--------|
| Shared code reuse | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Independent releases | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| Development velocity | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| Service boundaries | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| Testing simplicity | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Migration cost | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ |
| Long-term maintenance | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

**Recommendation: Hybrid Approach (Improved Monorepo)**

### Pros/Cons Summary Table

| **Aspect** | **Monorepo (Current)** | **Split Repository** | **Hybrid (Recommended)** |
|------------|------------------------|----------------------|--------------------------|
| **Code Reuse** | Excellent - direct imports | Poor - requires versioning | Excellent - direct imports |
| **Shared Library Updates** | Atomic - single commit | Complex - multi-repo coordination | Atomic - single commit |
| **Service Independence** | Medium - shared repo | High - separate repos | High - clear boundaries in monorepo |
| **Release Management** | Complex - all services together | Simple - per-service | Flexible - can be per-service or grouped |
| **CI/CD Complexity** | Simple - one pipeline | Complex - multiple pipelines | Medium - one pipeline, conditional builds |
| **Developer Onboarding** | Medium - large codebase | Simple - smaller codebase | Medium - but clear structure |
| **Cross-Service Changes** | Easy - single PR | Hard - multiple PRs/repos | Easy - single PR |
| **Testing** | Excellent - integrated tests | Complex - coordination needed | Excellent - integrated tests |
| **Migration Effort** | None - status quo | High - 1-2 weeks | Low - 2-3 days |
| **Git Performance** | Slower with growth | Fast - small repos | Faster - can use sparse checkout |
| **Dependency Management** | Simple - single go.mod | Complex - version coordination | Simple - single go.mod (or workspaces) |

---

## Implementation Roadmap

### Immediate Next Steps (Weeks 1-2)

1. **Goal 1 - Phase 1.1**: Design & implement presentation request configuration schema
2. **Goal 2**: Implement hybrid monorepo restructuring
3. **Documentation**: Create ADR (Architecture Decision Record) for both decisions

### Short Term (Weeks 3-6)

1. **Goal 1 - Phase 1.2 & 2.1**: Implement PresentationBuilder and ClaimsExtractor
2. Begin integration with verifier-proxy
3. Write comprehensive tests

### Medium Term (Weeks 7-12)

1. **Goal 1 - Phase 2.2 & 3**: Complete OIDC mapping and integration
2. E2E testing with real wallets
3. Performance optimization

### Long Term (Months 4-6)

1. **Goal 1 - Phase 4**: Advanced DCQL features
2. Template management API
3. Admin UI for presentation requests
4. Consider additional service extractions if patterns emerge

---

## Open Questions

1. **Configuration Storage**: File-based vs database for presentation request templates?
2. **Backward Compatibility**: How long to support old scope-based flows?
3. **Claims Transformation**: What transformations are needed? (Date formats, name composition, etc.)
4. **Multi-Credential Scenarios**: How to handle claims from multiple VPs in single response?
5. **Performance**: What are acceptable latency targets for claims processing?
6. **Versioning**: If we keep monorepo, how do we version services independently?
7. **Service Extraction**: Are there other services that should be split out (issuer, registry)?

---

## Success Metrics

**Goal 1 - DCQL Implementation:**
- [ ] 100% of DCQL spec Section 6 implemented
- [ ] Test coverage > 80% for new code
- [ ] Performance: <100ms for claims processing
- [ ] Zero breaking changes to existing flows
- [ ] Both verifier and verifier-proxy use shared code

**Goal 2 - Code Organization:**
- [ ] Clear service boundaries in directory structure
- [ ] Reduced cross-service coupling (measured by import graph)
- [ ] Improved developer experience (survey feedback)
- [ ] No regression in CI/CD performance
- [ ] Documented decision rationale (ADR)

---

## Appendix: File Structure Examples

### Presentation Request Configuration Example

```yaml
# config/presentation_requests/eudi_pid_basic.yaml
id: "eudi_pid_basic"
name: "EU Digital Identity - Basic PID"
description: "Request basic personal identification data from EUDI wallet"
version: "1.0"

# Map to OIDC scopes
oidc_scopes:
  - "pid"
  - "openid"

# DCQL query structure
dcql:
  credentials:
    - id: "eudi_pid"
      format: "vc+sd-jwt"
      meta:
        vct_values:
          - "urn:eu.europa.ec.eudi:pid:1"
      claims:
        - path: ["given_name"]
        - path: ["family_name"]
        - path: ["birthdate"]
        - path: ["place_of_birth", "country"]
        - path: ["nationalities"]

# Map VP claims to OIDC UserInfo/IDToken claims
claim_mappings:
  # VP claim path → OIDC claim name
  given_name: "given_name"
  family_name: "family_name"
  birthdate: "birthdate"
  "place_of_birth.country": "birth_country"  # Nested claim flattening
  nationalities: "nationalities"             # Array passthrough

# Optional transformations
claim_transforms:
  birthdate:
    type: "date_format"
    from: "YYYY-MM-DD"
    to: "YYYYMMDD"
```

### Hybrid Directory Structure Example

```
vc/
├── README.md                    # Root README with repo overview
├── go.mod                       # Single Go module
├── go.sum
├── Makefile                     # Root-level targets
├── docker-compose.yaml          # All services
│
├── services/                    # All deployable services
│   ├── verifier_proxy/
│   │   ├── cmd/verifier_proxy/
│   │   │   └── main.go
│   │   ├── internal/
│   │   │   ├── apiv1/
│   │   │   ├── httpserver/
│   │   │   ├── db/
│   │   │   └── integration/    # Service-specific integration tests
│   │   ├── config/
│   │   │   └── presentation_requests/  # Service-specific configs
│   │   ├── README.md            # verifier_proxy-specific docs
│   │   ├── Dockerfile
│   │   └── Makefile             # Service-specific targets
│   │
│   ├── verifier/
│   │   ├── cmd/verifier/
│   │   ├── internal/
│   │   ├── README.md
│   │   └── ...
│   │
│   ├── issuer/
│   ├── registry/
│   └── apigw/
│
├── libs/                        # Shared libraries (renamed from pkg/)
│   ├── openid4vp/
│   │   ├── dcql.go
│   │   ├── presentation_builder.go
│   │   ├── claims_extractor.go
│   │   └── ...
│   ├── openid4vci/
│   ├── sdjwt3/
│   ├── model/
│   ├── configuration/
│   └── ...
│
├── tools/                       # Shared development tools
│   ├── scripts/
│   │   └── run-oidc-conformance.sh
│   └── ...
│
├── docs/                        # Cross-service documentation
│   ├── architecture/
│   │   ├── ADR-001-monorepo-structure.md
│   │   └── ADR-002-dcql-implementation.md
│   ├── api/
│   └── diagrams/
│
└── .github/
    └── workflows/
        ├── ci.yaml              # Unified CI with conditional service builds
        └── release.yaml
```

---

**Next Steps:** Review this plan and provide feedback on:
1. Phase priorities
2. Timeline adjustments
3. Resource allocation
4. Open questions that need decisions
