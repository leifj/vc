# OpenID Connect Conformance Suite Testing Strategy

## Overview

This document describes the automated testing strategy for the verifier-proxy **OIDC Provider** implementation using the [OpenID Connect Conformance Suite](https://openid.net/certification/testing/).

**Important:** This tests the verifier-proxy's role as an **OIDC Provider** (issuing ID tokens to relying parties), not its credential verification capabilities. The verifier-proxy:
- ✅ Acts as an OpenID Provider (tested here)
- ✅ Verifies presentations from wallets (tested via integration tests)
- ❌ Does NOT issue verifiable credentials (separate VC Issuer service)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Local Machine                                                   │
│                                                                 │
│  ┌──────────────────┐       ┌──────────────────┐              │
│  │  Docker Compose  │       │     ngrok        │              │
│  │                  │       │                  │              │
│  │  - MongoDB       │       │  HTTPS Tunnel    │              │
│  │  - verifier-proxy│◄──────┤  :8080 → public │              │
│  │    :8080         │       │                  │              │
│  └──────────────────┘       └────────┬─────────┘              │
│                                      │                         │
└──────────────────────────────────────┼─────────────────────────┘
                                       │
                                       │ HTTPS
                                       │
                              ┌────────▼─────────┐
                              │                  │
                              │  OpenID Connect  │
                              │ Conformance Suite│
                              │                  │
                              │  https://...     │
                              │  .authlete.net   │
                              └──────────────────┘
```

## Prerequisites

1. **ngrok installed** - For public HTTPS tunneling
   ```bash
   # Install ngrok (if not already installed)
   curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
   echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
   sudo apt update && sudo apt install ngrok
   
   # Authenticate ngrok (free account required)
   ngrok config add-authtoken YOUR_AUTH_TOKEN
   ```

2. **Docker Compose** - Already available in project

3. **OpenID Connect Conformance Suite Account**
   - Register at https://www.certification.openid.net/
   - Create test plan for "OP - OpenID Provider"

## Test Plans

The OpenID Connect Conformance Suite offers several test plans for OP testing:

### 1. Basic OP Tests (Recommended Starting Point)
- **Plan:** `oidcc-basic-certification-test-plan`
- **Profile:** Authorization Code Flow
- **Tests:**
  - Discovery endpoint validation
  - JWKS endpoint validation
  - Authorization endpoint (code flow)
  - Token endpoint (code exchange)
  - UserInfo endpoint
  - ID Token validation

### 2. RP-Initiated Logout Tests
- **Plan:** `oidcc-rpinitiated-logout-certification-test-plan`
- **Tests:** Session management and logout

### 3. Dynamic Registration Tests
- **Plan:** `oidcc-client-test-plan`
- **Tests:** RFC 7591/7592 compliance (our recent implementation!)

### 4. FAPI Advanced Tests (Optional)
- **Plan:** `fapi-rw-id2-test-plan`
- **Tests:** High-security profile compliance

## Setup

### 1. Local Configuration

Create a conformance testing configuration file:

```bash
# File: config.conformance.yaml
```

This configuration:
- Uses public ngrok URL as `external_url` and `issuer`
- Enables HTTPS in discovery metadata
- Configures proper timeouts for testing
- Uses test-friendly durations

### 2. Start ngrok Tunnel

```bash
# Start ngrok tunnel on port 8080
ngrok http 8080 --log=stdout --log-level=debug > ngrok.log 2>&1 &

# Get the public HTTPS URL
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
echo "Public URL: $NGROK_URL"
```

### 3. Update Configuration with ngrok URL

```bash
# Update config.conformance.yaml with actual ngrok URL
sed "s|NGROK_URL_PLACEHOLDER|$NGROK_URL|g" config.conformance.template.yaml > config.conformance.yaml
```

### 4. Start verifier-proxy with Conformance Config

```bash
# Start MongoDB
docker-compose up -d mongo mongo-init-verifier-proxy

# Wait for MongoDB initialization
sleep 10

# Start verifier-proxy with conformance config
VC_CONFIG_YAML=config.conformance.yaml go run cmd/verifier-proxy/main.go
```

### 5. Verify Setup

```bash
# Test discovery endpoint
curl -s "$NGROK_URL/.well-known/openid-configuration" | jq .

# Expected: issuer should match $NGROK_URL
```

## Automated Testing Script

Create `scripts/run-oidc-conformance.sh`:

```bash
#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Step 1: Check prerequisites
echo_info "Checking prerequisites..."

if ! command -v ngrok &> /dev/null; then
    echo_error "ngrok not found. Please install: https://ngrok.com/download"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo_error "jq not found. Please install: sudo apt-get install jq"
    exit 1
fi

echo_info "Prerequisites OK"

# Step 2: Start MongoDB
echo_info "Starting MongoDB..."
docker-compose up -d mongo mongo-init-verifier-proxy
sleep 10

# Step 3: Start ngrok tunnel
echo_info "Starting ngrok tunnel..."
ngrok http 8080 --log=stdout --log-level=info > ngrok.log 2>&1 &
NGROK_PID=$!
echo_info "ngrok PID: $NGROK_PID"

# Wait for ngrok to start
sleep 3

# Get ngrok URL
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')

if [ -z "$NGROK_URL" ] || [ "$NGROK_URL" == "null" ]; then
    echo_error "Failed to get ngrok URL"
    kill $NGROK_PID 2>/dev/null || true
    exit 1
fi

echo_info "ngrok URL: $NGROK_URL"

# Step 4: Generate conformance config
echo_info "Generating conformance configuration..."

cat > config.conformance.yaml <<EOF
---
common:
  mongo:
    uri: mongodb://localhost:27017
  production: false

verifier_proxy:
  api_server:
    addr: :8080
    tls:
      enabled: false
  external_url: "$NGROK_URL"
  oidc:
    issuer: "$NGROK_URL"
    signing_key_path: "./developer_tools/private_rsa.pem"
    id_token_duration: 3600
    access_token_duration: 3600
    refresh_token_duration: 86400
    authorization_code_duration: 600
    session_duration: 1800
    subject_type: "public"  # Use public for testing (easier)
    subject_salt: "conformance-test-salt"
  openid4vp:
    presentation_timeout: 600
    supported_credentials:
      - vct: "urn:eudi:pid:1"
        scopes:
          - "profile"
          - "pid"
EOF

echo_info "Configuration generated"

# Step 5: Start verifier-proxy
echo_info "Starting verifier-proxy..."
VC_CONFIG_YAML=config.conformance.yaml go run cmd/verifier-proxy/main.go > verifier-proxy.log 2>&1 &
PROXY_PID=$!
echo_info "verifier-proxy PID: $PROXY_PID"

# Wait for service to start
sleep 5

# Step 6: Test discovery endpoint
echo_info "Testing discovery endpoint..."
DISCOVERY_URL="$NGROK_URL/.well-known/openid-configuration"
echo_info "Discovery URL: $DISCOVERY_URL"

if ! curl -sf "$DISCOVERY_URL" > /dev/null; then
    echo_error "Discovery endpoint not accessible"
    kill $PROXY_PID 2>/dev/null || true
    kill $NGROK_PID 2>/dev/null || true
    exit 1
fi

echo_info "Discovery endpoint OK"

# Step 7: Display test configuration
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo_info "OpenID Connect Conformance Suite Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Issuer URL:           $NGROK_URL"
echo "Discovery Endpoint:   $NGROK_URL/.well-known/openid-configuration"
echo "Registration Endpoint: $NGROK_URL/register"
echo ""
echo "Test Plan Setup:"
echo "1. Go to: https://www.certification.openid.net/"
echo "2. Create new test plan: 'oidcc-basic-certification-test-plan'"
echo "3. Configuration:"
echo "   - Server metadata location: $NGROK_URL/.well-known/openid-configuration"
echo "   - Client registration: DYNAMIC (automatic)"
echo ""
echo "Logs:"
echo "   - ngrok:          tail -f ngrok.log"
echo "   - verifier-proxy: tail -f verifier-proxy.log"
echo ""
echo "Press Ctrl+C to stop all services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo_info "Shutting down services..."
    kill $PROXY_PID 2>/dev/null || true
    kill $NGROK_PID 2>/dev/null || true
    echo_info "Cleanup complete"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for Ctrl+C
wait $PROXY_PID
```

## Manual Testing Procedure

### Phase 1: Discovery & Registration

1. **Access Conformance Suite**
   - Navigate to https://www.certification.openid.net/
   - Login with your account

2. **Create Test Plan**
   - Click "Create Test Plan"
   - Select: "OpenID Provider Tests" → "oidcc-basic-certification-test-plan"
   - Configuration:
     - **Discovery URL**: `<your-ngrok-url>/.well-known/openid-configuration`
     - **Client Registration**: Select "Dynamic Registration"
     - **Response Type**: `code`
     - **Client Authentication**: `client_secret_basic`

3. **Run Discovery Tests**
   - Test: `oidcc-server-discovery`
   - Test: `oidcc-server-jwks`
   - All should pass ✅

### Phase 2: Authorization Code Flow

4. **Run Authorization Tests**
   - Test: `oidcc-code-basic`
   - **Note**: This requires wallet interaction (OpenID4VP)
   - For conformance testing, you may need to mock the wallet response

5. **Run Token Tests**
   - Test: `oidcc-codereuse`
   - Test: `oidcc-token-endpoint`
   - Should validate our code replay protection ✅

### Phase 3: Advanced Tests

6. **Dynamic Registration Tests**
   - Test: `oidcc-client-registration`
   - Test: `oidcc-client-registration-update`
   - Should validate RFC 7591/7592 implementation ✅

7. **PKCE Tests**
   - Test: `oidcc-ensure-request-with-valid-pkce-succeeds`
   - Should validate S256 code challenge ✅

## Automated Test Runner (Python)

For fully automated testing, create `scripts/conformance_tester.py`:

```python
#!/usr/bin/env python3
"""
OpenID Connect Conformance Suite Automated Tester
"""
import subprocess
import time
import requests
import json
import sys
from typing import Optional

class ConformanceTester:
    def __init__(self, ngrok_url: str):
        self.ngrok_url = ngrok_url
        self.discovery_url = f"{ngrok_url}/.well-known/openid-configuration"
        self.conformance_api = "https://www.certification.openid.net/api"
        
    def verify_discovery(self) -> bool:
        """Verify discovery endpoint is accessible"""
        try:
            resp = requests.get(self.discovery_url, timeout=10)
            resp.raise_for_status()
            metadata = resp.json()
            
            # Verify required fields
            required = [
                "issuer", "authorization_endpoint", "token_endpoint",
                "jwks_uri", "registration_endpoint", "scopes_supported"
            ]
            
            for field in required:
                if field not in metadata:
                    print(f"❌ Missing required field: {field}")
                    return False
            
            print("✅ Discovery endpoint valid")
            return True
            
        except Exception as e:
            print(f"❌ Discovery endpoint failed: {e}")
            return False
    
    def verify_jwks(self) -> bool:
        """Verify JWKS endpoint"""
        try:
            # Get JWKS URI from discovery
            disc = requests.get(self.discovery_url).json()
            jwks_uri = disc.get("jwks_uri")
            
            resp = requests.get(jwks_uri, timeout=10)
            resp.raise_for_status()
            jwks = resp.json()
            
            if "keys" not in jwks or len(jwks["keys"]) == 0:
                print("❌ JWKS has no keys")
                return False
            
            print(f"✅ JWKS endpoint valid ({len(jwks['keys'])} keys)")
            return True
            
        except Exception as e:
            print(f"❌ JWKS endpoint failed: {e}")
            return False
    
    def verify_registration(self) -> bool:
        """Verify dynamic registration endpoint"""
        try:
            disc = requests.get(self.discovery_url).json()
            reg_endpoint = disc.get("registration_endpoint")
            
            # Test registration
            client_data = {
                "redirect_uris": ["https://example.com/callback"],
                "client_name": "Conformance Test Client",
                "grant_types": ["authorization_code"],
                "response_types": ["code"]
            }
            
            resp = requests.post(
                reg_endpoint,
                json=client_data,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            resp.raise_for_status()
            
            client = resp.json()
            if "client_id" not in client or "client_secret" not in client:
                print("❌ Registration response missing credentials")
                return False
            
            print(f"✅ Registration endpoint valid (client_id: {client['client_id'][:8]}...)")
            return True
            
        except Exception as e:
            print(f"❌ Registration endpoint failed: {e}")
            return False
    
    def run_validation(self) -> bool:
        """Run all validation checks"""
        print(f"\n🔍 Validating {self.ngrok_url}\n")
        
        checks = [
            ("Discovery Endpoint", self.verify_discovery),
            ("JWKS Endpoint", self.verify_jwks),
            ("Registration Endpoint", self.verify_registration),
        ]
        
        results = []
        for name, check in checks:
            print(f"\nTesting: {name}")
            result = check()
            results.append(result)
            time.sleep(1)
        
        print("\n" + "="*60)
        passed = sum(results)
        total = len(results)
        
        if passed == total:
            print(f"✅ All checks passed ({passed}/{total})")
            return True
        else:
            print(f"❌ Some checks failed ({passed}/{total})")
            return False

def main():
    if len(sys.argv) < 2:
        print("Usage: ./conformance_tester.py <ngrok-url>")
        sys.exit(1)
    
    ngrok_url = sys.argv[1].rstrip('/')
    tester = ConformanceTester(ngrok_url)
    
    success = tester.run_validation()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
```

## Known Limitations & Workarounds

### 1. OpenID4VP Wallet Requirement

**Issue**: The conformance suite expects a traditional OIDC flow, but our proxy requires wallet interaction.

**Workarounds**:
- Create a mock wallet client that automatically responds to presentation requests
- Use a test mode that bypasses wallet verification
- Implement a "conformance mode" configuration flag

### 2. Redirect URI Mismatch

**Issue**: Conformance suite may use dynamic redirect URIs.

**Solution**: Already handled by dynamic client registration ✅

### 3. HTTPS Requirement

**Issue**: Conformance suite requires HTTPS.

**Solution**: ngrok provides HTTPS automatically ✅

## Conformance Mode Implementation

Add a conformance testing mode to bypass wallet requirements:

```yaml
# config.conformance.yaml
verifier_proxy:
  testing:
    conformance_mode: true
    auto_approve_presentations: true
    mock_vp_response: |
      {
        "given_name": "John",
        "family_name": "Doe",
        "birthdate": "1990-01-01",
        "sub": "conformance-test-user"
      }
```

## Success Criteria

- ✅ Discovery endpoint passes all tests
- ✅ JWKS endpoint validates correctly
- ✅ Dynamic registration (RFC 7591/7592) passes
- ✅ Authorization code flow completes
- ✅ Token endpoint validates correctly
- ✅ UserInfo endpoint returns correct claims
- ✅ PKCE validation works
- ✅ Code replay protection verified

## Next Steps

1. **Implement the automation script**
   ```bash
   chmod +x scripts/run-oidc-conformance.sh
   ./scripts/run-oidc-conformance.sh
   ```

2. **Add conformance mode** to verifier-proxy

3. **Create mock wallet** for automated testing

4. **Document results** in certification report

5. **Apply for certification** (optional)

## References

- [OpenID Connect Certification](https://openid.net/certification/)
- [Conformance Suite Documentation](https://gitlab.com/openid/conformance-suite/-/wikis/home)
- [OP Testing Guide](https://openid.net/certification/op_testing/)
- [RFC 7591 - Dynamic Registration](https://tools.ietf.org/html/rfc7591)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
