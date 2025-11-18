# OpenID Connect Conformance Testing - Quick Start

## TL;DR

```bash
# One command to rule them all
./scripts/run-oidc-conformance.sh
```

Then follow the on-screen instructions to run tests at <https://www.certification.openid.net/>

## What This Does

Automated setup for testing the verifier-proxy **OIDC Provider** implementation against the official OpenID Connect Conformance Suite.

**Scope:** This tests the verifier-proxy's OIDC Provider capabilities (issuing ID tokens to relying parties). It does NOT test:
- Verifiable credential issuance (separate VC Issuer service)
- OpenID4VP presentation verification (covered by integration tests)

**Architecture:**

```text
Local Machine                           Internet
┌─────────────────────┐                 ┌──────────────────────┐
│ verifier-proxy:8080 │──── ngrok ─────>│ OpenID Connect       │
│ MongoDB:27017       │     HTTPS       │ Conformance Suite    │
└─────────────────────┘                 └──────────────────────┘
```

## Output Example

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OpenID Connect Conformance Suite Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Issuer URL:           https://abc123.ngrok.io
Discovery Endpoint:   https://abc123.ngrok.io/.well-known/openid-configuration
Registration Endpoint: https://abc123.ngrok.io/register

Test Plan Setup:
1. Go to: https://www.certification.openid.net/
2. Create new test plan: 'oidcc-basic-certification-test-plan'
3. Configuration:
   - Server metadata location: https://abc123.ngrok.io/.well-known/openid-configuration
   - Client registration: DYNAMIC (automatic)
```

## Prerequisites

```bash
# Install ngrok (Ubuntu/Debian)
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | \
  sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | \
  sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install ngrok

# Authenticate (free account)
ngrok config add-authtoken YOUR_TOKEN

# Install jq
sudo apt-get install jq
```

## Files Created

- `scripts/run-oidc-conformance.sh` - Automated setup script
- `scripts/conformance_validator.py` - Endpoint validation tool
- `scripts/README-conformance.md` - Detailed documentation
- `docs/verifier-proxy/OIDC_CONFORMANCE_TESTING.md` - Full strategy guide

## Test Coverage

### ✅ Automated Tests

- Discovery endpoint
- JWKS endpoint
- Dynamic client registration (RFC 7591)
- Client CRUD operations (RFC 7592)
- Metadata compliance

### 🔄 Manual Tests (Conformance Suite)

- Authorization Code Flow
- Token Exchange
- UserInfo endpoint
- PKCE validation
- Code replay prevention

## Troubleshooting

**ngrok not accessible:**

```bash
curl http://localhost:4040/api/tunnels | jq .
```

**verifier-proxy not starting:**

```bash
tail -f verifier-proxy.log
```

**MongoDB not initialized:**

```bash
docker-compose up mongo-init-verifier-proxy
```

## Next Steps

1. Run the automated script
2. Copy the ngrok URL from output
3. Go to OpenID Connect Conformance Suite
4. Create test plan with your ngrok URL
5. Run tests
6. Review results

## Documentation

- Full guide: `docs/verifier-proxy/OIDC_CONFORMANCE_TESTING.md`
- Scripts README: `scripts/README-conformance.md`
- Dynamic registration: `docs/verifier-proxy/dynamic-client-registration.md`

## Support

Questions? See the full documentation in `docs/verifier-proxy/OIDC_CONFORMANCE_TESTING.md`
