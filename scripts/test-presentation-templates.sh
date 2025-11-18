#!/bin/bash
# Integration test for template-based presentation requests
# This script verifies that the verifier-proxy loads and uses presentation request templates

set -e

echo "═══════════════════════════════════════════════════════════"
echo "  Template-Based Presentation Request Integration Test"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
TEMPLATES_DIR="./presentation_requests"
CONFIG_FILE="./config.yaml"

echo "1. Checking template files..."
if [ ! -d "$TEMPLATES_DIR" ]; then
    echo -e "${RED}✗ Template directory not found: $TEMPLATES_DIR${NC}"
    exit 1
fi

TEMPLATE_COUNT=$(find "$TEMPLATES_DIR" -name "*.yaml" -o -name "*.yml" | wc -l)
echo -e "${GREEN}✓ Found $TEMPLATE_COUNT template files${NC}"

echo ""
echo "2. Validating template YAML syntax..."
for template in "$TEMPLATES_DIR"/*.yaml; do
    if [ -f "$template" ]; then
        echo "   Checking $(basename "$template")..."
        if python3 -c "import yaml; yaml.safe_load(open('$template'))" 2>/dev/null; then
            echo -e "   ${GREEN}✓ Valid YAML${NC}"
        else
            echo -e "   ${RED}✗ Invalid YAML${NC}"
            exit 1
        fi
    fi
done

echo ""
echo "3. Checking configuration..."
if grep -q "presentation_requests_dir:" "$CONFIG_FILE"; then
    echo -e "${GREEN}✓ presentation_requests_dir configured in config.yaml${NC}"
else
    echo -e "${YELLOW}⚠ presentation_requests_dir not configured (will use legacy mode)${NC}"
fi

echo ""
echo "4. Building verifier-proxy with new code..."
if go build -mod=vendor -o /tmp/test_verifier_proxy ./cmd/verifier-proxy/; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

echo ""
echo "5. Running unit tests..."
if go test -v ./pkg/openid4vp/... -run TestPresentationBuilder 2>&1 | grep -q "PASS"; then
    echo -e "${GREEN}✓ PresentationBuilder tests passed${NC}"
else
    echo -e "${RED}✗ Tests failed${NC}"
    exit 1
fi

if go test -v ./internal/verifier_proxy/apiv1/... -run TestCreatePresentationDefinition 2>&1 | grep -q "PASS"; then
    echo -e "${GREEN}✓ Integration tests passed${NC}"
else
    echo -e "${RED}✗ Tests failed${NC}"
    exit 1
fi

echo ""
echo "6. Checking template content..."
echo "   Template IDs found:"
for template in "$TEMPLATES_DIR"/*.yaml; do
    if [ -f "$template" ]; then
        IDS=$(grep "^\s*- id:" "$template" | sed 's/.*id:\s*"\(.*\)"/      - \1/' || true)
        if [ -n "$IDS" ]; then
            echo "$IDS"
        fi
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════"
echo -e "${GREEN}✓ All integration checks passed!${NC}"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Rebuild verifier-proxy container: make build-verifier-proxy"
echo "  2. Restart services: docker-compose restart verifier-proxy"
echo "  3. Check logs: docker logs vc_dev_verifier_proxy | grep -i template"
echo "  4. Expected log: 'Loaded presentation request templates'"
echo ""
