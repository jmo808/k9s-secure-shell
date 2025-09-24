#!/bin/bash

# Build script for ephemeral K9s architecture

set -e

REGISTRY="harbor.bbmxclus1.blackbutterfly.mx"
SESSION_LAUNCHER_IMAGE="$REGISTRY/k9s/session-launcher:v1.1-latest"
EPHEMERAL_K9S_IMAGE="$REGISTRY/k9s/k9s-ephemeral:v0.50.12-latest"

echo "🏗️  Building ephemeral K9s architecture..."
echo ""

# Build session launcher
echo "📦 Building session launcher service..."
cd session-launcher
podman build -t "$SESSION_LAUNCHER_IMAGE" .
echo "✅ Session launcher built: $SESSION_LAUNCHER_IMAGE"
cd ..

echo ""

# Build ephemeral k9s container  
echo "📦 Building ephemeral K9s container..."
podman build -f Dockerfile.ephemeral -t "$EPHEMERAL_K9S_IMAGE" .
echo "✅ Ephemeral K9s built: $EPHEMERAL_K9S_IMAGE"

echo ""

# Push both images
echo "🚀 Pushing images to Harbor registry..."
echo "Pushing session launcher..."
podman push "$SESSION_LAUNCHER_IMAGE"
echo "✅ Session launcher pushed"

echo "Pushing ephemeral K9s..."
podman push "$EPHEMERAL_K9S_IMAGE"
echo "✅ Ephemeral K9s pushed"

echo ""
echo "🎉 Build complete!"
echo ""
echo "Images built and pushed:"
echo "  • Session Launcher: $SESSION_LAUNCHER_IMAGE"
echo "  • Ephemeral K9s:    $EPHEMERAL_K9S_IMAGE"
echo ""
echo "Next steps:"
echo "  1. Deploy the session launcher service"
echo "  2. Update OAuth2-proxy configuration"
echo "  3. Test ephemeral session creation"