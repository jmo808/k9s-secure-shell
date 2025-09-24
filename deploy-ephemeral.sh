#!/bin/bash

echo "Starting ephemeral session launcher deployment..."

echo "--- CRITICAL PRE-FLIGHT CHECKS ---"
echo "1. Docker images built/pushed with ./build-ephemeral.sh"
echo "   - Session launcher: harbor.bbmxclus1.blackbutterfly.mx/k9s/session-launcher:v1.1-latest"
echo "   - Ephemeral K9s: harbor.bbmxclus1.blackbutterfly.mx/k9s/k9s-ephemeral:v0.50.12-latest"
echo "2. Image names updated in k8s-ephemeral/ manifests"
echo "3. OAuth2-Proxy configuration includes skip_auth_regex for /ttyd/.*"
echo "4. Gateway routes configured for admin.blackbutterfly.mx"
echo "5. RBAC permissions configured for session creation"
echo "----------------------------------"
read -p "Are these steps complete and ready to apply? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Deployment aborted."
    exit 1
fi

# Apply the ephemeral manifests
echo "Applying admin-web namespace and resources..."
kubectl apply -f k8s-ephemeral/

echo "Ephemeral deployment applied."

# Show deployment status
echo ""
echo "Checking deployment status..."
kubectl get pods -n admin-web
kubectl get services -n admin-web
kubectl get httproutes -n admin-web

echo ""
echo "🎉 Ephemeral session launcher deployed!"
echo "Access at: https://admin.blackbutterfly.mx/"