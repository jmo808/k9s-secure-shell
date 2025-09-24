# K9s Remote Admin (Ephemeral Cloud Shell)

Ephemeral, browser-based administrative shell that launches isolated [k9s](https://k9scli.io) sessions on demand. Each request creates a short-lived pod with `k9s`, `kubectl`, and `kubelogin` preinstalled, authenticates the operator through Entra ID, and destroys the workload when the browser disconnects.

---

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Build the container images](#build-the-container-images)
- [Configuration](#configuration)
  - [OIDC-enabled kubeconfig](#oidc-enabled-kubeconfig)
  - [OAuth2-Proxy & branding](#oauth2-proxy--branding)
  - [Gateway & networking](#gateway--networking)
  - [Container registry credentials](#container-registry-credentials)
- [Deploy to the cluster](#deploy-to-the-cluster)
- [Access & session workflow](#access--session-workflow)
- [Session lifecycle & cleanup](#session-lifecycle--cleanup)
- [Operations & maintenance](#operations--maintenance)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)

## Key Features

- **True ephemerality** – Pods terminate when the ttyd connection closes or after a configurable timeout.
- **OIDC device-code flow** – Operators authenticate with Entra ID using `kubelogin`'s device flow.
- **Role-based controls** – Minimal RBAC permissions scoped to the `admin-web` namespace.
- **Isolated surface area** – No shared history; `start-ephemeral-k9s.sh` scrubs kubeconfig and token caches per session.
- **Zero-trust ingress** – OAuth2-Proxy front-ends all traffic; HTTPRoute terminates TLS at the Cilium Gateway.
- **Simple operator experience** – Single "Launch session" button and direct ttyd terminal for k9s/kubectl.

## Architecture

```
Browser ──► OAuth2-Proxy ──► Session Launcher (Go API)
                               │
                               └──► Creates Job → Pod running ttyd+k9s
                                            │
                                            └──► ttyd WebSocket proxied back through OAuth2-Proxy
```

| Component | Location | Purpose |
|-----------|----------|---------|
| `session-launcher` | `session-launcher/main.go` | REST API that creates Kubernetes Jobs and proxies ttyd traffic. |
| Ephemeral terminal image | `Dockerfile.ephemeral` | Container with `k9s`, `kubectl`, `kubelogin`, and hardening defaults. |
| OAuth2-Proxy | `k8s-ephemeral/02-oauth-*.yaml` | Handles Entra ID login, header propagation, and custom theming. |
| Gateway route & network policy | `k8s-ephemeral/03-gateway-route.yaml` | Exposes `admin.blackbutterfly.mx` and restricts ingress/egress. |
| Support scripts | `build-ephemeral.sh`, `deploy-ephemeral.sh`, `start-ephemeral-k9s.sh` | Build/push images, apply manifests, and run in-container session bootstrap. |
| k9s defaults | `k9s-config.yaml` | Opinionated UI and performance tuning shipped with every session. |

## Prerequisites

- Access to the target Kubernetes cluster with `kubectl` permissions to the `admin-web` namespace.
- Container runtime capable of building and pushing images (tested with Podman; Docker works with flag changes).
- Credentials to push to `harbor.bbmxclus1.blackbutterfly.mx` or your own registry.
- Entra ID tenant with a registered OAuth2 application for both OAuth2-Proxy and kubelogin device-code flow.
- DNS entry pointing `admin.blackbutterfly.mx` (or your custom hostname) to the cluster ingress.

## Build the container images

Run from `bbmx-infra/infrastructure/k9s-remote-admin`.

```bash
# Update REGISTRY/IMAGE tags in build-ephemeral.sh if needed
./build-ephemeral.sh
```

The script builds and pushes two images:

- `k9s/session-launcher` – HTTP control plane that creates session Jobs.
- `k9s/k9s-ephemeral` – ttyd-based shell that runs k9s.

> **Tip:** Replace the default tag suffixes (e.g., `v1.1-latest`) with immutable versions before promoting to production.

## Configuration

### OIDC-enabled kubeconfig

`k8s-ephemeral/01-session-launcher.yaml` wraps an Entra ID device-code flow kubeconfig inside the `k9s-kubeconfig` ConfigMap. Update:

- `clusters[0].cluster.server` – API server URL.
- `--oidc-issuer-url` – Your tenant ID.
- `--oidc-client-id` – Application ID registered for kubelogin.
- Additional `--oidc-extra-scope` values if required.

The kubeconfig is mounted read-only at `/root/.kube/config` in each ephemeral pod.

### OAuth2-Proxy & branding

Edit `k8s-ephemeral/02-oauth-config.yaml` (or `02-oauth-proxy.yaml` if using the slim manifests):

- Regenerate `cookie-secret` (32 hex chars) and rotate `client-secret` regularly.
- Update `client-id`/`client-secret` with your Web Proxy app registration.
- Replace static assets in `k8s-ephemeral/bbmxlogo.png` or `custom-sign-in.html` to customize the login page.
- Adjust `skip_auth_regex` if you expose additional internal endpoints.

### Gateway & networking

`k8s-ephemeral/03-gateway-route.yaml` binds the route to `public-gateway/https`. Confirm:

- Your Gateway name/namespace matches the cluster (Cilium example provided).
- NetworkPolicy selectors align with your namespaces and labels.
- Hostname matches the DNS entry you control.

### Container registry credentials

Ensure the cluster can pull images from the Harbor registry. If you use a different registry:

1. Update the `REGISTRY` variable and tags in `build-ephemeral.sh` and manifests.
2. Create/push the images to the new registry.
3. Create image pull secrets in `admin-web` (not included by default) and reference them in the Deployment/Jobs if required.

## Deploy to the cluster

1. Review the pre-flight checklist echoed by `./deploy-ephemeral.sh`.
2. Confirm secrets, image tags, and hostnames are correct.
3. Apply all manifests:

```bash
./deploy-ephemeral.sh
```

The script prompts for confirmation and then applies everything under `k8s-ephemeral/`.

### Manual apply (optional)

To tailor the rollout, you can apply individual manifests in order:

```bash
kubectl apply -f k8s-ephemeral/01-session-launcher.yaml
kubectl apply -f k8s-ephemeral/02-oauth-config.yaml
kubectl apply -f k8s-ephemeral/03-gateway-route.yaml
kubectl apply -f k8s-ephemeral/04-oauth2-proxy-deployment.yaml
```

## Access & session workflow

1. Operators navigate to `https://admin.blackbutterfly.mx/` and authenticate via Entra ID.
2. The web UI calls `POST /session` on the Session Launcher, creating a Job that starts the ttyd+ k9s pod.
3. Once the pod reports Ready, the UI redirects the browser to `/terminal/<session-id>`.
4. The ttyd terminal launches `k9s`; on first use, the bundled `start-ephemeral-k9s.sh` instructs the user to visit `https://login.microsoftonline.com/device` and enter the displayed device code.
5. When the user exits or disconnects, the pod self-terminates and the Job is cleaned up automatically.

### Default commands available in the shell

- `k9s` – Full-screen cluster explorer.
- `kubectl` / aliases (`k`, `kgn`, `kwho`).
- `session-info` – Display session metadata.

## Session lifecycle & cleanup

| Control | Source | Default | Notes |
|---------|--------|---------|-------|
| `SESSION_TIMEOUT` env | Job spec | `3600` seconds | Max interactive time before forced cleanup. |
| Job TTL | `session-launcher/main.go` | 10 minutes post-completion | Removes completed Jobs. |
| Monitor watchdog | `start-ephemeral-k9s.sh` | 2-second poll | Terminates pod if ttyd exits. |
| Cache cleanup | `start-ephemeral-k9s.sh` | N/A | Wipes kubelogin, kube caches, and shell history. |

Modify `ACTIVE_TTL_SECONDS` or `SESSION_TIMEOUT` in the Go code/start script to change durations.

## Operations & maintenance

- **Update binaries:** Bump `K9S_VERSION`, `kubectl` URL, and `KUBELOGIN_VERSION` in `Dockerfile.ephemeral`. Rebuild/push images afterward.
- **Rotate secrets:** Recreate the `oauth2-proxy-creds` Secret any time credentials change. Re-apply manifests; Deployment will roll pods.
- **Logging:**
  - Session launcher: `kubectl logs deployment/session-launcher -n admin-web`.
  - OAuth2-Proxy: `kubectl logs deployment/oauth2-proxy -n admin-web`.
  - Individual sessions: `kubectl logs job/<session-job> -n admin-web` (while pod exists).
- **RBAC:** Adjust `k8s-ephemeral/01-session-launcher.yaml` Role if the launcher needs to create resources in additional namespaces.
- **Branding:** Update assets under `k8s-ephemeral/` and re-apply to refresh templates/images.

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|--------------|------------|
| Login loop / `403 Forbidden` | OAuth2-Proxy client secret incorrect or redirect URL mismatch | Verify `oauth2-proxy-creds` secret and Entra ID app registration redirect URIs. |
| Session stuck in `pending` with `ErrImagePull` | Images not pushed or registry auth missing | Re-run `./build-ephemeral.sh` and confirm pull secrets in `admin-web`. |
| Browser disconnects immediately | WebSocket blocked | Ensure Gateway/ingress allows WebSocket upgrades and `skip_auth_regex` covers `/ttyd/`. |
| `kubelogin` never completes | Device code disabled or scopes missing | Check Entra ID app permissions and `--oidc-extra-scope` values in kubeconfig. |
| Jobs piling up | TTL too high or cleanup failing | Inspect `session-launcher` logs and adjust `TTL_SECONDS`/`ACTIVE_TTL_SECONDS`. |

## Repository layout

```
k9s-remote-admin/
├── build-ephemeral.sh          # Build & push both container images
├── deploy-ephemeral.sh         # Confirmation gate + kubectl apply
├── Dockerfile.ephemeral        # Ephemeral ttyd+k9s image
├── k9s-config.yaml             # Default k9s configuration
├── start-ephemeral-k9s.sh      # Session bootstrap & cleanup script
├── k8s-ephemeral/              # Kubernetes manifests (namespace, RBAC, gateway, OAuth2)
└── session-launcher/           # Go HTTP service & Dockerfile
```

---

**Change management:** Always update the manifests under `k8s-ephemeral/` rather than patching live resources. Re-apply the manifests so the desired state is tracked in version control.
