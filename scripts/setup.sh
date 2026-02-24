#!/bin/bash
set -e

# ============================================================
# Kubernetes Security Hardening Lab - Cluster Setup Script
# ============================================================
# Usage: ./scripts/setup.sh
# Requires: kind, kubectl, helm, envsubst (brew install gettext)
# ============================================================

# --- Preflight checks ---

if [ ! -f .env ]; then
  echo "Error: .env file not found. Copy .env.example and fill in your LAB_DIR."
  exit 1
fi

source .env

if ! command -v kind &>/dev/null; then
  echo "Error: kind is not installed. https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
  exit 1
fi

if ! command -v kubectl &>/dev/null; then
  echo "Error: kubectl is not installed."
  exit 1
fi

if ! command -v envsubst &>/dev/null; then
  echo "Error: envsubst not found. Run: brew install gettext"
  exit 1
fi

if ! docker info &>/dev/null; then
  echo "Error: Docker is not running. Start Docker Desktop and retry."
  exit 1
fi

echo ""
echo "================================================"
echo " Kubernetes Security Hardening Lab - Setup"
echo "================================================"
echo ""

# --- Generate kind config ---

envsubst < cluster/kind-config.yaml.template > cluster/kind-config.yaml
echo "✓ Generated cluster/kind-config.yaml"

# --- Tear down existing cluster if present ---

if kind get clusters 2>/dev/null | grep -q security-lab; then
  echo "Deleting existing security-lab cluster..."
  kind delete cluster --name security-lab
fi

# --- Create cluster ---

echo ""
echo "[Phase 1] Creating cluster..."
kind create cluster --config cluster/kind-config.yaml --name security-lab
echo "✓ Cluster created"

# --- Wait for API server to be ready ---

echo "Waiting for API server to be ready..."
until kubectl cluster-info &>/dev/null; do
  echo "  API server not ready yet, retrying in 5s..."
  sleep 5
done
echo "✓ API server ready"

# --- Install Calico CNI ---

echo ""
echo "[CNI] Installing Calico..."
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml

echo "Waiting for Calico daemonset to roll out..."
kubectl rollout status daemonset/calico-node -n kube-system --timeout=180s
echo "✓ Calico ready"

# --- Wait for all nodes to be Ready ---

echo "Waiting for all nodes to be Ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s
echo "✓ All nodes Ready"

# --- Phase 2: Namespaces + PSS labels ---

echo ""
echo "[Phase 2] Creating namespaces and applying Pod Security Standards..."
kubectl create namespace dev     2>/dev/null || echo "  namespace dev already exists"
kubectl create namespace staging 2>/dev/null || echo "  namespace staging already exists"
kubectl create namespace production 2>/dev/null || echo "  namespace production already exists"

kubectl label namespace dev \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted \
  --overwrite

kubectl label namespace staging \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted \
  --overwrite

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted \
  --overwrite

echo "✓ Namespaces and PSS labels applied"

# --- Phase 2: RBAC ---

echo ""
echo "[Phase 2] Applying RBAC..."
kubectl apply -f rbac/roles/
kubectl apply -f rbac/bindings/

kubectl patch serviceaccount default -n dev \
  -p '{"automountServiceAccountToken": false}'
kubectl patch serviceaccount default -n staging \
  -p '{"automountServiceAccountToken": false}'
kubectl patch serviceaccount default -n production \
  -p '{"automountServiceAccountToken": false}'

echo "✓ RBAC applied, service account automount disabled"

# --- Phase 3: Resource controls ---

echo ""
echo "[Phase 3] Applying ResourceQuotas and LimitRanges..."
kubectl apply -f pod-security/compliant/resource-quota.yaml
kubectl apply -f pod-security/compliant/limit-range.yaml
echo "✓ Resource controls applied"

# --- Phase 4: Network Policies ---

echo ""
echo "[Phase 4] Deploying sample app and applying Network Policies..."
kubectl apply -f network-policies/app.yaml

echo "Waiting for app pods to be ready..."
kubectl wait --for=condition=Ready pods \
  -l 'app in (frontend,api,database)' \
  -n production --timeout=120s

kubectl apply -f network-policies/default-deny.yaml
kubectl apply -f network-policies/allow-rules/
echo "✓ Network Policies applied"

# --- Done ---

echo ""
echo "================================================"
echo " Setup complete!"
echo "================================================"
echo ""
echo "Cluster status:"
kubectl get nodes
echo ""
echo "System pods:"
kubectl get pods -n kube-system
echo ""
echo "Next steps:"
echo "  - Verify network policies: kubectl get networkpolicies -n production"
echo "  - Run attack simulations:  ./scripts/attack-simulation.sh"
echo "  - View audit logs:         kubectl logs -n falco -l app=falco -f"