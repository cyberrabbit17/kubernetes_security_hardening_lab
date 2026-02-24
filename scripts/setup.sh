#!/bin/bash
set -e

if [ ! -f .env ]; then
  echo "Error: .env file not found. Copy .env.example and fill in your LAB_DIR."
  exit 1
fi

source .env

# Generate kind config from template
envsubst < cluster/kind-config.yaml.template > cluster/kind-config.yaml
echo "✓ Generated cluster/kind-config.yaml"

# Create directories
mkdir -p "$LAB_DIR/audit-logs"
mkdir -p "$LAB_DIR/audit-config"

# Delete existing cluster if present
if kind get clusters | grep -q security-lab; then
  echo "Deleting existing security-lab cluster..."
  kind delete cluster --name security-lab
fi

# Create cluster
echo "Creating cluster..."
kind create cluster --config cluster/kind-config.yaml --name security-lab

# Install Calico
echo "Installing Calico CNI..."
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml

echo "Waiting for Calico to be ready..."
kubectl rollout status daemonset/calico-node -n kube-system --timeout=120s

# Reapply phases
echo "Applying namespaces and PSS labels..."
kubectl create namespace dev
kubectl create namespace staging
kubectl create namespace production

kubectl label namespace dev \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

kubectl label namespace staging \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

echo "Applying RBAC..."
kubectl apply -f rbac/roles/
kubectl apply -f rbac/bindings/

kubectl patch serviceaccount default -n dev \
  -p '{"automountServiceAccountToken": false}'
kubectl patch serviceaccount default -n staging \
  -p '{"automountServiceAccountToken": false}'
kubectl patch serviceaccount default -n production \
  -p '{"automountServiceAccountToken": false}'

echo "Applying resource quotas and limit ranges..."
kubectl apply -f pod-security/compliant/resource-quota.yaml
kubectl apply -f pod-security/compliant/limit-range.yaml

echo ""
echo "✓ Cluster ready. All phases reapplied."
echo "  Run: kubectl get nodes && kubectl get pods -n kube-system"