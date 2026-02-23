# Kubernetes Security Hardening Lab

A hands-on security lab demonstrating defense-in-depth across a multi-node Kubernetes cluster. This project implements and validates security controls across the build, deploy, and runtime phases — covering RBAC, Pod Security Standards, Network Policies, runtime threat detection, and vulnerability scanning.

Built to demonstrate practical Kubernetes security knowledge relevant to DevSecOps and platform engineering roles.

---

## Threat Model Summary

This lab defends against the following attack categories:

| Threat | Attack Scenario | Control | Phase |
|--------|----------------|---------|-------|
| Privilege Escalation | Pod runs as root, escapes to host | Pod Security Standards (restricted) | Phase 3 |
| Lateral Movement | Compromised pod reaches database directly | Network Policies (zero-trust) | Phase 4 |
| Credential Theft | Pod reads its own service account token | RBAC + automount disabled | Phase 2 |
| Malicious Process | Attacker spawns shell inside container | Falco runtime rules | Phase 5 |
| Vulnerable Images | Known CVEs in base image reach production | Trivy + CI/CD gate | Phase 6 |
| Audit Gap | No record of who accessed secrets | API server audit logging | Phase 1 |
| Spoofing | Stolen service account token reused | Token rotation + short TTL | Phase 2 |
| Denial of Service | Pod consumes all node resources | LimitRanges + ResourceQuotas | Phase 3 |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   kind cluster                       │
│                                                      │
│  ┌──────────────────────┐                           │
│  │   control-plane node  │                           │
│  │  - kube-apiserver     │ ← audit logging enabled  │
│  │  - etcd               │                           │
│  │  - scheduler          │                           │
│  │  - controller-manager │                           │
│  └──────────────────────┘                           │
│                                                      │
│  ┌─────────────┐   ┌─────────────┐                 │
│  │ worker node │   │ worker node │                  │
│  │             │   │             │                  │
│  │  dev pods   │   │ staging /   │                  │
│  │             │   │ prod pods   │                  │
│  └─────────────┘   └─────────────┘                 │
│                                                      │
│  Namespaces: dev | staging | production             │
└─────────────────────────────────────────────────────┘
```

**Kubernetes version:** v1.33.1
**kind version:** v0.29.0
**Platform:** Apple Silicon (darwin/arm64) + Docker Desktop

---

## Project Structure

```
k8s-security-lab/
├── README.md
├── cluster/
│   ├── kind-config.yaml          # Cluster definition with audit logging
│   └── audit-config/
│       └── audit-policy.yaml     # API server audit policy
├── rbac/
│   ├── roles/
│   │   ├── auditor.yaml
│   │   ├── developer.yaml
│   │   └── namespace-admin.yaml
│   └── bindings/
│       ├── auditor-binding.yaml
│       └── developer-binding.yaml
├── pod-security/
│   ├── compliant/
│   └── non-compliant/
├── network-policies/
│   ├── default-deny.yaml
│   └── allow-rules/
├── falco/
│   ├── custom-rules.yaml
│   └── alert-screenshots/
├── trivy/
│   └── ci-workflow.yaml
├── docs/
│   ├── rbac-matrix.md
│   ├── security-baseline.md
│   ├── threat-model.md
│   └── attack-scenarios.md
├── scripts/
│   ├── setup.sh
│   └── attack-simulation.sh
└── audit-logs/                   # gitignored - generated at runtime
```

---

## Prerequisites

- Docker Desktop (4GB+ RAM, 2+ CPUs allocated)
- [kind v0.20.0+](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Helm 3](https://helm.sh/docs/intro/install/)
- [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/k8s-security-lab
cd k8s-security-lab

# Create audit config directories
mkdir -p audit-logs

# Create the cluster (see note below on Apple Silicon)
kind create cluster --config cluster/kind-config.yaml --name security-lab

# Verify cluster is healthy
kubectl get nodes
kubectl get pods -n kube-system

# Verify audit logging is working
kubectl get secrets -n kube-system
cat audit-logs/audit.log | tail -5
```

---

## ⚠️ Apple Silicon + Docker Desktop Setup Note

This lab was developed on Apple Silicon (M-series Mac) with Docker Desktop and kind v0.29 / Kubernetes v1.33. Getting audit logging working required a non-obvious two-layer mount approach that is **not documented in the official kind docs**.

**The problem:** Audit logging requires the API server pod to read a policy file and write logs. The API server runs as a static pod inside the kind node container. You need to get files from your Mac → into the kind node → into the API server pod. These are two separate mount operations that must both be configured.

**The solution:** Use `extraMounts` (kind-level) AND `extraVolumes` in `kubeadmConfigPatches` (kubeadm-level) together:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    # extraMounts: Mac filesystem → kind node container
    extraMounts:
      - hostPath: /absolute/path/to/audit-config/audit-policy.yaml
        containerPath: /etc/kubernetes/audit-policy.yaml
        readOnly: true
      - hostPath: /absolute/path/to/audit-logs
        containerPath: /var/log/kubernetes
        readOnly: false
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-log-path: /var/log/kubernetes/audit.log
            audit-log-maxage: "30"
            audit-policy-file: /etc/kubernetes/audit-policy.yaml
          # extraVolumes: kind node → API server pod container
          extraVolumes:
            - name: audit-policy
              hostPath: /etc/kubernetes/audit-policy.yaml
              mountPath: /etc/kubernetes/audit-policy.yaml
              readOnly: true
              pathType: File
            - name: audit-logs
              hostPath: /var/log/kubernetes
              mountPath: /var/log/kubernetes
              readOnly: false
              pathType: DirectoryOrCreate
```

**Why this matters architecturally:** kind nodes are Docker containers. The API server is a static pod running inside those containers. Mounts work at each layer independently:
- `extraMounts` operates at the Docker layer (host → container)
- `extraVolumes` operates at the Kubernetes layer (node → pod)

Skipping either layer causes the API server to crash on startup with a generic `context deadline exceeded` error that doesn't mention the missing file.

**Other gotchas encountered:**
- The audit policy file must be a **file**, not a directory. Running `mkdir -p path/audit-policy.yaml` will create a directory at that path, causing a `hostPath type check failed: is not a file` error.
- Docker Desktop on Mac does **not** allow bind mounts from `/etc/kubernetes` by default. Use paths inside your home directory instead.
- `pathType: File` and `pathType: DirectoryOrCreate` are required on kind v0.29+ with Apple Silicon — omitting them causes silent failures.

---

## Security Controls Implemented

### Phase 1 — Cluster Setup + Audit Logging
API server audit logging captures all access to secrets at `RequestResponse` level (full request and response body) and all pod/configmap/serviceaccount access at `Metadata` level. This creates a forensic trail for incident response.

### Phase 2 — RBAC
Three roles implement least-privilege access across namespaces. Developers have no access to secrets by design. The default service account has automounting disabled in all namespaces.

See [docs/rbac-matrix.md](docs/rbac-matrix.md) for the full permission matrix.

### Phase 3 — Pod Security Standards
The `production` namespace enforces the `restricted` PSS profile. Non-compliant pod examples and their rejection reasons are documented in `pod-security/non-compliant/`.

### Phase 4 — Network Policies
Default-deny-all policies are applied to all namespaces. Traffic is selectively re-allowed based on pod labels. A 3-tier app (frontend → API → database) demonstrates the zero-trust model with verified lateral movement blocking.

### Phase 5 — Falco Runtime Security
Custom Falco rules detect shell spawning in containers, writes to sensitive directories, and suspicious outbound connections. Three attack simulations with captured alerts are in `falco/alert-screenshots/`.

### Phase 6 — Trivy Vulnerability Scanning
Trivy is integrated into a GitHub Actions pipeline that blocks deployments containing HIGH or CRITICAL CVEs. Results are uploaded to the GitHub Security tab as SARIF.

---

## Running the Attack Simulations

```bash
# Make the script executable
chmod +x scripts/attack-simulation.sh

# Run all scenarios (requires a running cluster with Falco installed)
./scripts/attack-simulation.sh

# Or run individual scenarios:

# Scenario 1: Privileged container attempting host filesystem access
kubectl run attacker --image=ubuntu --privileged -- sleep 3600
kubectl exec -it attacker -- ls /proc/1/root

# Scenario 2: Shell spawned inside running container (triggers Falco)
kubectl exec -it <any-pod> -- /bin/bash

# Scenario 3: Service account token theft
kubectl exec -it <any-pod> -- cat /run/secrets/kubernetes.io/serviceaccount/token
```

Watch Falco alerts in real time:
```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

---

## Teardown

```bash
kind delete cluster --name security-lab
```

---

## References

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Falco Rules Reference](https://falco.org/docs/rules/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [kind Configuration Reference](https://kind.sigs.k8s.io/docs/user/configuration/)
