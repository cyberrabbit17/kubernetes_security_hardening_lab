# Security Baseline

## Overview

This document defines the security baseline for the Kubernetes Security Hardening Lab. It describes the security posture of the cluster, the controls implemented at each layer, and the rationale for configuration decisions. It serves as the reference document for what "secure by default" means in this environment.

---

## Cluster Configuration

| Setting | Value | Rationale |
|---------|-------|-----------|
| Kubernetes version | v1.29.2 | Stable LTS release with known-good security defaults |
| CNI | Calico v3.28 | Enforces NetworkPolicy at kernel level via eBPF |
| Audit logging | Disabled (known issue) | Docker Desktop Apple Silicon incompatibility — see README |
| Default namespace PSS | Not enforced | Only named namespaces have PSS labels applied |
| RBAC | Enabled (default) | Node + RBAC authorization mode |

---

## Namespace Security Posture

| Namespace | PSS Enforce | PSS Warn | PSS Audit | Purpose |
|-----------|-------------|----------|-----------|---------|
| `dev` | — | restricted | restricted | Development workloads, warn-only to unblock developers |
| `staging` | baseline | restricted | restricted | Pre-production, enforces basic hygiene |
| `production` | restricted | restricted | restricted | Production workloads, full hardening enforced |
| `kube-system` | — | — | — | System components, not modified |
| `falco` | — | — | — | Security tooling, requires elevated privileges |

### Pod Security Standards Profile Definitions

**Privileged** — No restrictions. Used only for system namespaces.

**Baseline** — Prevents known privilege escalation vectors: no privileged containers, no host namespaces (hostNetwork, hostPID, hostIPC), no hostPath volumes, no dangerous capabilities. Allows running as root.

**Restricted** — Full hardening. Requires non-root user, drops all capabilities, enforces seccomp RuntimeDefault, blocks privilege escalation, requires read-only root filesystem with explicit volume mounts for writable paths.

---

## Pod Security Requirements (Production)

All pods deployed to the `production` namespace must comply with the following security context:

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001        # or any UID > 0
    runAsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: 100m
          memory: 128Mi
        limits:
          cpu: 500m
          memory: 256Mi
```

Non-compliant pods are rejected at admission by the Pod Security Admission controller. No exceptions are granted in the production namespace.

---

## Network Security Baseline

### Default Posture
All namespaces that contain workloads have a `default-deny-all` NetworkPolicy applied. This denies all ingress and egress traffic to all pods by default. Traffic must be explicitly allowed.

### Allowed Traffic (Production)

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| frontend | api | 8080 | TCP | Application tier communication |
| api | database | 8080 | TCP | Data tier communication |
| any | kube-dns | 53 | UDP/TCP | DNS resolution |

### Blocked Traffic (Production)

| Source | Destination | Reason |
|--------|-------------|--------|
| frontend | database | Lateral movement prevention |
| database | api | No upstream communication needed |
| database | frontend | No upstream communication needed |
| any | Kubernetes API (10.96.0.1:443) | SA tokens disabled, no API access needed |
| any | External internet | No egress rules defined |

---

## Resource Limits (Production)

### LimitRange — Per Container

| Resource | Min | Default Request | Default Limit | Max |
|----------|-----|----------------|---------------|-----|
| CPU | 50m | 100m | 500m | 2 cores |
| Memory | 64Mi | 128Mi | 256Mi | 2Gi |

Containers without explicit resource requests/limits will have the defaults applied automatically.

### ResourceQuota — Production Namespace

| Resource | Limit |
|----------|-------|
| Total pods | 20 |
| Total secrets | 50 |
| Total configmaps | 50 |
| CPU requests | 4 cores |
| CPU limits | 8 cores |
| Memory requests | 4Gi |
| Memory limits | 8Gi |

---

## RBAC Baseline

See [rbac-matrix.md](rbac-matrix.md) for the full permission matrix.

### Principles Applied

**Least privilege** — Every role grants the minimum permissions required. When in doubt, deny and add permissions incrementally.

**Explicit over implicit** — No role inherits from another role in this lab. All permissions are explicitly enumerated.

**No wildcard verbs in production scope** — The `namespace-admin` role uses `*` but is scoped to staging only. No role with wildcard permissions exists in production.

**Service account isolation** — `automountServiceAccountToken: false` is set on the default service account in all three namespaces. Pods that need API access must use a dedicated service account with explicit permissions.

---

## Image Security Baseline

| Requirement | Enforcement | Status |
|-------------|-------------|--------|
| No CRITICAL CVEs | Trivy CI scan, exit code 1 | ✅ Enforced |
| No HIGH CVEs | Trivy CI scan, exit code 1 | ✅ Enforced |
| Non-root base image | PSS restricted profile | ✅ Enforced |
| Minimal base image | Convention (nginx:alpine) | ⚠️ Convention only |
| Image signing | Not implemented | ❌ Not enforced |
| Private registry | Not implemented | ❌ Not enforced |

### Approved Base Images

| Image | Use Case | Last Scanned | HIGH | CRITICAL |
|-------|----------|-------------|------|----------|
| nginx:alpine | Web server / proxy | See trivy/ directory | TBD | TBD |

Update this table after each Trivy scan run.

---

## Runtime Security Baseline

Falco is deployed as a DaemonSet across all nodes. The following rule categories are active:

| Category | Rule | Severity | Response |
|----------|------|----------|----------|
| Execution | Shell spawned in container | WARNING | Alert |
| Credential access | Sensitive file read (/etc/passwd, /etc/shadow, SA token) | ERROR | Alert |
| Persistence | Package manager execution | ERROR | Alert |
| Discovery | K8s service account token read | WARNING | Alert |
| Default rules | Falco default ruleset | Various | Alert |

### Alert Response Policy

| Severity | Response Time | Action |
|----------|--------------|--------|
| CRITICAL | Immediate | Auto-isolate pod, page on-call |
| ERROR | 15 minutes | Page on-call security engineer |
| WARNING | 1 hour | Create ticket, review during business hours |
| NOTICE | Next business day | Review and triage |

Note: Automated response requires Falcosidekick integration, which is not implemented in this lab. Alerts are currently logged only.

---

## Security Control Coverage by Attack Phase

| Kill Chain Phase | Threat | Control | Coverage |
|-----------------|--------|---------|----------|
| Initial Access | Vulnerable image | Trivy CI scan | ✅ |
| Execution | Shell in container | Falco | ✅ |
| Persistence | Package install | Falco + readOnlyRootFilesystem | ✅ |
| Privilege Escalation | Root process | runAsNonRoot | ✅ |
| Privilege Escalation | Privileged container | PSS restricted | ✅ |
| Defense Evasion | Log tampering | Falco default rules | ⚠️ |
| Credential Access | SA token theft | automountServiceAccountToken | ✅ |
| Credential Access | Secret read via kubectl | RBAC | ✅ |
| Discovery | K8s API enumeration | RBAC + no SA token | ✅ |
| Lateral Movement | Pod-to-pod | NetworkPolicy | ✅ |
| Exfiltration | Data via network | NetworkPolicy egress | ⚠️ |
| Impact | Resource exhaustion | ResourceQuota + LimitRange | ✅ |

---

## Known Gaps and Accepted Risks

| Gap | Risk | Accepted Reason | Remediation Path |
|-----|------|-----------------|-----------------|
| No audit logging | Cannot forensically reconstruct API access | Docker Desktop / Apple Silicon incompatibility | Use Linux nodes or cloud provider |
| No image signing | Supply chain attack could bypass Trivy | Lab environment only | Implement Cosign in CI pipeline |
| No mTLS | In-cluster traffic unencrypted | Low risk in isolated lab | Deploy Istio or Linkerd |
| No external SIEM | Audit logs not immutable | Lab environment only | Stream to CloudWatch / Splunk |
| No OPA/Gatekeeper | Some policies enforced by convention only | PSS covers most cases | Add Gatekeeper for custom policies |
| Falco metadata gaps | Container enrichment limited on Docker Desktop | Known Apple Silicon limitation | Deploy on Linux nodes |