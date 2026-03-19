# Threat Model

## Methodology

This threat model uses the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) applied to a Kubernetes workload running a 3-tier application (frontend, API, database) in a production namespace.

The attacker model assumes an external attacker who has achieved initial access to a running container — either through a vulnerability in the application code, a compromised base image, or a supply chain attack. The threat model does not cover physical access to nodes or compromise of the cloud provider control plane.

## System Overview

```
Internet
    │
    ▼
[ frontend pod ]  ──────────────────────────────────────────────────────────────────
    │                                                                               │
    │ allowed                                                                  blocked
    ▼                                                                               │
[ api pod ]  ──────────────────────────────────────────────────────────────────────
    │                                                                               │
    │ allowed                                                                  blocked
    ▼                                                                               │
[ database pod ] ◄──────────────────────────────────────────────────────────────────
         │
         │ Kubernetes API (blocked - no SA token)
         ▼
    [ K8s API Server ]
```

## STRIDE Threat Analysis

### S — Spoofing

| Threat | Description | Likelihood | Impact | Control | Status |
|--------|-------------|------------|--------|---------|--------|
| Service account token reuse | Attacker steals a pod's SA token and uses it to impersonate the pod against the K8s API | Medium | High | `automountServiceAccountToken: false` on all default SAs | ✅ Mitigated |
| Certificate theft | Attacker steals a developer's client certificate to impersonate them | Low | High | Certificates stored locally, 365-day expiry, replaced by OIDC in production | ⚠️ Partially mitigated |
| Pod identity spoofing | Malicious pod claims to be a trusted service | Low | Medium | NetworkPolicy uses pod label selectors, not IP addresses | ✅ Mitigated |

### T — Tampering

| Threat | Description | Likelihood | Impact | Control | Status |
|--------|-------------|------------|--------|---------|--------|
| Container filesystem modification | Attacker modifies files inside a running container to persist access | Medium | High | `readOnlyRootFilesystem: true` on all production pods | ✅ Mitigated |
| ConfigMap modification | Attacker with dev access modifies a ConfigMap to inject malicious config | Medium | Medium | Developer role cannot modify ConfigMaps in production, only dev namespace | ✅ Mitigated |
| Image tampering | Attacker pushes a backdoored image to the registry | Low | Critical | Trivy CI scan blocks images with HIGH/CRITICAL CVEs before deployment | ✅ Mitigated |
| ETCD tampering | Direct modification of cluster state via etcd | Very Low | Critical | etcd access limited to API server, not exposed outside cluster | ✅ Mitigated |

### R — Repudiation

| Threat | Description | Likelihood | Impact | Control | Status |
|--------|-------------|------------|--------|---------|--------|
| Denied secret access | User claims they did not read a secret | Medium | Medium | API server audit logging captures all secret access at RequestResponse level | ✅ Mitigated |
| Denied privilege escalation attempt | Attacker denies attempting to escalate privileges | Low | Medium | Falco captures shell spawning, sensitive file reads, and SA token access | ✅ Mitigated |
| Audit log tampering | Attacker deletes or modifies audit logs to cover tracks | Low | High | Audit logs written to host path outside container, Falco detects log file tampering | ⚠️ Partially mitigated |

### I — Information Disclosure

| Threat | Description | Likelihood | Impact | Control | Status |
|--------|-------------|------------|--------|---------|--------|
| Secret exfiltration via kubectl | Developer reads secrets directly from the K8s API | Medium | High | Secrets explicitly excluded from developer and auditor roles | ✅ Mitigated |
| Service account token harvest | Process inside container reads its own SA token | Medium | High | automountServiceAccountToken disabled, Falco rule detects reads | ✅ Mitigated |
| Lateral data access | Compromised frontend pod reads data from database directly | High | Critical | NetworkPolicy blocks frontend→database traffic | ✅ Mitigated |
| Node filesystem access | Container mounts host filesystem to read node secrets | Medium | Critical | PSS restricted profile blocks hostPath volumes | ✅ Mitigated |
| Environment variable leakage | Secrets passed as env vars are readable via /proc | Low | Medium | Secrets should be mounted as volumes, not env vars (not enforced in this lab) | ❌ Not mitigated |

### D — Denial of Service

| Threat | Description | Likelihood | Impact | Control | Status |
|--------|-------------|------------|--------|---------|--------|
| Resource exhaustion | Runaway pod consumes all CPU/memory on a node | Medium | High | LimitRange enforces max CPU 2 cores, max memory 2Gi per container | ✅ Mitigated |
| Pod proliferation | Attacker creates thousands of pods to exhaust cluster capacity | Low | High | ResourceQuota limits production namespace to 20 pods | ✅ Mitigated |
| Secret/ConfigMap exhaustion | Attacker floods namespace with secrets to exhaust quota | Low | Medium | ResourceQuota limits secrets to 50, ConfigMaps to 50 | ✅ Mitigated |
| Network flooding | Compromised pod floods other pods with traffic | Low | Medium | Network policies limit which pods can communicate | ⚠️ Partially mitigated |

### E — Elevation of Privilege

| Threat | Description | Likelihood | Impact | Control | Status |
|--------|-------------|------------|--------|---------|--------|
| Container breakout via privileged pod | Attacker runs privileged container to escape to host | High | Critical | PSS restricted profile blocks `privileged: true` | ✅ Mitigated |
| Root process exploitation | Process running as root inside container exploits kernel vulnerability | Medium | Critical | `runAsNonRoot: true` enforced, containers run as UID 10001 | ✅ Mitigated |
| Capability abuse | Process uses Linux capabilities (e.g. CAP_NET_ADMIN) to escalate | Medium | High | All capabilities dropped (`capabilities.drop: ALL`) | ✅ Mitigated |
| Privilege escalation via setuid | Process uses setuid binary to gain root | Medium | High | `allowPrivilegeEscalation: false` on all containers | ✅ Mitigated |
| RBAC escalation | Developer creates a RoleBinding to grant themselves more permissions | Low | High | Developer role does not include permissions to create RoleBindings | ✅ Mitigated |
| HostPath mount escape | Container mounts host path to read node credentials | Medium | Critical | PSS restricted profile blocks hostPath volumes | ✅ Mitigated |

## Residual Risk

The following threats are acknowledged but not fully mitigated in this lab environment:

**Secret injection via environment variables** — Kubernetes allows secrets to be passed as environment variables, which are readable from `/proc/[pid]/environ`. The current lab does not enforce that secrets must be mounted as volumes. In production this would be enforced via OPA/Gatekeeper policy.

**Audit log integrity** — Audit logs are written to the host filesystem but are not shipped to an immutable external SIEM. An attacker with node-level access could tamper with them. In production, logs would be streamed to a managed logging service (e.g. CloudWatch, Splunk) in real time.

**Image signing** — Trivy scans for known CVEs but does not verify image provenance. A supply chain attack that produces a clean image could bypass Trivy. In production, Cosign or Notary would be used to verify image signatures before admission.

**mTLS between services** — Traffic between frontend, API, and database pods is unencrypted within the cluster. NetworkPolicy controls which pods can communicate but does not encrypt traffic. In production, a service mesh (Istio or Linkerd) would provide mTLS.

## Attack Surface Summary

| Surface | Exposure | Notes |
|---------|----------|-------|
| Container runtime | Low | PSS restricted, non-root, read-only filesystem |
| Network | Low | Default-deny NetworkPolicy, Calico enforcement |
| Kubernetes API | Low | RBAC least-privilege, SA automount disabled |
| Node | Low | No hostPath mounts, no privileged containers |
| Supply chain | Medium | Trivy CI scan, no image signing |
| Secrets management | Medium | RBAC blocks direct access, no external secrets manager |
| Audit trail | Medium | Local audit logs, no external SIEM |