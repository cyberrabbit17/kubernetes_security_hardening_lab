# RBAC Permission Matrix

## Overview

This document defines the role-based access control model implemented across the security hardening lab. Three roles are defined following the principle of least privilege — each role grants only the permissions required for its function and nothing more.

## Roles

| Role | Type | Scope | Bound To |
|------|------|-------|----------|
| `auditor` | ClusterRole | Cluster-wide | `auditor1` user |
| `developer` | Role | `dev` namespace only | `developer1` user |
| `namespace-admin` | Role | `staging` namespace only | (unbound - available for staging leads) |

## Permission Matrix

### Core Resources

| Resource | auditor | developer (dev) | namespace-admin (staging) | cluster-admin |
|----------|---------|-----------------|---------------------------|---------------|
| pods | get, list, watch | get, list, watch, create, update, patch, delete | * | * |
| pods/log | get, list, watch | get, list, watch | * | * |
| pods/exec | — | get, list, watch, create | * | * |
| deployments | get, list, watch | get, list, watch, create, update, patch | * | * |
| services | get, list, watch | get, list, watch, create, update, patch, delete | * | * |
| configmaps | get, list, watch | get, list, watch, create, update, patch, delete | * | * |
| **secrets** | **—** | **—** | * | * |
| serviceaccounts | get, list, watch | — | * | * |
| namespaces | get, list, watch | — | — | * |
| nodes | get, list, watch | — | — | * |
| networkpolicies | get, list, watch | — | * | * |
| roles / rolebindings | get, list, watch | — | * | * |
| clusterroles / clusterrolebindings | get, list, watch | — | — | * |
| events | get, list, watch | — | * | * |

Legend: `—` = no access, `*` = full access (all verbs)

## Key Security Decisions

**Secrets are explicitly excluded from developer role.** Developers must retrieve secrets through a secrets manager (e.g. Vault, AWS Secrets Manager) rather than reading them directly from the Kubernetes API. This prevents credential exposure via `kubectl get secret` even if a developer's kubeconfig is compromised.

**Auditor is a ClusterRole, not a Role.** Security auditors need visibility across all namespaces to perform their function. Scoping them to a single namespace would create blind spots. The trade-off is accepted because the auditor role is read-only — it cannot create, modify, or delete any resource.

**namespace-admin is scoped to staging only.** Full administrative access is limited to the staging namespace, preventing staging administrators from accidentally or maliciously modifying production workloads. They cannot access nodes, cluster-level resources, or other namespaces.

**Default service accounts have automounting disabled.** In all three namespaces (dev, staging, production), the default service account has `automountServiceAccountToken: false`. Any pod that does not explicitly need to communicate with the Kubernetes API will not have a token mounted, limiting the blast radius of a container compromise.

## User Authentication

Users are authenticated via X.509 certificates signed by the cluster CA. This approach was chosen over service account tokens because:

- Certificates can be issued with expiry dates (365 days in this lab)
- Certificate revocation is handled by rotating the cluster CA
- The CN field maps directly to the Kubernetes username, O field maps to groups
- No additional identity provider infrastructure is required for a lab environment

In production, this would be replaced with an OIDC provider (e.g. Okta, Google Workspace) for centralized identity management and easier revocation.

## Certificate Details

| User | CN | O (Group) | Expiry |
|------|----|-----------|--------|
| developer1 | developer1 | dev-team | 365 days from issuance |
| auditor1 | auditor1 | audit-team | 365 days from issuance |

## Verification Commands

```bash
# Check what developer1 can do in dev namespace
kubectl auth can-i --list --as developer1 -n dev

# Verify developer1 cannot access secrets
kubectl auth can-i get secrets -n dev --as developer1

# Verify auditor1 has cluster-wide read access
kubectl auth can-i list pods --as auditor1 -n production

# Verify auditor1 cannot modify anything
kubectl auth can-i delete pods --as auditor1 -n production

# Verify developer1 cannot access production
kubectl auth can-i get pods -n production --as developer1
```