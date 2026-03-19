# Attack Scenarios

## Overview

This document describes four attack scenarios simulated against the lab cluster. Each scenario maps to a real-world attack technique, identifies which security control detects or prevents it, and documents the observed output.

All simulations were run against the `production` namespace using the frontend pod as the entry point — simulating an attacker who has achieved RCE through a vulnerability in the frontend application.

---

## Scenario 1: Shell Execution in Container

### Attack Technique
**MITRE ATT&CK:** T1059 - Command and Scripting Interpreter

An attacker exploits a vulnerability in the frontend application to gain remote code execution, then attempts to spawn an interactive shell to explore the environment and pivot to other systems.

### Simulation

```bash
kubectl exec -n production <frontend-pod> -- sh -c "echo 'attacker was here'"
```

### Expected Outcome
Falco fires a `WARNING` level alert for the `Shell Spawned in Container` rule.

### Observed Falco Alert
```
Warning Shell spawned in container
(user=root container=frontend image=nginx proc=sh
parent=runc cmdline=sh -c echo 'attacker was here')
```

### Controls Triggered
| Control | Layer | Effect |
|---------|-------|--------|
| Falco - Shell Spawned in Container rule | Runtime | Alert fired |
| readOnlyRootFilesystem | Build | Attacker cannot write persistence files |
| Network Policy default-deny | Network | Attacker cannot reach other pods or external C2 |

### Remediation
In production, `kubectl exec` access would be restricted via RBAC — developers would not have `pods/exec` permissions in production. The Falco alert would trigger an automated response via Falcosidekick (PagerDuty, Slack, etc).

---

## Scenario 2: Sensitive File Read

### Attack Technique
**MITRE ATT&CK:** T1003 - OS Credential Dumping / T1552 - Unsecured Credentials

After gaining shell access, an attacker attempts to read sensitive system files to harvest credentials, understand the user landscape, or find privilege escalation paths.

### Simulation

```bash
kubectl exec -n production <frontend-pod> -- cat /etc/passwd
```

### Expected Outcome
Falco fires an `ERROR` level alert for the `Sensitive File Read in Container` rule.

### Observed Falco Alert
```
Error Sensitive file read in container
(user=root file=/etc/passwd container=frontend
image=nginx proc=cat)
```

### Controls Triggered
| Control | Layer | Effect |
|---------|-------|--------|
| Falco - Sensitive File Read rule | Runtime | Alert fired |
| runAsNonRoot + runAsUser: 10001 | Build | Process runs as unprivileged user |
| capabilities.drop: ALL | Build | No capabilities to leverage even with passwd contents |

### Remediation
The alert severity is `ERROR` reflecting that credential access attempts are higher severity than shell spawning. In production this would immediately page the security team. `/etc/shadow` reads would trigger the same rule at even higher severity.

---

## Scenario 3: Lateral Movement Attempt

### Attack Technique
**MITRE ATT&CK:** T1021 - Remote Services / T1210 - Exploitation of Remote Services

After compromising the frontend pod, an attacker attempts to reach the database tier directly, bypassing the API layer to access data without going through application-level controls.

### Simulation

```bash
# From frontend pod, attempt to reach database directly
kubectl exec -n production <frontend-pod> -- \
  wget -qO- --timeout=5 http://database:8080
```

### Expected Outcome
Connection times out. NetworkPolicy blocks frontend→database traffic at the kernel level via Calico eBPF enforcement.

### Observed Output
```
wget: download timed out
command terminated with exit code 1
```

### Controls Triggered
| Control | Layer | Effect |
|---------|-------|--------|
| NetworkPolicy default-deny-all | Network | All traffic blocked by default |
| No allow rule for frontend→database | Network | No exception exists for this path |
| Calico eBPF enforcement | Network | Drop enforced at kernel level, not application level |

### Why This Matters
Unlike firewall rules that operate at the perimeter, Kubernetes NetworkPolicy enforces at the pod level. Even if an attacker pivots from one pod to another within the same namespace, they still cannot reach unauthorized services. The database is unreachable from the frontend regardless of what IP address or service name the attacker tries.

---

## Scenario 4: Service Account Token Theft

### Attack Technique
**MITRE ATT&CK:** T1528 - Steal Application Access Token

Kubernetes automatically mounts a service account token into every pod by default. An attacker who gains container access can read this token and use it to authenticate against the Kubernetes API, potentially enumerating cluster resources or escalating privileges.

### Simulation

```bash
kubectl exec -n production <frontend-pod> -- \
  cat /run/secrets/kubernetes.io/serviceaccount/token
```

### Expected Outcome
The token file does not exist because `automountServiceAccountToken: false` is set on the default service account in the production namespace. The attack fails at the source.

### Observed Output
```
cat: can't open '/run/secrets/kubernetes.io/serviceaccount/token': No such file or directory
```

### Controls Triggered
| Control | Layer | Effect |
|---------|-------|--------|
| automountServiceAccountToken: false | Configuration | Token never mounted into pod |
| Falco - K8s Service Account Token Read rule | Runtime | Would alert if token existed and was read |
| RBAC least-privilege | Authorization | Even if token existed, default SA has no permissions |

### Defence in Depth
This scenario demonstrates layered defence — even if one control failed, others would catch it. If `automountServiceAccountToken` was accidentally set to `true`, the RBAC permissions on the default service account are minimal. If an attacker somehow obtained a privileged token, Falco would alert on the read attempt. All three controls must fail simultaneously for this attack to succeed.

---

## Scenario 5: Package Manager Execution (Persistence Attempt)

### Attack Technique
**MITRE ATT&CK:** T1105 - Ingress Tool Transfer / T1059 - Command and Scripting Interpreter

After gaining shell access, an attacker attempts to install additional tools (netcat, curl, nmap) using the package manager to facilitate further exploitation, data exfiltration, or establishing persistence.

### Simulation

```bash
kubectl exec -n production <frontend-pod> -- apk --help
```

### Expected Outcome
Falco fires an `ERROR` level alert for the `Package Management in Container` rule. Additionally, because `readOnlyRootFilesystem: true` is set, any actual package installation would fail even if the alert was ignored.

### Observed Falco Alert
```
Error Package manager run in container
(user=root container=frontend image=nginx
proc=apk cmdline=apk --help)
```

### Controls Triggered
| Control | Layer | Effect |
|---------|-------|--------|
| Falco - Package Management in Container rule | Runtime | Alert fired on apk execution |
| readOnlyRootFilesystem: true | Build | Package installation would fail — cannot write to filesystem |
| Immutable container image | Build | No package manager should be in production images |

### Remediation
Production images should be built without package managers where possible (distroless images). The Falco alert acts as a signal that an attacker is active even if the installation fails.

---

## Summary

| Scenario | Technique | Prevented | Detected | Control |
|----------|-----------|-----------|----------|---------|
| Shell execution | T1059 | No | ✅ Yes | Falco |
| Sensitive file read | T1552 | No | ✅ Yes | Falco |
| Lateral movement | T1210 | ✅ Yes | No | NetworkPolicy |
| SA token theft | T1528 | ✅ Yes | ✅ Yes | automountServiceAccountToken + Falco |
| Package manager | T1105 | ✅ Yes | ✅ Yes | readOnlyRootFilesystem + Falco |

### Key Observation

Prevention and detection are complementary — not all attacks can be prevented (an attacker with RCE can always run commands), but every attack can be detected. The goal is to ensure no attack goes unobserved, and that the blast radius of any successful attack is minimised by the preventive controls.