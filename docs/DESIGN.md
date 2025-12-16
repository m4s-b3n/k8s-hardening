# Project Plan: Kubernetes Hardening Demo

## Overview

This repo contains everything needed to demonstrate Kubernetes hardening for the DevOpsCon Amsterdam talk: **"Vibes Don't Scale: Kubernetes Hardening That Forgives Devs, Not Defaults"**.

The demo should visually show the difference between an unhardened "default" cluster and a properly hardened one - ideally by showing an attack/misconfiguration succeed in one and fail in the other.

---

## 🎯 Demo Goals

1. **Show, don't tell** - Expert audience needs to see real impact, not slides
2. **Side-by-side comparison** - "Unhardened" vs "Hardened" cluster
3. **Reproducible** - Anyone can clone this repo and run the demo themselves
4. **Resilient** - Clusters prepared in advance, online during demo for image pulls
5. **Full AppArmor support** - Required for the abstract
6. **Vibe-coded villain apps** - Sample apps that demonstrate real AI-generated mistakes
7. **Backup recording** - asciinema recording of full demo in case of Murphy's Law

---

## 🤖 The Problem with Vibe-Coded Apps

AI-assisted coding ("vibe coding") produces functional code fast, but older/smaller models and inexperienced prompters create predictable security anti-patterns:

### Common Security Mistakes in AI-Generated Code

| Category                      | Problem                                          | Example                                                        |
| ----------------------------- | ------------------------------------------------ | -------------------------------------------------------------- |
| **Vulnerable Dependencies**   | Older models suggest outdated/CVE-laden packages | `requests==2.5.0`, `log4j 2.14.1`, `lodash 4.17.15`            |
| **Overpermissive Operations** | Code requests more permissions than needed       | `privileged: true`, `runAsUser: 0`, `hostNetwork: true`        |
| **Hardcoded Secrets**         | Secrets embedded in code or env vars             | `API_KEY=sk-...` in Dockerfile, secrets in ConfigMaps          |
| **Dangerous Syscalls**        | Code uses debugging/tracing calls                | `ptrace()`, `mount()`, raw socket access                       |
| **Unrestricted File Access**  | Writes to sensitive paths                        | Writing to `/etc/`, `/proc/`, `/var/run/docker.sock`           |
| **No Resource Limits**        | Missing CPU/memory constraints                   | No `resources.limits`, leads to noisy neighbor/DoS             |
| **Chatty Network Access**     | Phone-home telemetry, unrestricted egress        | Calls to `api.openai.com`, analytics endpoints                 |
| **Latest Tags**               | No pinned versions                               | `FROM python:latest`, `image: nginx:latest`                    |
| **Verbose Logging**           | Logs contain sensitive data                      | Logging full request bodies, tokens, PII                       |
| **Insecure Defaults**         | Copy-pasted configs with security disabled       | `--insecure-skip-tls-verify`, `allowPrivilegeEscalation: true` |
| **Over-scoped RBAC**          | Default SA or cluster-wide permissions           | `automountServiceAccountToken: true`, `ClusterRoleBinding`     |

### How Each Issue Is Demonstrated & Fixed

| Category                      | Demo (Villain App) | What Happens (Unsafe)                    | How It's Fixed (Hardened)                            | Fix Type          |
| ----------------------------- | ------------------ | ---------------------------------------- | ---------------------------------------------------- | ----------------- |
| **Overpermissive Operations** | `vibe-privileged`  | Pod runs as root, mounts host filesystem | PSA `restricted` blocks at admission                 | 🚫 Blocked        |
| **Dangerous Syscalls**        | `vibe-debugger`    | `ptrace()` attaches to PID 1             | seccomp profile denies syscall, container killed     | 🚫 Blocked        |
| **Unrestricted File Access**  | `vibe-filewriter`  | Writes backdoor to `/etc/cron.d/`        | AppArmor profile denies write to `/etc/**`           | 🚫 Blocked        |
| **Chatty Network Access**     | `vibe-phonehome`   | POSTs secrets to `https://evil.com`      | NetworkPolicy default-deny-egress blocks             | 🚫 Blocked        |
| **No Resource Limits**        | `vibe-cryptominer` | Consumes all CPU, no limits set          | Kyverno policy requires `resources.limits`           | 🚫 Blocked        |
| **Latest Tags**               | `vibe-cryptominer` | Uses `image: python:latest`              | Kyverno policy rejects `:latest` tag                 | 🚫 Blocked        |
| **Hardcoded Secrets**         | `vibe-phonehome`   | `SECRET_KEY` in env var                  | Kyverno policy warns/blocks secrets in plain env     | ⚠️ Warned/Blocked |
| **Insecure Defaults**         | `vibe-privileged`  | `allowPrivilegeEscalation: true`         | PSA `restricted` rejects, Kyverno mutates to `false` | 🔧 Auto-mutated   |
| **Vulnerable Dependencies**   | `vibe-cvemagnet`   | Image has Critical/High CVEs             | Trivy Operator scans → Kyverno blocks if CVSS ≥ 7.0  | 🚫 Blocked        |
| **Verbose Logging**           | `vibe-leaky`       | Logs contain API keys, tokens, PII       | Falco detects secret patterns → alerts/kills pod     | 🚨 Detected       |
| **Over-scoped RBAC**          | `vibe-snooper`     | Lists secrets across all namespaces      | Kyverno blocks default SA, enforces scoped RBAC      | 🚫 Blocked        |

**Legend:**

- 🚫 **Blocked** – Admission controller or runtime profile prevents execution entirely
- ⚠️ **Warned/Blocked** – Policy can audit/warn or enforce depending on config
- 🔧 **Auto-mutated** – Kyverno mutating policy fixes the manifest automatically
- 🚨 **Detected** – Runtime monitoring detects and alerts (can optionally kill pod)
- 🔍 **Shift-left** – Handled in CI/CD pipeline (mentioned for completeness)

### Why This Matters for the Talk

The audience will instantly recognize these patterns from their own codebases. By showing these "mistakes" being blocked by hardening, we prove that:

1. **Platform beats process** - You can't review every vibe-coded PR
2. **Guardrails enable velocity** - Devs can move fast because bad stuff is impossible
3. **Defense in depth works** - Multiple layers catch different failure modes

---

## 🎬 Demo Playbook: How to Demonstrate Each Attack

For each villain app, this section details:

- **What to deploy** - The kubectl command
- **Unsafe cluster** - What happens and how to observe the attack succeeding
- **Hardened cluster** - What happens and how to observe the protection working

### 1. `vibe-privileged` – Root Container with Host Mount

**The Attack:** Pod runs as root and mounts the host filesystem, allowing full node compromise.

| Cluster  | Deploy Command                                                   |
| -------- | ---------------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-privileged.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-privileged.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds
kubectl --context=unsafe apply -f demos/vibe-privileged.yaml
# pod/vibe-privileged created

# Show it's running as root with host mount
kubectl --context=unsafe exec vibe-privileged -- id
# uid=0(root) gid=0(root)

kubectl --context=unsafe exec vibe-privileged -- ls /host/etc/
# Shows host's /etc directory - FULL NODE ACCESS!

# Even scarier: read the host's shadow file
kubectl --context=unsafe exec vibe-privileged -- cat /host/etc/shadow
# root:$6$... (password hashes!)
```

**On Hardened Cluster:**

```bash
# PSA restricted namespace rejects immediately
kubectl --context=hardened apply -f demos/vibe-privileged.yaml
# Error from server (Forbidden): error when creating "demos/vibe-privileged.yaml":
# pods "vibe-privileged" is forbidden: violates PodSecurity "restricted:latest":
#   privileged (container "app" must not set securityContext.privileged=true),
#   runAsNonRoot (pod or container "app" must set securityContext.runAsNonRoot=true),
#   hostPath volumes (volume "hostfs" uses hostPath)

# Nothing is running
kubectl --context=hardened get pods
# No resources found
```

**Talking Point:** _"The pod never even starts. PSA rejected it at the API server level. No runtime magic needed."_

---

### 2. `vibe-phonehome` – Exfiltrate Secrets via HTTP

**The Attack:** App reads secrets and POSTs them to an external endpoint.

| Cluster  | Deploy Command                                                  |
| -------- | --------------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-phonehome.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-phonehome.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds
kubectl --context=unsafe apply -f demos/vibe-phonehome.yaml

# Check logs - secret was exfiltrated!
kubectl --context=unsafe logs vibe-phonehome
# [INFO] Reading secret from /var/run/secrets/kubernetes.io/serviceaccount/token
# [INFO] POSTing to https://webhook.site/abc123...
# [INFO] Response: 200 OK - Data received!

# Or watch in real-time with a test webhook
# (Pre-set up webhook.site or requestbin before demo)
```

**On Hardened Cluster:**

```bash
# Deploy succeeds (no PSA violation)
kubectl --context=hardened apply -f demos/vibe-phonehome.yaml

# But egress is blocked! Check logs:
kubectl --context=hardened logs vibe-phonehome
# [INFO] Reading secret from /var/run/secrets/kubernetes.io/serviceaccount/token
# [INFO] POSTing to https://webhook.site/abc123...
# [ERROR] Connection timed out - unable to reach external host

# Show the NetworkPolicy that blocks it
kubectl --context=hardened get networkpolicy -n demo
# NAME                  POD-SELECTOR   AGE
# default-deny-egress   <none>         1h
```

**Talking Point:** _"The app started, but it can't phone home. NetworkPolicy is the firewall inside your cluster."_

---

### 3. `vibe-cryptominer` – No Resource Limits, Latest Tag

**The Attack:** Uses `image: python:latest` and has no resource limits, consuming all node CPU.

| Cluster  | Deploy Command                                                    |
| -------- | ----------------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-cryptominer.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-cryptominer.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds
kubectl --context=unsafe apply -f demos/vibe-cryptominer.yaml

# Watch CPU spike
kubectl --context=unsafe top pods
# NAME              CPU(cores)   MEMORY(bytes)
# vibe-cryptominer  2000m        50Mi          # Eating all available CPU!

# Or show with htop inside the container
kubectl --context=unsafe exec -it vibe-cryptominer -- top
# Shows 100% CPU usage
```

**On Hardened Cluster:**

```bash
# Kyverno rejects immediately
kubectl --context=hardened apply -f demos/vibe-cryptominer.yaml
# Error from server: error when creating "demos/vibe-cryptominer.yaml":
# admission webhook "validate.kyverno.svc" denied the request:
#
# policy Pod/demo/vibe-cryptominer for resource violation:
#   require-resource-limits:
#     require-limits: 'validation error: CPU and memory limits are required.
#       rule require-limits failed at path /spec/containers/0/resources/limits/'
#   disallow-latest-tag:
#     validate-image-tag: 'validation error: Using latest tag is not allowed.
#       rule validate-image-tag failed at path /spec/containers/0/image/'

# Nothing running
kubectl --context=hardened get pods
# No resources found
```

**Talking Point:** _"Two violations in one pod: no limits and latest tag. Kyverno catches both before the scheduler even sees it."_

---

### 4. `vibe-debugger` – Dangerous Syscalls (ptrace)

**The Attack:** Uses `ptrace()` to attach to PID 1 and dump process memory.

| Cluster  | Deploy Command                                                 |
| -------- | -------------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-debugger.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-debugger.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds
kubectl --context=unsafe apply -f demos/vibe-debugger.yaml

# Check logs - ptrace worked!
kubectl --context=unsafe logs vibe-debugger
# [DEBUG] Attempting ptrace attach to PID 1...
# [DEBUG] Successfully attached to init process
# [DEBUG] Reading memory at 0x7fff...
# [DEBUG] Found 47 environment variables in process memory
```

**On Hardened Cluster:**

```bash
# Deploy succeeds (seccomp is runtime, not admission)
kubectl --context=hardened apply -f demos/vibe-debugger.yaml

# But the syscall is denied! Check logs:
kubectl --context=hardened logs vibe-debugger
# [DEBUG] Attempting ptrace attach to PID 1...
# [ERROR] Operation not permitted (errno 1)
# [ERROR] ptrace(PTRACE_ATTACH, 1) failed: seccomp killed the syscall

# Show the seccomp profile in use
kubectl --context=hardened get pod vibe-debugger -o jsonpath='{.spec.securityContext.seccompProfile}'
# {"type":"Localhost","localhostProfile":"deny-dangerous.json"}
```

**Talking Point:** _"The container started, but the kernel said no. seccomp is your syscall firewall - it blocks what the app can even ask for."_

---

### 5. `vibe-filewriter` – Write to Sensitive Paths

**The Attack:** Writes malicious files to sensitive paths _within the container filesystem_ (e.g., `/etc/passwd`, `/etc/shadow`). While this doesn't directly compromise the host, it demonstrates container escape prep and shows AppArmor's file-level restrictions.

> **Note:** This demo shows AppArmor blocking writes _inside the container_. Host filesystem access via hostPath would be blocked earlier by PSA.

| Cluster  | Deploy Command                                                   |
| -------- | ---------------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-filewriter.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-filewriter.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds
kubectl --context=unsafe apply -f demos/vibe-filewriter.yaml

# Check logs - file was written inside container!
kubectl --context=unsafe logs vibe-filewriter
# [WRITE] Attempting to write to /etc/passwd...
# [WRITE] Success! Added backdoor user to /etc/passwd
# [WRITE] Attempting to write to /tmp/malware.sh...
# [WRITE] Success! Wrote malicious script

# Verify the modification
kubectl --context=unsafe exec vibe-filewriter -- tail -1 /etc/passwd
# backdoor:x:0:0::/root:/bin/bash
```

**On Hardened Cluster:**

```bash
# Deploy succeeds (AppArmor is runtime enforcement)
kubectl --context=hardened apply -f demos/vibe-filewriter.yaml

# But writes to /etc/** are denied by AppArmor!
kubectl --context=hardened logs vibe-filewriter
# [WRITE] Attempting to write to /etc/passwd...
# [ERROR] Permission denied (AppArmor: DENIED operation="open")
# [WRITE] Attempting to write to /tmp/malware.sh...
# [WRITE] Success! (AppArmor allows /tmp writes)

# Show AppArmor profile annotation
kubectl --context=hardened get pod vibe-filewriter -o jsonpath='{.metadata.annotations}'
# {"container.apparmor.security.beta.kubernetes.io/app":"localhost/k8s-hardening-deny-writes"}
```

**Talking Point:** _"AppArmor restricts what files a process can touch, even inside its own container. /etc is off-limits, but /tmp is fine - least privilege at the filesystem level."_

---

### 6. `vibe-lateral` – Cross-Namespace Network Scanning

**The Attack:** Scans for services in other namespaces to find attack vectors.

| Cluster  | Deploy Command                                                |
| -------- | ------------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-lateral.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-lateral.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds
kubectl --context=unsafe apply -f demos/vibe-lateral.yaml

# Check logs - services discovered!
kubectl --context=unsafe logs vibe-lateral
# [SCAN] Scanning 10.96.0.0/12 for services...
# [FOUND] 10.96.0.1:443 - kubernetes.default.svc (API server!)
# [FOUND] 10.96.45.12:5432 - postgres.production.svc
# [FOUND] 10.96.78.34:6379 - redis.cache.svc (no auth!)
# [SCAN] Found 14 services across 6 namespaces
```

**On Hardened Cluster:**

```bash
# Deploy succeeds
kubectl --context=hardened apply -f demos/vibe-lateral.yaml

# Network is blocked! Check logs:
kubectl --context=hardened logs vibe-lateral
# [SCAN] Scanning 10.96.0.0/12 for services...
# [TIMEOUT] 10.96.0.1:443 - connection timed out
# [TIMEOUT] All scans failed - no reachable services
# [SCAN] Found 0 services (network restricted)

# Show namespace isolation policy
kubectl --context=hardened get networkpolicy -n demo
# NAME                    POD-SELECTOR   AGE
# deny-cross-namespace    <none>         1h
```

**Talking Point:** _"Namespaces aren't security boundaries by default. NetworkPolicy makes them actual boundaries."_

---

### 7. `vibe-cvemagnet` – Vulnerable Dependencies

**The Attack:** Uses an image with known Critical CVEs (e.g., old log4j, outdated base image).

| Cluster  | Deploy Command                                                  |
| -------- | --------------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-cvemagnet.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-cvemagnet.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds
kubectl --context=unsafe apply -f demos/vibe-cvemagnet.yaml

# It's running with known vulnerabilities
kubectl --context=unsafe get pods
# NAME            READY   STATUS    RESTARTS   AGE
# vibe-cvemagnet  1/1     Running   0          10s

# (If Trivy is installed for visibility, show scan results)
kubectl --context=unsafe get vulnerabilityreports -n demo
# Shows Critical/High CVEs - but nothing stopped it!
```

**On Hardened Cluster:**

```bash
# First deploy attempt - image already scanned by Trivy Operator
kubectl --context=hardened apply -f demos/vibe-cvemagnet.yaml

# Kyverno blocks based on Trivy scan results!
# Error from server: error when creating "demos/vibe-cvemagnet.yaml":
# admission webhook "validate.kyverno.svc" denied the request:
#
# policy Pod/demo/vibe-cvemagnet for resource violation:
#   block-critical-cves:
#     check-vulnerabilities: |
#       Image ghcr.io/.../vibe-cvemagnet:1.0.0 has 3 CRITICAL vulnerabilities:
#       - CVE-2021-44228 (log4j) CVSS 10.0
#       - CVE-2022-22965 (Spring4Shell) CVSS 9.8
#       - CVE-2021-3711 (OpenSSL) CVSS 9.8
#       Deployment blocked: CVSS >= 7.0 not allowed

# Show the Trivy scan
kubectl --context=hardened get vulnerabilityreports -n demo -o wide
```

**Talking Point:** _"The image was pre-scanned. Kyverno asked Trivy 'is this safe?' and Trivy said 'absolutely not'. No CVEs in prod."_

---

### 8. `vibe-leaky` – Logs Secrets to stdout

**The Attack:** App logs API keys, tokens, and PII in plain text.

| Cluster  | Deploy Command                                              |
| -------- | ----------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-leaky.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-leaky.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds
kubectl --context=unsafe apply -f demos/vibe-leaky.yaml

# Secrets are in the logs!
kubectl --context=unsafe logs vibe-leaky
# [INFO] Starting application...
# [DEBUG] Loaded config: {"api_key": "sk-proj-abc123xyz", "db_password": "hunter2"}
# [INFO] Connecting to database with password: hunter2
# [DEBUG] Bearer token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Anyone with log access can see these secrets!
```

**On Hardened Cluster:**

```bash
# Deploy succeeds (this is runtime detection)
kubectl --context=hardened apply -f demos/vibe-leaky.yaml

# Falco detects the secret patterns!
# In a separate terminal, watch Falco alerts:
kubectl --context=hardened logs -n falco -l app=falco -f
# 14:23:45.123456789: Warning Sensitive data in logs
#   (pod=vibe-leaky ns=demo container=app
#   pattern="api_key.*sk-" log_line="[DEBUG] Loaded config...")
# 14:23:45.234567890: Warning Sensitive data in logs
#   (pod=vibe-leaky ns=demo container=app
#   pattern="password" log_line="[INFO] Connecting to database...")

# Show Falco is configured to detect this
kubectl --context=hardened get configmap falco-rules -n falco -o yaml | grep -A5 "secret"
```

**Talking Point:** _"Falco watches stdout in real-time. The moment a secret pattern appears, you get an alert. In production, this triggers PagerDuty."_

---

### 9. `vibe-snooper` – RBAC Abuse with Default ServiceAccount

**The Attack:** Uses the default ServiceAccount to list secrets across namespaces.

> **Setup required for unsafe cluster:** By default, the default ServiceAccount has no permissions. To make this demo work, the unsafe cluster setup creates an overly-permissive ClusterRoleBinding (simulating a common misconfiguration):
>
> ```yaml
> # Applied during unsafe cluster setup - DO NOT DO THIS IN PRODUCTION
> apiVersion: rbac.authorization.k8s.io/v1
> kind: ClusterRoleBinding
> metadata:
>   name: insecure-default-sa-binding
> roleRef:
>   apiGroup: rbac.authorization.k8s.io
>   kind: ClusterRole
>   name: cluster-admin # The mistake: giving default SA cluster-admin
> subjects:
>   - kind: ServiceAccount
>     name: default
>     namespace: demo
> ```

| Cluster  | Deploy Command                                                |
| -------- | ------------------------------------------------------------- |
| Unsafe   | `kubectl --context=unsafe apply -f demos/vibe-snooper.yaml`   |
| Hardened | `kubectl --context=hardened apply -f demos/vibe-snooper.yaml` |

**On Unsafe Cluster:**

```bash
# Deploy succeeds (using default SA with overly-permissive ClusterRoleBinding)
kubectl --context=unsafe apply -f demos/vibe-snooper.yaml

# Check logs - secrets enumerated!
kubectl --context=unsafe logs vibe-snooper
# [RBAC] Checking my permissions...
# [RBAC] Can list secrets in demo: true
# [RBAC] Can list secrets in production: true (!)
# [ENUM] Listing all secrets in cluster...
# [FOUND] production/db-credentials: username=admin, password=s3cr3t
# [FOUND] production/api-keys: stripe_key=sk_live_...
# [ENUM] Enumerated 23 secrets across 8 namespaces
```

**On Hardened Cluster:**

```bash
# Kyverno blocks at admission!
kubectl --context=hardened apply -f demos/vibe-snooper.yaml
# Error from server: error when creating "demos/vibe-snooper.yaml":
# admission webhook "validate.kyverno.svc" denied the request:
#
# policy Pod/demo/vibe-snooper for resource violation:
#   restrict-service-account:
#     validate-sa: |
#       Pods must not use the default ServiceAccount.
#       Set automountServiceAccountToken: false or specify a dedicated SA.

# Alternative: If we allow it but restrict RBAC
kubectl --context=hardened logs vibe-snooper
# [RBAC] Checking my permissions...
# [RBAC] Can list secrets in demo: false
# [RBAC] Can list secrets in production: false
# [ERROR] Forbidden: cannot list secrets - no permissions granted
```

**Talking Point:** _"Default ServiceAccounts are cluster-wide gossip networks. Kyverno forces you to be explicit about identity."_

---

## 📋 Quick Reference: Demo Commands Cheat Sheet

```bash
# === SETUP (before talk) ===
export KUBECONFIG_UNSAFE=~/.kube/config-unsafe
export KUBECONFIG_HARDENED=~/.kube/config-hardened

# Verify both clusters are running
kubectl --context=unsafe get nodes
kubectl --context=hardened get nodes

# === DEMO PATTERN (for each villain app) ===

# 1. Show the manifest (optional, for transparency)
cat demos/vibe-<name>.yaml

# 2. Deploy to unsafe - watch it succeed/attack
kubectl --context=unsafe apply -f demos/vibe-<name>.yaml
kubectl --context=unsafe logs vibe-<name>

# 3. Deploy to hardened - watch it fail/be blocked
kubectl --context=hardened apply -f demos/vibe-<name>.yaml
kubectl --context=hardened logs vibe-<name>  # if it ran

# 4. Clean up before next demo
kubectl --context=unsafe delete -f demos/vibe-<name>.yaml
kubectl --context=hardened delete -f demos/vibe-<name>.yaml

# === FALCO MONITORING (keep in separate terminal) ===
kubectl --context=hardened logs -n falco -l app=falco -f

# === TRIVY SCAN RESULTS ===
kubectl --context=hardened get vulnerabilityreports -A
```

---

## 🏗️ Architecture: WSL2 + Minikube/Hyper-V

```
┌─────────────────────────────────────────────────────────────────────┐
│  Windows Host (Hyper-V enabled)                                     │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │ WSL2 (Ubuntu)                                                   │    │
│  │  - All scripts (Bash)                                          │    │
│  │  - kubectl, helm, docker                                       │    │
│  │  - Calls minikube.exe for Hyper-V operations                   │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                            │                                           │
│                   minikube.exe (interop)                            │
│                            │                                           │
│            ┌────────────────┴─────────────────┐                      │
│            │                                  │                      │
│            ▼                                  ▼                      │
│  ┌────────────────────────┐  ┌────────────────────────┐    │
│  │ Hyper-V VM             │  │ Hyper-V VM             │    │
│  │ minikube-unsafe        │  │ minikube-hardened      │    │
│  │ ┌──────────────────┐   │  │ ┌──────────────────┐   │    │
│  │ │ Kubernetes       │   │  │ │ Kubernetes       │   │    │
│  │ │ - PSA privileged │   │  │ │ - PSA restricted │   │    │
│  │ │ - No policies    │   │  │ │ - Kyverno        │   │    │
│  │ │ - No AppArmor    │   │  │ │ - AppArmor       │   │    │
│  │ │ - No seccomp     │   │  │ │ - seccomp        │   │    │
│  │ │ - No netpol      │   │  │ │ - Network deny   │   │    │
│  │ └──────────────────┘   │  │ └──────────────────┘   │    │
│  └────────────────────────┘  └────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

### How It Works

**From WSL2 (Bash):**

```bash
# Cluster creation - calls Windows minikube via interop
# Note: --cni=calico is required for NetworkPolicy support
minikube.exe start --driver=hyperv --profile=unsafe --cni=calico
minikube.exe start --driver=hyperv --profile=hardened --cni=calico

# Export kubeconfig to WSL (one-time after cluster create)
minikube.exe -p hardened kubectl config view --raw > ~/.kube/config-hardened
minikube.exe -p unsafe kubectl config view --raw > ~/.kube/config-unsafe

# Everything else is pure Linux
export KUBECONFIG=~/.kube/config-hardened
kubectl get pods           # Native Linux kubectl
helm install kyverno ...   # Native Linux helm
kubectl apply -f manifests/
```

**What requires `minikube.exe` (5%):**
| Operation | Why Windows? |
|-----------|-------------|
| `minikube.exe start --driver=hyperv` | Hyper-V API |
| `minikube.exe delete -p <profile>` | Hyper-V API |
| `minikube.exe -p <profile> ip` | Queries VM |
| `minikube.exe -p <profile> image load` | Push to VM |

**What's pure Linux (95%):**
| Operation | Command |
|-----------|---------|
| All kubectl commands | `kubectl apply`, `kubectl logs`, etc. |
| Helm installs | `helm install kyverno ...` |
| Docker builds | `docker build -t ...` |
| Push to ghcr.io | `docker push ghcr.io/...` |
| All demo commands | The actual presentation |

### Why WSL2 + Minikube/Hyper-V?

| Requirement           | Solution                                 |
| --------------------- | ---------------------------------------- |
| AppArmor              | ✅ Full support (real Hyper-V Ubuntu VM) |
| seccomp               | ✅ Full support                          |
| Two parallel clusters | ✅ Via `--profile` flag                  |
| Automated setup       | ✅ Bash scripts in WSL2                  |
| No PowerShell         | ✅ Only `minikube.exe` calls via interop |
| Reproducible          | ✅ Script the whole thing                |
| Resource usage        | ~4GB RAM per cluster                     |
| Setup time            | ~5 min per cluster                       |

### Why NOT other options?

| Option                   | Problem                                                        |
| ------------------------ | -------------------------------------------------------------- |
| Kind (Docker)            | No real AppArmor (inherits from host, Docker Desktop has none) |
| K8s inside WSL2          | WSL2 kernel doesn't have AppArmor enabled by default           |
| VirtualBox               | Conflicts with Hyper-V on Windows                              |
| Vagrant                  | Extra complexity, Hyper-V provider is less mature              |
| Linux minikube + Hyper-V | Hyper-V driver only exists in Windows minikube.exe             |
| Pure PowerShell          | Pain to write, Bash is better                                  |

---

## 🔐 How seccomp & AppArmor Are Set Up

**No Ansible needed!** Minikube's ISO already has both seccomp and AppArmor support. We just need to load profiles.

### seccomp Setup (Built-in)

seccomp is handled by containerd/Kubernetes - no node setup required:

```yaml
# Option 1: Use RuntimeDefault (built-in, zero setup)
securityContext:
  seccompProfile:
    type: RuntimeDefault

# Option 2: Custom profiles - copy to node once
# minikube.exe -p hardened cp profiles/deny-ptrace.json /var/lib/kubelet/seccomp/
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: deny-ptrace.json
```

### AppArmor Setup (DaemonSet Approach)

Minikube's ISO has AppArmor enabled. We just need to load our profiles on the node.

**Recommended: Profile Loader DaemonSet**

```yaml
# A DaemonSet that:
# 1. Reads AppArmor profiles from a ConfigMap
# 2. Runs apparmor_parser to load them on each node
# 3. Keeps profiles loaded after node restart
```

This is the **production-grade, GitOps-friendly** approach:

- Fully declarative (`kubectl apply`)
- No SSH, no Ansible, no manual steps
- Profiles stored in ConfigMaps alongside other manifests
- Works with any number of nodes

**Repo will include:**

```
manifests/hardening/
├── seccomp/
│   ├── profiles/                    # JSON seccomp profiles
│   │   ├── deny-ptrace.json
│   │   └── deny-mount.json
│   └── copy-profiles.sh             # One-time: copies to node via minikube cp
│
└── apparmor/
    ├── profiles/                    # AppArmor profile definitions
    │   ├── deny-write-etc
    │   └── deny-raw-sockets
    ├── configmap.yaml               # Profiles as ConfigMap
    └── profile-loader-daemonset.yaml # Loads profiles on node startup
```

### Alternative: One-Time SSH Setup

For simplicity, we could also just SSH in during cluster setup:

```bash
# In setup.sh - after cluster creation
minikube.exe -p hardened ssh << 'EOF'
  # Load AppArmor profiles
  sudo apparmor_parser -r /path/to/profiles/*
EOF

# Copy seccomp profiles
minikube.exe -p hardened cp seccomp-profiles/ /var/lib/kubelet/seccomp/
```

**Verdict:** Use DaemonSet for AppArmor (shows real-world practice), SSH copy for seccomp (simpler).

---

## � Vulnerability Scanning with Trivy Operator + Kyverno

We can block pods that use images with known CVEs **at runtime** using Trivy Operator + Kyverno.

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  Hardened Cluster                                                    │
│                                                                     │
│  1. Pod created with image:tag                                      │
│              │                                                      │
│              ▼                                                      │
│  ┌─────────────────────────────────────────┐                        │
│  │ Trivy Operator (runs continuously)       │                        │
│  │ - Scans all images in cluster           │                        │
│  │ - Creates VulnerabilityReport CRDs      │                        │
│  └─────────────────────────────────────────┘                        │
│              │                                                      │
│              ▼                                                      │
│  ┌─────────────────────────────────────────┐                        │
│  │ VulnerabilityReport (CRD)                │                        │
│  │ - image: vibe-cvemagnet:v1.0.0          │                        │
│  │ - criticalCount: 3                      │                        │
│  │ - highCount: 12                         │                        │
│  │ - summary.criticalCount >= 1 → FAIL     │                        │
│  └─────────────────────────────────────────┘                        │
│              │                                                      │
│              ▼                                                      │
│  ┌─────────────────────────────────────────┐                        │
│  │ Kyverno Policy                           │                        │
│  │ - Checks VulnerabilityReport for image  │                        │
│  │ - Blocks if criticalCount > 0           │                        │
│  │ - Or blocks if CVSS score >= 7.0        │                        │
│  └─────────────────────────────────────────┘                        │
│              │                                                      │
│              ▼                                                      │
│         ❌ Pod Rejected                                              │
└─────────────────────────────────────────────────────────────────────┘
```

### Kyverno Policy Example

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-vulnerable-images
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-vulnerabilities
      match:
        any:
          - resources:
              kinds:
                - Pod
      context:
        - name: vulnReport
          apiCall:
            urlPath: "/apis/aquasecurity.github.io/v1alpha1/namespaces/{{request.namespace}}/vulnerabilityreports"
            jmesPath: 'items[?metadata.labels."trivy-operator.resource.name" == ''{{request.object.metadata.name}}''] | [0]'
      validate:
        message: "Image has critical vulnerabilities. Found {{vulnReport.report.summary.criticalCount}} critical CVEs."
        deny:
          conditions:
            any:
              - key: "{{vulnReport.report.summary.criticalCount}}"
                operator: GreaterThan
                value: 0
```

### Trivy Operator Setup

```bash
# Install Trivy Operator via Helm (in setup.sh)
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm install trivy-operator aquasecurity/trivy-operator \
  --namespace trivy-system \
  --create-namespace \
  --set trivy.ignoreUnfixed=true
```

### Demo Flow

| Cluster  | What Happens                                             |
| -------- | -------------------------------------------------------- |
| Unsafe   | `vibe-cvemagnet` deploys fine (no scanning)              |
| Hardened | Trivy scans → finds CVEs → Kyverno blocks → Pod rejected |

### Why This Is Powerful

1. **Zero developer effort** - Scanning happens automatically
2. **Shift-left + runtime** - CI can warn, cluster enforces
3. **Configurable threshold** - Block critical only, or critical+high
4. **Real CVEs** - Not a contrived demo, actual vulnerabilities

### Handling the First-Deploy Race Condition

Trivy scans _after_ images are pulled, but Kyverno validates _at admission_. First deploy would succeed because no VulnerabilityReport exists yet.

**Solution:** Run pods that pull all villain images on bootstrap, triggering Trivy to scan them before any demo deployment:

```bash
# In setup.sh - after Trivy Operator is installed, pull images to trigger scans
for img in vibe-privileged vibe-cvemagnet vibe-leaky vibe-phonehome; do
  kubectl --context=hardened run "prescan-$img" \
    --image="ghcr.io/<owner>/k8s-hardening/$img:latest" \
    --restart=Never \
    --command -- sleep 1
  kubectl --context=hardened delete pod "prescan-$img" --ignore-not-found
done

# Wait for Trivy to scan (usually ~30s per image)
echo "Waiting for Trivy scans to complete..."
sleep 60
kubectl --context=hardened get vulnerabilityreports -A
```

This ensures VulnerabilityReports exist before we demo `vibe-cvemagnet`.

---

## 🚨 Runtime Secret Detection with Falco

Falco is a CNCF runtime security tool that monitors syscalls via eBPF. It can detect secrets being written to stdout/stderr by intercepting `write()` syscalls.

> **Technical note:** Falco doesn't parse log files - it intercepts the `write()` syscall to file descriptors 1 (stdout) and 2 (stderr) in real-time via eBPF. This is more reliable than log parsing because it catches secrets before they hit any log aggregator.

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  Hardened Cluster                                                    │
│                                                                     │
│  ┌─────────────────────────────────────────┐                        │
│  │ vibe-leaky Pod                           │                        │
│  │ print(f"Using API key: {api_key}")      │                        │
│  └─────────────────────────────────────────┘                        │
│              │                                                      │
│              │ write() syscall to fd=1 (stdout)                     │
│              ▼                                                      │
│  ┌─────────────────────────────────────────┐                        │
│  │ Falco (DaemonSet on each node via eBPF)  │                        │
│  │ - Intercepts write() syscalls           │                        │
│  │ - Matches data against secret patterns  │                        │
│  │ - Regex: API keys, JWTs, AWS keys, etc  │                        │
│  └─────────────────────────────────────────┘                        │
│              │                                                      │
│              ▼                                                      │
│  ┌─────────────────────────────────────────┐                        │
│  │ Falco Rule Triggered                     │                        │
│  │ "Secret leaked in container logs"       │                        │
│  │ → Alert to Slack/PagerDuty              │                        │
│  │ → (Optional) Kill pod via response engine│                        │
│  └─────────────────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Falco Rule Example

```yaml
# Custom rule to detect secrets in logs
- rule: Sensitive Data in Logs
  desc: Detect API keys, tokens, or credentials being logged
  condition: >
    (fd.name in (stdout, stderr)) and
    (evt.arg.data regex "(?i)(api[_-]?key|secret[_-]?key|password|bearer|aws_access_key_id|private[_-]?key)\s*[=:]\s*['\"]?[a-zA-Z0-9+/=_-]{16,}")
  output: >
    Sensitive data detected in logs 
    (pod=%k8s.pod.name namespace=%k8s.ns.name container=%container.name data=%evt.arg.data)
  priority: WARNING
  tags: [secrets, logging]
```

### Falco Setup

```bash
# Install Falco via Helm (in setup.sh)
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco-system \
  --create-namespace \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true
```

### Demo Flow

| Cluster  | What Happens                                               |
| -------- | ---------------------------------------------------------- |
| Unsafe   | `vibe-leaky` logs secrets, nobody notices                  |
| Hardened | Falco detects pattern → fires alert → (optional) kills pod |

### Why Falco for This

| Alternative                | Why Not                                      |
| -------------------------- | -------------------------------------------- |
| Gitleaks                   | For git repos, not runtime logs              |
| Log redaction (Fluent Bit) | Hides the problem, doesn't detect/alert      |
| OPA/Kyverno                | Admission-time only, can't see runtime logs  |
| **Falco**                  | ✅ Runtime detection, patterns, alerts, CNCF |

---

## 🛡️ Complete Security Tool Stack

We now have a **defense-in-depth** strategy covering all 10 common vibe-coding security mistakes. Here's how all the tools work together:

### Tool Overview

| Tool               | Layer            | What It Does                                      | Works in Hyper-V VM? |
| ------------------ | ---------------- | ------------------------------------------------- | -------------------- |
| **PSA**            | Admission        | Built-in K8s Pod Security Admission               | ✅ Yes (K8s native)  |
| **Kyverno**        | Admission        | Policy-as-code, validate/mutate/generate + RBAC   | ✅ Yes (K8s native)  |
| **Network Policy** | Runtime          | Default-deny egress, namespace isolation          | ✅ Yes (CNI: Calico) |
| **seccomp**        | Runtime (kernel) | Syscall filtering per container                   | ✅ Yes (real kernel) |
| **AppArmor**       | Runtime (kernel) | MAC for file/network/capability restrictions      | ✅ Yes (real kernel) |
| **Trivy Operator** | Continuous       | Scans images for CVEs, creates reports            | ✅ Yes (K8s native)  |
| **Falco**          | Runtime (eBPF)   | Detects anomalies, secrets in logs, syscall abuse | ✅ Yes (eBPF works)  |

### Why Everything Works in Hyper-V VMs

```
┌─────────────────────────────────────────────────────────────────────┐
│  Docker Desktop / WSL2 Kernel         │  Hyper-V VM (Minikube)      │
│                                       │                             │
│  ❌ AppArmor: Not enabled in kernel   │  ✅ AppArmor: Full support  │
│  ❌ seccomp: Limited                  │  ✅ seccomp: Full support   │
│  ❌ eBPF: Restricted                  │  ✅ eBPF: Full support      │
│  ❌ Kernel modules: Can't load        │  ✅ Kernel modules: OK      │
│                                       │                             │
│  Reason: Shared/restricted kernel     │  Reason: Real Ubuntu VM     │
└─────────────────────────────────────────────────────────────────────┘
```

### Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ADMISSION TIME                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Layer 1: PSA (Pod Security Admission)                        │   │
│  │ • Blocks privileged containers                               │   │
│  │ • Enforces non-root, no hostNetwork, no hostPID              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Layer 2: Kyverno Policies                                    │   │
│  │ • Validates: resource limits, image tags, registries         │   │
│  │ • Mutates: adds seccomp, fixes allowPrivilegeEscalation      │   │
│  │ • Blocks: CVE-laden images (via Trivy reports)               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Layer 3: Network Policy (applied at pod creation)            │   │
│  │ • Default deny egress                                        │   │
│  │ • Namespace isolation                                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│                         RUNTIME                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Layer 4: seccomp (Kernel syscall filtering)                  │   │
│  │ • Blocks ptrace, mount, raw sockets                          │   │
│  │ • Per-container profile                                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Layer 5: AppArmor (Kernel MAC)                               │   │
│  │ • Restricts file paths (/etc/**, /proc/**)                   │   │
│  │ • Limits network capabilities                                │   │
│  │ • Per-container profile                                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Layer 6: Falco (Runtime detection via eBPF)                  │   │
│  │ • Detects secrets in logs                                    │   │
│  │ • Detects anomalous behavior                                 │   │
│  │ • Alerts + optional pod kill                                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      CONTINUOUS                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Layer 7: Trivy Operator (Background scanning)                │   │
│  │ • Scans all images continuously                              │   │
│  │ • Creates VulnerabilityReport CRDs                           │   │
│  │ • Kyverno reads reports to block new pods                    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Coverage Matrix: Tools vs Security Issues

| Security Issue              | PSA | Kyverno | NetPol | seccomp | AppArmor | Trivy | Falco |
| --------------------------- | --- | ------- | ------ | ------- | -------- | ----- | ----- |
| Privileged containers       | ✅  | ✅      |        |         |          |       |       |
| Root user                   | ✅  | ✅      |        |         |          |       |       |
| Host filesystem access      | ✅  |         |        |         | ✅       |       |       |
| Dangerous syscalls (ptrace) |     |         |        | ✅      |          |       | ✅    |
| Write to /etc/\*\*          |     |         |        |         | ✅       |       |       |
| Egress to internet          |     |         | ✅     |         |          |       |       |
| Cross-namespace traffic     |     |         | ✅     |         |          |       |       |
| No resource limits          |     | ✅      |        |         |          |       |       |
| Latest image tag            |     | ✅      |        |         |          |       |       |
| Vulnerable dependencies     |     | ✅\*    |        |         |          | ✅    |       |
| Secrets in logs             |     |         |        |         |          |       | ✅    |
| allowPrivilegeEscalation    | ✅  | ✅†     |        |         |          |       |       |
| Over-scoped RBAC            |     | ✅      |        |         |          |       |       |

_\* Kyverno blocks based on Trivy reports_  
_† Kyverno can mutate to fix automatically_

### Installation Order (in setup.sh)

```bash
# 1. CNI with NetworkPolicy support (comes with Minikube, or install Calico)
# 2. Kyverno (admission controller)
helm install kyverno kyverno/kyverno -n kyverno-system --create-namespace

# 3. Trivy Operator (needs to run before Kyverno CVE policies take effect)
helm install trivy-operator aquasecurity/trivy-operator -n trivy-system --create-namespace

# 4. Falco (runtime detection)
helm install falco falcosecurity/falco -n falco-system --create-namespace --set driver.kind=ebpf

# 5. seccomp profiles (copy to node)
minikube.exe -p hardened cp seccomp-profiles/ /var/lib/kubelet/seccomp/

# 6. AppArmor profiles (via DaemonSet or SSH)
kubectl apply -f manifests/hardening/apparmor/

# 7. PSA labels on namespaces
kubectl apply -f manifests/hardening/pod-security/

# 8. Network Policies
kubectl apply -f manifests/hardening/network-policies/

# 9. Kyverno policies (last, so all other tools are ready)
kubectl apply -f manifests/hardening/kyverno/
```

### Resource Requirements (Hardened Cluster)

| Component       | CPU Request | Memory Request | Notes                    |
| --------------- | ----------- | -------------- | ------------------------ |
| Kyverno         | 100m        | 256Mi          | 3 replicas in HA         |
| Trivy Operator  | 100m        | 128Mi          | Scans run as Jobs        |
| Falco           | 100m        | 512Mi          | DaemonSet, eBPF overhead |
| **Total added** | ~300m       | ~900Mi         | On top of base K8s       |

With 4GB RAM per cluster, this fits comfortably.

---

## �🔄 GitOps with Flux (Automated Cluster Setup)

Flux is used as **infrastructure** to automatically deploy manifests to both clusters. It's not part of the demo - it just sets everything up.

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  GitHub Repo                                            │
│                                                         │
│  manifests/                                             │
│  ├── hardening/         ────▶ Hardened cluster (Flux)    │
│  │   ├── kyverno/            (auto-synced on bootstrap) │
│  │   ├── trivy/                                        │
│  │   ├── falco/                                        │
│  │   ├── network-policies/                             │
│  │   ├── apparmor/                                     │
│  │   └── seccomp/                                      │
│  │                                                      │
│  └── demos/             ────▶ Manual kubectl apply       │
│      └── vibe-*.yaml         (during live demo)        │
└─────────────────────────────────────────────────────────┘
                          │
              Flux watches repo (hardening only)
                          │
        ┌─────────────────┴─────────────────┐
        │                                  │
        ▼                                  ▼
┌──────────────────┐        ┌──────────────────┐
│ minikube-unsafe    │        │ minikube-hardened  │
│                    │        │                    │
│ Flux syncs:        │        │ Flux syncs:        │
│ • (nothing)        │        │ • manifests/harden │
│                    │        │                    │
│ Demo deploys:      │        │ Demo deploys:      │
│ • kubectl apply    │        │ • kubectl apply    │
│   manifests/demos/ │        │   manifests/demos/ │
└──────────────────┘        └──────────────────┘
```

### Flux Bootstrap (In setup.sh)

```bash
# Bootstrap Flux on unsafe cluster - apps only
export KUBECONFIG=~/.kube/config-unsafe
flux bootstrap github \
  --owner=<your-github-user> \
  --repository=k8s-hardening \
  --path=clusters/unsafe \
  --personal

# Bootstrap Flux on hardened cluster - apps + hardening
export KUBECONFIG=~/.kube/config-hardened
flux bootstrap github \
  --owner=<your-github-user> \
  --repository=k8s-hardening \
  --path=clusters/hardened \
  --personal
```

### Flux Kustomizations

```yaml
# clusters/unsafe/kustomization.yaml
# Minimal - just Flux itself, no hardening
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: flux-system
  namespace: flux-system
spec:
  interval: 10m
  path: ./clusters/unsafe
  prune: true
  sourceRef:
    kind: GitRepository
    name: flux-system
```

```yaml
# clusters/hardened/hardening.yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: hardening
  namespace: flux-system
spec:
  interval: 5m
  path: ./manifests/hardening
  prune: true
  sourceRef:
    kind: GitRepository
    name: flux-system
```

### Manual Demo Deployment

During the talk, deploy villain apps with simple kubectl:

```bash
# On unsafe cluster
export KUBECONFIG=~/.kube/config-unsafe
kubectl apply -f manifests/demos/01-vibe-privileged.yaml  # Works!

# On hardened cluster
export KUBECONFIG=~/.kube/config-hardened
kubectl apply -f manifests/demos/01-vibe-privileged.yaml  # Blocked!
```

### Why Flux (Not ArgoCD)

| Aspect         | Flux                  | ArgoCD                     |
| -------------- | --------------------- | -------------------------- |
| Purpose here   | Silent infrastructure | Overkill                   |
| Resource usage | ~100MB RAM            | ~500MB RAM                 |
| UI             | None (don't need it)  | Has UI (would distract)    |
| Setup          | `flux bootstrap`      | More steps                 |
| Footprint      | Just does its job     | Would tempt you to show it |

### Public Repo + Public Images = No Secrets Needed

Since this is a **public demo repo**:

- GitHub repo is public → Flux can clone without credentials
- Images on ghcr.io are public → No `imagePullSecrets` needed
- Zero secrets management for the demo setup

---

## 📦 Monorepo + Semantic Release

This repo uses a **monorepo** approach with **single-version semantic release** for all villain apps.

### Why Monorepo?

| Aspect                  | Benefit                                                    |
| ----------------------- | ---------------------------------------------------------- |
| **Audience cloning**    | One `git clone`, everything's there                        |
| **Conference story**    | "Here's the repo" - simple                                 |
| **Maintainability**     | One place to update, one CI pipeline                       |
| **Flux/GitOps**         | Already structured with `clusters/`, `manifests/`, `apps/` |
| **No imagePullSecrets** | Public images, public repo                                 |

### Single Version Strategy

All villain apps share one version. When any app changes:

```
Commit: "feat: add network scanning to vibe-lateral"
Release: v1.3.0
Result: All 6 images tagged v1.3.0
```

**Why this works:**

- Apps are conceptually one unit ("the villain apps")
- Audience sees consistent versions
- Simple mental model
- One changelog

### CI/CD Workflow

```yaml
# .github/workflows/release.yaml
name: Release
on:
  push:
    branches: [main]

jobs:
  release:
    runs-on: ubuntu-latest
    outputs:
      new_release_published: ${{ steps.semantic.outputs.new_release_published }}
      new_release_version: ${{ steps.semantic.outputs.new_release_version }}
    steps:
      - uses: actions/checkout@v4
      - uses: cycjimmy/semantic-release-action@v4
        id: semantic
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  build-images:
    needs: release
    if: needs.release.outputs.new_release_published == 'true'
    strategy:
      matrix:
        app:
          [
            vibe-privileged,
            vibe-phonehome,
            vibe-cryptominer,
            vibe-debugger,
            vibe-filewriter,
            vibe-lateral,
            vibe-cvemagnet,
            vibe-leaky,
            vibe-snooper,
          ]
    steps:
      - uses: docker/build-push-action@v5
        with:
          context: ./apps/${{ matrix.app }}
          push: true
          tags: |
            ghcr.io/${{ github.repository }}/${{ matrix.app }}:${{ needs.release.outputs.new_release_version }}
            ghcr.io/${{ github.repository }}/${{ matrix.app }}:latest
```

### Image References in Manifests

```yaml
# manifests/apps/vibe-privileged.yaml
spec:
  containers:
    - name: vibe-privileged
      image: ghcr.io/<owner>/k8s-hardening/vibe-privileged:latest
      # Or pin to version: ghcr.io/<owner>/k8s-hardening/vibe-privileged:v1.3.0
```

---

## 📋 What to Demonstrate

Based on your abstract, here's what we should show:

### 1. Pod Security Admission (PSA)

| Unsafe Cluster         | Hardened Cluster         |
| ---------------------- | ------------------------ |
| Runs privileged pod ✅ | Blocks privileged pod ❌ |
| Runs as root ✅        | Forces non-root ❌       |
| hostNetwork works ✅   | hostNetwork blocked ❌   |

### 2. Policy-as-Code (Kyverno)

| Unsafe Cluster     | Hardened Cluster        |
| ------------------ | ----------------------- |
| Any image allowed  | Only allowed registries |
| No resource limits | Requires limits         |
| Latest tag works   | Latest tag blocked      |

### 3. Network Policies (Default Deny Egress)

| Unsafe Cluster            | Hardened Cluster          |
| ------------------------- | ------------------------- |
| Pod can curl internet     | Egress blocked by default |
| Pod can reach any service | Only allowed destinations |

### 4. seccomp Profiles

| Unsafe Cluster                 | Hardened Cluster           |
| ------------------------------ | -------------------------- |
| Container can call any syscall | Dangerous syscalls blocked |
| ptrace works                   | ptrace denied              |

### 5. AppArmor Profiles

| Unsafe Cluster               | Hardened Cluster                  |
| ---------------------------- | --------------------------------- |
| Container can write anywhere | Write paths restricted            |
| Can read sensitive files     | File access denied                |
| No process restrictions      | Execution limited to allowed bins |

### 6. Namespace Isolation

| Unsafe Cluster          | Hardened Cluster              |
| ----------------------- | ----------------------------- |
| Cross-namespace traffic | Namespace boundaries enforced |
| Shared service accounts | Scoped RBAC                   |

---

## � Sample "Villain" Apps

We'll build intentionally bad apps that demonstrate each security anti-pattern. These apps:

- Are built via GitHub Actions and pushed to `ghcr.io`
- Log verbosely so we can see exactly what they're trying to do
- Fail gracefully (show error message) when blocked by hardening
- Are simple enough to understand in 30 seconds

### App 1: `vibe-privileged` - The Overpermissive Container

```
Behavior: Tries to run as root, mount host filesystem, access Docker socket
Logs: "Attempting to read /etc/shadow... SUCCESS/BLOCKED"
Blocked by: PSA, seccomp, AppArmor
```

### App 2: `vibe-phonehome` - The Data Exfiltrator

```
Behavior: Reads env vars/secrets, POSTs them to external endpoint
Logs: "Found SECRET_KEY=***, sending to https://evil.com... SUCCESS/BLOCKED"
Blocked by: Network Policy (egress deny), Kyverno (no secrets in env)
```

### App 3: `vibe-cryptominer` - The Resource Hog

```
Behavior: No resource limits, spawns CPU-intensive process, uses latest tag
Logs: "Starting mining on all cores... SUCCESS/BLOCKED"
Blocked by: Kyverno (require limits, deny latest tag), ResourceQuota
```

### App 4: `vibe-debugger` - The Syscall Abuser

```
Behavior: Attempts ptrace, loads kernel modules, raw sockets
Logs: "Attaching debugger to PID 1... SUCCESS/BLOCKED"
Blocked by: seccomp profile, AppArmor
```

### App 5: `vibe-filewriter` - The Path Traverser

```
Behavior: Writes to /etc/passwd, /proc/sys, sensitive paths
Logs: "Writing backdoor to /etc/cron.d/... SUCCESS/BLOCKED"
Blocked by: AppArmor, read-only root filesystem
```

### App 6: `vibe-lateral` - The Namespace Hopper

```
Behavior: Tries to reach services in other namespaces, scan cluster
Logs: "Scanning kube-system services... SUCCESS/BLOCKED"
Blocked by: Network Policy (namespace isolation)
```

### App 7: `vibe-cvemagnet` - The Vulnerable Dependency Collector

```
Behavior: Uses intentionally old base image + vulnerable packages
Image: Based on python:3.8-slim (older) with requests==2.5.0, urllib3==1.24.1
Logs: "App running with vulnerable dependencies... (check Trivy scan)"
Blocked by: Trivy Operator scan → Kyverno policy rejects Critical/High CVEs
```

### App 8: `vibe-leaky` - The Secret Logger

```
Behavior: Logs sensitive data to stdout (API keys, tokens, passwords)
Logs: "Connecting with API_KEY=sk-proj-abc123..." "JWT token: eyJhbG..."
Detected by: Falco pattern matching → alerts on secret patterns in output
```

### App 9: `vibe-snooper` - The RBAC Abuser

```
Behavior: Uses default ServiceAccount to query K8s API, list secrets across namespaces
Logs: "Listing secrets in kube-system... SUCCESS/BLOCKED"
Blocked by: Kyverno policy blocks automountServiceAccountToken, enforces scoped RBAC
```

### CI/CD Pipeline

```yaml
# .github/workflows/build-villain-apps.yaml
# Builds all villain apps and pushes to ghcr.io/<owner>/vibe-*
# Tags: latest + git SHA for reproducibility
```

---

## 🎬 Demo Flow (Story-Centric + Audience Choice)

The demo follows a narrative arc, with **audience voting** to pick which attacks to show.

### 📊 Live Polling (QR Code on Cover Slide)

```
┌─────────────────────────────────────────────────────────────────────┐
│  Cover Slide                                                        │
│                                                                     │
│  "Vibes Don't Scale: Kubernetes Hardening..."                       │
│                                                                     │
│  ┌─────────────┐  ◄── Scan to vote for demos!                       │
│  │ ▄▄▄▄▄ ▄▄▄▄ │      "Which attacks should we try?"                │
│  │ █   █ █  █ │                                                     │
│  │ ▀▀▀▀▀ ▀▀▀▀ │      □ Privileged container escape                 │
│  └─────────────┘      □ Data exfiltration                          │
│                       □ Crypto miner (no limits)                   │
│       QR Code         □ Syscall abuse (ptrace)                     │
│                       □ File path traversal                        │
│                       □ Namespace hopping                          │
│                       □ CVE-laden image                            │
│                       □ Secrets in logs                            │
│                       □ RBAC abuse                                 │
└─────────────────────────────────────────────────────────────────────┘
```

**Why this works:**

- 🎯 Engagement from second 1 - audience is invested before you speak
- 🎓 Expert-adapted content - DevOpsCon attendees skip what they know
- ⏱️ Natural time management - "You voted for 5 demos, let's do those"
- 🛡️ Fallback ready - if WiFi fails or nobody votes, use default order

**Tool options:**

- **Slido** - Free tier, great for conferences
- **Mentimeter** - Pretty live visualizations
- **Strawpoll** - Simplest, no signup needed

### 🚨 Polling Failure Recovery Plan

| Scenario                 | What You See      | What You Say                                                                              | What You Do                        |
| ------------------------ | ----------------- | ----------------------------------------------------------------------------------------- | ---------------------------------- |
| **WiFi down**            | QR won't load     | "Looks like the conference WiFi is having a moment. No worries - I'll pick my favorites." | Use default "Must" order           |
| **Zero votes**           | Empty results     | "Wow, tough crowd! Let me spin the wheel of misfortune..."                                | Use random picker (see below)      |
| **1-2 votes only**       | Sparse results    | "We have a couple of votes - let's honor those and I'll fill in the rest."                | Do voted ones + fill with defaults |
| **All options tied**     | Even distribution | "Democracy has spoken: you want to see everything! Let's randomize."                      | Use random picker                  |
| **One option dominates** | 80%+ on one       | "Clear winner! But since we have time, let's add a few more."                             | Do winner + 3-4 defaults           |
| **Poll site crashes**    | Error page        | "Tech demo karma strikes again. Luckily I came prepared."                                 | Use default order                  |

**Random Picker Script (`scripts/pick-demos.sh`):**

Create a reusable script in the repo that handles both scenarios:

```bash
#!/bin/bash
# Usage:
#   ./pick-demos.sh 3              # Pick 3 random demos (no preselection)
#   ./pick-demos.sh 3 1 4 7 9      # Pick 3 from preselected demos (tied votes)
#
# Examples:
#   ./pick-demos.sh 5              # Full random: pick 5 demos from all 9
#   ./pick-demos.sh 3 2 5 6 8 9    # 5 demos tied, pick 3 randomly from them

ALL_DEMOS=("privileged" "phonehome" "cryptominer" "debugger" "filewriter" "lateral" "cvemagnet" "leaky" "snooper")
COUNT=${1:-3}
shift

# If no preselection, use all demos
if [ $# -eq 0 ]; then
  echo "🎰 No preselection - picking $COUNT from all demos..."
  pool=("${ALL_DEMOS[@]}")
else
  echo "🎰 Picking $COUNT from $# tied demos..."
  pool=()
  for idx in "$@"; do
    pool+=("${ALL_DEMOS[$((idx-1))]}")  # Convert 1-based to 0-based
  done
fi

echo ""
sleep 0.5
selected=()
for ((i=1; i<=COUNT; i++)); do
  idx=$((RANDOM % ${#pool[@]}))
  pick="${pool[$idx]}"
  selected+=("$pick")
  # Remove from pool (no duplicates)
  pool=("${pool[@]:0:$idx}" "${pool[@]:$((idx+1))}")
  echo "  $i. vibe-$pick"
  sleep 0.3
done

echo ""
echo "🎯 Selected demos: ${selected[*]}"
echo "   Let's hack!"
```

**How to use during the talk:**

| Scenario          | Command                       | Example                     |
| ----------------- | ----------------------------- | --------------------------- |
| WiFi dead         | `./pick-demos.sh 5`           | Pick 5 random from all 9    |
| 5 demos tied      | `./pick-demos.sh 3 1 2 5 7 9` | Pick 3 from those 5         |
| Zero votes        | `./pick-demos.sh 4`           | Pick 4 random from all      |
| Want to add chaos | `./pick-demos.sh 1`           | Pick 1 random wildcard demo |

**Or use a visual wheel:** [wheelofnames.com](https://wheelofnames.com) - pre-load with demo names, spin live.

**Pro tip:** Practice the recovery lines so they sound natural, not scripted. The audience loves a speaker who handles chaos gracefully.

### Demo Flow

```
[Cover slide with QR code]
"Scan this while I set the scene - vote for which attacks to demo"
         │
         ▼
[Hook: 2 min]
"Devs are vibe-coding. The code works. The security doesn't."
(Voting happens async while you talk)
         │
         ▼
[Show poll results: 30 sec]
"You voted for: privileged, phonehome, debugger, CVE scan, RBAC abuse"
"Let's do it."
         │
         ▼
[Act 1: The Problem - 5 min]
Show TOP VOTED attacks on UNSAFE cluster:
• Works! Attacker wins. "This is your cluster by default."
         │
         ▼
[Act 2: The Solution Layers - 15 min]
Same deploys on HARDENED cluster:
• BLOCKED! Platform wins.
(Show each layer based on what audience voted for)
         │
         ▼
[Act 3: The Rollout - 5 min]
"How do you add this to a live cluster without breaking everything?"
• Audit mode → Warn mode → Enforce mode
         │
         ▼
[Conclusion: 2 min]
"Platform beats process. Here's the repo."
         │
         ▼
[Q&A]
```

### Demo Priority (Default Order if No Votes)

| Priority | App                | Shows                             | Time  |
| -------- | ------------------ | --------------------------------- | ----- |
| 🟢 Must  | `vibe-privileged`  | PSA blocks at admission           | 2 min |
| 🟢 Must  | `vibe-phonehome`   | NetworkPolicy blocks egress       | 3 min |
| 🟢 Must  | `vibe-debugger`    | seccomp blocks syscalls           | 2 min |
| 🟢 Must  | `vibe-filewriter`  | AppArmor blocks file writes       | 2 min |
| 🟡 Nice  | `vibe-cryptominer` | Kyverno requires limits           | 2 min |
| 🟡 Nice  | `vibe-snooper`     | Kyverno blocks RBAC abuse         | 2 min |
| 🟡 Nice  | `vibe-cvemagnet`   | Trivy + Kyverno blocks CVEs       | 3 min |
| 🟠 Bonus | `vibe-lateral`     | NetworkPolicy namespace isolation | 2 min |
| 🟠 Bonus | `vibe-leaky`       | Falco detects secrets in logs     | 3 min |

---

## Technology Stack

| Component          | Choice                      | Rationale                                |
| ------------------ | --------------------------- | ---------------------------------------- |
| Repo Structure     | Monorepo                    | Single clone, simple story for audience  |
| Versioning         | Semantic Release (single)   | All apps share version, auto-changelog   |
| Local K8s          | Minikube + Hyper-V          | Full AppArmor/seccomp, real Linux VMs    |
| Control Plane      | WSL2 (Ubuntu)               | Bash scripts, native Linux tooling       |
| Automation         | Bash + minikube.exe interop | No PowerShell, only .exe calls for VMs   |
| GitOps             | Flux                        | Lightweight, auto-deploys manifests      |
| Policy Engine      | Kyverno                     | Easier to read than OPA/Rego             |
| Vuln Scanning      | Trivy Operator              | In-cluster scanning, Kyverno integration |
| Runtime Detection  | Falco                       | Detects secrets in logs, syscall abuse   |
| Container Runtime  | containerd (via Minikube)   | Default, AppArmor + seccomp support      |
| Demo Apps          | Custom "villain" apps       | Verbose logging, built via GH Actions    |
| Container Registry | ghcr.io (public)            | Free, no imagePullSecrets needed         |

---

## ❓ Open Questions for Discussion

1. **Kyverno vs OPA Gatekeeper?**

   - Kyverno is more readable (YAML-native) → **Current choice**
   - OPA/Gatekeeper is more common in enterprise
   - Could mention both exist, but demo uses Kyverno

2. **Interactive demo vs scripted?**

   - Fully manual kubectl commands (more authentic, more risk)
   - Semi-scripted with a demo.sh that prompts you
   - Pre-baked terminal recordings as backup (asciinema) → **Will create as insurance**

---

## ✅ Next Steps

Once we agree on the plan:

### Phase 1: Villain Apps & CI/CD

1. [ ] Create `vibe-privileged` app (Dockerfile + Python script)
2. [ ] Create `vibe-phonehome` app
3. [ ] Create `vibe-cryptominer` app
4. [ ] Create `vibe-debugger` app
5. [ ] Create `vibe-filewriter` app
6. [ ] Create `vibe-lateral` app
7. [ ] Create `vibe-cvemagnet` app (intentionally vulnerable deps)
8. [ ] Create `vibe-leaky` app (logs secrets to stdout)
9. [ ] Create `vibe-snooper` app (RBAC abuse)
10. [ ] Set up semantic-release config (`.releaserc`)
11. [ ] Create GitHub Actions release workflow
12. [ ] Test release + image push to ghcr.io

### Phase 2: Cluster Setup

13. [ ] Install/verify Minikube (Windows) + WSL2 + Hyper-V + Flux CLI
14. [ ] Create cluster setup script (Bash + minikube.exe interop)
15. [ ] Create Flux kustomizations for unsafe cluster (apps only)
16. [ ] Create Flux kustomizations for hardened cluster (apps + hardening)
17. [ ] Create kubeconfig export script for WSL
18. [ ] Test Flux bootstrap on both clusters

### Phase 3: Hardening Policies

19. [ ] Create PSA namespace labels
20. [ ] Write Kyverno policies
21. [ ] Create network policies
22. [ ] Set up seccomp profiles
23. [ ] Set up AppArmor profiles
24. [ ] Install Trivy Operator + CVE-blocking Kyverno policy
25. [ ] Install Falco + secret detection rules

### Phase 4: Demo Polish

26. [ ] Write demo runbook / cheat sheet
27. [ ] Create `scripts/pick-demos.sh` (random demo picker for ties/no votes)
28. [ ] Create `scripts/demo-aliases.sh` (bash aliases for faster typing during demo)
    - `k` → `kubectl`
    - `ku` → `kubectl --context=unsafe`
    - `kh` → `kubectl --context=hardened`
    - `kua` → `kubectl --context=unsafe apply -f`
    - `kha` → `kubectl --context=hardened apply -f`
    - `kul` → `kubectl --context=unsafe logs`
    - `khl` → `kubectl --context=hardened logs`
    - `kud` → `kubectl --context=unsafe delete -f`
    - `khd` → `kubectl --context=hardened delete -f`
29. [ ] Test full flow end-to-end
30. [ ] Create terminal recording backup (asciinema)
31. [ ] (Optional) Create slides template

---

## 📝 Notes

- Conference date: Check DevOpsCon Amsterdam 2026 dates
- CFS deadline: https://sessionize.com/devopsconmlcon-2026/
- Backup plan: Have a recorded video of the entire demo in case of laptop failure
