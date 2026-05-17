# Kubernetes Container Security Pipeline

**Project 1 of 2 — Hands-On DevSecOps Portfolio**  
Oluwaseyi Michael Falode | Cybersecurity & Cloud Security Engineer | Toronto, ON | May 2026

---

A complete three-layer Kubernetes container security pipeline built from scratch on a local Minikube cluster. Every command was run live in a real terminal. Every screenshot was captured during the actual session. Nothing was simulated.

## Project at a Glance

| | |
|---|---|
| **Tools** | Trivy · OPA Gatekeeper · Falco · Helm · Minikube · kubectl |
| **Platform** | macOS — Docker Desktop v29.1.3 — Minikube v1.38.1 — Kubernetes v1.35.1 |
| **Languages** | YAML (configuration) · Rego (OPA policy language) |
| **Frameworks** | CIS Kubernetes Benchmark · NIST SP 800-190 Container Security |
| **MITRE ATT&CK** | T1610 Deploy Container · T1543 Create Process · T1057 Process Discovery |
| **Completed** | Saturday, May 16, 2026 |

## The Problem This Project Solves

Containers are the backbone of modern application infrastructure. The problem is that security is often an afterthought — teams deploy containers quickly and check for security issues later, if at all.

This creates three dangerous gaps at different stages of the container lifecycle:

- **Gap 1 — Before deployment:** The container image itself may contain known vulnerabilities. A developer downloads a standard image and deploys it without ever checking what is inside.
- **Gap 2 — At deployment:** Even if the image is clean, the way the container is configured can be dangerous — for example, running with root access or access to the host machine's network.
- **Gap 3 — During runtime:** Even if the image is clean and the configuration is correct, something can still go wrong after the container starts running. An attacker might exploit a vulnerability and start running commands inside the container.

This pipeline addresses all three gaps simultaneously using three purpose-built open-source tools — one for each layer of risk.

## Pipeline Architecture

```
IMAGE IN REGISTRY (Docker Hub / ECR)
          |
  TRIVY  (Layer 1 — Before Deployment)     Scans image for CVEs, secrets, misconfigs
  Blocks: CRITICAL and HIGH severity CVEs
          |
          | image passes scan
          | kubectl apply / helm install
          v
  OPA GATEKEEPER  (Layer 2 — At Deployment)   Intercepts every deployment.
  Blocks: root containers, bad configs         Blocks policy violations.
          |
          | passes all policies
          | CONTAINER RUNNING IN POD ON NODE
          v
  FALCO  (Layer 3 — During Runtime)        Watches every syscall.
  Detects: shell spawns, file reads, exfil  Alerts in under 3 seconds.
```

## Repository Structure

```
k8s-container-security-pipeline/
├── gatekeeper/
│   ├── constraint-template.yaml   # Rego policy defining the no-root rule
│   ├── constraint.yaml            # Activates the policy across namespaces
│   ├── bad-pod.yaml               # Test pod with runAsUser: 0 (blocked)
│   └── good-pod.yaml              # Test pod with runAsUser: 1000 (allowed)
├── screenshots/
│   └── (18 screenshots from the live session)
├── docs/
│   └── Project1_K8s_Security_Pipeline_FINAL.pdf
└── README.md
```

## What Was Built — Full Results

| Deliverable | Outcome |
|---|---|
| Kubernetes cluster | Minikube v1.38.1 — single node, Kubernetes v1.35.1 — fully operational |
| OPA Gatekeeper | v3.17.1 deployed — validating webhook active — 20+ resources created |
| No-root policy | ConstraintTemplate + Constraint applied — enforced in default namespace |
| Bad pod test | runAsUser: 0 rejected at admission layer — pod never created or scheduled |
| Good pod test | nginx-unprivileged + runAsUser: 1000 — Running 1/1, 0 restarts |
| Trivy scan — nginx | 233 vulnerabilities found: CRITICAL: 3, HIGH: 22, MEDIUM: 86 |
| Trivy scan — unprivileged | 232 vulnerabilities found: CRITICAL: 3, HIGH: 21 — same Debian base OS |
| Falco deployment | Helm install — STATUS: deployed — falco pod Running 2/2 — eBPF active |
| Falco live alert | Shell spawn detected in <3 seconds — full forensic metadata logged |

---

## Step-by-Step Walkthrough

### Step 1 — Environment Check & Tool Installation

Verified all required tools before writing a single line of configuration.

```bash
docker --version         # check Docker version
kubectl version --client # check kubectl version
which trivy              # check if Trivy is installed
which minikube           # check if Minikube is installed
```

**Result:** Docker v29.1.3 ✓  kubectl v1.34.1 ✓  trivy: not found ✗  minikube: not found ✗

Installed missing tools via Homebrew:

```bash
brew install minikube    # installs Minikube
brew install trivy       # installs Trivy
```

**Result:** Minikube v1.38.1 ✓  Trivy v0.70.0 ✓

---

### Step 2 — Kubernetes Cluster Deployment

Started a single-node Kubernetes cluster inside Docker Desktop using Minikube.

```bash
minikube start --driver=docker
```

Minikube downloaded Kubernetes v1.35.1, created a Docker container as the cluster node (2 CPUs, 4600MB RAM), installed all Kubernetes internal components, and automatically configured kubectl.

```bash
kubectl get nodes                  # list all nodes in the cluster
kubectl get pods --all-namespaces  # list all running system pods
```

**Result:** minikube node STATUS=Ready, VERSION=v1.35.1. All 7 system pods Running in kube-system namespace with 0 restarts.

---

### Step 3 — OPA Gatekeeper — Admission Control

Installed OPA Gatekeeper v3.17.1 as a validating admission webhook. From this point forward, Kubernetes must ask Gatekeeper for approval before creating any resource.

```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.17.1/deploy/gatekeeper.yaml
```

**Result:** 20+ resources created including validatingwebhookconfiguration. All 4 gatekeeper-system pods Running.

Created project folder structure:

```bash
mkdir ~/devsecops-project && cd ~/devsecops-project
mkdir gatekeeper    # subfolder for all policy files
```

---

### Step 4 — Writing the No-Root Security Policy

#### ConstraintTemplate (`gatekeeper/constraint-template.yaml`)

Defines the rule logic in Rego. Checks every container in an incoming deployment request — if `runAsUser` is set to `0` (root), that is a violation.

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8snorootcontainers
spec:
  crd:
    spec:
      names:
        kind: K8sNoRootContainers
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8snorootcontainers
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          c.securityContext.runAsUser == 0
          msg := sprintf("BLOCKED: Container '%v' runs as root (UID 0)", [c.name])
        }
```

#### Constraint (`gatekeeper/constraint.yaml`)

Activates the ConstraintTemplate across all Pods in the cluster, excluding system namespaces.

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoRootContainers
metadata:
  name: deny-root-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces:
      - kube-system
      - gatekeeper-system
```

Applied both files:

```bash
kubectl apply -f ~/devsecops-project/gatekeeper/constraint-template.yaml
kubectl apply -f ~/devsecops-project/gatekeeper/constraint.yaml
```

**Result:** constrainttemplate k8snorootcontainers created ✓  constraint deny-root-containers created ✓  Policy now active.

---

### Step 5 — Testing Policy Enforcement

#### Test A — Bad Pod (`gatekeeper/bad-pod.yaml`)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: default
spec:
  containers:
  - name: bad-container
    image: nginx
    securityContext:
      runAsUser: 0  # ROOT USER — should be blocked
```

**Result:** Admission webhook "validation.gatekeeper.sh" denied the request. Error: BLOCKED: Container bad-container runs as root (UID 0). Pod never created.

#### Test B — Good Pod (`gatekeeper/good-pod.yaml`)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: default
spec:
  containers:
  - name: good-container
    image: nginxinc/nginx-unprivileged   # security-conscious image
    securityContext:
      runAsUser: 1000
```

**Result:** STATUS=Running, READY=1/1, RESTARTS=0. Policy passed, container healthy.

> **Key lesson:** The standard `nginx` image requires root to bind port 80 — it CrashLoopBackOffs with `runAsUser: 1000`. The fix is `nginxinc/nginx-unprivileged`, which binds port 8080 and is built to run as a non-root user.

| Pod | Configuration | Result |
|---|---|---|
| bad-pod (nginx) | runAsUser: 0 (root) | BLOCKED |
| good-pod v1 (nginx) | runAsUser: 1000 — wrong image | CrashLoopBackOff |
| good-pod v2 (nginx-unprivileged) | runAsUser: 1000 — correct image | Running |

---

### Step 6 — Trivy Image Vulnerability Scanning

Scanned container images for known CVEs before deployment (Layer 1 of the pipeline).

```bash
trivy image nginx
trivy image nginxinc/nginx-unprivileged 2>/dev/null | grep 'Total:'
```

| Image | CRITICAL | HIGH | MEDIUM | TOTAL |
|---|---|---|---|---|
| nginx (standard) | 3 | 22 | 86 | 233 |
| nginxinc/nginx-unprivileged | 3 | 21 | 86 | 232 |

Both images have nearly identical vulnerability counts because they are both built on Debian Linux. The vulnerabilities come from the underlying OS packages, not from nginx itself. A truly hardened image would use Alpine Linux as the base OS.

**Notable finding:** The `bash` package inside the nginx image has a privilege escalation vulnerability (TEMP-0841856). An attacker who gains any level of access inside the container could potentially escalate privileges using this vulnerability.

---

### Step 7 — Falco Runtime Threat Detection

Installed Falco as the third and final security layer. While Trivy and Gatekeeper prevent problems before and at deployment, Falco watches what actually happens inside containers while they are running.

```bash
# Add Falco chart repository to Helm
helm repo add falcosecurity https://falcosecurity.github.io/charts

# Update repository
helm repo update

# Install Falco with eBPF driver
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true
```

**Result:** STATUS=deployed. falco pod Running 2/2. eBPF agents spinning up on all nodes and monitoring all containers.

#### Triggering a Live Alert

Opened an interactive shell inside the running container to simulate a post-exploitation scenario:

```bash
kubectl exec -it good-pod -- /bin/sh
$ whoami    # ran inside the container — shows user 1000
$ exit      # exited the container shell
```

Immediately read the Falco logs:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20
```

**Result:** Falco fired an alert in under 3 seconds:

> "Notice A shell was spawned in a container with an attached terminal."  
> Metadata: `user_uid=1000, process=sh, container=good-pod, image=nginx-unprivileged, namespace=default`

The alert contains everything a security operations team needs to investigate and respond: who triggered it, what process was spawned, which container, which image, and which namespace. In a production environment this alert would be forwarded to a SIEM (Splunk, Elasticsearch) and could trigger an automated response — isolating the pod or cordoning the node — within seconds.

---

## How to Reproduce This Project

**Prerequisites:** Docker Desktop, Homebrew (macOS)

```bash
# 1. Install tools
brew install minikube trivy

# 2. Start cluster
minikube start --driver=docker

# 3. Verify cluster
kubectl get nodes
kubectl get pods --all-namespaces

# 4. Install OPA Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.17.1/deploy/gatekeeper.yaml

# 5. Apply the no-root policy
kubectl apply -f gatekeeper/constraint-template.yaml
kubectl apply -f gatekeeper/constraint.yaml

# 6. Test enforcement
kubectl apply -f gatekeeper/bad-pod.yaml   # should be BLOCKED
kubectl apply -f gatekeeper/good-pod.yaml  # should be allowed

# 7. Scan images with Trivy
trivy image nginx
trivy image nginxinc/nginx-unprivileged

# 8. Install Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true

# 9. Trigger and observe a Falco alert
kubectl exec -it good-pod -- /bin/sh
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=20
```

---

## Security Frameworks Referenced

- **CIS Kubernetes Benchmark** — industry-standard hardening guide for Kubernetes clusters
- **NIST SP 800-190** — Application Container Security Guide
- **MITRE ATT&CK** — T1610 (Deploy Container), T1543 (Create Process), T1057 (Process Discovery)

---

*Oluwaseyi Michael Falode · Cybersecurity & Cloud Security Engineer · Toronto, ON · May 2026*
