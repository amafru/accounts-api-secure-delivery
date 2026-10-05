# Section 5: Admission and runtime

Threats: **T1** and **T2** (signed images), **T3** (host escape, lateral movement, exfiltration), **T4** (credential theft), **T5** (resource limits).

## Admission policies: mode on day one and what promotes them

Cluster is shared with other teams, so every policy is scoped to the `accounts` namespace first. Widening is a separate step per namespace, each starting in Audit.

| Policy (file) | Day one | Promotion to Enforce |
|---|---|---|
| `accounts-baseline-critical`: no privileged, no host namespaces, no hostPath (`policies/kyverno/accounts-baseline.yaml`) | **Enforce** | n/a. These are takeover paths with no legitimate use in this workload, so waiting only extends exposure |
| `accounts-rbac-guard`: no wildcard or secrets access in Roles | **Enforce** | n/a. Same reasoning |
| `accounts-baseline-hygiene`: non-root hardening, requests and limits, pinned approved image, no secret env vars | **Audit** | 14 consecutive days with zero failures in the namespace's policy reports, and the CI manifest tests green. These could break a working deployment, so we measure first |
| `accounts-verify-images`: signed by the pipeline KMS key (`policies/kyverno/verify-images.yaml`) | **Audit** | Every running `accounts-api` pod verified for 14 days, and a rehearsed key-rotation overlap (two keys trusted). Not enforceable until `cosign.pub` is real |

**Exceptions:** by namespace name for now. Any exception is a dated, reviewed entry, in line with the Section 3 waiver rule.

**Evidence:** `kyverno test policies/kyverno/tests` (before: original rejected; after: fix accepted). **Executed**: 48 passed, 0 failed (`docs/evidence/kyverno-test.txt`). `verifyImages` cannot be tested offline because it needs registry access.

## Runtime detection

One custom Falco rule for this workload: any process other than the service reading the database credential file. Full rule, alert payload, routing, on-call owner and three-step runbook: `runtime/falco/detection-and-runbook.md`. Not executed here.

## Egress: allow the KYC provider, deny the rest

**Layer argued for: Kubernetes NetworkPolicy** (`policies/network/accounts-api-egress.yaml`). Default-deny for the namespace, then `accounts-api` may reach only CoreDNS, Postgres (5432) and the KYC provider (443).

Why this layer: built in, reviewable as code, enforced below the application so a compromised container cannot switch it off, and it needs no change to the shared cluster's CNI choice.

**What it still fails to stop:**
- **IP-based only.** NetworkPolicy cannot allow a hostname. If the KYC provider changes IPs or sits on a shared CDN, the list is either stale (outage) or too broad (other tenants of that CDN are reachable).
- **DNS exfiltration.** DNS must stay open, so data can leave encoded in lookups to an attacker's name server.
- **Anything inside the allowed 443 flow**, including data sent to the KYC provider's own address by a compromised pod.
- **Depends on the CNI actually enforcing NetworkPolicy** (VPC CNI network policy support or Calico). Unconfirmed in this submission.
- Node-network pods bypass it, which is why `hostNetwork` is blocked at admission.

**Next layer (not built):** a VPC-level domain allowlist (AWS Network Firewall on SNI) or Cilium FQDN policy, plus DNS query logging.

## Traceability and deprioritised

Controls here map to T1 to T5. **Deliberately not built:** admission coverage for bare `Pod`s created outside controllers beyond what autogen provides, ClusterRole guarding (system roles use wildcards), and a service mesh for mTLS. Compensating cover: RBAC guard blocks wildcard and secrets access in Roles (known gap: init and ephemeral containers, and RoleBindings to powerful ClusterRoles, are not yet covered), and traffic is limited by NetworkPolicy.
