# Section 4: Review and remediate

Threats: **T3** over-privileged identity and lateral movement, **T1** supply chain, **T4** secrets and insider, **T5** DoS. Ranked by exploitability in this environment (shared multi-tenant EKS, PII and card data, one RCE away from the pod), not by scanner severity.

Fixed files: `review/workload/fixed/accounts-api.yaml`, `review/terraform/fixed/main.tf`, `review/iam/pod-role-policy.fixed.json`.
Prevention: `policies/kyverno/` (admission) and `policies/checkov/` (IaC scan). Evidence: `docs/evidence/`.

## (a) Workload manifest and RBAC

| Rank | Defect | Why it ranks here | Fix |
|---|---|---|---|
| 1 | `/var/run/docker.sock` mounted via hostPath | Anyone with code execution in the pod can ask the node's Docker daemon to start a privileged container: full node takeover, then every tenant on that node. Note the manifest says `privileged: false`, which is irrelevant here. | Mount removed. Kyverno `no-hostpath` blocks all hostPath volumes |
| 2 | Role grants `*` on `secrets`, `pods`, `configmaps` | Read every secret in the namespace and create pods (mount hostPath, borrow another service account): a second route to node escape | One `get` on one named ConfigMap. Kyverno `no-wildcard-or-secrets-rbac` |
| 3 | `hostNetwork: true` | Pod shares the node's network: bypasses NetworkPolicy, reaches node-local services (kubelet, metadata) | `hostNetwork: false`. Kyverno `no-host-namespaces` |
| 4 | hostPath `/var/log` mounted | In a shared cluster `/var/log` holds other tenants' pod logs, which contain PII | Removed (same rule as 1) |
| 5 | Runs as root (`runAsUser: 0`), no `allowPrivilegeEscalation: false`, writable filesystem, no dropped capabilities, no seccomp | Amplifies every defect above (root can use the socket and write to host mounts) | Non-root UID 10001, read-only root FS, all capabilities dropped, seccomp `RuntimeDefault`. Kyverno `nonroot-hardening` |
| 6 | DB credentials via `envFrom` secretRef | Readable from `/proc/<pid>/environ`, crash dumps, debug endpoints | Mounted as a read-only file from `accounts-api-db`. Kyverno `no-secret-env` |
| 7 | `image: ...:latest` | Mutable and unpinned: a supply-chain swap needs no change to the manifest | Pinned by digest from the approved ECR. Kyverno `pinned-approved-image` |
| 8 | No CPU or memory requests or limits | One pod can starve the node and its neighbours (T5) | Requests and limits set. Kyverno `require-resources` |

**Left as is, deliberately:** liveness and readiness probes (reliability, not exploitability; I don't know the app's health endpoints), and `automountServiceAccountToken` (stays on because the Role reads one ConfigMap; reach is that single object).
**Also fixed, not a security finding:** the original had no `selector`/labels, which `apps/v1` requires.
**Not yet in place:** a NetworkPolicy (Section 5).

### How the policy prevents recurrence

The scanner is not the control. The control is **admission**: Kyverno rejects the pod or Role at the API server, so a future copy-pasted manifest fails regardless of who wrote it. Shift-left scanning only catches what goes through the pipeline, and admission catches `kubectl apply` too.

Two design choices worth defending:
- The rule set targets **paths to the host and to other tenants**, not just the `privileged` flag. The original would have passed a pure "no privileged containers" policy, so `no-privileged` passes on it in the "before" test, which shows the trap.
- A built-in scanner check for the Docker socket exists, but **nothing built in flags the `/var/log` hostPath**. The blanket `no-hostpath` rule does.

## (b) Terraform

| Rank | Defect | Why | Fix |
|---|---|---|---|
| 1 | `publicly_accessible = true` plus Postgres (5432) open to `0.0.0.0/0` | Each alone is half a problem; together the production database is on the internet and only a password stands between it and the data | Private; ingress only from the pod security group |
| 2 | CloudTrail not multi-region, no log-file validation, no global events | Activity in other regions and all IAM and STS calls are invisible, and log tampering is undetectable: attackers and insiders act unseen (T4) | All three set to true |
| 3 | `password = var.db_password` | Plaintext credential in Terraform state and variables, never rotated, shared by whoever can read state | `manage_master_user_password = true`; RDS stores and rotates it in Secrets Manager |
| 4 | `backup_retention_period = 0` and `skip_final_snapshot = true` | Deletion, ransomware or a bad migration is unrecoverable | 14 days retention, final snapshot, deletion protection |
| 5 | `storage_encrypted = false` | Data at rest readable from snapshots or disks. Least directly exploitable here | Encrypted with a customer-managed KMS key |

**Prevention:** ten Checkov custom policies (`policies/checkov/CKV2_ACCT_001` to `010`) plus `policies/checkov/test.sh`, which asserts the original **fails** and the fix **passes**. **Executed:** original 10 failed, 0 passed; fixed 10 passed, 0 failed (`docs/evidence/checkov-terraform.txt`).

## (c) IAM policy on the pod identity role

**Defects, in order:** (1) `Allow` with `NotAction` on `Resource: *` means every action except two IAM deletes: near-admin, including creating users and attaching policies, so an RCE becomes account takeover. (2) `secretsmanager:GetSecretValue` on `*` reads every secret in the account. (3) `kms:Decrypt` on `*` decrypts anything the key policies allow.

**Shipped version:** `GetSecretValue` on the one RDS-managed secret ARN pattern, and `kms:Decrypt` on one key only when called through Secrets Manager.

**One line, what mine denies that the original allowed:** everything except reading one database secret and decrypting with one key (no IAM changes, no other secrets or keys, no other AWS services).

Honest limits: the secret ARN pattern `rds!db-*` is the RDS-managed naming and should be narrowed to the exact ARN after the first apply; the key ARN is a placeholder. Statement 2 of the original showed a garbled `Resource` in the brief; I read it as `*`.

## Evidence and what was and was not executed

| Check | Status |
|---|---|
| Checkov custom Terraform policies, before and after | **Executed**, output in `docs/evidence/checkov-terraform.txt` |
| Checkov built-in Kubernetes checks | **Executed**: original 21 failed, fixed 4 failed (readiness and liveness probes, deliberately left; token mount, deliberate; no NetworkPolicy, Section 5) |
| `kyverno test` on the Kyverno policies | **Executed**, 48 passed, 0 failed (Kyverno 1.19.1), output in `docs/evidence/kyverno-test.txt`. CI runs the same |

## Overall ranking across all three artefacts (by time to impact, my judgement)

Ranked by how fast an attacker with code execution in the pod reaches the node, other tenants or customer data. Defects are in the three `original` files: `review/workload/original/accounts-api.yaml`, `review/terraform/original/main.tf`, `review/iam/pod-role-policy.original.json`. The defect themes were drafted with AI help and I then did the ranking and the reasoning below.

**Tier 1: seconds**
1. Docker socket `hostPath` (plus the `/var/log` hostPath, also a known node-escape route). Gives the node's container runtime, so root on the node and every tenant on it, even with `privileged: false`.
2. Public RDS with `0.0.0.0/0` on 5432. Needs no foothold at all: only a password stands between the internet and customer data.
3. Plaintext DB password. Pairs with #2: password in state plus a public database is a one-step compromise.
4. Role with `*` on secrets, pods and configmaps. Dumps credentials and can schedule pods on other nodes.

**Tier 2: minutes**
5. IAM `NotAction` on `*`. Near-admin on the whole account. It covers everything in #6, so #6 is moot if this exists.
6. `GetSecretValue` and `kms:Decrypt` on `*`. Every secret in the account.
7. `hostNetwork: true`. Shares the node network: sniff other pods, reach the node metadata service.
8. Secrets via `envFrom`. Lower than it looks: code running in the app can read the secret anyway, this mainly adds leakage through crash logs and `kubectl describe`. Hygiene, not a path.

**Tier 3: minutes to hours**
9. Root user. Needs a second exploit (container breakout) to matter.

**Tier 4: drift and visibility**
10. `:latest` tag and no limits (DoS, instability, no reproducible rollback).
11. No backups and unencrypted storage (ransomware and offline snapshot reads).
12. CloudTrail single-region with no log validation (does not speed the attacker up, but they stay invisible, and it blinds T4 insiders).

**Disagreement worth noting:** scanner severity would put "unencrypted storage" and "root user" above `envFrom`, and would treat the public database as one finding among many. I rank by foothold needed and time to impact instead.
