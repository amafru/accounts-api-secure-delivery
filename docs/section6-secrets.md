# Section 6: Secrets

Threats: **T2** (no secrets in pipeline), **T3** and **T4** (stolen or misused credential).

## Delivery (`secrets/external-secrets.yaml`)
Secrets Manager is the source of truth. External Secrets Operator (ESO) syncs it into a Kubernetes Secret, mounted as a **file** (not env vars). Nothing sensitive lives in git, manifests or workflow files. ESO's role should read only the one DB secret. **Not built here:** the `eso-reader` ServiceAccount and its IAM policy are placeholders to be created.

Honest limit: the synced secret sits in etcd. **Encrypt etcd at rest** with an EKS KMS envelope key (secrets encryption on the cluster), otherwise anyone with node or etcd access reads it in clear base64.

## Rotation

| Credential | Mechanism | Normal rotation | Emergency target |
|---|---|---|---|
| RDS database password | RDS-managed master password rotation (no custom Lambda). Schedule not set in this repo | target every 30 days | **under 10 minutes** |
| KMS signing key | Key alias swap, both public keys trusted during overlap | yearly | under 1 hour |
| Pipeline AWS access | OIDC, no stored key: nothing to rotate. Role session is 1 hour | n/a | n/a |
| Third-party KYC API key | Secrets Manager entry (no ExternalSecret written for it yet), manual with provider | 90 days | under 1 hour |

**Emergency rotation (DB password), in order:**
1. `aws secretsmanager rotate-secret --secret-id <rds secret>` (new password set in RDS and Secrets Manager).
2. Force ESO to resync now instead of waiting up to 15 minutes: `kubectl -n accounts annotate externalsecret accounts-api-db force-sync=$(date +%s) --overwrite`.
3. Restart the pods: `kubectl -n accounts rollout restart deploy/accounts-api` (the app reads the file at start).
4. Check the DB for sessions still using the old credential and terminate them.
5. CloudTrail: list `GetSecretValue` calls in the exposure window.

Weakest step: the app must tolerate a restart. Without that, rotation causes an outage and people hesitate to rotate.

## Log redaction

**Design only: no application logging or Fluent Bit configuration exists in this repo.** The table is what I would build and where.

| Layer | What is redacted | How |
|---|---|---|
| Pipeline (GitHub Actions) | Secrets and any value derived from them | GitHub `secrets` masking; no `set -x`; Gitleaks gate blocks committed secrets |
| Application | Passwords, tokens, card numbers (PAN), national ID | Structured logging with a redaction filter on field names, plus a PAN pattern check |
| Cluster logs | Same patterns, as a second pass | Log shipper filter (Fluent Bit) before leaving the cluster |

**What this still leaks:** GitHub masking only matches exact values, so a transformed secret (base64, split or URL-encoded) is not masked. Field-name redaction misses secrets in free-text messages and exception stacks. Pattern matching has false negatives. Treat logs as sensitive, restrict who can read them.

## Encryption statement
**Target state:** RDS, ECR, etcd secrets and CloudTrail encrypted with customer-managed KMS keys. **In this repo today:** RDS uses a customer-managed key (`review/terraform/fixed`); ECR uses KMS without a named key (AWS-managed fallback); CloudTrail and etcd encryption are not configured here, they are the next step. Key custody: platform team administers, only the service roles can use them, and the signing key admins hold no `kms:Sign` grant (see `docs/section2-build-integrity.md` for the key-policy caveat). This addresses **T3 and T4**: stolen disk, snapshot or backup is unreadable without the key. It does not stop an attacker already running as the service.
