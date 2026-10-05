# accounts-api: secure delivery (assessment submission)

Placeholders (account `123456789012`, `ap-south-1`, IP ranges `10.20.30.0/24`, `203.0.113.0/28`, `EXAMPLE-ORG`) stand in for real values. Controls are tagged `[T1]` to `[T5]` to the threat model in `docs/threat-model.md`.

## Where things are
| Brief section | Files |
|---|---|
| 1 Threat model | `docs/threat-model.md` |
| 2 Build integrity | `.github/workflows/build-release.yml`, `infra/`, `cosign.pub`, `docs/section2-build-integrity.md` |
| 3 Gates and waivers | `.github/workflows/security-gates.yml`, `.security/`, `CODEOWNERS`, `docs/section3-gates.md` |
| 4 Review and remediate | `review/` (original and fixed), `docs/section4-review-remediate.md`, `docs/evidence/` |
| 5 Admission, runtime, egress | `policies/`, `runtime/falco/`, `docs/section5-admission-runtime.md` |
| 6 Secrets | `secrets/`, `docs/section6-secrets.md` |
| Part 2 decisions | `docs/decisions.md` |

## Run the policy tests (reviewer)
Needs Python 3.10+, [Kyverno CLI](https://kyverno.io/docs/kyverno-cli/), and `pip install checkov pytest pyyaml`.

```bash
# Kyverno: before/ must be rejected, after/ must pass
kyverno test policies/kyverno/tests

# Checkov custom Terraform policies: original fails, fixed passes
bash policies/checkov/test.sh

# Waiver checker unit tests, and a manual run
(cd .security && pytest -q)
python .security/check_waivers.py .security/waivers.yaml .trivyignore
```
CI runs the Kyverno and Checkov tests in the `policy-tests` job and the waiver tests in the `waivers` job (`security-gates.yml`).

## Not executed or not real yet
- `kyverno test` passes (48 of 48, `docs/evidence/kyverno-test.txt`). The Falco rule has not been run against a live Falco, and `verifyImages` needs registry access so is not testable offline.
- `build-release.yml` is a blueprint: there is no Dockerfile or app source here, and it will fail until a real image and `cosign.pub` exist.
- Placeholders to supply: org and team names in `CODEOWNERS`, `security-lead` and `security-deputy` in `check_waivers.py`, the `security-admin` role ARN, `rds!db-EXAMPLE`, the `eso-reader` ServiceAccount, `EXAMPLE-KEY-ID`, `AWS_BUILD_ROLE_ARN`, PagerDuty and Slack targets.
- Known gaps: Kyverno critical rules cover `containers` only (init and ephemeral containers) and RBAC guard covers Roles only (a RoleBinding to a powerful ClusterRole passes). First fix after SHA pinning.
- The example waiver in `.security/waivers.yaml` expires 2026-11-04.
- `cosign.pub` is a placeholder until the KMS key is created.
- GitHub Actions are pinned by tag, not SHA (first Monday task).
- No production deploy job, so no manual-approval stage exists.
