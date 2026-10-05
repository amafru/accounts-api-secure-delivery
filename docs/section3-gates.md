# Section 3: Pipeline gates and the waiver path

Threats served: **T1** supply chain (SCA, IaC), **T2** pipeline compromise (waivers cannot be silently abused), **T2** insider and secret exposure (history scan). Workflow: `.github/workflows/security-gates.yml`.

## Tools (one line each)

| Category | Tool | Why | Gave up |
|---|---|---|---|
| SCA + IaC | Trivy | One binary covers dependencies and Terraform/K8s misconfig, which keeps the pipeline small | Best-of-breed IaC depth (Checkov), used for the Section 4 prevention rules |
| SAST | Semgrep | Fast, rule-based, tunable by us; prioritised first | Deep data-flow analysis a heavier SAST would offer |
| Secrets | Gitleaks | Scans every commit on every branch (`--log-opts=--all`, `fetch-depth: 0`), not just the diff | Live validation of whether a found key is still active |

Roadmap: best-in-class per category once the baseline is trusted.

## Severity thresholds

- **Blocks a merge:** Trivy HIGH/CRITICAL *that has a fix available*; Semgrep `ERROR`; any Gitleaks finding.
- **Reports only:** unfixed vulnerabilities, Semgrep `WARNING`.
- **Reasoning:** a gate engineers cannot act on gets disabled. "Fixable and serious" is actionable today. Secrets block at any severity because a leaked credential is never low risk and false positives are cheap to allowlist.

## Waiver mechanism (read this one first)

**Shape:** an in-repo register, `.security/waivers.yaml`, checked by `.security/check_waivers.py` on every run.

| Question | Answer |
|---|---|
| Who approves? | A named security reviewer. `approver` must be in the reviewer set, and CODEOWNERS forces a security-team review on any change to the file |
| Where does it live? | In the repo, versioned, diffable. Signed commits are required by branch protection |
| What does a waiver cover? | One finding in one scope (e.g. `CVE-x` in `requirements.txt:libY`), never a whole tool |
| What must it contain? | Reason, compensating control, ticket, approver, dates (all required, else the build fails) |
| How does it expire? | Hard cap of 30 days from approval. `expires_on` in the past fails the build |
| What happens on lapse? | Two things at once: the entry is dropped from the generated `.trivyignore`, so the finding blocks again, and the checker exits 1 naming the waiver. Demonstrated in the tests (`test_expired_waiver_fails_and_is_not_active`) |

Why this shape: waivers that never expire become permanent holes, and a gate with no waiver path gets switched off. A short, specific, auditable exception keeps the gate alive.

**Honest limits:** branch protection (signed commits, required reviews, CODEOWNERS enforcement) is repository configuration, not code in this repo; the check script cannot prove it is switched on. The approver list is duplicated in the script and CODEOWNERS and could drift. A security admin could still approve a bad waiver; the audit trail catches it afterwards, not before.

## Break-glass (production down)

`workflow_dispatch` with a required `incident_id` and `reason`, running in a protected `break-glass` environment that needs two named approvers. The gates **still run and report**; only blocking is lifted. The job opens a `security-review` issue recording actor, reason, incident id and run link, with a 24h post-incident review.

**Gap:** this submission wires the audit record and approval; the exact "lift blocking" switch for a given deployment job is not implemented here.

## False-positive load and first tuning

Expect noise mainly from Semgrep rules on generic patterns and from Trivy findings in unreachable dependencies. First tuning: restrict Semgrep to `p/ci` plus language packs, then add path excludes for tests and fixtures. Trivy noise is controlled by `ignore-unfixed` and by dated waivers rather than permanent ignores. Gitleaks gets a reviewed allowlist for known test fixtures.
