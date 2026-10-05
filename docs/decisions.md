# Part 2: Decisions

## Three biggest decisions

1. **Signing with our own KMS key, no public transparency log.** Chosen because this is a regulated workload and a public log would publish build metadata we do not want public. Cost: we lose third-party tamper evidence and own key custody and rotation (`docs/section2-build-integrity.md`).
2. **Enforce only takeover paths on day one; everything that could break a working deploy starts in Audit.** Privileged, host namespaces, hostPath and wildcard RBAC are Enforce (no legitimate use here). Hygiene rules and `verifyImages` are Audit. **This is the place I chose not to enforce:** image signature verification is Audit, not Enforce, because `cosign.pub` is a placeholder until the KMS key exists and a shared cluster cannot take a self-inflicted outage.
3. **No ClusterRole guard and no service mesh.** System ClusterRoles legitimately use wildcards, so a guard would need a long exception list that rots. Compensating cover: Roles are guarded, pod creation is removed from the app's RBAC, NetworkPolicy limits traffic. mTLS is deferred.

## Enforcement posture and promotion evidence

| Policy | Day one | Promoted when |
|---|---|---|
| Critical baseline, RBAC guard | Enforce | n/a |
| Hygiene baseline | Audit | 14 consecutive days, zero failures in policy reports, CI tests green |
| Verify images | Audit | All running pods verified 14 days, key-rotation overlap rehearsed, real `cosign.pub` |

Evidence so far: `kyverno test` 48 passed, 0 failed (before: original rejected, after: fix accepted). Checkov custom checks: original 10 failed, fixed 10 passed (`docs/evidence/`).

## Blast radius

**(a) RCE in `accounts-api`.** The attacker runs as the service. Reaches: the DB credential and customer data through the service's own connection; the pod's IAM role, now limited to one DB secret and its key; the KYC provider over the allowed 443 flow. Does not reach (by design): the node (no docker socket, hostPath, hostNetwork or privilege), other tenants (default-deny NetworkPolicy, no wildcard RBAC), other secrets or keys (scoped IAM). Detection: Falco fires if a non-service process reads the credential file. Not covered: data read by the service's own process.

**(b) Maintainer GitHub account takeover.** One compromised maintainer cannot merge alone: CODEOWNERS requires the security team on workflows, policies, `cosign.pub` and infra, and the KMS `Sign` permission is limited to the pipeline role on the main branch (OIDC `sub`). They can push a malicious feature branch but it cannot be signed. The residual risk is a colluding or also-compromised approver, or an org admin weakening branch protection: then the pipeline builds and signs malicious code, and the signature proves provenance, not intent. Mitigations still needed: org-level audit alerts on branch-protection changes, SHA-pinned Actions.

## One attack path we would not detect: DNS exfiltration

DNS must stay open for the service, so a compromised pod can encode data into lookups to an attacker-controlled name server. NetworkPolicy allows it, Falco does not look at it, and the volume is small and slow so nothing alarms.
**Cost to close:** turn on Route 53 Resolver query logging and alert on high volume or unusual domains (days of work, low run cost, detection only), or route egress through AWS Network Firewall with domain allowlisting (weeks, ongoing cost per endpoint and traffic, prevents rather than detects). Start with logging.

## Regulatory framing

| Requirement area (PCI DSS v4.0 / data protection) | Where addressed |
|---|---|
| Secure development and vulnerability management (Req 6) | Trivy, Semgrep, Gitleaks gates, waivers with expiry |
| Restrict access by need to know (Req 7) | Scoped IAM, RBAC guard, CODEOWNERS |
| Protect stored account data (Req 3) | KMS-encrypted RDS, ECR and secrets; no plaintext credentials |
| Network segmentation and egress control (Req 1) | Default-deny NetworkPolicy, KYC-only egress (limits noted) |
| Logging and monitoring (Req 10) | Multi-region CloudTrail with log validation, Falco alerting |
| Incident response (Req 12) | Falco runbook, emergency rotation under 10 minutes |

## What was cut, and the first Monday task

**Cut:** production deploy stage with manual approval, WAF and Shield (T5), just-in-time engineer access, mTLS, a live run of Falco and `verifyImages`.
**First Monday task: pin every GitHub Action to a full commit SHA** (with Dependabot to update them). Today they use tags, which a compromised upstream maintainer can move. This closes the largest open gap in T2 at the lowest cost.
