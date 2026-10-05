# Section 2: Build and release integrity

Threats served: **T1** supply chain (SBOM, signing, immutable tags), **T2** pipeline compromise (OIDC scoping, key custody). Files: `.github/workflows/build-release.yml`, `infra/oidc-trust-policy.json`, `infra/release.tf`.

## Decisions

- **SBOM:** CycloneDX generated from the built image (not the source tree), then attested with `cosign attest`. It is signed and bound to the image digest, so it cannot be swapped without detection. It is not a build-log artefact.
- **Signing: keyed, AWS KMS.** Keyed because a bank cannot accept signing metadata (repo, workflow, image name) in a public transparency log. **Trust root: the KMS key.** The private half is non-exportable, only the pipeline role holds `kms:Sign`, key admins have no `kms:Sign` grant (but can edit the key policy, so separation holds only if `kms:PutKeyPolicy` sits with a separate security-admin role; that role is a placeholder here), and every use is in CloudTrail. The public key (`cosign.pub`) is what verifiers hold.
- **OIDC:** the role trusts GitHub only when `sub` equals `repo:EXAMPLE-ORG/accounts-api:ref:refs/heads/main`. **What this denies:** pull requests, forks, feature branches and every other repo can no longer assume the role, so a malicious PR or workflow in another repo cannot push or sign.
- **Immutable tags:** ECR `image_tag_mutability = IMMUTABLE` blocks re-pushing an existing tag. Tag is the commit SHA, and deployment references the **digest**, so even a tag-policy mistake cannot change what runs.

## What the signature proves, and what it does not

**Proves:** this exact image digest was signed by an identity that could call `kms:Sign` on our key, which means our pipeline role (or someone who compromised it).

**Does not prove:**
- the code is safe or free of vulnerabilities (a malicious dependency or commit signs just as cleanly)
- the source was reviewed or that the commit was legitimate
- anything about build integrity if the pipeline role or the workflow itself is compromised (threat T2)
- freshness: without a transparency log there is no public record, and a stolen key signs anything

An over-read signature ("signed, therefore safe") is the real risk, so the SBOM, scan gates and admission policy sit around it rather than behind it.

## Honest limits and trade-offs

- No transparency log means no public tamper-evidence. Mitigation is CloudTrail on KMS use, not a substitute.
- Verification here uses `--insecure-ignore-tlog` deliberately because no log is used.
- Key rotation: KMS asymmetric keys do not auto-rotate. A rotation plan means a new key, a new `cosign.pub`, and a Kyverno policy listing both keys during overlap. Not implemented here.
- Actions are version tags, not SHAs (Monday task). Terraform has not been applied.
