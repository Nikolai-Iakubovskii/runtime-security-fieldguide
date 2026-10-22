# Secret Exposure Review

**Checked:** 2026-10-22  
**Scope:** This conditional module extends runtime and component audits where a repository, build, artifact, or deployment path may hold a credential or other secret. It is an evidence review, not a credential-validation exercise.

## Authorization and safe observation

Review only sources, histories, artifacts, accounts, and environments explicitly authorized by their owner. Start with read-only inspection and synthetic data. Do not run broad scans, test a credential with a third party, print a token prefix, or place an observed secret in a ticket, terminal transcript, or this record. Prefer a secret-free finding identifier, such as `<finding-042>`, and a masked location.

Record `not applicable` or `unknown` with the owner, evidence reviewed, and reason; neither is evidence that no secret exists.

## Coverage record

| Surface | Evidence to collect | Owner | Status |
| --- | --- | --- | --- |
| Current source and configuration | authorized paths, access exposure, review time, finding ID | `<owner>` | pass/finding/unknown/not applicable |
| Git history and refs | authorized branches, tags, reachable refs, clone depth | `<owner>` | pass/finding/unknown/not applicable |
| CI and build outputs | authorized logs, caches, reports, image metadata | `<owner>` | pass/finding/unknown/not applicable |
| Images and mobile artifacts | image digest or artifact version, access exposure | `<owner>` | pass/finding/unknown/not applicable |

For Git, inspect all authorized history and reachable refs, not only the current working tree. A shallow clone creates an explicit history gap: record its depth, the unavailable range, and the owner decision to obtain complete authorized history or leave the result unknown. Build outputs can include generated configuration, debug symbols, archives, and mobile packages; record only their version or digest, never contents that could disclose a secret.

## Detection limits and evidence

GitHub documents that secret scanning detects supported patterns in the full Git history across branches. Push protection is a separate capability. Availability, custom-pattern coverage, bypasses, entitlement, and which patterns apply must be verified for the specific organization and repository; do not treat a clean result as universal detection. [Secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning) [Push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)

| Finding field | Record safely |
| --- | --- |
| Location and access | repository/artifact class, masked path, authorized audience |
| Exposure time | observed/possible start and end, or `unknown` |
| Secret type and owner | generic type and accountable owner; no value or prefix |
| Evidence | finding ID, tool/source version, checked time, reviewer |
| Decision | remediated/accepted/unknown, with recheck date |

Source-supported facts above describe GitHub capabilities. Recommended checks compare authorized source, history, CI outputs, images, and mobile artifacts against the declared secret-handling boundary and preserve only masked evidence.

## Confirmed exposure response

A confirmed exposed credential requires owner-authorized revocation or rotation from a clean administrative context. Update every authorized consumer, verify the affected service health, and—within authority—verify the old credential is invalid. Removing a value from the current Git tree alone is insufficient. Rewriting shared history needs separately scoped authority and coordination; rotation still takes priority because copies and clones may remain.

## Compatibility, rollback, and recheck

Rotation can interrupt consumers that have not adopted the replacement. Prepare an owner-approved rollback that preserves revocation and does not restore the exposed credential; use a newly issued replacement if rollback is required. Recheck after repository-history changes, CI changes, new artifact types, credential-provider changes, incident evidence, or changes to access exposure.

## Completion record

| Item | Owner | Evidence ID | Unknowns or gaps | Compatibility/rollback | Recheck trigger |
| --- | --- | --- | --- | --- | --- |
| `<surface>` | `<owner>` | `<finding-or-review-id>` | `<gap>` | `<consumer/rollback>` | `<trigger>` |

## Sources

- GitHub, [Secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning), accessed 2026-10-22.
- GitHub, [Push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection), accessed 2026-10-22.
