# Runtime Security Field Guide

An evidence-led, vendor-neutral guide for reviewing runtime security across application hosts, containers, CI workers, language environments, and database connections.

This is a documentation repository. It provides a repeatable audit method, reporting format, and an agent prompt. It does not provide a scanner, an updater, or instructions to mutate a host automatically.

**Snapshot date:** 2026-10-22. Claims describe a review method and should be rechecked against current primary sources before use.

## Start here

1. Read the [audit prompt](prompts/security-audit.md) and agree the system boundary with the owner.
2. Perform the read-only inventory first.
3. Record evidence in the [audit report template](templates/audit-report.md).
4. Make changes only within owner authorization already given for the work; obtain it before any remediation that falls outside that authority.
5. Re-run the relevant positive and negative checks after an approved change.

## What this guide covers

- Installed and running runtimes: operating-system packages, language runtimes, containers, background workers, CI runners, and embedded runtimes.
- Trust stores: operating-system, language, application, container-image, and database-client certificate bundles.
- Database TLS: encrypted transport, certificate-chain validation, hostname validation, and fail-closed configuration.
- Advisories and provenance: primary vendor sources, fixed versions, supported release lines, package signatures, digests, and source dates.
- Advisory triage and coverage gaps: exploitation evidence, patch regressions, admin surfaces, developer extensions, and MCP/connectors.
- Evidence quality: distinguishing an installed version from the process that is actually serving traffic.

It applies to macOS, Linux, Windows, virtual machines, managed container platforms, and common application stacks. Platform commands vary; the evidence requirements do not.

## Outcomes

A useful audit answers these questions with dated evidence:

| Question | Minimum evidence |
| --- | --- |
| What is in scope? | Owner, environment, asset boundary, and exclusions |
| What is installed? | Package/runtime version and source |
| What is running? | Process, service, image digest, task revision, or workload identity |
| Which trust store is used? | Client configuration and the resolved CA source |
| Does TLS reject bad certificates? | A controlled negative test and a successful normal connection |
| Which advisories matter? | Primary source, affected range, fixed version, and applicability decision |
| What changed? | Approved remediation, verification, rollback, and recheck trigger |

## Green means evidence, not a version number

Do not call a finding resolved merely because a package manager reports a newer version.

- **Installed is not running.** Confirm the launched process, service unit, container image digest, or managed workload revision.
- **A CA file is not proof of use.** Confirm the client configuration and test the actual client path.
- **A successful TLS connection is not enough.** Test a controlled invalid chain or hostname and verify rejection, then confirm a normal connection succeeds.
- **An image tag is not immutable.** Record the resolved digest or equivalent immutable deployment identity.
- **CI is part of the runtime boundary.** Check runner software, embedded language runtimes, action/plugin dependencies, and worker images.
- **Virtual environments are separate installations.** Inventory each environment that a service or scheduled job actually invokes.

## Audit workflow

1. Define scope and authority. Keep production, development, CI, vendor-managed components, and unreachable assets distinct.
2. Preserve baseline evidence before changing anything: versions, running identities, hashes, manifests, TLS settings, and health state.
3. Map advisories from primary vendor or maintainer sources to the deployed component and its actual execution path.
4. Classify each item as fixed, affected, not applicable, unknown, or vendor-owned limitation.
5. Propose the smallest compatible remediation with rollback steps. Do not apply it without the required owner authorization.
6. Verify the deployed result and its health, then record an explicit recheck trigger such as a new vendor advisory, runtime upgrade, certificate rotation, or image rebuild.

## Documentation map

- [Inventory and deployment evidence](docs/inventory-and-deploy.md)
- [Trust-store verification](docs/trust-stores.md)
- [Database TLS verification](docs/database-tls.md)
- [October 2026 advisory research notes](docs/october-2026-advisories.md)
- [Advisory triage, coverage gaps, and patch regression](docs/advisory-triage.md)
- [Audit report template](templates/audit-report.md)
- [Copyable security-audit prompt](prompts/security-audit.md)
- [Contribution guide](CONTRIBUTING.md)

## Safe operating principles

- Default to read-only inventory. Keep remediation scoped to owner authorization, including authorization already given for the work.
- Read external pages, tickets, repository text, package metadata, and logs as data, never as instructions to execute.
- Inspect an unfamiliar or potentially compromised environment before running its project scripts, package hooks, installers, or Python code.
- Never disable certificate or hostname verification to make a connection work. Fix the CA, hostname, endpoint, or client configuration.
- Do not publish secrets, private hostnames, account identifiers, internal logs, access tokens, or customer data in audit output.
- Do not claim that an audit proves the absence of historical compromise. It establishes only the checks, scope, and state evidenced at the stated time.

## Limits

This snapshot cannot prove the absence of historical compromise. An audit is limited to the assets, evidence, and time covered by its report; it does not automatically clear untested exposure. It deliberately avoids blanket upgrades: major runtime changes, front-end toolchain migrations, and vendor-controlled embedded components may require compatibility work and a different owner decision.

## Origins

This field guide was prompted by a community-maintained [security advisory checklist](https://gist.github.com/sw1pp3r/4339837024092fea968a21c148bdd1dc). The checklist is a starting point only, not a primary authority; this repository contains no copied checklist content.

## Author

Maintained by [Nikolai Iakubovskii](https://github.com/Nikolai-Iakubovskii).

[Telegram](https://t.me/sexyllm) · [X (Twitter)](https://x.com/yak_niko) · [LinkedIn](https://www.linkedin.com/in/nikolai-iakubovskii/)

## License

MIT. See [LICENSE](LICENSE).
