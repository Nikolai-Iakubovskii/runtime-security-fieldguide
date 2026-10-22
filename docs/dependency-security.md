# Dependency Security Coverage

**Checked against linked primary sources:** 2026-10-22. This is a review method,
not a claim that any one tool covers every ecosystem or deployed artifact.

## Coverage matrix is mandatory

Create one row for every application, worker, build root, and delivered image.
Include every source root and lockfile, or the resolved inventory where no
lockfile exists. `Unknown`, unsupported formats, unavailable transitive data,
and missing artifacts are coverage gaps, not clean results.

| Component and scope | Language / package manager | Source roots and lockfile or resolved inventory | Direct / transitive; production / development / build / CI | Audit tool and version | Advisory data checked at | Final build or image digest | Result and unsupported or missing coverage |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `service` | `language / manager` | `root; lockfile or inventory ID` | `direct + transitive; production` | `tool version` | `YYYY-MM-DDThh:mm:ssZ` | `sha256:...` | `affected / fixed / unknown; gap` |

Review source resolution and the final installed artifact or image separately.
A manifest or lockfile describes intended resolution; an image or deployed
artifact can contain system packages, copied files, or a different resolution.
OSV-Scanner documents supported source lockfiles and installed-image artifacts
as distinct inputs, with format-specific limits. Record those limits and verify
the deployed digest or equivalent immutable identity. [OSV-Scanner supported
languages and lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

## Choose evidence by ecosystem

Use a tool and input that supports the actual artifact. The routes below are
examples of evidence sources, not a universal command recipe.

| Ecosystem | Prefer resolved source evidence | Also review |
| --- | --- | --- |
| npm, pnpm, Yarn | Committed lockfile and production/development graph | Final installed application or image; `npm audit` covers only the registry and graph it is given. |
| Python | `requirements` lock, Poetry/Pipenv/uv lock, or installed distribution inventory | Each deployed virtual environment, wheelhouse, and image. |
| Ruby | `Gemfile.lock` | Bundled gems in the deployed image or application package. |
| PHP / Composer | `composer.lock` | Vendor tree and the PHP runtime image or release artifact. |
| Java / JVM | Maven or Gradle resolved dependency report / lock where maintained | Built JAR/WAR, native image, and container layers. |
| Go | `go.sum` and resolved module graph | Compiled binary provenance and final image; static binaries need build evidence. |
| Rust | `Cargo.lock` | Compiled binary provenance and final image. |
| .NET | `packages.lock.json` or resolved restore assets | Published output and final image. |
| iOS / Apple platforms | SwiftPM resolved package file or CocoaPods lockfile, as applicable | Produced application archive and embedded framework inventory. |
| Android | Gradle dependency-locking or resolved dependency report, as maintained | Produced APK/AAB and bundled native libraries. |
| OS packages and containers | Package database or SBOM tied to the image digest | The final image and deployed digest, including base-image packages. |

If the ecosystem, package manager, lockfile, artifact, or transitive graph is
not supported by the selected tool, identify the omitted input and owner. Do
not infer clean transitive coverage from a successful direct-dependency check.

## Support lifecycle and backports

For every runtime, base image, package manager, and security-relevant component,
record the support status, security-support end date, primary lifecycle source,
source check date, and migration owner and deadline. An upstream end-of-life
release normally receives no further upstream security patches; confirm the
component's own policy and the date used. [Node.js end-of-life
policy](https://nodejs.org/en/about/eol)

| Component | Deployed version / digest | Support status and security-support end | Primary lifecycle source and checked date | Upstream version or supported-distribution backport | Migration owner and deadline |
| --- | --- | --- | --- | --- | --- |
| `runtime` | `version / digest` | `supported / EOL / unknown; date` | `URL; YYYY-MM-DD` | `upstream fixed version or distro advisory/backport` | `role; YYYY-MM-DD` |

Do not treat an upstream version comparison as proof that a supported Linux or
other distributor package is vulnerable: distributors can backport fixes.
Use that distributor's advisory and package-release evidence. Conversely, a
vendor image or managed runtime can be unsupported even when a newer upstream
release exists.

## Recurring review recipe

Assign an accountable owner and retain the last successful run and next run for
each row. A weekly cadence is a reasonable policy recommendation for actively
maintained production services; it is not a vendor requirement. Adjust it for
exposure, release rate, and owner capacity.

1. List all ecosystem roots, package managers, lockfiles, resolved inventories,
   build contexts, final artifacts, and deployed image or release digests.
2. Where GitHub is the selected platform, separately enable and review the
   dependency graph, Dependabot alerts, and Dependabot security updates through
   an owner-authorized configuration change. GitHub documents separate limits
   for dependency-graph and alert availability, patch availability, and indirect
   dependencies. An alert or coverage failure without a verified fix remains
   open, not clean.
   [Dependabot security updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates)
3. Configure and review regular version updates separately from security updates
   where the platform provides both. For Dependabot, the owner-authorized
   `dependabot.yml` declaration identifies each ecosystem, directory, and update
   schedule for normal version updates. GitHub distinguishes Dependabot security
   updates from version updates; one does not substitute for the other.
   [Dependabot version updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-version-updates)
4. Use pull-request dependency review or an equivalent check where available;
   record unavailable support rather than assuming it ran.
5. Schedule reassessment of released images, runtimes, and trust stores, because
   a source-only result does not prove the released artifact remains current.

| Owner | Cadence and policy basis | Last successful review | Next scheduled review | Graph / alerts evidence | Version-update evidence | Released artifact, runtime, and trust-store evidence |
| --- | --- | --- | --- | --- | --- |
| `role` | `weekly recommendation; rationale` | `timestamp` | `timestamp` | `reference` | `reference` | `digest / release / bundle reference` |

Inventory evidence alone does not authorize configuration. Record or propose
automation through the owning change process; when the owner has authorized the
configuration, record its scope, approval, and rollback.
