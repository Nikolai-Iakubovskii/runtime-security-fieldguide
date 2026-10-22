# Runtime Security Inventory and Deployment Field Guide

This guide turns a security advisory into a bounded, reviewable remediation.
It is a checklist, not a claim that a version scan proves a system is safe.

Related documents: [trust stores](trust-stores.md), [database TLS](database-tls.md),
and [October 2026 advisories](october-2026-advisories.md).

## 1. Establish scope before touching anything

Record the advisory, affected versions, fixed versions, date checked, owner,
and every environment that may execute the affected component. Use these five
states consistently:

| State | Meaning |
| --- | --- |
| Installed | Present on disk or registered by a package manager. |
| Active | Confirmed executing in a process, container, task, worker, or browser. |
| Inactive | Installed but no active execution was observed. |
| Not present | Not found in the bounded inspection scope. |
| Unknown | Could not be tested or the result was ambiguous. |

`Not present` is never evidence that the component was never installed or
executed. `Unknown` is not a pass.

Start with read-only inventory. Do not print environment variables, tokens,
full process arguments, connection strings, container inspection output, or
unredacted logs. Capture only versions, executable paths, image digests, service
labels, exit status, and redacted error classes.

Before any version command, establish that its executable path is known and
trusted for the incident. If the runtime or environment may be compromised,
inspect static package metadata first; do not execute it to discover its version.

```bash
# Command resolution; execute a version command only after approving its path
command -v php node python3 java nginx httpd
php -v 2>/dev/null | head -1
node --version 2>/dev/null
python3 --version 2>/dev/null
java -version 2>&1 | head -3

# Process identity without arguments or environment
ps -axo pid=,ppid=,user=,comm= | head -200
pgrep -f 'php-fpm|nginx|httpd|node|java'
```

## 2. Inventory the runtime that actually serves traffic

For each application, identify the source declaration, artifact, deployment,
and live executor. A patch is incomplete if any of these layers remains old.

| Layer | Evidence to collect |
| --- | --- |
| Source | Manifest, lockfile, Dockerfile, CI workflow, and version file. |
| Build | Base-image digest, build log, dependency resolution, and SBOM if available. |
| Deploy | Image digest or release revision, desired/running/pending counts, and rollout status. |
| Runtime | PID or task identity, executable path, effective runtime version, and start time. |
| Health | Application health, dependency connectivity, worker status, and bounded logs. |

Check service managers separately. A package can be updated while a long-lived
process still executes a deleted or old binary.

```bash
# Linux examples
systemctl show example.service -p MainPID -p ActiveState -p SubState

# macOS examples
launchctl print gui/$(id -u)/example.label 2>/dev/null | \
  rg 'state =|pid =|program =|last exit' | head -40

# Container summary; avoid `docker inspect` without a narrow format
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.ID}}\t{{.Status}}'
docker image inspect image:tag --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.version"}}'
```

On Windows, use approved service/PID tools; for browsers, desktop agents, IDE
plugins, and CI runners, inventory their runtime as well as the system runtime.

## 3. PHP and Composer are separate checks

PHP CLI can be patched while web requests use FPM, Apache `mod_php`, CGI/FastCGI,
or an application worker with a different binary. Composer is a dependency
manager; it is not an AI feature and does not prove the PHP runtime is patched.

Check each serving path:

- CLI: `php -v` and `command -v php`.
- FPM: the service status, pool configuration, master/worker PID, and binary.
- Apache: loaded PHP module or proxy FastCGI configuration, then the active
  Apache parent/worker process.
- CGI/FastCGI: configured handler path and a safe application diagnostic.
- Queue/cron workers: supervisor or scheduler command plus the live worker PID.

Do not expose a public `phpinfo()` endpoint. Record Composer and its lockfile
separately from PHP; do not run `composer update` as a blanket response.

## 4. Node.js: production, development, and embedded copies

Inventory Node in package managers, version managers, containers, serverless
images, build workers, browser automation, desktop products, and CI runners.
`node --version` in an interactive shell says nothing about an already-running
service or a vendor-bundled Node binary.

```bash
# A safe version check for a known executable path
/path/to/known/node --version

# A process-to-executable check on macOS or Linux
pid=12345 # set only after identifying the service PID
lsof -p "$pid" -d txt 2>/dev/null | head -5
```

Separate production dependency resolution from development tooling. A production
audit can be clean while test, CSS, coverage, or build packages still have
findings. Conversely, a development-only finding is not proof of a remotely
reachable production vulnerability, but it can affect build secrets or artifacts.
State the scanned graph and residual scope. Run `npm audit --omit=dev` and a full
audit as separate scoped checks when appropriate; audit requests can disclose
package names to the configured registry. Do not use `npm audit fix --force` as an
automatic remediation.

For a runner, plugin, browser driver, or desktop product, use the vendor's
official release. Verify its archive checksum or signature, retain a rollback
copy, and confirm that a real job starts with the new distribution. Do not
substitute an embedded runtime binary by hand unless the vendor explicitly
documents that operation.

## 5. Python: environments and certificates

Inspect Python environments without importing unknown packages first. Static
metadata can identify a package version without executing `sitecustomize`,
`.pth` files, or application code.

```bash
# Static metadata only; adapt this approved virtual-environment root.
venv_root=/approved/virtual-environments
find "$venv_root" -type f \( -path '*/certifi-*.dist-info/METADATA' -o \
  -path '*/pip-*.dist-info/METADATA' -o -path '*/uv-*.dist-info/METADATA' \) \
  -exec rg -H -n -m 1 '^Version:' {} \; | head -100
```

Before activating an environment implicated in a supply-chain incident, verify
the incident window and affected artifacts from the publisher's advisory. Use a
trusted clean installer or known-good package tool to repair a confirmed environment; do not run
an untrusted `pip`, project script, or arbitrary package import merely to
inspect it.

For managed projects, add a narrow fixed floor to the dependency declaration
and update the lockfile when it is tracked. Reconcile the active virtual
environment afterward. A `certifi` version alone is insufficient: the actual
client may use the OS store, a custom bundle, a proxy, or a vendor store.

Package managers can carry vendored CA bundles independent of the virtual
environment's `certifi` and OS store. For the 2026 CA incident, the pip 26.2.2
floor is independent of the venv `certifi` version; OS distrust or `PIP_CERT`
alone does not prove an old pip is fixed. uv's default bundled store is likewise
independent of system roots unless system or custom roots were explicitly selected.
Use the exact version-floor table in [October 2026 advisories](october-2026-advisories.md).

New environments, `ensurepip`, bootstrap wheels, and cached image layers can
reintroduce old package-manager copies. Use a trusted clean installer or known-good
rehydration process, obtain the fix from an independently trusted channel, and
verify its published hash or signature; never use `-k` to self-update. Run the
package manager's consistency check and relevant tests. Record unmanaged
environments rather than inventing a manifest only to make inventory look tidy.

## 6. Trust stores and TLS probes

Use the [trust-store guide](trust-stores.md) to map each client to its effective
CA source. Typical distinct stores include the OS bundle, Homebrew or Linux
package bundle, Python `certifi`, JVM `cacerts` or blocklists, Node/OpenSSL,
browser/desktop product bundles, and application-packaged CA files.

For an incident with published negative test hosts, use all published hosts and
one ordinary positive-control host. Require chain validation and hostname
validation. Record accepted, rejected, and unknown outcomes separately.

```python
# Illustrative probe shape: use approved target hosts and a timeout.
import socket, ssl
ctx = ssl.create_default_context(cafile="/approved/ca-bundle.pem")
ctx.check_hostname = True
ctx.verify_mode = ssl.CERT_REQUIRED
with socket.create_connection(("control.example", 443), timeout=8) as raw:
    with ctx.wrap_socket(raw, server_hostname="control.example"):
        pass
```

Interpretation matters:

- A negative host accepted: the tested client trusts that tested chain.
- A negative host rejected: it rejects that tested chain only.
- A positive control accepted: the probe still has ordinary TLS connectivity.
- Timeout, proxy interception, DNS failure, or protocol mismatch: unknown.

Never turn off verification, use `-k`, or set a permissive callback to produce
a passing result. A client configuration file may not apply to quiet mode,
explicit CA overrides, another account, another container, or an already-running
process. Re-test those separate paths where they are in scope.

## 7. Java, web servers, and operating-system context

For Java, inspect the JVM path used by the running process, not only `java -version`.
Record `JAVA_HOME`, the selected trust store or blocklist, and whether
an update can overwrite it; then verify downstream connections after a controlled restart.

For nginx, validate configuration before reload and verify the effective binary:

```bash
nginx -t
nginx -V 2>&1 | head -5
```

For Apache, inspect active modules and handlers as well as the package version.
Check distributor advisories for backports; preserve a tested configuration rollback.

## 8. Database TLS requires a real connection test

Inventory every database client: API, background worker, migration runner,
scheduled job, CLI repair script, and test harness. Search for permissive TLS
settings such as `rejectUnauthorized: false`, `verify=False`, or `sslmode`
values that omit hostname verification.

Use an official regional/provider CA bundle, retain the current and next CA
during a planned rotation when the provider requires overlap, and validate:

1. A minimal query through the real application configuration succeeds.
2. A deliberately wrong hostname fails with a hostname-validation error.
3. Migration and worker paths use the same strict policy.
4. The deployed task definition or service configuration retains the setting.

Never paste connection strings; use a least-privilege test account where possible.

## 9. Build, deploy, and prove the rollout

Use the project's exact release gates. Typical gates are dependency consistency,
unit tests, type checks, migration validation, build, image creation, and an
application-specific smoke test. Do not replace them with a generic command.

For containerized delivery, capture the immutable deployed digest rather than
only a mutable tag. An SBOM, provenance attestation, or build metadata can add
evidence when the platform supports it. `docker buildx` options vary by version;
consult its local help and platform documentation before relying on a command.

An attestation being present is not enough: verify the registry subject digest,
signer identity, issuer, and expected build authority using the platform's
documented verifier. A classic Docker image store and `docker buildx --load` may
not retain attestations; verify the pushed registry artifact explicitly.

For CI, pin third-party actions to immutable commit SHAs, give each job the
least permissions it needs, and isolate secrets from untrusted pull-request
code and checkouts. Inventory the runner's embedded runtime as well as the
workflow's declared runtime, then prove the actual job used the expected one
from bounded job evidence. A workflow file alone does not establish the runner
binary or the runtime that executed a prior job.

After an approved production deployment, verify all of the following:

- release revision or digest matches the intended artifact;
- desired, running, and pending task counts are healthy;
- API and worker processes both use the new configuration;
- migrations complete with strict database TLS;
- HTTP health and a dependency-backed health or query pass;
- bounded recent logs contain no TLS, certificate, database, or startup errors;
- restarted PIDs or tasks have new start times and expected executable paths.

HTTP 200 alone is not sufficient: a worker, database pool, or warehouse may fail.
Do not restart production merely to gather evidence; require authorization and rollback.

## 10. Backups, routes, and recovery evidence

Before changing a service, preserve configuration, data volumes, and rollback.
Do not downgrade to a known-vulnerable runtime; retain a patched artifact where possible.

For backup paths, verify upload, download, cryptographic integrity, freshness,
and a restore or restore drill. Test the production egress route, not only a
developer workstation. Different routes can receive different certificates or
intermediaries. A narrowly approved alternate route can be valid if it retains
TLS validation and its scope is documented; it is not evidence that every host
or route is repaired.

Treat a backup artifact as verified only after its prior download, authenticated
integrity check, freshness check, and approved recovery evidence all passed.
A later failed retry is independently unknown; a successful transfer alone is
insufficient and neither result proves a universal pass or failure.

## 11. Residual-risk record template

Use this table in the change record and update it after every verification.

| Component/context | Installed | Active | Trust/dependency source | Evidence | Result | Owner and next trigger |
| --- | --- | --- | --- | --- | --- | --- |
| Example service | version | PID/digest/version | OS, bundled, or lockfile | test date and redacted result | pass/fail/unknown | team; next vendor release |

Include inactive and not-present components when they were deliberately checked.
For vendor-owned artifacts, record the installed vendor version, embedded runtime
version, remediation boundary, and recheck trigger. Do not label a fleet “fully
patched” while any relevant row remains unknown or vendor-blocked.

## Primary-source starting points

- [PHP releases](https://www.php.net/releases/)
- [Node.js security releases](https://nodejs.org/en/blog/vulnerability/)
- [Python certifi releases](https://github.com/certifi/python-certifi/releases)
- [uv releases](https://github.com/astral-sh/uv/releases)
- [NGINX security advisories](https://nginx.org/en/security_advisories.html)
- [Apache HTTP Server vulnerabilities](https://httpd.apache.org/security/vulnerabilities_24.html)
- [GitHub Actions Runner releases](https://github.com/actions/runner/releases)
- [Docker build attestations](https://docs.docker.com/build/metadata/attestations/)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)

Use the advisory publisher and the affected product vendor as the authority for
current version ranges, mitigations, and recovery instructions. Date every
verification: security conclusions expire as runtimes, trust stores, routes,
and vendor artifacts change.
