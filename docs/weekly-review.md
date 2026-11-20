# Weekly Security Review Flow

**Written:** 2026-11-20

Advisories now arrive several times a week, and a monthly audit misses the gap
between "fix published" and "fix running". This page is an ordered, read-only
review that one operator can finish in an hour for a small estate. It does not
replace the full [audit prompt](../prompts/security-audit.md); it feeds it.

A weekly cadence is a recommendation, not a vendor requirement. Run the flow
sooner when a KEV entry or a vendor "exploited in the wild" statement matches a
product in the inventory.

## 0. Keep the inventory current

Start from a short list of what runs where: hosts and their OS release,
long-lived services and their runtime, container images by digest, reverse
proxies and tunnels, databases, CI runners, and administrator workstations.
Note for each one whether it is internet-reachable. Repositories show intended
configuration; a deploy note, process list, or image digest shows what runs.
A repository finding with no known deployment is `unknown`, not safe.

## 1. Pull the week's advisory delta

1. Fetch the CISA KEV JSON feed and list entries whose `dateAdded` is after the
   previous review. Record the catalog version and release time.
2. Read the vendor feeds for the products in the inventory: the OS
   distribution's notices, language runtimes, databases, proxies, browsers, and
   the container runtime.
3. Check the package registries' malware and advisory feeds for packages in the
   lockfiles, with extra attention to AI-agent, MCP, and build tooling, which
   often run with broad credentials.
4. Treat news, social posts, and researcher landing pages as leads. Confirm
   each claim with the vendor, maintainer, or distribution source, and record
   where the researcher's claimed impact differs from the vendor's.

## 2. Read the conditions before rating

For each advisory, write down the condition that makes it exploitable and check
it against the effective configuration: a protocol enabled on a listener, a
module in use, a build option such as musl versus glibc, an authentication mode,
or a code path such as an asynchronous upload filter. Rate the result as
affected, not applicable with evidence, or unknown. A version match without the
condition is still upgraded on the normal path, but it is not an emergency.

## 3. Compare installed with running

Most misses in practice are fixes that were installed but never loaded.

- Linux: compare `uname -r` with the newest installed kernel and read
  `/var/run/reboot-required.pkgs`. A pending kernel or `libc6` reboot older than
  a few days is a finding.
- Services: compare each long-lived process start time with the install time of
  its runtime package. A configuration reload can keep the old binary mapped.
- macOS: compare the running version with the newest offered update, and the
  running Homebrew services with `brew outdated`. A minor release behind is a
  finding when the newer release has security content.
- Containers: compare the running image digest with the rebuilt image digest,
  not the tag.

## 4. Audit dependencies with honest coverage

Run the ecosystem's production-only audit for each lockfile, or a cross-ecosystem
scanner such as OSV-Scanner where available. Report separately:

- production findings with a fixed version and the reachability condition;
- development-only findings;
- projects with no lockfile, unpinned requirements, or ecosystems with thin
  advisory data, such as Pub or SwiftPM, as `unable to verify`;
- base images pinned only by a floating tag, and third-party CI actions pinned by
  tag rather than commit SHA.

For a malicious-package advisory, also search installed environments, image
layers, tool installers, and CI caches, because lockfiles do not show what an
earlier install left behind.

## 5. Change safely when a fix is approved

Back up the configuration and capture the effective configuration (for example
`nginx -T`) before a package update. Some packages replace site or service files
during post-install, so compare the effective configuration afterwards. Restart
or reboot so the new code runs, then verify the process identity, a normal
request through the real route, and the service's own health check. Record a
rollback path before the change.

Checks that caught real problems during the first run of this flow:

- After a reboot, list failed units (`systemctl --failed`). A configuration
  error that only bites at boot, such as a malformed `sysctl.d` line, can sit
  unnoticed for months while the setting was applied once by hand.
- Compare the candidate version on each host. Regional package mirrors can lag
  by days, so one host may not be offered a kernel that its peers already run.
  Record the lagging host as pending rather than fixed.
- Rebuild out-of-tree kernel modules (for example DKMS) for the new kernel and
  confirm the build before rebooting.
- A service manager can rename a service on restart. Homebrew now registers
  services as `sh.brew.<formula>`, while services first started by an older
  Homebrew keep the `homebrew.mxcl.<formula>` label until the next restart.
  Scripts and health checks that name the label need to accept both.
- Keep the previous runtime versions until the restarted services have run
  cleanly, so that rollback does not need a download.
- Restart the services that listen for network connections onto the new runtime
  in the same window, and list the remaining long-running jobs that will pick
  it up on their next restart.
- Turn on the registry's image scanning before the next push, then read the
  operating-system findings against what the service process loads. An
  official runtime image can carry a vulnerable system `libssl` or `zlib`
  while the runtime binary links its own bundled copies; record the package,
  the distribution fix, whether the process loads it, and the base-image
  rebuild as the recheck trigger.
- A major-version library fix can change runtime behaviour that type checks
  do not catch, such as default-value handling or record-key exhaustiveness.
  Run the full tests for every schema consumer before deploying it, and keep a
  low-reachability finding open as a planned task rather than forcing the
  upgrade into a security hotfix.
- Treat an optional hardening dependency that fails to import as a finding.
  A guarded import that falls back silently can switch a protection off for
  weeks; log a warning when it is missing.

## 6. Record and schedule

For each item record the advisory, the asset, the condition check, the state
(fixed and verified, affected, not applicable, development-only, vendor-owned,
or unknown), the evidence and its timestamp, and the recheck trigger. Carry
unresolved items into the next weekly review instead of closing them on intent.
