# November 2026 Security Advisories: Verification Guide

**Verified:** 2026-11-20
**Window:** advisories and incidents published 2026-11-06 to 2026-11-20.
**Audience:** operators of small self-hosted estates: Linux VPS, a macOS home
server, containers, Node.js and Python services, and AI-agent tooling.

This note records what the cited sources said on the verification date. Version
numbers are patch floors for these advisories, not a claim that they remain the
newest releases. nginx is covered separately in the
[nginx HTTP/2 advisory note](november-2026-nginx-http2-advisories.md).
Inventory first: a vulnerable product that is not installed is not an exposure.

## Triage table

| Topic | Applies when | Remediation floor or action | Exploitation status at check | Primary source |
| --- | --- | --- | --- | --- |
| OpenSSH CVE-2026-123158 | sshd built with musl libc and without PAM (for example Alpine), password authentication on, one account with `*` in the password field and another with a SHA-crypt hash | Upstream 10.6p2; distribution backport; disabling password authentication is a stopgap | CISA KEV, added 2026-11-09 | [OpenSSH release notes](https://www.openssh.com/releasenotes.html), [Alpine notice](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/), [Ubuntu tracker](https://ubuntu.com/security/CVE-2026-123158) |
| PostgreSQL 2026-11-12 release | Any supported server below the new minor; client tools `pg_dump`, `pg_restore`, `vacuumdb`, `reindexdb` | 18.7, 17.12, 16.16, 15.20, 14.25, then the listed post-update steps | No exploitation statement | [PostgreSQL release](https://www.postgresql.org/about/news/postgresql-187-1712-1616-1520-1425-and-19-rc-2-released-3442/) |
| Node.js November release | Every 22.x, 24.x, 26.x runtime, including containers, CI runners, and bundled copies | 22.23.5, 24.22.3, 26.13.1 | No exploitation statement | [Node.js advisory](https://nodejs.org/en/blog/vulnerability/november-2026-security-releases) |
| Ubuntu kernel USN-9173-1 | Ubuntu 24.04 and 22.04 generic kernels | Noble `6.8.0-151.151`, then reboot | Not stated | [USN-9173-1](https://ubuntu.com/security/notices/USN-9173-1) |
| Chromium CVE-2026-125350 | Chrome and Chromium-based browsers and embedded runtimes | Chrome 157.0.8103.50 or later | Google reports an exploit in the wild; CISA KEV 2026-11-10 | [Chrome release](https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop_018223192.html) |
| macOS 27.2.1 and supported older releases | Macs below the 2026-11-09 releases | macOS 27.2.1 or the equivalent supported-branch update | No exploitation statement | [Apple security content](https://support.apple.com/en-us/149718) |
| PyPI `agent-framework` 1.26.1 and 1.26.2 | Any environment, image, or CI cache that installed those versions | Pin 1.26.0 or earlier; treat an affected environment as exposed and rotate reachable credentials | Confirmed malicious releases, removed from PyPI | [GHSA-764m-3ppc-5m73](https://github.com/advisories/GHSA-764m-3ppc-5m73) |
| LiteLLM CVE-2026-40217 | LiteLLM proxy with the custom-code guardrail test endpoint and a proxy-admin credential | 1.83.11 or later (the advisory header and text disagree; use the higher value) | CISA KEV, added 2026-11-18 | [GHSA-wxxx-gvqv-xp7p](https://github.com/BerriAI/litellm/security/advisories/GHSA-wxxx-gvqv-xp7p) |
| runc CVE-2026-119101 | CRIU checkpoint and restore with an untrusted image | runc 1.3.7, 1.4.4, or 1.5.3 | Not stated | GitHub advisory GHSA-g2c3-j8g3-7gpw |
| containerd CVE-2026-95839 | containerd v2 pulling a malformed image | 2.2.10, 2.3.7, or 2.4.2 | Not stated | GitHub advisory GHSA-vwhp-8p66-mq4f |
| Docker Engine CVE-2026-115538 | Swarm encrypted overlay networks on hosts using firewalld | 29.9.3 | Not stated | GitHub advisory GHSA-6jhp-7446-hf7f |
| MCP Python SDK CVE-2026-115563 | `mcp` OAuth client connecting to an untrusted MCP server | 1.30.0 or 2.2.0 | Not stated | GitHub advisory GHSA-qx49-fqc8-xw99 |
| React Server Components CVE-2026-126187 | Applications serving `react-server-dom-webpack`, `-parcel`, or `-turbopack` | 19.0.9, 19.1.10, 19.2.9, or 19.3.1 | Not stated | GitHub advisory GHSA-xqc2-xf4c-x3h3 |
| npm `follow-redirects` CVE-2026-116689 | Code that sets custom credential headers and follows cross-origin redirects | 1.16.2 | Not stated | [GHSA-mrwp-f3q8-3g9p](https://github.com/advisories/GHSA-mrwp-f3q8-3g9p) |
| npm `multer` CVE-2026-113872 | Upload handlers with an asynchronous `fileFilter` | 2.5.0; a synchronous `fileFilter` is the documented workaround | Not stated | [GHSA-q7qp-rjg7-q26m](https://github.com/advisories/GHSA-q7qp-rjg7-q26m) |

### CISA KEV context (2026-11-20)

The CISA KEV JSON feed, catalog version `2026.11.18` released at
`2026-11-18T19:17:41Z` with 1,786 entries, lists the OpenSSH, Chromium, and
LiteLLM entries above. In the same window it also added Synology DSM
CVE-2024-10441, Check Point Gaia CVE-2026-123039, Microsoft Outlook
CVE-2026-124194, Barracuda ESG CVE-2026-116606 and CVE-2026-111560, Cisco
BroadWorks CVE-2026-20320, Perforce Puppet Enterprise CVE-2026-115731, Apache
Axis CVE-2026-90436, and others. A KEV listing sets priority; it does not show
that a product is installed. None of the 18 November nginx CVEs was in this
catalog version.

## 1. OpenSSH: a KEV entry that does not apply to most glibc hosts

The OpenSSH entry is a good example of reading conditions before acting. The
bypass depends on musl's `crypt()` behaviour and on sshd being built without
PAM. Ubuntu marks every release not affected. The realistic exposure in a
glibc-based estate is a container or appliance image based on Alpine or another
musl distribution that runs sshd with password authentication. Inventory those
images by digest, check `sshd -T` in the running container for
`passwordauthentication`, and record glibc hosts as not applicable with the
tracker link as evidence.

## 2. PostgreSQL: update both servers and client tools

The release fixes 52 vulnerabilities; the highest listed score is CVSS 8.8,
mostly with low privileges required. Several high-scoring issues are in
`pg_dump` and `pg_restore`, so backup hosts and operator workstations need the
new client tools, not only the server. After the update, the release notes ask
operators to reindex suspect GIN indexes, GiST indexes that use
`gist_trgm_ops`, and B-tree indexes on `bpchar` columns declared without a
length; to take a new full backup when incremental backups are in use; and to
check `NOT NULL NO INHERIT` constraints on partitioned tables. Record which of
these conditions exist before the maintenance window so that the reindex work
can be planned and timed. PostgreSQL 14.25 is the final 14.x release.

## 3. Installed is not running: kernels, libc, and long-lived processes

A security update can be installed for days while the host still runs the old
code. After a kernel or `libc6` update on Ubuntu,
`/var/run/reboot-required` and `/var/run/reboot-required.pkgs` record the
pending reboot; compare `uname -r` with the newest `/boot/vmlinuz-*`. The same
applies to Node.js, Python, and PostgreSQL processes started before a package
update. Record the process start time against the package install time and
treat the item as not fixed until the restart or reboot has happened and the
service is healthy again.

## 4. Supply-chain malware in a legitimate package name

The `agent-framework` releases ran a credential stealer through a `.pth` file,
which Python executes at every interpreter start without importing the package.
Searching lockfiles alone is not enough. Check every virtual environment,
container image, CI cache, and tool installer (`pipx`, `uv tool`) for the two
versions, and inspect `site-packages/*.pth` files for unexpected code. If an
affected version was installed, follow the incident-response path in the audit
prompt: preserve evidence, rebuild from a clean source, and rotate every
credential the environment could read, including CI and OIDC-issued tokens.

## 5. Library advisories need a reachability note

Dependency scanners report `follow-redirects`, `multer`, `undici`, `zod`, and
similar packages across many lockfiles. Upgrade production dependencies on the
normal release path, but record the condition that makes each one exploitable.
For example, the `multer` crash needs an asynchronous `fileFilter`; a handler
without one is still worth upgrading but is not urgent. Keep
development-only findings, such as `undici` pulled in by a local CLI, separate
from production findings.

## Suggested verification order

1. KEV entries that match installed and reachable products.
2. Pending reboots and restarts for already installed security updates.
3. Internet-facing runtimes: PostgreSQL where reachable, Node.js services,
   browsers on administrator machines.
4. Supply-chain malware checks in Python environments and CI caches.
5. Production dependency upgrades with a recorded reachability note.
6. Development-only findings on the normal maintenance cadence.

## Recheck triggers

Recheck on a new KEV catalog version, a distribution status change for any CVE
above, a new PostgreSQL or Node.js release, a rebuilt base image, or a new
malicious-package advisory for a package in the inventory.
