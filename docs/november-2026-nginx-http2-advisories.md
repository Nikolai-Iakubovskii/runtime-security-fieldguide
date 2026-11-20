# November 2026 nginx HTTP/2 Advisory Triage

**Checked:** 2026-11-18; distribution status, researcher disclosure, and KEV status updated 2026-11-20  
**Scope:** nginx Open Source and NGINX Plus deployments, including distribution packages and container images.  
**Primary sources:** [nginx security advisories](https://nginx.org/en/security_advisories.html), [nginx 1.30.7 release](https://github.com/nginx/nginx/releases/tag/release-1.30.7), [F5 CVE-2026-123007 advisory](https://my.f5.com/manage/s/article/K000163926), [F5 CVE-2026-123633 advisory](https://my.f5.com/manage/s/article/K000163928), [Ubuntu CVE-2026-123007 tracker](https://ubuntu.com/security/CVE-2026-123007), [Ubuntu CVE-2026-123633 tracker](https://ubuntu.com/security/CVE-2026-123633), [Debian CVE-2026-123007 tracker](https://security-tracker.debian.org/tracker/CVE-2026-123007), [nginx2root researcher disclosure](https://nginx2root.com/), and the [CISA KEV feed](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## Decision record

Two 18 November advisories affect HTTP/2 client-facing configurations. The
nginx Open Source ranges below end at mainline 1.31.8. The Open Source fixes are
1.30.7 on the stable branch and 1.31.9 on the mainline branch. NGINX Plus uses
the supported vendor build identified in the relevant F5 advisory, rather than
either Open Source branch floor. Treat an internet-reachable deployment with
HTTP/2 enabled as urgent until a supported package update is deployed or the
owner-approved temporary mitigation is in place. This note does not assert
observed exploitation in a particular environment.

| Advisory | Upstream condition | Confirmed effect | Potential effect | Fixed upstream |
| --- | --- | --- | --- | --- |
| [CVE-2026-123007](https://nginx.org/en/security_advisories.html) | Open Source from 1.9.5 with HTTP/2 enabled. Stable 1.30.0–1.30.6 and mainline versions through 1.31.8 are affected. | Memory corruption and a worker crash | Code execution where ASLR is disabled or bypassed | Open Source 1.30.7 or 1.31.9. NGINX Plus vendor build in [F5 advisory](https://my.f5.com/manage/s/article/K000163926) |
| [CVE-2026-123633](https://nginx.org/en/security_advisories.html) | Open Source from 1.19.7 with HTTP/2 enabled, a proxied backend, and low `worker_connections`. Stable 1.30.0–1.30.6 and mainline versions through 1.31.8 are affected. | Worker denial of service | Code execution where ASLR is disabled or bypassed | Open Source 1.30.7 or 1.31.9. NGINX Plus vendor build in [F5 advisory](https://my.f5.com/manage/s/article/K000163928) |

The upstream release also fixes advisories with separate preconditions. Include
them in the same package decision only after recording whether the deployment
uses the affected feature: resolver response processing, HTTP/3, TLS 1.3 request
bodies, the mail proxy module, `alias` with `try_files`, stream client-certificate
validation, and stream `ssl_preread`. The [release note](https://github.com/nginx/nginx/releases/tag/release-1.30.7)
names the affected components and links to the upstream changes. A service is not
cleared merely because its HTTP/2 configuration is out of scope.

[CVE-2026-120993](https://nginx.org/en/security_advisories.html) is separate
from the release-1.30.7 fixes. It affects only mainline Open Source 1.31.4–1.31.8
when PROXY protocol version 2 is used and is fixed in 1.31.9. Assess it from the
effective listener configuration and upgrade it on its own path. The listed
1.30.7 stable release is not its fixed branch.

## Researcher disclosure and exploitation status

The finder's disclosure site, [nginx2root.com](https://nginx2root.com/),
attributed to Xint, groups CVE-2026-123007, CVE-2026-123633, CVE-2026-123634
(resolver), CVE-2026-121810 (HTTP/3), and CVE-2026-113425 (mail proxy) and
claims a path from a remote client to root on the server host. At the
2026-11-20 check the vendor and distribution sources read for this note
described worker crashes, denial of service, and code execution in the worker
process where ASLR is disabled or bypassed. They did not describe a privilege
escalation from the worker user to root. Treat the root claim as the
researcher's claim until the full write-up or a vendor statement is reviewed,
and do not lower priority because of that gap: code execution in a worker can
expose TLS private keys, upstream credentials, and proxied traffic.

At the 2026-11-20 check, none of the November nginx CVEs was in the CISA KEV
catalog (catalog version 2026.11.18). This note did not establish whether
public exploit code exists. Recheck KEV, the researcher site, and vendor
advisories before closing; an exploit release or KEV listing raises the urgency
of every unpatched HTTP/2 listener.

## Inventory and applicability

Record the package or image provenance, full build version, active binary path,
container digest or service revision, effective configuration, listener exposure,
and the HTTP protocol negotiated by a controlled client. Record the proxied
upstream and `worker_connections` evidence for CVE-2026-123633. A package-manager
version, image tag, or static configuration file alone does not prove what is
serving traffic.

When a repository is the starting point, search for every place nginx can enter
a deployment: `nginx.conf` and site files, configuration templates and heredocs
in setup scripts, package installs (`apt-get install nginx`, `apk add nginx`, and
similar), Dockerfile `FROM` lines and Compose or Kubernetes images that ship
nginx or OpenResty, ingress controller charts, and deployment runbooks. A
repository shows intended configuration only. Map each hit to a running host or
image before rating it, and record a hit with no known deployment as `unknown`
rather than as safe.

Identify where HTTP/2 terminates. HTTP/2 enabled at a CDN edge does not establish
that the origin nginx accepts HTTP/2, and an origin setting does not establish the
edge protocol. Inspect both boundaries where they exist. Check both directive
forms in the effective nginx configuration: the legacy `listen ... http2` form
and the newer `http2 on;` form. Include inherited server blocks and generated
configuration in the evidence.

Do not compare a distribution package version mechanically with 1.30.7 or 1.31.9.
Debian- and Ubuntu-derived packages can carry a security backport under an older
upstream-looking version. Conversely, upstream release numbers do not prove a
distribution package includes the fix. Check the relevant distribution security
tracker, package changelog, and installed package build, then verify the running
process or rebuilt image. The Ubuntu tracker applies to Ubuntu-distributed nginx
packages. nginx.org or other third-party packages installed on Ubuntu require
their own package provenance and vendor advisory. On 2026-11-18 Ubuntu marked
supported nginx packages vulnerable for both CVEs. On 2026-11-19 Ubuntu
published USN-9159-1 with fixed builds for both CVEs; at the 2026-11-20 check
the trackers listed, for example, `1.24.0-2ubuntu7.20` for 24.04 LTS,
`1.28.3-2ubuntu1.13` for 26.04 LTS, and `1.18.0-6ubuntu14.23` for 22.04 LTS.
Older releases are fixed only through ESM or Ubuntu Pro packages. Read the
tracker for the exact release rather than copying these values.

At the same check the Debian tracker for CVE-2026-123007 listed fixes in
trixie security (`1.26.3-3+deb13u11`, DSA-6642-1), bookworm security
(`1.22.1-9+deb12u11`, DLA-4918-1), and sid (`1.30.6-4`), and still listed
forky `1.30.6-3` as vulnerable. Check the Debian tracker for CVE-2026-123633
separately; this note did not record it.

Products that bundle their own nginx build, such as virtual appliances, hosting
control panels, Kubernetes ingress controllers, and vendor VM images, need that
product vendor's fixed build or image. The host operating system's nginx
package status does not cover a bundled binary. For example, the 1C-Bitrix
security team announced a `bx-nginx` 1.30.7 build for its VM and environment
packages in a [Russian-language post](https://habr.com/ru/articles/1109970/).
Record each bundled product as its own inventory item.

## Remediation and closure

Install the vendor-supported package update or rebuild from a fixed base image,
then restart or roll out the workload so the running processes execute the new
binary. A configuration reload alone can leave the old executable mapped. A
temporary removal of HTTP/2 from client listeners prevents the two HTTP/2 paths
described above, but changes client protocol behaviour and does not address the
other 1.30.7 or 1.31.9 fixes. Test the resulting HTTP/1.1 path, application
health, proxying, and capacity before treating that mitigation as usable. Restore
HTTP/2 only after the fixed deployment is verified.

Close each advisory with dated evidence of the vendor fix or supported backport,
the deployed process or immutable image identity, the effective listener and
module configuration, a successful normal request through the live route, and a
controlled negative check that confirms HTTP/2 is unavailable when the temporary
mitigation is selected. Record that state as mitigated, not patched, until the
vendor fix is deployed. Preserve the prior listener configuration for rollback
and test the restored protocol path before rolling it back. Recheck on package
or base-image rebuild, configuration change, distribution advisory update, or a
new nginx advisory.
