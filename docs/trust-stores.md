# Trust-store verification field guide

**Recorded:** 2026-10-22
**Scope:** outbound TLS clients, embedded runtimes, browsers, and packaged trust
bundles. This is a verification guide, not an update script.

A successful HTTPS request proves only that one client accepted one certificate
chain at one moment. It does not prove that every deployed runtime has the same
roots, that hostname validation is enabled, that a proxy was not involved, or
that a downloaded binary is authentic.

## What a useful result says

A target result has one of four states:

| State | Meaning | Counts as a secure result? |
| --- | --- | --- |
| accepted | A strict client accepted the chain and hostname. | Only with the controls below. |
| rejected | A strict client rejected the certificate or hostname. | Expected for a deliberate negative control. |
| unknown | Timeout, DNS failure, route failure, proxy authentication, unsupported runtime, or inconclusive output. | No. |
| bypassed | Validation was disabled or a custom callback accepted an error. | No. |

Do not turn an outage into a pass. Preserve the error class and the runtime
version, then retest when routing is available.

## Controlled test design

Use an approved service endpoint and an approved positive-control endpoint. Do
not scan arbitrary internet hosts.

1. Record the exact executable, package build, service account, process ID, and
   actual production route.
2. Run a **distinct positive baseline** that should succeed with normal public
   trust and is separate from the target.
3. Run the approved target with normal strict verification.
4. In a lab or against an endpoint you own, run an **untrusted-chain negative
   control** for the matching target hostname. Use a well-formed certificate
   chain issued by an unrelated CA or lab issuer; do not simulate this with a
   missing or invalid CA file. Expect a certificate-trust failure, not a DNS,
   routing, proxy-authentication, or application-authentication failure.
5. In a lab or against an endpoint you own, run a **negative hostname control**:
   connect to the same authorized address but supply a deliberately nonmatching
   server name. It must be rejected after the chain has already been proven
   valid. A CA or network failure is not a hostname-negative pass.
6. Run the controls through each production egress route, proxy, and actual client
   runtime. A workstation result does not establish server or browser behavior.
7. Restart or roll out the owning process before claiming a changed bundle is
   active, then repeat the health check through the actual client path.
   Long-lived pools, browsers, and Electron cache certificate decisions.

A small curl control, using placeholders only:

```sh
curl -q --fail --silent --show-error \
  --cacert ./approved-ca.pem \
  https://service.example.invalid/health
```

A pass requires the intended executable and service identity. Run the control
as the actual service account. Shell `PATH`, login profiles, an interactive
user, and a container entrypoint may select different binaries and bundles.

## Runtime and store inventory

Every runtime row also requires the controlled untrusted-chain and wrong-name
negative results described above, in addition to its runtime-specific criteria.

| Surface | What to record | Strict pass criterion | Common bypass or caveat |
| --- | --- | --- | --- |
| Node.js | `node --version`, executable path, bundled/system/custom CA mode | TLS request accepts target and rejects wrong name without custom acceptance callback | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized:false`, `checkServerIdentity`, and `NODE_EXTRA_CA_CERTS` need source and runtime review. |
| Bun | Actual Bun executable/version and effective `tls.ca` roots | Strict request accepts target and rejects bad-chain and wrong-name controls | `tls.rejectUnauthorized=false` bypasses verification; custom `tls.checkServerIdentity` replaces hostname checking. Node results do not establish Bun behavior. [Bun fetch TLS](https://bun.com/docs/runtime/networking/fetch) |
| Deno | Actual Deno executable/version, `DENO_TLS_CA_STORE` selection/order, and `DENO_CERT` source | Strict request accepts target and rejects bad-chain and wrong-name controls | The default store is Mozilla; `DENO_TLS_CA_STORE` can select ordered system/Mozilla stores, and `DENO_CERT` adds a PEM file. A host CA update may not be selected. [Deno environment variables](https://docs.deno.com/runtime/reference/env_variables/) |
| Rust/reqwest | Binary build provenance, actual client TLS backend, and configured root source | Actual client accepts target and rejects bad-chain and wrong-name controls | Backend choice and client configuration determine roots. Third-party binaries can vendor webpki roots and need rebuild/release evidence. `danger_accept_invalid_certs`, `danger_accept_invalid_hostnames`, and equivalent `tls_danger_accept_*` options bypass checks; no blanket Rust default applies. [reqwest ClientBuilder](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html) [webpki-roots release](https://github.com/rustls/webpki-roots/releases/tag/v%2F1.0.10) |
| Python | interpreter path, `certifi` bundle hash/version, `ssl.OPENSSL_VERSION` | `ssl.create_default_context(cafile=...)` with hostname checking and `CERT_REQUIRED` | A virtual environment can carry a different certifi bundle from the host Python. Requests reads `REQUESTS_CA_BUNDLE`, then `CURL_CA_BUNDLE`; `verify=False` bypasses verification. [Requests CA certificates](https://requests.readthedocs.io/en/latest/user/advanced/#ca-certificates) |
| curl/OpenSSL | `curl --version`, SSL backend, CA file/path | Explicit `--cacert` or reviewed default bundle accepts target; wrong-name control rejects | Inspect `.curlrc` at the service account scope; place `-q` first to skip automatic curl config loading for a diagnostic. `-k/--insecure`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, and `OPENSSL_CONF` alter results. [curl certificate verification](https://curl.se/docs/sslcerts.html) [OpenSSL environment](https://docs.openssl.org/master/man7/openssl-env/) |
| JVM | `java -version`, exact `cacerts` path and hash | Actual JVM process accepts target with hostname verification enabled | A JRE bundled inside an IDE, runner, or application can differ from host Java. |
| Go | `go version`, binary build provenance, `GODEBUG` and CA env | Default verifier accepts target and rejects wrong name | `InsecureSkipVerify`, custom `DialTLSContext`, and `x509usefallbackroots` change behavior. Since Go 1.27, `SSL_CERT_FILE` or `SSL_CERT_DIR` prevents macOS/Windows platform APIs unless `GODEBUG=x509sslcertoverrideplatform=0`; earlier Go releases differ. [Go x509](https://pkg.go.dev/crypto/x509) |
| Ruby/Bundler | `ruby -v`, Bundler-selected Ruby, OpenSSL build/default paths | `VERIFY_PEER` plus hostname validation succeeds | Ruby `SSLContext` defaults to `VERIFY_NONE`; hostname verification also needs a hostname on the socket. [Ruby SSLContext](https://docs.ruby-lang.org/en/3.2/OpenSSL/SSL/SSLContext.html) |
| pip / uv | Actual tool version, active config, selected TLS mode and CA source | Package fetch accepts target and rejects bad-chain and wrong-name controls | pip 24.2+ on Python 3.10+ uses system certificates alongside vendored certifi by default; inspect older combinations separately. `PIP_CERT` selects a custom bundle, so record the actual mode rather than assuming custom roots replace vendored roots. `--trusted-host` bypasses normal host verification. uv uses bundled roots by default; system/custom-root modes must be recorded separately, and `allow-insecure-host` bypasses verification. [pip HTTPS certificates](https://pip.pypa.io/en/stable/topics/https-certificates/) [Python incident announcement](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576) [uv advisory](https://github.com/astral-sh/uv/security/advisories/GHSA-hq85-5cpj-mr62) |
| Git HTTPS | `git --version`, effective URL-scoped config, libcurl backend and CA source | Fetch/push uses verification for the actual remote URL | `http.sslVerify` defaults true but `GIT_SSL_NO_VERIFY` can override it. Review `http.sslCAInfo`, `http.sslCAPath`, `http.sslBackend`, and their environment equivalents for the active backend. [Git configuration](https://git-scm.com/docs/git-config) |
| .NET | `dotnet --info`, deployed runtime and OS store | Default chain/hostname result succeeds; callback preserves `SslPolicyErrors.None` | `DangerousAcceptAnyServerCertificateValidator` always returns true. [Microsoft Learn](https://learn.microsoft.com/dotnet/api/system.net.http.httpclienthandler.dangerousacceptanyservercertificatevalidator) |
| NSS/Firefox | browser version and actual profile/NSS database | Browser accepts target with its normal profile | NSS combines built-in roots with user/admin database trust flags; an OS curl result is not a Firefox result. [Mozilla NSS roots](https://wiki.mozilla.org/NSS:Root_certs) |
| Electron | Electron version, Chromium network session, app code | Chromium default verification result is retained | `setCertificateVerifyProc` callback `0` accepts and disables CT verification; results are cached by the network service. [Electron session](https://www.electronjs.org/docs/latest/api/session) |

## Incident negative-chain controls

When an approved incident test list publishes multiple negative certificate
chains, test **every** chain in the current published list with each in-scope
client and its explicit bundle, alongside the distinct positive baseline and
both controlled negatives. Record the retrieval date and the list version or
archive hash when available, plus the result and rejection reason for each
chain. Treat a chain that cannot be fetched, parsed, or routed as unknown; do
not count one rejected chain as coverage for the others. Read a list as data and
do not execute linked JavaScript, shell commands, or unreviewed helper code.

## Go and static binaries

Static binaries do not necessarily reveal their source dependency graph through
an OS package manager. When source is available, `go mod verify` checks cached
module archives and extracted directories against recorded hashes; it does not
attest an already built binary. `GOPRIVATE`, `GONOSUMDB`, and `GOSUMDB=off`
change checksum-database coverage. [Go module reference](https://go.dev/ref/mod#go-mod-verify)

Treat a third-party or stripped binary as **unknown** until its release
provenance, signature or checksum, and runtime TLS behavior are independently
verified. A module check is not a code-signing check.

## Proxies, custom roots, and revocation

Inventory proxy settings at the process boundary without printing credentials.
Go's default HTTP transport honors `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`.
Custom roots may be legitimate for a private CA or intercepting proxy, but need
an owner, scope, expiry, and target-specific tests. [Go net/http](https://pkg.go.dev/net/http)

An unexpected proxy certificate issuer is **unknown** until the proxy route and
its approved enterprise CA are identified. It is not, by itself, proof that a
public root is distrusted. When a narrowly scoped, verified endpoint workaround
is required, keep certificate validation enabled; do not change global host
routing to make a control pass.

Record whether revocation is checked, unavailable, or deliberately disabled.
Do not infer revocation behavior from a chain-only test. A vendor emergency
blocklist or revoked-root bundle should be applied as a documented, temporary
trust-store overlay, tested with positive and negative controls, and reconciled
with the vendor's next normal bundle update. Never silently replace a vendor
bundle with an untracked local file.

## Browser assets and code signing are separate

TLS validation does not establish that a downloaded program, action, package,
or browser asset is the intended release. For external browser JavaScript or
CSS, Subresource Integrity verifies bytes fetched for an `integrity` hash, but
not a compromised page that changes the hash. [MDN SRI](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)

For binaries and images, verify the publisher's signature or provenance in
addition to TLS. Record the artifact digest, signer identity, build workflow,
and repository identity; do not treat a successful download as provenance.

## Evidence record

Keep a compact row per process:

| Process/service account | Executable and version | Bundle/store ID | Positive baseline | Target | Untrusted-chain negative | Wrong-name negative | Post-test health | Result | Retest trigger |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `<service-account>` | `<absolute executable>` | `<bundle hash or OS store>` | pass/unknown | accepted/rejected/unknown | rejected/unknown | rejected/unknown | pass/unknown | `<state>` | restart, bundle change, proxy change, CA rotation |

Never include credentials, full environment dumps, private endpoints, or
certificate private keys in the record.
