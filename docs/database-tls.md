# PostgreSQL TLS verification field guide

**Recorded:** 2026-10-22
**Scope:** PostgreSQL clients, connection pools, migration jobs, workers,
operator scripts, and managed PostgreSQL endpoints. This guide verifies TLS;
it does not change schemas, credentials, or database parameters.

## The required client property

For a network PostgreSQL connection, require all three properties:

1. TLS is required.
2. The server chain terminates at an intended CA.
3. The requested hostname matches the server certificate.

For libpq, use `sslmode=verify-full` and an intended `sslrootcert`. PostgreSQL
documents that `prefer` is the default and may fall back to non-TLS; `require`
encrypts but does not provide hostname protection; `verify-full` verifies both
the chain and requested hostname. [libpq SSL modes](https://www.postgresql.org/docs/current/libpq-ssl.html)

| Setting | Encryption | Chain validation | Hostname validation | Suitable for production identity verification? |
| --- | --- | --- | --- | --- |
| `disable`, `allow`, `prefer` | no or conditional | no | no | no |
| `require` | yes | compatibility-dependent | no | no |
| `verify-ca` | yes | yes | no | no for public CA use |
| `verify-full` | yes | yes | yes | yes |

`PGSSLMODE`, `PGSSLROOTCERT`, and related environment variables supply default
connection parameters when calling code does not directly specify a value. Audit
precedence and effective parameters across service definitions, CI jobs, operator
shells, and connection-service files, not only application source. [libpq environment](https://www.postgresql.org/docs/current/libpq-envars.html)

## Safe connection-string pattern

Use placeholders and keep secrets out of shell history and logs:

```text
postgresql://<user>@<db-host>:5432/<database>?sslmode=verify-full&sslrootcert=<absolute-ca-path>
```

The `<db-host>` must be the hostname covered by the certificate. Do not replace
it with an arbitrary IP address, a convenience alias, or a proxy address unless
that exact name is covered and has been verified.

## Practical libpq controls

Use a test-only, authorized resolved address. `host` supplies the TLS server
name while `hostaddr` fixes the TCP destination, so retain the same `hostaddr`
when changing only the hostname. Do not use this pattern against a failover
endpoint unless its current authorized address has been confirmed immediately
before the check.

```sh
psql -X -v ON_ERROR_STOP=1 \
  "host=<correct-host> hostaddr=<same-authorized-resolved-address> \
  port=5432 dbname=<database> user=<user> sslmode=verify-full \
  sslrootcert=<absolute-ca-path> gssencmode=disable connect_timeout=10" \
  -c 'SELECT 1;'
```

For the negative control, change only `host=<deliberately-wrong-name>` and keep
`hostaddr`, port, CA, credentials, and all other parameters unchanged. Expect a
hostname error after the matching-host baseline succeeds. DNS, authentication,
CA-loading, routing, or protocol errors are unknown outcomes, not a hostname
negative pass. `gssencmode=disable` makes this explicitly an SSL test where
working GSSAPI infrastructure would otherwise be preferred over SSL. [libpq
connection parameters](https://www.postgresql.org/docs/current/libpq-connect.html)

## Managed RDS-style endpoints

For Amazon RDS PostgreSQL, download the official **regional** CA bundle, record
its source URL and checksum, and trust the root CA only. AWS says registering
intermediate CAs can interfere with automatic server-certificate rotation.
[RDS certificate bundles](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)

Use the provider endpoint as the requested hostname and test `verify-full`.
AWS's PostgreSQL guidance uses `sslrootcert` with `sslmode=verify-full`; it
also explains that RDS can require TLS with `rds.force_ssl`. [RDS PostgreSQL
SSL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)

## Database proxies are two TLS legs

Treat application-to-proxy and proxy-to-database as separate connections. Record
the effective host, CA source, TLS policy, owner, and evidence for each leg.
The application validates the proxy server certificate; its direct-RDS CA recipe
does not automatically apply to an RDS Proxy endpoint. AWS states that RDS Proxy
uses ACM certificates. Source checked 2026-10-22: [RDS Proxy TLS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.howitworks.html).

For PgBouncer, use client settings to validate the proxy on the application-to-
proxy leg. `client_tls_sslmode` governs client certificates presented to
PgBouncer: its `verify-full` has the same behavior as `verify-ca` for client
certificates and does not validate a database-backend hostname. On the proxy-to-
database leg, `server_tls_sslmode=verify-full` with `server_tls_ca_file` validates
the backend chain and name; the default `prefer` does not validate either.
Source checked 2026-10-22: [PgBouncer configuration](https://www.pgbouncer.org/config.html).

For a managed proxy-to-database leg, the vendor may own the certificate policy
and prevent customer CA injection or negative testing in production. Record the
available configuration and vendor evidence, and mark an untestable leg as
unknown rather than implying a customer-controlled test occurred.

## Node.js `pg` and TypeORM

`pg` passes its `ssl` object to Node TLS. Use a CA bundle and strict
verification; do not provide a custom hostname-acceptance callback.

```ts
import { readFileSync } from 'node:fs';

const databaseTls = {
  ca: readFileSync('<absolute-ca-path>', 'utf8'),
  rejectUnauthorized: true,
};

// Pool, TypeORM datasource, and worker bootstrap must use the same value.
const config = { host: '<db-host>', database: '<database>', ssl: databaseTls };
```

When `pg` parses a `connectionString` containing `sslmode`, `sslrootcert`,
`sslcert`, or `sslkey`, it replaces the separately supplied `ssl` object.
Review both configuration sources before concluding the CA is active.
[node-postgres SSL](https://node-postgres.com/features/ssl)

For TypeORM, audit every constructor that can reach production: the API pool,
CLI datasource used by migrations, long-lived workers, one-shot jobs, repair
scripts, and test bootstrap. Local test PostgreSQL may intentionally use
`ssl: false`, but that exception must be bounded to local/test configuration
and never inherited by a deployment task.

## Verification sequence

| Step | Evidence | Pass criterion |
| --- | --- | --- |
| Inventory | process owner, executable, actual route, and effective host/CA/policy for each TLS leg | each production entry point and leg is listed |
| Positive baseline | authorized normal target through the actual client path | strict client succeeds |
| Target chain and hostname | read-only `SELECT 1` through the real client path | strict client succeeds |
| Untrusted-chain negative | matching hostname with a well-formed unrelated CA or lab-issued chain | fails with certificate-trust error, not DNS, routing, CA-loading, or authentication error |
| Negative hostname | authorized same endpoint with a deliberately wrong TLS server name | fails specifically after a valid-chain baseline |
| Server view | `pg_stat_ssl` during the test | client backend reports `ssl = true` for that observed session/leg |
| Rollout | replacement process/task identity and startup logs, followed by health check | new process uses the intended configuration and health check succeeds |

Run the untrusted-chain control only in a lab or against an endpoint you own,
with the matching hostname and a well-formed unrelated CA or lab issuer. A
missing or invalid CA file is not an untrusted-chain control. A wrong-hostname
test is valid only after the positive baseline and target strict-chain test pass.
If DNS, routing, CA loading, credentials, TLS protocol, or authentication fails
first, record **unknown**, not “hostname rejected.” Run negative controls only
against services you own or are authorized to test; they are controls, not an
internet scan. Do not disable verification for any control.
After the control tests, rerun the approved health check through the actual
deployed client path and route.

A minimal read-only SQL observation, run only with approved credentials, is:

```sql
SELECT ssl, version, cipher
FROM pg_stat_ssl
WHERE pid = pg_backend_pid();
```

This proves that one observed backend session is encrypted. It does not prove
certificate validation for either proxy leg, hostname verification, or that all
other pools and workers use the same CA.

## Server enforcement and identity

Set server-side force-TLS policy where supported, then verify it separately.
Server force-TLS prevents plaintext fallback; it does not prove the client
validated the server identity. PostgreSQL describes `verify-full` as the mode
that protects against both eavesdropping and man-in-the-middle spoofing.
[PostgreSQL SSL support](https://www.postgresql.org/docs/current/libpq-ssl.html)

Where SCRAM is used over a network, consider the documented channel-binding
requirements as a separate anti-spoofing control. It does not replace CA and
hostname validation. [PostgreSQL spoofing guidance](https://www.postgresql.org/docs/current/preventing-server-spoofing.html)

## CA rotation and rollback

Before a CA rotation:

1. Obtain the new bundle from the provider's official distribution point.
2. Record the bundle version, roots, checksum, and expiry/rotation schedule.
3. Test the positive baseline, target, untrusted-chain negative, and
   wrong-name controls in a non-production environment, then through each
   production code path and customer-testable TLS leg during an approved rollout.
   For a managed leg without an authorized safe test, record the vendor-managed
   evidence and an unknown verification gap.
4. Keep verification enabled during rollback. Rolling back to
   `rejectUnauthorized:false`, `sslmode=require`, or an untracked bundle is not
   a safe rollback.
5. Confirm the replacement process has restarted, repeat the health check through
   the actual client path, and observe `pg_stat_ssl` where it applies.

A CA bundle refresh without a process restart is incomplete for runtimes that
load roots at startup. A successful API request does not prove migrations,
workers, or maintenance scripts adopted the new bundle.

## Completion record

For a vendor-managed leg without an authorized safe test, record the available
vendor evidence and `unknown` in the affected control and status fields.

| Entry point | TLS leg | Effective host | CA/policy | Owner and evidence | Positive baseline | Strict `SELECT 1` | Untrusted-chain negative | Wrong-name control | `pg_stat_ssl` | Restarted | Post-test health | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `<api-pool>` | app → proxy or DB | `<host>` | `<CA hash; verify-full>` | `<owner; config/vendor evidence>` | pass/unknown | pass/unknown | rejected/unknown | rejected/unknown | true/unknown | yes/no | pass/unknown | accepted/rejected/unknown |
| `<proxy>` | proxy → DB | `<host>` | `<CA hash; verify-full>` | `<owner; config/vendor evidence>` | pass/unknown | pass/unknown | rejected/unknown | rejected/unknown | true/unknown | yes/no | pass/unknown | accepted/rejected/unknown |

Do not record connection strings containing passwords, client private keys,
cloud account identifiers, or private database addresses.
