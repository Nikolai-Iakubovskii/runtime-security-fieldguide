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
the chain and requested hostname. [libpq SSL modes](https://www.postgresql.org/docs/current/libpq-connect.html)

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
| Inventory | process owner, executable, effective host, CA file hash, TLS settings | each production entry point is listed |
| Positive control | authorized known-good endpoint | strict client succeeds |
| Target chain and hostname | read-only `SELECT 1` through the real client path | strict client succeeds |
| Negative hostname | authorized same endpoint with a deliberately wrong TLS server name | fails specifically after a valid-chain baseline |
| Server view | `pg_stat_ssl` during the test | client backend reports `ssl = true` |
| Rollout | replacement process/task identity and startup logs | new process uses the intended configuration |

A wrong-hostname test is valid only after the positive control and target
strict-chain test pass. If DNS, routing, CA loading, credentials, TLS protocol,
or authentication fails first, record **unknown**, not “hostname rejected.”
Run hostname-negative tests only against services you own or are authorized to
test; they are a control, not an internet scan.

A minimal read-only SQL observation, run only with approved credentials, is:

```sql
SELECT ssl, version, cipher
FROM pg_stat_ssl
WHERE pid = pg_backend_pid();
```

This proves that one backend is encrypted. It does not prove that the client
verified the hostname or that all other pools and workers use the same CA.

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
3. Test strict positive, target, and wrong-name controls in a non-production
   environment, then through each production code path during an approved
   rollout.
4. Keep verification enabled during rollback. Rolling back to
   `rejectUnauthorized:false`, `sslmode=require`, or an untracked bundle is not
   a safe rollback.
5. Confirm the replacement process has restarted and observe `pg_stat_ssl`.

A CA bundle refresh without a process restart is incomplete for runtimes that
load roots at startup. A successful API request does not prove migrations,
workers, or maintenance scripts adopted the new bundle.

## Completion record

| Entry point | Effective hostname | CA bundle hash | Strict `SELECT 1` | Wrong-name control | `pg_stat_ssl` | Restarted | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `<api-pool>` | `<db-host>` | `<sha256>` | pass/unknown | rejected/unknown | true/unknown | yes/no | accepted/rejected/unknown |
| `<worker-or-job>` | `<db-host>` | `<sha256>` | pass/unknown | rejected/unknown | true/unknown | yes/no | accepted/rejected/unknown |

Do not record connection strings containing passwords, client private keys,
cloud account identifiers, or private database addresses.
