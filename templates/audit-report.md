# Runtime Security Audit Report

**Report ID:** `RSA-YYYY-NNN`
**Prepared:** `YYYY-MM-DDThh:mm:ssZ`
**Owner:** `team-or-role`
**Scope:** `production | staging | development | CI | vendor-managed`
**Assessment window:** `YYYY-MM-DD to YYYY-MM-DD`
**Status:** `open | mitigated | verified | accepted-risk | unknown`

## Fix now

| ID | Finding | Priority and reason | Fix owner | Due date | Evidence |
| --- | --- | --- | --- | --- | --- |
| `RSA-001` | `actionable finding` | `critical; deployed, reachable, and supported fix exists` | `role` | `YYYY-MM-DD` | `redacted reference` |

## Plan

| ID | Finding | Priority and reason | Fix owner | Due date | Dependency or compatibility constraint |
| --- | --- | --- | --- | --- | --- |
| `RSA-002` | `planned remediation` | `high; mitigation or migration required` | `role` | `YYYY-MM-DD` | `constraint and rollback` |

## Unable to verify

| ID | Component / scope | Missing evidence or unsupported coverage | Owner | Recheck date / trigger |
| --- | --- | --- | --- | --- |
| `RSA-003` | `artifact or control` | `missing deployed digest or unsupported input` | `role` | `YYYY-MM-DD / deployment` |

## Scope and baseline

| Field | Record |
| --- | --- |
| In-scope assets | `service, worker, host class, or image family` |
| Exclusions | `explicit exclusions and why` |
| Baseline source | `inventory command/result location, redacted as needed` |
| Deployed runtime | `process/service/image digest/workload revision` |
| Installed runtime | `package/runtime version and source` |
| CA/trust source | `OS/language/application/container/client trust store` |
| Advisory / exploitation status | `CVE/advisory, KEV/EPSS check date, confirmed-exploitation status` |
| Incident and evidence windows | `relevant acquisition/exposure period; telemetry reviewed` |
| Regression state | `exact build/configuration known issues; pilot/rollback/pending restart` |
| Coverage owner | `owner for admin, appliance, extension, or connector surface` |
| Evidence timestamp | `YYYY-MM-DDThh:mm:ssZ` |

## Mandatory module and dependency coverage

| Module | Status: applicable / not applicable / unknown | Scope and evidence | Owner | Recheck trigger |
| --- | --- | --- | --- | --- |
| Dependency security | `state` | `coverage matrix reference` | `role` | `artifact or advisory change` |
| Service/container hardening | `state` | `deployed configuration reference` | `role` | `task or policy change` |
| Secrets | `state` | `review reference` | `role` | `secret or deployment change` |
| Application security | `state` | `review reference` | `role` | `release or route change` |
| Mobile security | `state` | `review reference` | `role` | `mobile release` |

| Component and scope | Language / package manager | Roots / lockfile or inventory | Graph scope and audit tool/version | Advisory data checked at | Final build or image digest | Result and coverage gaps |
| --- | --- | --- | --- | --- | --- | --- |
| `service` | `language / manager` | `roots; lockfile or inventory` | `direct/transitive; prod/dev/build/CI; tool` | `timestamp` | `sha256:...` | `state; unsupported or missing input` |

| Component | Deployed version / digest | Support status and end date | Lifecycle source / checked date | Upstream fix or supported-distro backport | Migration owner / deadline |
| --- | --- | --- | --- | --- | --- |
| `runtime` | `version / digest` | `supported / EOL / unknown; date` | `URL; date` | `evidence` | `role; date` |

| Owner | Cadence and policy basis | Last successful review | Next scheduled review | Graph, alert, version-update, PR-review, artifact/runtime/trust-store evidence |
| --- | --- | --- | --- | --- |
| `role` | `weekly recommendation; rationale` | `timestamp` | `timestamp` | `references` |

## Findings

| ID | Component | Environment | Finding | Priority and reason | Advisory / window | Regression / coverage owner | Source | Evidence | Status | Fix owner / due date | Rollback | Recheck trigger |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `RSA-001` | `runtime` | `production` | `description` | `priority and exposure rationale` | `status and dates` | `state / role` | `primary source URL` | `redacted evidence reference` | `open` | `role / YYYY-MM-DD` | `documented step` | `new advisory or upgrade` |

## Certificate and database-client checks

Create a separate table for every TLS leg or identify the leg in the first
column, for example `app → proxy` or `proxy → database`.

| TLS leg / check | Expected result | Observed result | Evidence timestamp |
| --- | --- | --- | --- |
| `app → database`: normal connection to `db.example.invalid` | Succeeds with trusted chain and matching hostname | `record` | `YYYY-MM-DDThh:mm:ssZ` |
| `app → database`: invalid certificate chain | Client rejects connection | `record` | `YYYY-MM-DDThh:mm:ssZ` |
| `app → database`: hostname mismatch | Client rejects connection | `record` | `YYYY-MM-DDThh:mm:ssZ` |
| `app → database`: post-negative normal connection / health | Succeeds through the same client path | `record` | `YYYY-MM-DDThh:mm:ssZ` |
| `app → database`: TLS configuration | Verification enabled; no bypass callback or insecure override | `record` | `YYYY-MM-DDThh:mm:ssZ` |

## Production, development, and vendor limits

| Area | Classification | Decision | Reason | Owner | Recheck trigger |
| --- | --- | --- | --- | --- | --- |
| `dependency or runtime` | `production / development / vendor-managed` | `fix / defer / accept / unknown` | `compatibility or access rationale` | `role` | `event/date` |

## Accepted-risk record

| ID | Accepted risk | Approver | Rationale | Review date | Recheck trigger |
| --- | --- | --- | --- | --- | --- |
| `RSA-004` | `bounded risk` | `authorized role` | `documented decision` | `YYYY-MM-DD` | `advisory, release, or deadline` |

## Remediation record

| Change | Authorization | Verification | Rollback readiness | Completed |
| --- | --- | --- | --- | --- |
| `approved change` | `owner/ticket/change record` | `deployed identity, health, positive and negative tests` | `tested or documented rollback` | `YYYY-MM-DDThh:mm:ssZ` |

## Notes and limitations

State unknowns, unavailable evidence, vendor-owned components, and boundaries. Do not infer that a current clean check proves no historical compromise.
