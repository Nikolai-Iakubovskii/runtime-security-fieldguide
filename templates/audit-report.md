# Runtime Security Audit Report

**Report ID:** `RSA-YYYY-NNN`
**Prepared:** `YYYY-MM-DDThh:mm:ssZ`
**Owner:** `team-or-role`
**Scope:** `production | staging | development | CI | vendor-managed`
**Assessment window:** `YYYY-MM-DD to YYYY-MM-DD`
**Status:** `open | mitigated | verified | accepted-risk | unknown`

## Scope and baseline

| Field | Record |
| --- | --- |
| In-scope assets | `service, worker, host class, or image family` |
| Exclusions | `explicit exclusions and why` |
| Baseline source | `inventory command/result location, redacted as needed` |
| Deployed runtime | `process/service/image digest/workload revision` |
| Installed runtime | `package/runtime version and source` |
| CA/trust source | `OS/language/application/container/client trust store` |
| Evidence timestamp | `YYYY-MM-DDThh:mm:ssZ` |

## Findings

| ID | Component | Environment | Finding | Source | Evidence | Status | Fix owner | Rollback | Recheck trigger |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `RSA-001` | `runtime` | `production` | `description` | `primary source URL` | `redacted evidence reference` | `open` | `role` | `documented step` | `new advisory or upgrade` |

## Certificate and database-client checks

| Check | Expected result | Observed result | Evidence timestamp |
| --- | --- | --- | --- |
| Normal connection to `db.example.invalid` | Succeeds with trusted chain and matching hostname | `record` | `YYYY-MM-DDThh:mm:ssZ` |
| Invalid certificate chain | Client rejects connection | `record` | `YYYY-MM-DDThh:mm:ssZ` |
| Hostname mismatch | Client rejects connection | `record` | `YYYY-MM-DDThh:mm:ssZ` |
| TLS configuration | Verification enabled; no bypass callback or insecure override | `record` | `YYYY-MM-DDThh:mm:ssZ` |

## Production, development, and vendor limits

| Area | Classification | Decision | Reason | Owner | Recheck trigger |
| --- | --- | --- | --- | --- | --- |
| `dependency or runtime` | `production / development / vendor-managed` | `fix / defer / accept / unknown` | `compatibility or access rationale` | `role` | `event/date` |

## Remediation record

| Change | Authorization | Verification | Rollback readiness | Completed |
| --- | --- | --- | --- | --- |
| `approved change` | `owner/ticket/change record` | `deployed identity, health, positive and negative tests` | `tested or documented rollback` | `YYYY-MM-DDThh:mm:ssZ` |

## Notes and limitations

State unknowns, unavailable evidence, vendor-owned components, and boundaries. Do not infer that a current clean check proves no historical compromise.
