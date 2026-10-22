# Application Security Verification

**Checked:** 2026-10-22  
**Scope:** This conditional module extends runtime and component audits with application behavior. It does not claim complete ASVS coverage or replace provider-specific payment and webhook requirements.

## Authorization and test boundary

Run active checks only in an explicitly authorized test environment with two owner-controlled test accounts and synthetic data. Record `not applicable` or `unknown` with evidence and an owner; never infer absence from an untested route. Do not perform payment, refund, production state-changing, broad scan, or load-test activity merely because an audit is authorized.

## Verification checklist

| Area | Bounded positive and negative evidence | Limit and owner |
| --- | --- | --- |
| Object and tenant authorization | Account A accesses its own object; Account A is denied Account B's equivalent object | record route/object class and authorization owner |
| Authentication and sessions | intended sign-in/session renewal works; revoked or expired session is denied | record revocation propagation and unknown paths |
| Paid features and subscriptions | server accepts authoritative provider state; altered client-side entitlement flag is not sufficient | provider semantics require its current documentation |
| Webhooks | valid signed test event reaches intended handler once; invalid signature, wrong target, stale event, or replay is rejected/idempotent as applicable | verify signature, target, event authenticity, freshness, and replay semantics per provider |
| Rate limits | an authorized synthetic request below a low test-only threshold succeeds; a bounded request above it is denied | run only in an authorized test environment, without load generation; result does not prove abuse resistance at scale |
| File and API input | allowed synthetic input is handled; malformed or unauthorized input is rejected safely | cover relevant parsers and storage paths |
| Data exposure | authorized response has intended fields; cross-role response omits restricted fields | record cache, export, and error-path gaps |

OWASP ASVS provides a verification basis for authentication, session management, authorization, API and file handling, and business logic. Business logic must still be tested in the actual workflow: a library CVE inventory cannot establish tenant ownership, entitlement, or provider-event enforcement. [OWASP ASVS](https://owasp.org/projects/asvs) [ASVS index](https://cheatsheetseries.owasp.org/IndexASVS.html)

For payment and subscription controls, the application must make its authorization decision from the relevant authoritative provider state on the server; client flags are presentation inputs, not proof of entitlement. Before recording pass/fail, obtain the provider's current signed-event, lifecycle, freshness, and idempotency requirements. The provider documentation is the source for exact semantics, accepted retries, and event ordering.

## Evidence and decisions

| Check | Owner | Evidence | Result | Unknowns | Recheck trigger |
| --- | --- | --- | --- | --- | --- |
| `<area>` | `<owner>` | test case ID, synthetic account roles, time | pass/fail/unknown/not applicable | `<gap>` | route, policy, provider, or release change |

Keep evidence free of customer data, session values, signed event bodies, tokens, internal hostnames, and identifiers. A denied negative case must be specific to the intended control; an infrastructure error is `unknown`, not a successful denial.

## Compatibility and rollback

Authorization, session, rate-limit, and webhook changes can affect legitimate clients, delayed provider retries, or offline flows. Stage them through an owner-approved environment, preserve sufficient observability to distinguish denial from outage, and use a rollback that does not re-enable cross-tenant access or trust client entitlements. Recheck after identity, authorization, payment-provider, webhook, parser, deployment, or API contract changes.

## Sources

- OWASP, [Application Security Verification Standard 5.0](https://owasp.org/projects/asvs), accessed 2026-10-22.
- OWASP Cheat Sheet Series, [ASVS index](https://cheatsheetseries.owasp.org/IndexASVS.html), accessed 2026-10-22.
