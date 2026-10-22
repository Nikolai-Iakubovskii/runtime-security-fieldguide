# Mobile Security Verification

**Checked:** 2026-10-22  
**Scope:** Conditional iOS and Android review for an actual signed release artifact, installed build, or deployed version. This extends runtime/component audits; record its SDK inventory in the [dependency security review](dependency-security.md). It is not MASVS certification or a claim of full compliance.

## Authorization and artifact identity

Test only owner-controlled artifacts, devices, test accounts, and synthetic data. Record package/bundle identifier only when public-safe, version, signing state, artifact digest where available, installed/deployed version, owner, and acquisition time. Do not give bypass or exploit instructions, and do not run broad scans or production state-changing tests under audit authority alone.

| Question | Evidence | Status |
| --- | --- | --- |
| What was tested? | signed artifact/build, version, digest, acquisition path | pass/unknown/not applicable |
| What ships with it? | dependency and SDK inventory; link to dependency review | pass/unknown/not applicable |
| Who owns the decision? | mobile, backend, identity, and release owners | recorded/unknown |

## Review areas

| Area | Evidence to seek | Bounded check and limit |
| --- | --- | --- |
| Embedded secrets | package resources, generated configuration, symbols, and bundled files | masked finding ID only; never validate a live credential |
| Tokens, sessions, backups, logs | storage class, backup inclusion, redaction, lifecycle | authorized test account confirms expected handling; record unknown paths |
| TLS client trust | effective trust configuration and network exceptions | use the [trust-store verification guide](trust-stores.md)'s positive and controlled negative tests where authorized |
| Deep links and links | universal links/app links, routing, and authorization boundary | intended synthetic link works; untrusted or unauthorized route is safely rejected |
| WebView | origin allowlist, navigation policy, JavaScript bridge exposure | expected origin works; untrusted origin/bridge request is denied or unavailable |
| Platform permissions | requested permission purpose and runtime behavior | required permission flow works; unavailable permission degrades safely |
| Android components | exported components, intent filters, and server authorization | authorized call succeeds; unauthorized caller/input is denied |
| Server boundary | client claims versus server authorization | server remains authoritative for identity and entitlement |

OWASP MASVS organizes mobile verification across storage, cryptography, authentication, network communication, platform interaction, code, resilience, and privacy. Use it to scope evidence, then retain platform-specific conclusions only when supported by Apple or Android documentation for the deployed configuration. [OWASP MASVS](https://mas.owasp.org/MASVS/)

For Android, document the effective network-security configuration and exported-component behavior. Android documents that app components should not be exported unnecessarily and that network security configuration can customize trust and cleartext policy. [Android app components](https://developer.android.com/guide/components/fundamentals) [Network security configuration](https://developer.android.com/privacy-and-security/security-config)

For iOS, document the effective App Transport Security exceptions, associated-domain configuration, and data-protection/storage choice. Apple documents ATS as a policy that constrains network connections and documents associated domains for universal links. [Preventing insecure network connections](https://developer.apple.com/documentation/security/preventing_insecure_network_connections) [Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains)

## Findings, unknowns, and change safety

| Area | Owner | Evidence ID | Result | Unknowns/compatibility | Rollback | Recheck trigger |
| --- | --- | --- | --- | --- | --- | --- |
| `<area>` | `<owner>` | `<review-id>` | pass/fail/unknown/not applicable | `<constraint>` | `<safe rollback>` | release, SDK, entitlement, link, permission, or policy change |

Changes to trust, links, WebViews, permissions, or exported components can break older clients, provider callbacks, or accessibility flows. Validate a representative supported OS/device set before rollout; a rollback must preserve server-side authorization and must not weaken certificate validation. Recheck after a signed release, dependency/SDK change, build-pipeline change, server API or identity change, network exception change, or new platform requirement.

## Sources

- OWASP, [Mobile Application Security Verification Standard](https://mas.owasp.org/MASVS/), accessed 2026-10-22.
- Android Developers, [App components](https://developer.android.com/guide/components/fundamentals) and [Network security configuration](https://developer.android.com/privacy-and-security/security-config), accessed 2026-10-22.
- Apple Developer Documentation, [Preventing insecure network connections](https://developer.apple.com/documentation/security/preventing_insecure_network_connections) and [Supporting associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains), accessed 2026-10-22.
