# Contributing

Contributions must be English, public-safe, and reviewable as documentation without access to a private environment.

For every material claim, include:

- the affected component and scope;
- a primary source and publication or access date;
- the fixed version or clear applicability decision;
- compatibility and rollback considerations;
- the evidence expected after remediation, including a positive and negative check where relevant.

Do not submit secrets, internal identifiers, customer data, private logs, exploit material, bulk scanning instructions, or automatic host changes. Keep examples on reserved domains such as `example.invalid` and use placeholders for identities.

Run the documentation checks before proposing a change:

```sh
npx --yes markdownlint-cli2@0.24.0 '**/*.md'
lychee --offline --include-fragments '**/*.md'
```

Also check that each claim distinguishes observed evidence from a recommendation.
