# Security policy

TraceFoundry IR 0.1 is a local reference application, not a production-certified SOC platform. Review [the security model](docs/SECURITY_MODEL.md) and [implementation status](docs/IMPLEMENTATION_STATUS.md) before selecting evidence or enabling model disclosure.

Do not place real incident evidence, credentials, access tokens, private keys, personal data, or customer data in repository issues or pull requests. For a suspected vulnerability, use the repository's private vulnerability-reporting facility if enabled; otherwise contact the repository owner through an established private channel. Do not publish a sensitive proof of concept in a public issue.

Runtime evidence, SQLite state, signing keys, and credentials belong outside version control. `.gitignore` is a convenience, not a secret scanner. No retention, availability, or source-completeness guarantee is made by this release.

Security-related changes should include a concrete regression test and an update to the relevant trust assumption or implementation-status row. Preserve failed and uncertain execution states; never add an automatic retry around the authorization gateway.
