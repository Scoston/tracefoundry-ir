# Security model and residual risks

## Trusted and untrusted inputs

Evidence, papers, model responses, case descriptions, tool parameters, and research pack manifests are untrusted. They can influence a candidate analysis but cannot set policy, choose an approver identity, lower role requirements, introduce executable code, access arbitrary URLs, or issue a tool call from the model.

The application code, operating system, local administrator, protected state directory, signing keys, and configured provider destination are trusted in version 0.2. A host administrator controlling keys, state, and code can impersonate users or rewrite history. The design's independent approval service, external witness, and managed keys are required to reduce that trust concentration.

## Enforced boundaries

| Threat | Control | Residual limit |
| --- | --- | --- |
| Forged human identity in a request | Identity derived from authenticated session; local reauthentication before signing; principal kind checked | Local passwords are not enterprise MFA; credential compromise still matters |
| Approval copied to a different action | Canonical decision digest binds typed arguments, exact evidence, policy, code digest, tenant/case, destination, lifetime | Host-level key/code compromise is outside local integrity guarantees |
| One person filling multiple approval roles | Distinct-account role matching; duplicate reviews rejected | Enterprise identity governance must enforce one account per person |
| Revoked or stale authority | Current identity revision, roles, membership, lifetime, policy, code digest, and revocation audit checked again at use | Revocation racing an external dispatch cannot retract the disclosure |
| Replay or concurrent dispatch | Unique execution record; durable intent; serialized reservation; prior intent check | No distributed worker/lease protocol; one host only |
| Audit loss before dispatch | Checkpoint must succeed before dispatch; mismatched heads block access/work | Crash between commit and checkpoint requires manual reconciliation |
| Evidence tampering | AES-GCM authentication, original-byte hash, metadata hash, normalized-record digest, record locators | Authentic bytes can still be false or incomplete at the source |
| Prompt injection | Fixed tool set, no model tools, strict typed schemas, candidate validation, external authorization | Model claims can still be wrong or persuasive; human method review remains necessary |
| Fabricated citations | Chunk IDs must resolve inside the case; source and normalized hashes checked | A valid citation may not logically support a claim; human review must assess that |
| Cross-case/tenant access | Case membership and tenant checked on operations, references, results, audits, and downloads | Not independently penetration tested |
| Browser injection | Evidence escapes into inert text, restrictive CSP, no remote scripts, binary forced-download responses | Downloads may be dangerous in external applications; handle evidence appropriately |
| Forged checkpoint/key | Verifier requires independently supplied trust keys and checkpoint; domain-separated signatures | A co-administered checkpoint copy is not an independent witness |
| Silent export expansion | Snapshot bytes, manifest, recipient, approvals, and signed release receipt are bound | Authorized readers can copy data; this is not DLP |
| Dependency/runtime tampering | Pinned lock files, dependency audit, CI checks, code digest invalidating approvals | Package index/base image/build chain remain supply-chain dependencies |

## Privacy

Raw artifacts and application-visible model requests/responses are encrypted with a separate local AES key. Case descriptions, normalized records, claims, review rationales, operational arguments, and audit metadata can contain sensitive data and are not individually encrypted. Use an encrypted disk and encrypted backups, minimum case membership, and appropriate retention controls outside this local reference application.

General error responses do not echo submitted passwords or raw request bodies. API keys are never copied into model transcripts or audit payloads. Audit hashes of identifiers are not a promise of anonymity. The application records visible workflow context; it does not solicit internal chain-of-thought.

## Known limits

No live collection, automatic containment, remediation, OAuth token forwarding, arbitrary SQL, shell, dynamic code loading, or MCP execution is provided. No legal admissibility, regulated compliance, availability SLO, forensic completeness, or annual compute budget is certified. Automated tests are evidence of tested behavior in the stated environment; they are not proof of the absence of vulnerabilities.

Version 0.2 authenticates displayed review and result projections against their ledger receipts and detects missing record inventories. These checks protect against database-only modification without the signing keys and retained checkpoints. They do not protect against a host administrator who controls all trust material. Encrypted backups contain private signing and vault keys; protect their passphrase, trusted public key, and independent hash pin with separate custody.
