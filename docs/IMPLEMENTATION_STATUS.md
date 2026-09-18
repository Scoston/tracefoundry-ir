# Implementation status

Version 0.2 provides a runnable local application with the controls below. The original design describes a broader enterprise system. This table is the authoritative implementation boundary.

| Area | Implemented now | Remaining work |
| --- | --- | --- |
| Human authority | Named local accounts, password reauthentication, immutable proposal digest, signed reviews, current roles and membership, expiry, revocation, identity-revision binding, password change/reset | Enterprise IdP, MFA/step-up attestations, identity lifecycle synchronization, service identities |
| Separation of duties | Distinct-account role matching for exports, model disclosures, and pack promotion | Prove one account per physical human through authoritative enterprise identity; separate trust domains |
| Evidence | Raw byte preservation, encrypted vault, source metadata, SHA-256, normalized chunk IDs, record locators, coverage declarations | Native collectors, immutable cloud versions, acquisition signatures, custody integration |
| Source formats | Bounded CloudTrail, M365 AuditData/value, OCSF-shaped, generic JSON/JSONL | Complete vendor event coverage, pagination, native CloudTrail digest validation, full OCSF schema validation |
| Audit | Unsampled authoritative events, case/admin ledgers, SQL append-only triggers, signed checkpoints/history | Independent witness service, WORM retention, managed key custody, distributed reconciliation |
| Decisions | Closed registry, strict inputs, policy-owned role groups, exact evidence/code bindings | External policy service, richer target state/precondition checks |
| Execution | Unique durable intent, serialized local execution, no automatic retry, recorded failed/unknown state, two-person reconciliation without replay | Credential broker, workload identity, transactional outbox workers, enterprise queue |
| Findings | Candidates separated from accepted claims; citations required; observation/hypothesis/unresolved/contradicted labels preserved, reviewed finding challenges/dispositions, closure checks | Automated contradiction discovery and production-scale review qualification |
| Research conversion | Optional approved model drafting from supplied text; bounded declarative rules; test vectors; separate release approvals | PDF extraction pipeline, isolated build workers, executable code generation, signed container registry, independent method benchmarks |
| Model use | Disabled by default; fixed configurable endpoint; approved context; visible request/response artifacts; citation validation | Live provider qualification, context redaction policy, provider retention contracts, cost accounting and budget services |
| Exports | Fixed snapshot, exact selected artifacts, named recipient, two reviews, signed release receipt, offline verifier | Enterprise transfer destination controls, legal holds, disposal service, complete historical admin-authority evidence |
| UI | Login, case list, membership, staging, proposals, review, execution/results, findings, packs, paged audit trail, password change, reconciliation and finding challenges | Accessibility certification, large-case pagination, production-scale performance qualification |
| Response actions | None; no production mutation connectors | Reviewed endpoint isolation, identity disablement, rollback, restoration, independent verification |
| Packaging | Python package, dependency lock files, Dockerfile, source schemas, CI, tests, operating documents, encrypted signed backup/restore, local diagnostics, Windows/container acceptance jobs | Organizational release approval, penetration testing, hosted deployment, disaster recovery exercise |

The application does not implement arbitrary MCP server execution, tool installation, shell execution, or generated Python execution. Imported research can yield a validated pack of matching rules, not executable authority.

## Original acceptance catalog

`docs/design/verification/acceptance_catalog.json` retains all 40 original requirements, labeled as future implementation scenarios. Executable tests exercise portions of H01–H07, H09–H10, E01–E04, E07–E09, S01–S04, S06, R01–R03, R06–R07, P01, P03, and B03–B04 at the local application boundary. This is not a claim that the complete original scenario or an enterprise integration has passed.

Examples: the importer records a supplied coverage limit, but does not validate live pagination; the application rejects unrecognized bearer tokens by requiring its own session, but has no enterprise OAuth audience validator; registry digests bind the local Python and browser application files, but no signed MCP/container registry is deployed. Native source digest failures and provider coverage facts remain externally supplied declarations.

Use `docs/VALIDATION.md` for measured tests and limits. Preserve this distinction in demonstrations, publications, and deployment decisions.

The [0.2 review](REVIEW_AND_COMPLETION.md) records the corrected implementation gaps and external deployment work. Restore and backup are local operations with a 256 MB uncompressed profile; they do not implement WORM storage, legal holds, or an independent witness.
