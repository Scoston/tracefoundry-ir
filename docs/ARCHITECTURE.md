# Runtime architecture

This document describes the code in version 0.1. The complete proposed enterprise architecture remains in `design/TraceFoundry_IR_Design.md` and its Word counterpart.

## Components

| Component | Module | Responsibility |
| --- | --- | --- |
| HTTP boundary | `app.py` | Strict request bodies, size limits, trusted hosts, origin checks, sessions, CSRF, safe response headers |
| Approval gateway | `service.py` | Case authorization, immutable proposals, signed reviews, current policy, single-use intent, execution receipts |
| Identity and evidence state | `store.py` | SQLite transactions, authenticated identity records, session lifetime, rate limits, case ledgers, checkpoint history |
| Cryptographic boundary | `security.py` | RFC 8785, domain-separated SHA-256, ES256/P-256 attestations, AES-GCM raw artifact storage, scrypt passwords |
| Fixed tool registry | `tools.py`, `models.py` | Allowlisted operations and strict argument schemas; importers, bounded queries, declarative matching |
| Optional model adapter | `provider.py` | Approved external disclosure, fixed prompts, bounded request/response sizes, no tools, no redirects, validated candidates |
| Offline verifier | `verify.py` | Archive path/size checks, byte hashes, ledger, independently supplied checkpoint/key comparison, release attestations |
| Analyst console | `static/` | Case, evidence, review, result, pack, and audit workflows; inert evidence rendering |

All components currently share one application process, SQLite database, filesystem, and local key custodian. Logical component boundaries are implemented; independent enterprise trust domains are not.

## Authority sequence

1. A named human opens a case or stages selected bytes. The explicit instruction is audited.
2. A human submits an operation proposal. The server resolves evidence, argument defaults, tool source digest, current policy, lifetime, and mandatory role groups. A model cannot submit authority through any returned text.
3. Each reviewer inspects the immutable proposal and reauthenticates. The server derives subject and roles from the session and current trusted identity state, signs the exact review body, and records its digest.
4. The gateway revalidates scope, evidence, role eligibility, membership, signatures, expiry, revocations, policy, and source-code digest. Each policy group needs a different account.
5. A serialized transaction reserves the unique execution identifier and persists an intent. Its checkpoint must be written before dispatch.
6. Immediately before dispatch, the gateway checks approvals again. Local tools run in a second serialized transaction. An external model request has a separately preserved request artifact and audit event before network access.
7. Results, transcripts, parsing gaps, or an explicit failed/unknown outcome are preserved. Findings remain candidates until a new acceptance decision. A repeated execution request returns the original execution identity rather than dispatching again.

## Failure semantics

SQLite commit and filesystem checkpoint publication are not atomic. A crash or write error between them can produce a checkpoint mismatch. This is a blocking integrity condition, not a prompt to regenerate the witness silently. Preserve both states and reconcile from a independently retained checkpoint and backup.

An interrupted external call may have been billed or processed remotely. It is marked `OUTCOME_UNKNOWN`; it is never retried automatically. `tracefoundry recover` is an explicit operator command that changes abandoned `RUNNING` executions to `OUTCOME_UNKNOWN`, with no connector call. Version 0.1 does not have a reconciliation-resolution tool; a supervisor cannot close a case with unresolved executions. Track resolution outside the application and implement a reviewed reconciliation workflow before using this path operationally.

## Record formats

The original design schemas are illustrative contracts preserved under `docs/design/schemas/`. Runtime records use `schema_version: runtime-0.1` and are described by the authenticated OpenAPI schema and code models. They are not falsely advertised as instances of the original design schemas.

Decision and event digests use the original design's domain separation. Human reviews use `TFIR-APPROVAL-v1`; checkpoint, identity, session, and release attestations each use their own domain. Signatures are base64url-encoded fixed-width 64-byte ECDSA `r || s`, not JWTs. Trusted public keys are acquired independently, never accepted because a proposer or archive supplies them.

Audit records contain identifiers, policy facts, digests, timestamps, and actor references. Raw evidence and application-visible model exchanges are separate encrypted artifacts. Normalized rows, case descriptions, review rationales, findings, and decision arguments are sensitive database content: deploy encrypted storage and backup protection.

## Operational bounds

| Limit | Current behavior |
| --- | --- |
| Raw source | 2 MB per staged artifact |
| HTTP request body | 4.1 MB |
| Source parser | At most 10,000 records per import |
| Analysis selection | At most 20 artifact IDs and 10,000 normalized rows |
| Timeline result | At most 1,000 rows; truncation reported |
| Research text | UTF-8 text/Markdown, at most 120 KB; PDF extraction is external |
| Model context | At most 128,000 UTF-8 bytes |
| Model response | At most 1 MB and 1,000 requested output tokens |
| Approval lifetime | 1–60 minutes |
| Human session | 30 minutes |
| Login and review failures | Five failures per bucket per 15 minutes |

These are explicit local bounds, not capacity, latency, model-token accuracy, or annual compute-budget guarantees.
