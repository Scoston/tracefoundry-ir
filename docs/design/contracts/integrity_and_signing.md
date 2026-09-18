# Integrity and signing contract

## Artifact and record hashing

Raw artifact digest: SHA-256 over original bytes, before parsing or normalization. Preserve storage version and acquisition metadata. Normalized data has its own digest and source locator.

Decision digest: SHA-256 over UTF-8 `TFIR-DECISION-v1`, one zero byte, and RFC 8785 canonical UTF-8 bytes of `body`. Exclude the outer digest fields. `example_only` is transport metadata and must always cause production rejection when true; it never grants authority.

Audit digest: SHA-256 over UTF-8 `TFIR-EVENT-v1`, one zero byte, and RFC 8785 canonical bytes of the event `body`. The body includes the predecessor hash and sequence. It excludes the calculated event hash and checkpoint association.

Validate raw JSON with duplicate-key rejection before schema validation and canonicalization. A standard parser that silently keeps the last duplicate key is insufficient. Use a tested JCS implementation and conformance vectors; do not substitute general alphabetical JSON serialization. Preserve raw source bytes separately. Sequence numbers are decimal strings to avoid floating-point precision loss.

## Approval attestation signing

Use an organization-approved managed-key signature implementation. This design's initial signature profile is P-256 ECDSA over SHA-256, labeled ES256. Sign the domain-separated bytes consisting of UTF-8 `TFIR-APPROVAL-v1`, one zero byte, and the canonical approval `body`.

The envelope signature is base64url without padding of the fixed-width 64-byte `r || s` signature. Convert provider DER output using a vetted crypto library when necessary. This is an application attestation format, not a JWT or an implicit claim of JOSE wire compatibility. The `key_id` selects a separately trusted public key and algorithm profile, never a key supplied by the proposer.

The approval service signs only after authenticated human review. It cannot simply sign an agent-supplied record. Record the authentication event, human issuer and subject, roles at review, policy version, exact decision digest, review view digest, verdict, rationale and expiration. Recheck current authority at use. A signature proves the trusted service attested those bytes, not that a human reached a correct judgment.

The unsigned example in this package is not acceptable authority. An example that merely passes a JSON schema remains non-executable.

## Checkpoints and witnesses

Each checkpoint has a schema version, ledger ID, first and last sequence, event count, head hash, previous checkpoint digest, creation time, key ID and signature profile. Define a separate `TFIR-CHECKPOINT-v1` domain prefix and sign the canonical checkpoint body. The final checkpoint schema and verifier must be completed before production release.

Record a checkpoint at least every 60 seconds or 100 events, whichever comes first, plus review and execution milestones and closure, subject to capacity testing. Deposit it with an independently administered witness and preserve the witness receipt. The witness must expose an authenticated latest expected head and detect conflicting heads; a copy selected solely by the exporter is not independent evidence.

A verifier detects suffix removal only relative to a known checkpoint. Unwitnessed events can still be lost. An incomplete checkpoint or audit service outage blocks new dispatch while already produced receipts are durably buffered. Reconcile receipt producers and the audit service after recovery.

Pin object versions, not just object names. Restrict retention bypass, hold removal, storage administration and signing-key access. Preserve public keys, trust decisions and key revocation history with historical exports. Protect encryption-key deletion separately from object retention.

## Offline verification sequence

1. Parse manifest defensively; validate schema and reference paths; prohibit traversal and remote fetches.
2. Verify every included artifact byte count and hash; report missing files.
3. Resolve each required record, evidence locator, approval and receipt; identify declared omissions.
4. Recompute canonical decision and audit hashes using the correct domain prefixes.
5. Validate sequence continuity and predecessor links per ledger, including administrative ledgers needed to establish policy and key history.
6. Verify attestations and checkpoints with independently trusted keys, not keys trusted just because they are in the export.
7. Compare the final sequence and head with independently obtained witness records. Detect gaps, suffix truncation and divergent chains.
8. Validate approval authority, expiration, policy binding and single-use execution history with preserved authoritative records.
9. Report integrity, source coverage, trust assumptions and unresolved states separately. Never reduce all of these to one green check.

Replay analysis never replays historical side effects. Offline verification does not call the model or a live response tool.
