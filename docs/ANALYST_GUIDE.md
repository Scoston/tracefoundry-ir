# Analyst guide

## Start with a bounded case

Sign in with your named human account. Create a case with a concrete purpose. A supervisor or administrator adds other existing human accounts using **Manage access**. Accounts in other tenants cannot be added. Case membership controls the evidence, decision, result, download, and audit routes.

The initial account created by `init` can administer its own local case, but it cannot count as two reviewers. Use separate named accounts belonging to separate people for two-person operations.

## Preserve the source

Stage a file under **Evidence**. Record the source system, collection/export reference, known coverage, and native integrity status. `verified_externally` is your documented declaration, not a verification performed by TraceFoundry IR. A local hash does not repair a failed native source digest.

Staging records the exact human-selected bytes, hashes them, and stores them in the encrypted vault. It does not parse them or authorize further work. Names are display metadata; storage and downloads use server-generated identifiers.

For logs, choose **Propose import** and the actual format. Supported inputs include CloudTrail `Records`, M365 `value` records or `AuditData` JSON strings, OCSF-shaped events, generic event arrays, and JSONL. An import requires review and explicit execution. Invalid timestamps become visible warnings; malformed input fails without partial normalized rows. Zero imported events never establishes absence of activity.

For research drafting, stage UTF-8 text or Markdown containing the relevant method and its citation. PDF-to-text extraction is outside this runtime; retain the original PDF as separate source evidence if appropriate and document the derivation.

## Review and execute

**Propose operation** opens a typed scope form. Select exact artifacts and arguments, write a purpose, and set an approval lifetime. The server supplies mandatory role requirements, a source-code digest, evidence hashes, and the current policy.

In **Decisions**, expand the exact scope. Check the source, targets or selection, query boundaries, requested purpose, provider destination if present, and known gaps. To approve or reject, record your reasoning and re-enter your password. Rejection is terminal: corrected work requires a new proposal. A reviewer can revoke their approval; a supervisor can also revoke it. Revocation cannot reverse an operation that has already started.

After sufficient reviews, choose **Execute approved operation**. The server rechecks current authority; the UI's review count is not the authorization decision. Expired or revoked approvals, changed roles, changed membership, a different policy/tool build, changed evidence, or an unhealthy audit checkpoint block dispatch.

Every execution has a stable identifier. Repeating the request shows the same execution, not another tool run. `FAILED` needs investigation and a new proposal for any new attempt. `OUTCOME_UNKNOWN` means the platform cannot establish the remote outcome; do not assume the request failed or was safe to repeat. An operator must reconcile outside this release's limited workflow.

## Assess evidence

- **Timeline:** choose imported artifacts, optional actor/action substrings and timezone-qualified dates, and a result limit. Truncation is reported.
- **Suggest findings:** run deterministic event-name rules. Results are hypotheses, not a model response or a conclusion about malicious intent.
- **Run pack:** execute a previously released, digest-pinned research pack on selected imported evidence.
- **Model assess:** optional external disclosure. It requires two reviewers, including a supervisor. Inspect the configured endpoint and selected context. Responses are validated against supplied chunk IDs and remain unreviewed.
- **Accept finding:** a separate decision to accept a precisely stated claim with supporting/contradicting citations, evidence type, severity, and limitations. Acceptance does not change a hypothesis into an observation.
- **Record gap:** add a reviewed description of missing or uncertain coverage.

## Release a case bundle

Choose `export_case`, exact artifacts, and a case member as recipient. The server freezes the snapshot before approval and binds its hash, event count, and artifact count into the decision. New case records cannot expand the approved snapshot silently. Separate people review the release; one must qualify as a supervisor.

After execution, only the named recipient can retrieve the resulting export through the normal UI while its approvals are still valid. A revoked grant or expired approval blocks later retrieval. Copies already retrieved cannot be recalled. If a renewed release is needed, create a new export decision.

The bundle contains the frozen snapshot, selected bytes, signed approvals, and a signed release receipt. Unselected artifacts are explicitly listed as omissions. An offline verifier needs separately trusted public keys and a checkpoint corresponding to the snapshot's historical sequence.

## Close a case

A supervisor must approve a closure proposal that states the conclusion and residual uncertainty. Unresolved running/unknown executions block closure. Closed cases remain readable and may be exported through the normal release process; new investigative operations are blocked.

## Interpretation discipline

Preserve contradictions and uncertainty. A source log can be inaccurate; a parse can omit semantics; a human can accept a weak claim. Integrity checks establish consistency against retained records and trust anchors. They do not establish that every relevant activity was logged or that a conclusion is correct.
