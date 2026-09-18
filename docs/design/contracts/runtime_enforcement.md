# Runtime enforcement contract

## Trust and authority

The planner, retrieved evidence, imported papers, MCP tool descriptions, workflow checkpoints and queue messages are untrusted with respect to authorization. Only the approval service can attest human reviews. Only the gateway can lease execution credentials. The case database is never allowed to bypass the gateway's authorization policy.

The server constructs the immutable decision body from resolved canonical target IDs, registry tool digests, current policy, approved evidence references and validated typed arguments. In particular, required roles and the number of approvers are calculated from trusted policy. A client's proposed `required_approvals` values cannot reduce these requirements.

Default minimums are one qualified human for reads, analyses and acceptance of findings; two distinct humans for production changes, restoration, evidence release, pack promotion and changes to security policy. High-impact operations must satisfy the incident or service ownership roles specified by trusted policy. Closure requires the supervisor role. The root case instruction has a named human originator; services retain both that originator and their own workload identities.

## Exact scope of approval

Every tool or source selection, query window, branch choice, scope change, severity choice, accepted or rejected finding, response, restoration, export and closure is a decision. Mechanical computation may execute only within a specific recorded human instruction and fixed input set. Model-generated substitutions, fallback tools, extra sources, broader queries and newly discovered targets require another decision.

Multiple decisions can be reviewed together only as fully enumerated items, with a separate affirmative choice and approval record for each. No approval of unspecified future actions, timer-based approval, or agent-as-approver is permitted. Rejection and deterministic policy denial do not authorize any fallback action.

## Dispatch algorithm

The following is normative pseudocode, not working application code.

```text
receive execution request authenticated as an allowed coordinator
load authoritative immutable decision and requested execution identity
reject examples, malformed records, unknown actions and unknown tool digests
recalculate canonical decision digest; compare with stored digest
resolve tool from the signed registry; verify current validity and revocation
load current policy and case scope from the authoritative policy service
require bound policy version to be current, or return to human review
validate tool-specific parameters and resolved targets against trusted policy
load review attestations from the approval service
for each review used as authority:
    require human identity; validate issuer and authentication event
    verify service signature against independently trusted keys
    match exact decision ID, digest, policy, tenant and case
    require affirmative verdict, valid lifetime and no revocation
    recheck current role eligibility and case authorization
require all policy role groups and distinct-human requirements
revalidate evidence references, source access and target preconditions
require healthy audit persistence, budget, and credential broker
in a serialized transaction over the decision execution state:
    repeat revocation, expiry and fencing checks
    reject consumed authorization, or return its existing execution status
    reserve single use and create a durable execution intent and outbox record
    persist the corresponding authoritative audit event
obtain durable receipt from audit service before external dispatch
recheck worker lease and revocation fence immediately before dispatch
lease the minimum downstream authority for the exact action
invoke one registered connector using the execution ID as idempotency key
persist response, vendor request ID, errors and returned artifacts
if outcome is uncertain:
    mark OUTCOME_UNKNOWN
    prohibit blind retry of state-changing operation
    request human approval for a reconciliation action
else:
    submit a separate verification proposal if needed
return candidate outcome for human review
```

The intent and an external vendor action are not atomic. The platform records this limitation explicitly. If a revocation races a dispatched operation, best-effort cancellation is logged but reversal is not promised. A corrective or rollback operation requires fresh approval.

## Uncertainty and retries

Read retries are allowed only if the exact approved operation explicitly describes a bounded retry policy, expiration, rate limit and unchanged evidence boundary. A changed query, identity, source or collection interval requires review. A response attempt with unknown outcome is reconciled first. Reconciliation is a new human-approved read action; any repeated mutation is a new decision.

## Human reviews and findings

The review endpoint derives identity from an authenticated session; callers cannot submit an arbitrary identity or an `approved: true` field to set state. Use step-up authentication for response, release and policy changes. Store the exact review view digest and a concise human rationale. Shared links may notify reviewers but must never confer authorization by themselves.

Human acceptance does not convert an inference to an observation. Preserve `observation`, `hypothesis`, `unresolved` and `contradicted` semantics separately from review status. Accepted claims must have complete resolvable citations and state their coverage limits. Case closure is a separate supervisor decision.

## Mandatory type-specific payload contracts

The common audit schema is only the envelope. Before adapter release, implement strict payload schemas for source collection, model transaction, context selection, memory access, delegation, human review, policy check, execution intent, execution receipt, artifact transformation, custody, export, gap declaration, checkpoint and administrative change. Reject unknown fields by default except explicitly reviewed extension locations.

For model transactions, capture application-visible inputs and outputs or explicit policy-restricted references, ordered context, prompt and skill versions, tool registry version, model identification as actually reported, provider request IDs, and token usage. Record unavailable fields as unavailable. Do not request hidden chain of thought.

## Suggested API response behavior

| Condition | Response behavior |
| --- | --- |
| No identity or invalid session | 401; no state change |
| Insufficient authority or invalid signature | 403; append denial event |
| Stale proposal, consumed approval or changed precondition | 409 with recorded state; require review when appropriate |
| Expired approval | 410 or policy-specific 409; no dispatch |
| Invalid typed input | 422; no dispatch |
| Audit, policy or broker unavailable | 503; pause without granting authority |
| Accepted execution intent | 202 with stable execution ID; not a claim of completed action |

Tenant and case checks occur on every endpoint, reference lookup, cache read and download. A status or integrity endpoint must not leak records from another case.
