# API guide

Run the local service and authenticate with a named human account. API operations use the same gateway as the browser. `GET /api/openapi.json` returns current strict request schemas to an authenticated session. No API supports a caller-supplied approver identity or an `approved: true` shortcut.

## Session example

The following Python example uses a password prompt, keeps the session cookie in memory, and demonstrates creation of an unapproved proposal. It does not execute the proposed operation.

```python
from getpass import getpass
import httpx

with httpx.Client(base_url="http://127.0.0.1:8000") as client:
    response = client.post("/api/login", json={
        "username": "stephen", "password": getpass("Password: ")
    })
    response.raise_for_status()
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]

    response = client.post("/api/cases", json={
        "title": "Bounded source investigation",
        "description": "Investigate a supplied synthetic log export."
    })
    response.raise_for_status()
    case_id = response.json()["id"]

    response = client.post(f"/api/cases/{case_id}/decisions", json={
        "tool": "record_gap",
        "arguments": {
            "description": "Source logging completeness has not been validated.",
            "affected_scope": "Supplied source exports"
        },
        "purpose": "Record the known evidence boundary for human review.",
        "ttl_minutes": 30
    })
    response.raise_for_status()
    print(response.json()["digest"])
```

## Routes

| Method and path | Result / authority |
| --- | --- |
| `POST /api/login` | Human session, CSRF token; rate-limited local password authentication |
| `POST /api/logout` | Revoke the current session |
| `POST /api/password` | Current-password authentication; replace the password and invalidate sessions and pending reviews |
| `GET /api/me` | Current session identity and roles |
| `GET /api/tools` | Current registry, strict argument schemas, code digest, role policy |
| `GET /api/cases` | Only cases accessible to the current tenant/member |
| `POST /api/cases` | Explicit human case-creation instruction |
| `GET /api/cases/{case}` | Evidence metadata, decisions/reviews, results, findings, packs, integrity status |
| `POST /api/cases/{case}/members` | Add an existing same-tenant human; supervisor/admin required |
| `DELETE /api/cases/{case}/members/{username}` | Remove membership; supervisor/admin required |
| `POST /api/cases/{case}/evidence` | Stage base64-encoded exact bytes and source declarations |
| `POST /api/cases/{case}/decisions` | Create an immutable server-bound operation proposal |
| `POST /api/cases/{case}/decisions/{decision}/reviews` | Reauthenticate and sign a review of the supplied exact digest |
| `POST /api/cases/{case}/approvals/{approval}/revoke` | Reviewer or supervisor revocation with a reason |
| `POST /api/cases/{case}/decisions/{decision}/execute` | Mandatory gateway; unique execution intent and stable result identity |
| `GET /api/cases/{case}/audit` | Bounded ledger page and its signed retained checkpoint; access is audited |
| `GET /api/cases/{case}/artifacts/{artifact}` | Audited exact-byte retrieval; formal exports require the named recipient and a still-valid grant |

State-changing requests require `X-CSRF-Token`. Cross-origin requests are rejected. JSON duplicate keys, nonfinite numbers, unknown typed request fields, arbitrary SQL, and unregistered operations are not accepted. Password and evidence inputs are not echoed in validation errors.

## Decisions and results

The proposal response contains `body`, `digest`, and `state`. Review requests contain `verdict`, `rationale`, `password`, and the exact `decision_digest`. The current authenticated account supplies the identity. Review is separate from execution.

Role policy is server-owned. One analyst or supervisor can authorize local reads/analysis/finding acceptance. Closure requires a supervisor. Export and external-model requests need two distinct accounts, including a supervisor. Pack promotion needs separate administrator and supervisor accounts. Accounts can hold several roles, but one account cannot occupy two required positions.

Execution returns `RUNNING`, `COMPLETED`, `FAILED`, or `OUTCOME_UNKNOWN` with an execution identifier. A completed model request can still have `review_status: rejected_by_validator`; this means the exchange was recorded, not that the claims were accepted. Repeated execution requests return the same execution state and never trigger an automatic retry.

Typical errors: 401 invalid/expired session; 403 missing authority or invalid review; 404 unavailable case/reference; 409 stale policy, rejected decision, duplicate review, or incompatible state; 410 expired decision; 413 size limit; 422 invalid input/scope; 429 rate limit; 503 audit/integrity/infrastructure failure. Always inspect the machine-readable `error` and existing execution state before proposing another operation.

## Reconciliation and finding review

| Tool | Exact arguments | Required reviewers |
| --- | --- | --- |
| `reconcile_execution` | `execution_id`, `artifact_ids`, `assessment`, `conclusion`, `residual_uncertainty` | Analyst/supervisor plus a different supervisor |
| `challenge_finding` | `finding_id`, `explanation`, `citations` | Analyst or supervisor |
| `resolve_challenge` | `challenge_id`, `disposition`, `explanation`, `citations` | Analyst/supervisor plus a different supervisor |

Reconciliation assessment is `confirmed_no_external_effect`, `confirmed_external_effect`, or `unable_to_determine`. It records human interpretation of selected evidence, not independent proof of an external effect. The original execution remains unknown. Challenge disposition is `finding_upheld`, `finding_withdrawn`, or `uncertainty_retained`. Neither operation rewrites original records or runs a response connector. Case detail and exports include the separate records and authority references.

## Audit pagination

Use `?limit=100` (range 1–500). If `page.has_more` is true, request `?limit=100&before=NEXT_BEFORE&through=THROUGH` using the returned values. Keep `through` fixed while reading older pages. This preserves the same signed checkpoint even when new access events are appended. Pages contain chronological subsets, not a standalone full-ledger verification proof; assemble the full sequence and use independent trust material for offline verification.

Password change accepts only `current_password` and `new_password`. It requires the session CSRF token and returns `password_changed` and `sessions_invalidated`; the caller must log in again. No endpoint accepts an arbitrary target username for browser password changes.
