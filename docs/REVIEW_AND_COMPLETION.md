# Repository review and completed work

Reviewed baseline: `a2b82bc888f341ffc2721a7c1f361ce738a51590` (0.1.0). Follow-up release: 0.2.0, September 18, 2026.

The first release had working human authorization and cryptographic receipts, but several mutable database projections were not consistently checked against those receipts. Recovery and account administration also lacked complete operational paths. The changes below address those local implementation gaps. This review is not an independent penetration test or a claim that the proposed enterprise architecture is fully implemented.

## Findings and implemented corrections

| ID | Finding and practical effect | Correction | Verification |
| --- | --- | --- | --- |
| R01 | A database writer could change a rejected decision's cached state and remove its review row. Rejection was not independently enforced from complete review history. | Compare decision state, review inventory, signatures, and exact review receipts to the verified ledger before display or use. | Rejection rollback, missing-review, and tampered-review regression tests |
| R02 | Failure results, missing case projection rows, revoked-review display, and renamed normalized chunk IDs could misrepresent the investigation despite intact audit records. | Validate failure results and record inventories; derive revocation display from audit history; verify chunk identifiers against their preserved bodies. | Failure, deletion, revocation, and locator tampering tests |
| R03 | Recovery could bless a tampered completed execution as unknown and could race active execution. | Use a process-shared dispatch lock; recover only an authenticated running intent without a terminal receipt. Active execution blocks recovery and backup. | Crash injection before a tool effect; terminal-state tampering and concurrency tests |
| R04 | Unknown executions blocked closure with no reviewed reconciliation operation. | Add `reconcile_execution`, exact target binding, evidence selection, and two distinct reviewers including a supervisor. Preserve the original unknown result; record uncertainty; never dispatch a retry. | Approval, duplicate-resolution, unchanged-outcome, and closure tests |
| R05 | An accepted finding had no in-application challenge and disposition workflow. | Add citation-bound `challenge_finding` and two-person `resolve_challenge`; preserve the original finding and block closure while a challenge remains open. | Withdrawal/history, unresolved-closure, distinct-account, and real-browser checks |
| R06 | Password recovery was absent, and restoring an old session row could outlive an identity change. Reviews were not bound to an identity revision. | Add password change/reset and account enablement; bind sessions and new reviews to the current audited identity revision; authenticate session issuance; invalidate cached authority on identity change. | Session restoration, old password, pending review, CLI lifecycle, and browser tests |
| R07 | There was no consistent encrypted backup, verified restore, or complete local diagnostic command. | Add `doctor`, encrypted signed backups, and restore requiring independent key and hash pins. Verify all copied files, refuse overwrites, invalidate old sessions/authority, and never retry tools. | Round-trip restore, wrong passphrase/key/pin, existing destination, corrupted evidence, and CLI tests |
| R08 | Audit responses could pair events with a newer checkpoint, and returned the entire ledger at once. | Pin event pages and retained checkpoints under one lock; support bounded pages and an older-record browser control. | Stable-checkpoint pagination under intervening audited reads |
| R09 | Browser state persisted behind the login view and could be carried into another account's workspace. | Clear case data, dialogs, selection, and account state on logout or session loss; select only a currently accessible case after login. | Browser password-change/logout state-clearing checks |
| R10 | Offline exports checked signatures and bytes without all decision/review/evidence inventory associations. Export creation could also exceed verifier limits. | Verify ledger associations, unique complete record sets, selected/omitted artifact inventory, release tenant/scope/lifetime; reject oversized export scope before review. | Existing tampered-export suite plus updated valid-export verification |
| R11 | JSON exponent overflow could produce a nonfinite float; unsupported media-type requests lacked a denial record. | Reject overflow in the strict JSON parser and audit unsupported media-type denials. | Positive/negative parser suite, including exponent overflow |
| R12 | Validation omitted Windows, the installed container, and CLI maintenance; deployment accepted incomplete external-origin configuration. | Add Windows CI and a non-root container/API acceptance job; pin the official Python base image by digest; test CLI operations; validate an exact HTTPS origin and matching host for external binding. | Python matrix, Windows, browser, build, dependency audit, CLI tests, and container CI |

The database-tampering tests model a writer who lacks signing keys and retained checkpoints. They do not demonstrate an unauthenticated HTTP exploit. An administrator controlling the host, code, keys, and all retained state remains inside the local trust boundary.

## External work that remains

These requirements need additional implementation and organizational infrastructure. They are not marked complete or silently simulated.

| Requirement | What is still needed | Acceptance evidence |
| --- | --- | --- |
| Enterprise identity and MFA | Organization-owned IdP registration, authoritative identity lifecycle, reviewed claims/role mapping, MFA and step-up integration | Wrong issuer/audience, deprovisioning, recovery and distinct-person approval tests against the real IdP |
| Independent approval/audit custody | Managed signing keys, separate operator permissions, independently operated checkpoint witness, immutable retention | Key rotation/revocation and external rollback/truncation exercises; storage retention/version proof |
| Live cloud and SaaS acquisition | Scoped collector identities, qualified APIs, pagination/watermarks, source-native integrity checking, pinned object versions | Live-source coverage and omission/failure tests in authorized test tenants |
| Production response actions | Approved connector allowlist, credential broker, target preconditions, rollback and recovery verification | Isolate/restore exercises against designated nonproduction targets; independent confirmation |
| Research execution at enterprise scale | Isolated PDF extraction/build workers, reviewed method benchmarks, signed pack distribution | Hostile-document containment and independent method-fidelity evaluation; no arbitrary code in the current runtime |
| Production operations | Organizational threat review, deployment platform, encryption/retention policies, large-case pagination and performance work, disaster-recovery exercise, independent security and accessibility testing | Measured scale/availability and recovery objectives with real infrastructure; remediation of review findings |
| Release governance | Owner-selected license and release process, supported-platform policy, responsible-disclosure ownership | Recorded owner/organization decisions; no license was assigned without the owner's choice |

The local profile has no production mutation connectors. Connecting it to real systems requires implementing and validating those boundaries. Merely providing credentials does not turn this release into the full enterprise design.

## Operational references

The session changes follow the principle of renewing and invalidating authority after authentication or privilege changes described in the [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html). The backup uses SQLite's supported [Online Backup API](https://www.sqlite.org/backup.html) while the application lock keeps the database and checkpoint files consistent. Neither reference independently validates this implementation.

See [validation](VALIDATION.md) for measured results and [administration](ADMINISTRATION.md) for upgrade, backup, restore, and recovery procedures.
