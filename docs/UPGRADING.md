# Upgrade from 0.1 to 0.2

1. Stop the application and record any running execution IDs. Preserve the existing state directory, signing keys, independently retained checkpoint pins, and already released exports using the 0.1 backup procedure. Do not alter database or checkpoint heads.
2. Install the new code and its pinned runtime dependencies. The database remains schema version 1; no evidence or historical review migration is performed.
3. Run `tracefoundry --data-dir /protected/state doctor`. Any integrity failure blocks use until it is investigated against independently retained material. The command does not repair, rewrite, or re-sign old state.
4. If an authenticated running intent remains after the old process has stopped, run `tracefoundry --data-dir /protected/state recover`. It records an unknown outcome without retrying the tool. Inconsistent terminal records are rejected, not normalized into a new history.
5. Restart the service. Existing 0.1 sessions must sign in again. The application code digest changed, so pending 0.1 decisions cannot execute. Re-propose needed operations under the new version and collect new human reviews. Historical decisions and attestations remain preserved.
6. Use the new `reconcile_execution` workflow for unknown outcomes. Select independent evidence, record the assessment and residual uncertainty, and obtain two distinct eligible reviews including a supervisor. The original execution stays `OUTCOME_UNKNOWN`; closure is possible only after that reviewed assessment is recorded.
7. Create an encrypted backup, retain its SHA-256 and trusted audit public key independently, and perform an isolated restore check before using the updated state operationally.

The API gains password change and three additional tools. Audit responses are paged: the default is 100 records, maximum 500. Clients that previously assumed every record was in one response must follow `page.next_before` with the same `page.through` while `page.has_more` is true. Each page returns the same retained snapshot checkpoint. Events are chronological within a page; successive pages move backward.

Identity changes, including password changes, now invalidate that person's pending reviews as well as sessions. `user-update` requires an explicit reason and a requested change. `password-reset` does not enable a disabled account. Restore creates new identity-history revisions so backed-up sessions and pending approval authority cannot be revived.

Do not downgrade a live 0.2 state directory and continue operations under older code. The older gateway does not understand the new workflow controls. Retain the original isolated backup if a rollback is needed, and reconcile any activity after that backup before resuming.
