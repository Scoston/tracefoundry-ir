# Administration and deployment

## Local installation

Use the README commands. Keep the application on loopback for evaluation. `tracefoundry --data-dir /path/to/protected-state <command>` places the SQLite database, keys, checkpoint history, and encrypted artifacts in an explicit directory. No state is created simply by importing the package.

Initialization is allowed only in a new or empty directory. It generates separate P-256 approval and audit keys plus an AES-GCM vault key. On POSIX systems, the state directory is mode 0700 and private key files are mode 0600. On Windows, protect the directory with appropriate NTFS ACLs; POSIX mode bits are not an NTFS authorization policy.

`user-add` creates a human account from the trusted host console. Supported roles are `analyst`, `supervisor`, and `admin`. Local administration is a privileged trust boundary, not a browser capability.

```bash
tracefoundry user-add --username second-reviewer --roles supervisor
tracefoundry user-update --username second-reviewer --roles analyst
tracefoundry user-update --username second-reviewer --disable
```

Identity changes are signed and audited, and active sessions are invalidated. This release does not include a self-service password reset, automatic account enrollment, IdP synchronization, or key rotation workflow. Back up access and key custody procedures before use; do not edit signed identity rows directly.

## TLS and network exposure

Use a trusted TLS reverse proxy if evaluating beyond loopback. Set the exact public origin, host allowlist, and secure cookies:

```bash
export TFIR_ORIGIN=https://tracefoundry.example.org
export TFIR_ALLOWED_HOSTS=tracefoundry.example.org
export TFIR_SECURE_COOKIES=true
tracefoundry serve --host 0.0.0.0
```

These flags are necessary configuration, not a production-readiness statement. The CLI rejects a non-loopback bind without secure-cookie and public-origin settings. Proxy headers are disabled; a proxy must preserve the approved Host and Origin behavior. Cookies are HttpOnly and SameSite Strict; state-changing authenticated requests additionally require the session's CSRF token. No cross-origin API access is enabled.

The application uses a local cross-process file lock and SQLite serialization. Run one application worker on one host. A shared network filesystem is not a supported distributed coordination mechanism. Do not run multiple application versions against one state directory: tool source digests deliberately invalidate pending decisions when code changes.

## Optional model provider

The provider accepts a fixed HTTPS chat-completions-compatible endpoint. Configure all of `TFIR_MODEL_URL`, `TFIR_MODEL_ALLOWED_HOSTS`, `TFIR_MODEL_NAME`, and `TFIR_MODEL_API_KEY` in the service environment. `.env.example` is documentation; files are not automatically loaded. Inject the key through your secret-management system.

The endpoint must accept `messages`, `max_tokens`, and JSON `response_format`. Support differs by provider/model; this adapter is tested with mocked transport, not certified for every API. It disables redirects and environment proxy inheritance, caps bytes, and has a 45-second timeout. Enforce outbound network policy independently. The hostname allowlist is operator configuration, not a DNS-rebinding-resistant network firewall.

`model_assess` and `draft_pack` each require two human reviews. The request's exact context, model, prompt hashes, and endpoint are bound to authority. A request artifact exists before disclosure. Responses are preserved in encrypted artifacts even when their candidate conclusions fail validation. Oversized responses, timeouts, and transport failures produce explicit failure/unknown states and may have incomplete response capture. Hidden chain-of-thought is neither requested nor required.

## Backup and restore

1. Stop the application and preserve in-flight status. Do not assume a running model call had no external effect.
2. Copy the complete protected state directory: database, keys, checkpoint history, and current checkpoints. Use encrypted, access-controlled backups.
3. Retain public keys and selected checkpoint pins in an independently administered location. Copies in the same state directory are not independent witnesses.
4. Restore to an isolated directory, verify checkpoint consistency, then inspect interrupted executions. `tracefoundry recover` marks abandoned executions unknown and performs no retry.
5. If database and checkpoint heads disagree, keep both versions for investigation. Do not delete checkpoints or regenerate them to make an integrity error disappear.

SQLite commit and checkpoint publication have a documented crash window. No automatic integrity repair is provided. Recovery against independent evidence is an operational requirement. There is no legal-hold, retention-disposal, or source deletion feature in this release.

## Export verification

The export decision exposes the snapshot sequence in `binding.event_count`. Copy the corresponding retained checkpoint using the trusted host console, then transfer it and the public keys through an independently trusted path:

```bash
tracefoundry checkpoint CASE_ID --sequence SNAPSHOT_EVENT_COUNT --out expected-checkpoint.json
tracefoundry verify-export case-export.zip \
  --audit-key trusted-audit-public.pem \
  --approval-key trusted-approvals-public.pem \
  --expected-checkpoint expected-checkpoint.json
```

Use the historical snapshot checkpoint, not an unrelated later head. The verifier does not fetch URLs, extract archive paths, contact a model, or replay side effects. A successful verification reports byte/record/signature consistency and a matching supplied pin; source completeness remains unproven. Historical current-role/revocation enforcement is attested by the release service, not independently reconstructed from a complete external IdP/admin ledger.

## Container

The Dockerfile packages the local service as an unprivileged user. Provision a writable protected state volume, initialize accounts interactively, then serve behind TLS with explicit environment configuration. The image is not an independent sandbox for hostile generated code; no such execution feature exists. Pin a reviewed base-image digest and scan the finished image before organizational deployment. Container execution is not claimed as locally tested unless recorded in `VALIDATION.md`.
