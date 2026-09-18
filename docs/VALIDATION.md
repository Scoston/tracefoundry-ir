# Validation record

This document describes how the release is evaluated. The machine-readable `validation/results.json` records measured outcomes and the tested source-tree digest. Update it only from an actual completed run.

## Recorded local run: September 18, 2026

| Check | Measured result |
| --- | --- |
| Pytest | 84 passed; no failed, skipped, or errored tests |
| Statement coverage | 1,234 of 1,428 statements; 86.41% overall, including the CLI |
| Ruff lint and formatting | Passed for application, tests, and scripts |
| Firefox workflow | 14 flow checks passed; zero JavaScript page errors |
| Runtime dependency audit | 27 dependencies checked; zero reported vulnerabilities; zero skipped |
| Packaging | Wheel and source distribution built successfully |
| Original design package | 19 schema/example checks; 22 original files match their recorded hashes |

Python 3.12.14 on Linux was used locally. GitHub CI is configured for Python 3.11, 3.12, and 3.13; its live run status is separate from this local record. Two third-party deprecation warnings were observed from Starlette's httpx test client and its AnyIO BlockingPortal alias.

For the local browser run only, Firefox's content and GMP sandboxes were disabled with environment flags because this executor cannot create browser user namespaces. The test used a temporary loopback service, fictional evidence, and temporary accounts. The CI workflow uses Firefox's default sandbox settings. Neither mode is a browser sandbox security assessment.

The screenshots in `screenshots/` show this synthetic acceptance run. The [dependency report](validation/dependency-audit.json) preserves the audit result; [results.json](validation/results.json) also records file hashes for the tested application, test files, and scripts. The overall coverage number includes the CLI, which had no pytest statement coverage; selected CLI commands were exercised separately. Docker image execution was not performed.

## Application checks

The automated suite exercises the HTTP/session boundary, role and case authorization, review reauthentication, digest binding, revocation, expiry, distinct-account approvals, concurrent execution, durable intent, failed audit persistence, checkpoint mismatch, evidence/metadata/normalized-record tampering, forged keys, export scope, parser coverage warnings, candidate finding semantics, research pack validation, and mocked model responses/timeouts.

The model tests use synthetic responses and local mocked transport. They verify capture, rejection, disclosure gates, and no blind retry. They do not test a live provider, vendor billing, or model accuracy.

The browser acceptance script exercises the real application through the UI using synthetic evidence and temporary named accounts. It checks login, case creation, membership, evidence staging, proposal/review/execution, candidate finding acceptance, distinct-account export review, retrieval, and desktop/mobile layout. It does not substitute for an accessibility audit or independent penetration test.

The runtime dependency audit checks the pinned dependency set against the advisory data available when run. A clean result does not certify the absence of vulnerabilities. The package build verifies that a wheel/sdist can be produced; container execution is reported separately.

## Original design checks

The preserved design package has 19 schema/example checks and 40 future acceptance scenarios. Its report is historical and intentionally retains its original wording. The current application tests, status table, and measured results are separate. Do not claim all 40 enterprise acceptance scenarios passed because a local unit test covers part of one requirement.

## Remaining validation

- Enterprise SSO/MFA, managed keys, WORM storage, independent witness custody, live collectors, and production response connectors are not implemented or tested.
- No production incident data or real customer tenant was used.
- No multi-host load, failover, disaster-recovery exercise, external penetration test, or regulatory assessment was performed.
- The local database/checkpoint crash window is intentionally fail-closed and requires operator reconciliation.
- UI escaping and CSP are tested; complete browser compatibility and assistive-technology certification are not claimed.
