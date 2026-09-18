# Research to investigation packs

The original paper builds tools from research and code. TraceFoundry IR v0.1 implements a constrained version: research becomes a tested pack of matching rules. It does not execute paper-supplied or model-generated code.

## Author or draft

Start with `packs/cloudtrail-audit-visibility.json`. Record actual source titles, links, and a concise explanation of how each research method became an investigation rule. Source links are metadata and are never fetched automatically. Do not imply a paper validated a cyber rule it did not evaluate.

An optional `draft_pack` operation can propose a pack from staged UTF-8 research text or Markdown. It sends the exact selected text and goal to the configured provider only after two human reviews, including a supervisor. The request and visible response are preserved. Output must satisfy the same strict rule format and positive/negative tests as a hand-authored pack. A valid draft is saved as an **unreviewed source artifact**, not released or executed.

The model can invent or misinterpret a source even when JSON validation passes. Reviewers must check source fidelity and test expectations independently. The generated tests are evidence of internal consistency, not an independent scientific benchmark.

## Contract

```json
{
  "name": "Audit visibility review",
  "version": "1.0.0",
  "sources": [{
    "title": "Source title",
    "url": "https://example.org/research",
    "method_note": "Describe the actual translation and its limitations."
  }],
  "rules": [{
    "id": "logging-stopped",
    "field": "action",
    "equals": "StopLogging",
    "claim": "Logging was stopped; verify authorization and coverage impact.",
    "severity": "high"
  }],
  "tests": [
    {"event": {"action": "StopLogging"}, "expected_rule_ids": ["logging-stopped"]},
    {"event": {"action": "GetObject"}, "expected_rule_ids": []}
  ]
}
```

Rules support exact string matching on `actor`, `action`, `resource`, `ip`, or `outcome`. There is no regex engine, scripting, SQL, code execution, network fetch, or dependency installation. Every rule needs a positive test, and the pack needs a negative test. Unique IDs and strict fields are required.

```bash
tracefoundry validate-pack packs/cloudtrail-audit-visibility.json
```

Validation does not grant release authority.

## Release and run

Stage the pack JSON, then propose `promote_pack` referencing its artifact ID. The body includes its digest and test count. Separate administrator and supervisor accounts review the exact pack and its method. Execution creates an immutable case-scoped pack.

Propose `run_pack` with its exact pack ID and selected imported artifacts. The proposal binds the pack digest. Review and execute the operation. Matches create candidate hypotheses with chunk citations. Accepting a finding requires another review.

Pack scope in this release is the case. Reusing a method in another case requires a new staged pack and release; cross-case tenant-wide distribution and a managed signed pack registry remain future work.
