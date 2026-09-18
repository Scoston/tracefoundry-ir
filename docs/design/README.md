# TraceFoundry IR engineering package

This package specifies a proposed cybersecurity research to incident response tool system. Read `TraceFoundry_IR_Design.md` or the accompanying Word design first. Every operational decision requires an authenticated human review. The model can propose work and cannot confer authority.

## Contents

- `schemas/`: JSON Schema 2020-12 contracts for decisions, approval attestations, evidence and audit envelopes.
- `examples/`: fictional linked records. Every record has `example_only: true`. The approval is explicitly unsigned. The sample hashes match the included bytes; there is no real authentication, protected storage or checkpoint witness.
- `contracts/`: server-side enforcement, approval signing and evidence verification requirements.
- `diagrams/`: editable canonical diagram definitions, Mermaid source and PNG figures used in the design. The figures use a deterministic custom layout. Mermaid static checks are not a claim of Mermaid host rendering acceptance.
- `verification/`: design-file validation and an implementation acceptance catalog. The catalog describes future integration and security tests; it is not a list of tests already passed by an application.

## Scope and implementation status

This is a design handoff, not an executable incident response agent. It includes no live connectors, approval server, model integration, runtime policy engine, signing keys or vendor credentials. No production system was accessed or changed.

The examples intentionally show only a subset of a case. The evidence import authorization and collection receipt are outside the subset and are named as gaps. The tool-image and pack digests are fictional design values. A real case export must include or explicitly resolve every required reference and an independently obtained expected checkpoint head.

Production services must reject `example_only: true`, unsigned attestations and untrusted keys. A schema-valid approval must still fail unless its signature, identity, roles, digest, lifetime and single-use state all pass trusted server-side validation.

## Rechecking these files

Use Python 3 with `jsonschema` and `rfc8785` installed, then run:

```bash
python verification/validate_design.py
```

This validates contract shape, canonical example hashes, selected links and negative schema fixtures. It does not test live enforcement. `verification/validation_report.json` records the checks performed during preparation.

Research references and dates are in the design. The working name TraceFoundry IR is a proposed name; no availability or trademark search is implied.
