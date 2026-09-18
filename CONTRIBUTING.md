# Contributing

Use Python 3.11 or newer and the development lock file. Keep pull requests scoped to a concrete behavior, explain its impact on authority and evidence, and run the commands in the README.

- A planner, model response, document, log, tool description, or queue message must not grant authority.
- New tools need strict typed arguments, a registry entry, server-owned role policy, exact evidence bindings, failure handling, bounded resources, and negative authorization tests.
- Side effects begin only after a durable single-use intent and audit checkpoint. Unknown outcomes require investigation; never silently retry.
- Preserve raw bytes, source locators, parser/version context, visible model transactions, and explicit coverage gaps.
- UI content from evidence must remain inert. Do not introduce `innerHTML` with unescaped evidence, remote scripts, `eval`, or arbitrary SQL/shell execution.
- Use synthetic data only. Do not add private evidence, credentials, data files from `var/`, or signing keys.
- Keep `docs/design/` as the historical design package. Describe implementation differences in current documents rather than rewriting the original assertions.
- Tests should challenge trust boundaries and real behavior rather than restating implementation details.

Contributions intentionally submitted for inclusion are covered by the [Apache License, Version 2.0](LICENSE), as described in Section 5 of that license.
