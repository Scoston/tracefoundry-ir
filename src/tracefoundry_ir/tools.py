"""Closed tool registry: parsing and matching only; no shell, SQL, or code evaluation."""

from datetime import UTC, datetime
from pathlib import Path

from . import models
from .security import canonical, sha256, strict_json
from .store import Fault

REGISTRY = {
    "reconcile_execution": (
        models.ReconcileArgs,
        [["analyst", "supervisor"], ["supervisor"]],
        "Record an evidence-based assessment of an unknown execution; never retry or rewrite its original result",
    ),
    "challenge_finding": (
        models.ChallengeArgs,
        [["analyst", "supervisor"]],
        "Challenge an accepted finding with preserved source citations",
    ),
    "resolve_challenge": (
        models.ResolveChallengeArgs,
        [["analyst", "supervisor"], ["supervisor"]],
        "Review a finding challenge with a second human; retain the original claim and evidence",
    ),
    "draft_pack": (
        models.DraftPackArgs,
        [["analyst", "supervisor"], ["supervisor"]],
        "Send selected research text to the configured model to draft a declarative pack; release remains separate",
    ),
    "import_logs": (
        models.ImportArgs,
        [["analyst", "supervisor"]],
        "Normalize staged logs; preserve raw bytes",
    ),
    "timeline": (
        models.TimelineArgs,
        [["analyst", "supervisor"]],
        "Query an exact set of evidence",
    ),
    "suggest_findings": (
        models.ArtifactArgs,
        [["analyst", "supervisor"]],
        "Generate rule-based candidate findings",
    ),
    "accept_finding": (
        models.FindingArgs,
        [["analyst", "supervisor"]],
        "Record a reviewed claim with citations",
    ),
    "record_gap": (models.GapArgs, [["analyst", "supervisor"]], "Declare a source or coverage gap"),
    "close_case": (
        models.CloseArgs,
        [["supervisor"]],
        "Close the investigation with uncertainty recorded",
    ),
    "export_case": (
        models.ExportArgs,
        [["analyst", "supervisor"], ["supervisor"]],
        "Release an exact snapshot to a named case member",
    ),
    "model_assess": (
        models.ModelArgs,
        [["analyst", "supervisor"], ["supervisor"]],
        "Send selected context to the configured model; candidates only",
    ),
    "promote_pack": (
        models.PromoteArgs,
        [["admin"], ["supervisor"]],
        "Release a validated declarative research pack",
    ),
    "run_pack": (
        models.RunPackArgs,
        [["analyst", "supervisor"]],
        "Run a pinned pack on selected evidence",
    ),
}
POLICY = "local-human-review-v1"


def registry_digest() -> str:
    # Bind the gateway and the human review UI to the same immutable release.
    root = Path(__file__).parent
    files = sorted(p for p in root.rglob("*") if p.suffix in {".py", ".js", ".html", ".css"})
    return sha256(
        canonical({p.relative_to(root).as_posix(): sha256(p.read_bytes()) for p in files})
    )


def matching_roles(groups: list[list[str]], users: list[dict]) -> bool:
    """Each policy group needs a different human, even if one has several roles."""
    if not groups:
        return True
    return any(
        set(user["roles"]) & set(groups[0])
        and matching_roles(groups[1:], [u for u in users if u["username"] != user["username"]])
        for user in users
    )


def parse_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Timezone required")
        return parsed.astimezone(UTC).isoformat()
    except (ValueError, TypeError, OverflowError) as exc:
        raise ValueError("Expected an ISO 8601 timestamp with timezone") from exc


def text(value) -> str:
    if value is None:
        return ""
    return (value if isinstance(value, str) else canonical(value).decode())[:2000]


def parse_logs(data: bytes, artifact_id: str, format_name: str) -> tuple[list[dict], list[str]]:
    source = data.decode("utf-8-sig")
    locators = []
    try:
        parsed = strict_json(source)
        if isinstance(parsed, dict) and "Records" in parsed:
            records, prefix = parsed["Records"], "/Records"
        elif isinstance(parsed, dict) and "value" in parsed:
            records, prefix = parsed["value"], "/value"
        elif isinstance(parsed, dict):
            records, prefix = [parsed], ""
        elif isinstance(parsed, list):
            records, prefix = parsed, ""
        else:
            raise ValueError("Expected JSON objects")
        if not isinstance(records, list):
            raise ValueError("Expected a record array")
        locators = [
            f"{prefix}/{i}" if not (isinstance(parsed, dict) and records == [parsed]) else "/"
            for i in range(len(records))
        ]
    except ValueError as exc:
        # Duplicate-key and nonfinite failures must never be hidden by format fallback.
        if "Duplicate JSON" in str(exc) or "Non-finite" in str(exc):
            raise
        lines = [(i, line) for i, line in enumerate(source.splitlines(), 1) if line.strip()]
        records = [strict_json(line) for _, line in lines]
        locators = [f"line:{i}" for i, _ in lines]
    if len(records) > 10000:
        raise ValueError("Record limit exceeded; split the source under a new approved scope")
    rows, warnings = [], []
    for index, (original, locator) in enumerate(zip(records, locators, strict=True)):
        if not isinstance(original, dict):
            raise ValueError("Every record must be an object")
        if original.get("example_only") is True:
            raise ValueError("Design authority examples cannot be imported as case evidence")
        event = original
        if format_name == "m365" and isinstance(original.get("AuditData"), str):
            event = strict_json(original["AuditData"])
            if not isinstance(event, dict):
                raise ValueError("AuditData must be an object")
            locator += "/AuditData (JSON-encoded)"
        if format_name == "cloudtrail":
            identity = event.get("userIdentity") or {}
            identity = identity if isinstance(identity, dict) else {}
            normalized = {
                "event_time": event.get("eventTime"),
                "actor": identity.get("arn") or identity.get("principalId"),
                "action": event.get("eventName"),
                "resource": event.get("resources") or event.get("requestParameters"),
                "ip": event.get("sourceIPAddress"),
                "outcome": event.get("errorCode", "not_reported"),
            }
        elif format_name == "m365":
            normalized = {
                "event_time": event.get("CreationTime"),
                "actor": event.get("UserId"),
                "action": event.get("Operation"),
                "resource": event.get("ObjectId"),
                "ip": event.get("ClientIP"),
                "outcome": event.get("ResultStatus", "not_reported"),
            }
        elif format_name == "ocsf":
            actor = event.get("actor") or {}
            actor = actor if isinstance(actor, dict) else {}
            event_time = event.get("time")
            if isinstance(event_time, (int, float)) and not isinstance(event_time, bool):
                event_time = datetime.fromtimestamp(event_time / 1000, UTC).isoformat()
            normalized = {
                "event_time": event_time,
                "actor": actor.get("user") or actor,
                "action": event.get("activity_name") or event.get("type_name"),
                "resource": event.get("resources"),
                "ip": (event.get("src_endpoint") or {}).get("ip")
                if isinstance(event.get("src_endpoint"), dict)
                else "",
                "outcome": event.get("status", "not_reported"),
            }
        else:
            normalized = {
                key: event.get(key, "")
                for key in ("event_time", "actor", "action", "resource", "ip", "outcome")
            }
        normalized = {key: text(value) for key, value in normalized.items()}
        try:
            normalized["event_time"] = parse_time(normalized["event_time"])
        except ValueError:
            normalized["event_time"] = ""
            warnings.append(f"{artifact_id}:{index}: source timestamp missing or invalid")
        rows.append(
            {
                "chunk_id": f"{artifact_id}:{index}",
                "artifact_id": artifact_id,
                "locator": locator,
                "record_sha256": sha256(canonical(original)),
                **normalized,
            }
        )
    if not rows:
        warnings.append("Zero records imported. This does not establish absence of activity.")
    return rows, warnings


RULES = [
    {
        "id": "audit-control",
        "actions": ["StopLogging", "DeleteTrail", "PutEventSelectors"],
        "claim": "Audit collection was changed; validate the actor, authorization, and coverage impact.",
        "severity": "high",
    },
    {
        "id": "credential-change",
        "actions": ["CreateAccessKey", "UpdateLoginProfile", "Add service principal credentials."],
        "claim": "A credential change requires verification against an authorized change record.",
        "severity": "medium",
    },
    {
        "id": "privilege-change",
        "actions": ["AttachUserPolicy", "PutRolePolicy", "Add member to role."],
        "claim": "A privilege change requires review of the permission delta and approval history.",
        "severity": "high",
    },
    {
        "id": "agent-workflow-change",
        "actions": ["EditFlow", "CreateFlow", "UpdateBot"],
        "claim": "An automation or agent configuration changed; inspect connectors, identities, and change authorization.",
        "severity": "medium",
    },
]


def candidates(rows: list[dict]) -> list[dict]:
    return [
        {
            "rule": rule["id"],
            "claim": rule["claim"],
            "severity": rule["severity"],
            "classification": "hypothesis",
            "review_status": "unreviewed",
            "citations": [{"chunk_id": row["chunk_id"], "relation": "supports"}],
            "limitations": "An event match does not prove malicious intent or causation.",
        }
        for row in rows
        for rule in RULES
        if row["action"] in rule["actions"]
    ]


def validate_pack(data: bytes) -> dict:
    pack = strict_json(data)
    required = {"name", "version", "sources", "rules", "tests"}
    if not isinstance(pack, dict) or set(pack) != required:
        raise ValueError("Pack requires exactly name, version, sources, rules, and tests")
    for field in ("name", "version"):
        if not isinstance(pack[field], str) or not 1 <= len(pack[field]) <= 100:
            raise ValueError("Invalid pack name/version")
    if not isinstance(pack["sources"], list) or not 1 <= len(pack["sources"]) <= 20:
        raise ValueError("Research sources required")
    for source in pack["sources"]:
        if not isinstance(source, dict) or set(source) != {"title", "url", "method_note"}:
            raise ValueError("Each source requires title, url, and method_note")
        if any(not isinstance(v, str) or not 1 <= len(v) <= 2000 for v in source.values()):
            raise ValueError("Invalid source metadata")
    if not isinstance(pack["rules"], list) or not 1 <= len(pack["rules"]) <= 50:
        raise ValueError("Pack must have 1 to 50 rules")
    ids = set()
    for rule in pack["rules"]:
        if not isinstance(rule, dict) or set(rule) != {
            "id",
            "field",
            "equals",
            "claim",
            "severity",
        }:
            raise ValueError("Invalid rule fields")
        if any(not isinstance(v, str) or not 1 <= len(v) <= 2000 for v in rule.values()):
            raise ValueError("Invalid rule values")
        if rule["field"] not in {"actor", "action", "resource", "ip", "outcome"}:
            raise ValueError("Rule field not permitted")
        if (
            rule["severity"] not in {"informational", "low", "medium", "high", "critical"}
            or rule["id"] in ids
        ):
            raise ValueError("Invalid severity or duplicate rule id")
        ids.add(rule["id"])
    if not isinstance(pack["tests"], list) or not 2 <= len(pack["tests"]) <= 100:
        raise ValueError("Pack requires 2 to 100 test vectors")
    covered, negative = set(), False
    for test in pack["tests"]:
        if (
            not isinstance(test, dict)
            or set(test) != {"event", "expected_rule_ids"}
            or not isinstance(test["event"], dict)
            or not isinstance(test["expected_rule_ids"], list)
        ):
            raise ValueError("Invalid test vector")
        expected = test["expected_rule_ids"]
        if any(not isinstance(i, str) for i in expected):
            raise ValueError("Invalid expected rule ids")
        actual = [r["id"] for r in pack["rules"] if test["event"].get(r["field"]) == r["equals"]]
        if sorted(actual) != sorted(expected):
            raise ValueError("Pack reference test failed")
        covered.update(actual)
        negative = negative or not actual
    if covered != ids or not negative:
        raise ValueError("Every rule needs a positive test and the pack needs a negative test")
    return pack


def run_pack(pack: dict, rows: list[dict]) -> list[dict]:
    return [
        {
            "rule": rule["id"],
            "claim": rule["claim"],
            "severity": rule["severity"],
            "classification": "hypothesis",
            "review_status": "unreviewed",
            "citations": [{"chunk_id": row["chunk_id"], "relation": "supports"}],
        }
        for row in rows
        for rule in pack["rules"]
        if row.get(rule["field"]) == rule["equals"]
    ]


def bounded_rows(rows: list[dict], args: dict) -> dict:
    start = parse_time(args["start"]) if args["start"] else ""
    end = parse_time(args["end"]) if args["end"] else ""
    if start and end and start > end:
        raise Fault(422, "invalid_time_window")
    matched = [
        r
        for r in rows
        if (not args["actor"] or args["actor"].casefold() in r["actor"].casefold())
        and (not args["action"] or args["action"].casefold() in r["action"].casefold())
        and (not start or (r["event_time"] and r["event_time"] >= start))
        and (not end or (r["event_time"] and r["event_time"] <= end))
    ]
    matched.sort(key=lambda r: (r["event_time"], r["chunk_id"]))
    return {
        "rows": matched[: args["limit"]],
        "matched": len(matched),
        "truncated": len(matched) > args["limit"],
        "coverage_note": "This is a query of selected imported evidence, not proof of complete source coverage.",
    }
