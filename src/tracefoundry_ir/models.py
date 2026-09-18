from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Short = Annotated[str, Field(min_length=1, max_length=200)]
Identifier = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Login(StrictModel):
    username: Identifier
    password: Annotated[str, Field(min_length=1, max_length=256)]


class PasswordChange(StrictModel):
    current_password: Annotated[str, Field(min_length=1, max_length=256)]
    new_password: Annotated[str, Field(min_length=14, max_length=256)]


class CaseCreate(StrictModel):
    title: Short
    description: Annotated[str, Field(min_length=1, max_length=3000)]


class MemberAdd(StrictModel):
    username: Identifier


class EvidenceUpload(StrictModel):
    filename: Short
    content_base64: Annotated[str, Field(max_length=4_000_000)]
    source: Short
    source_version: Short = "unavailable"
    coverage: Literal["complete", "partial", "unknown"] = "unknown"
    coverage_note: Annotated[str, Field(min_length=8, max_length=2000)]
    source_integrity: Literal["not_checked", "failed", "verified_externally"] = "not_checked"
    integrity_note: Annotated[str, Field(max_length=2000)] = "Not assessed"


class Proposal(StrictModel):
    tool: Identifier
    arguments: dict
    purpose: Annotated[str, Field(min_length=8, max_length=3000)]
    ttl_minutes: Annotated[int, Field(ge=1, le=60)] = 30


class Review(StrictModel):
    verdict: Literal["approve", "reject"]
    rationale: Annotated[str, Field(min_length=8, max_length=3000)]
    password: Annotated[str, Field(min_length=1, max_length=256)]
    decision_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Reason(StrictModel):
    reason: Annotated[str, Field(min_length=8, max_length=2000)]


class ImportArgs(StrictModel):
    artifact_id: Identifier
    format: Literal["cloudtrail", "m365", "ocsf", "generic"]


class ArtifactArgs(StrictModel):
    artifact_ids: Annotated[list[Identifier], Field(min_length=1, max_length=20)]


class TimelineArgs(ArtifactArgs):
    actor: Annotated[str, Field(max_length=200)] = ""
    action: Annotated[str, Field(max_length=200)] = ""
    start: Annotated[str, Field(max_length=40)] = ""
    end: Annotated[str, Field(max_length=40)] = ""
    limit: Annotated[int, Field(ge=1, le=1000)] = 200


class Citation(StrictModel):
    chunk_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}:[0-9]+$")]
    relation: Literal["supports", "contradicts"] = "supports"


class FindingArgs(StrictModel):
    claim: Annotated[str, Field(min_length=8, max_length=4000)]
    classification: Literal["observation", "hypothesis", "unresolved", "contradicted"]
    severity: Literal["informational", "low", "medium", "high", "critical"]
    citations: Annotated[list[Citation], Field(min_length=1, max_length=30)]
    limitations: Annotated[str, Field(min_length=8, max_length=2000)]


class GapArgs(StrictModel):
    description: Annotated[str, Field(min_length=8, max_length=2000)]
    affected_scope: Short


class CloseArgs(StrictModel):
    conclusion: Annotated[str, Field(min_length=8, max_length=4000)]
    residual_uncertainty: Annotated[str, Field(min_length=8, max_length=2000)]


class ExportArgs(ArtifactArgs):
    recipient: Identifier


class ModelArgs(ArtifactArgs):
    question: Annotated[str, Field(min_length=8, max_length=2000)]


class PromoteArgs(StrictModel):
    artifact_id: Identifier


class DraftPackArgs(PromoteArgs):
    goal: Annotated[str, Field(min_length=8, max_length=2000)]


class RunPackArgs(ArtifactArgs):
    pack_id: Identifier


class ReconcileArgs(ArtifactArgs):
    execution_id: Identifier
    assessment: Literal[
        "confirmed_no_external_effect", "confirmed_external_effect", "unable_to_determine"
    ]
    conclusion: Annotated[str, Field(min_length=20, max_length=4000)]
    residual_uncertainty: Annotated[str, Field(min_length=8, max_length=2000)]


class ChallengeArgs(StrictModel):
    finding_id: Identifier
    explanation: Annotated[str, Field(min_length=20, max_length=4000)]
    citations: Annotated[list[Citation], Field(min_length=1, max_length=30)]


class ResolveChallengeArgs(StrictModel):
    challenge_id: Identifier
    disposition: Literal["finding_upheld", "finding_withdrawn", "uncertainty_retained"]
    explanation: Annotated[str, Field(min_length=20, max_length=4000)]
    citations: Annotated[list[Citation], Field(min_length=1, max_length=30)]
