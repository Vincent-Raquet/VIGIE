"""Format de sortie imposé au LLM (SPEC §7.6) : données uniquement, jamais exécutées.

`OUTPUT_SCHEMA` est envoyé en `output_config.format` (sorties structurées) : le modèle n'a
aucun outil. Le schéma reste dans le sous-ensemble sûr (types, enums, required,
additionalProperties) ; les bornes de longueur et de nombre sont appliquées ensuite par
`LLMPlan` (Pydantic), puis le validateur métier décide élément par élément.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from vigie.db.enums import Priority

MAX_TASKS = 200
MAX_NEW_TASKS = 5


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PersonSummary(_Out):
    person_id: int
    summary: str = Field(max_length=600)


class LLMTask(_Out):
    ref: str = Field(
        pattern=r"^((incident|milestone|carry|followup):[a-z0-9:]{1,60}|new-[0-9]{1,2})$"
    )
    title: str = Field(min_length=1, max_length=120)
    actions: list[str] = Field(default_factory=list, max_length=6)
    priority: Priority
    assignee_id: int | None = None
    estimate_h: float = Field(ge=0.25, le=16)
    due: date | None = None
    incident_ids: list[int] = Field(default_factory=list, max_length=20)
    milestone_id: int | None = None
    rationale: str = Field(default="", max_length=300)


class Risk(_Out):
    text: str = Field(max_length=300)
    severity: Literal["low", "medium", "high"]


class Escalation(_Out):
    text: str = Field(max_length=300)
    to: Literal["coordinator", "manager"]


class LLMPlan(_Out):
    summary_exec: str = Field(max_length=600)
    per_person: list[PersonSummary] = Field(default_factory=list, max_length=20)
    tasks: list[LLMTask] = Field(default_factory=list, max_length=MAX_TASKS)
    risks: list[Risk] = Field(default_factory=list, max_length=10)
    escalations: list[Escalation] = Field(default_factory=list, max_length=10)


def _obj(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_STR = {"type": "string"}
_INT = {"type": "integer"}
_INT_OR_NULL = {"anyOf": [_INT, {"type": "null"}]}

OUTPUT_SCHEMA: dict[str, Any] = _obj(
    {
        "summary_exec": _STR,
        "per_person": {
            "type": "array",
            "items": _obj({"person_id": _INT, "summary": _STR}, ["person_id", "summary"]),
        },
        "tasks": {
            "type": "array",
            "items": _obj(
                {
                    "ref": _STR,
                    "title": _STR,
                    "actions": {"type": "array", "items": _STR},
                    "priority": {"type": "string", "enum": [p.value for p in Priority]},
                    "assignee_id": _INT_OR_NULL,
                    "estimate_h": {"type": "number"},
                    "due": {"anyOf": [{"type": "string", "format": "date"}, {"type": "null"}]},
                    "incident_ids": {"type": "array", "items": _INT},
                    "milestone_id": _INT_OR_NULL,
                    "rationale": _STR,
                },
                [
                    "ref",
                    "title",
                    "actions",
                    "priority",
                    "assignee_id",
                    "estimate_h",
                    "due",
                    "incident_ids",
                    "milestone_id",
                    "rationale",
                ],
            ),
        },
        "risks": {
            "type": "array",
            "items": _obj(
                {"text": _STR, "severity": {"type": "string", "enum": ["low", "medium", "high"]}},
                ["text", "severity"],
            ),
        },
        "escalations": {
            "type": "array",
            "items": _obj(
                {"text": _STR, "to": {"type": "string", "enum": ["coordinator", "manager"]}},
                ["text", "to"],
            ),
        },
    },
    ["summary_exec", "per_person", "tasks", "risks", "escalations"],
)
