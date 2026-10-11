"""Modèle de données (SPEC §5.1).

Les listes de références de la spec (`signal_ids[]`, `axis_ids[]`, `depends_on[]`…) sont des
tables d'association avec clés étrangères : le validateur s'appuie sur l'intégrité
référentielle de la base plutôt que sur des tableaux non contrôlés.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Identity,
    Integer,
    MetaData,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from vigie.db import enums
from vigie.db.jobs import MAX_PAYLOAD_BYTES

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def _enum(enum_cls: type[StrEnum], name: str) -> SAEnum:
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=lambda members: [m.value for m in members],
        validate_strings=True,
    )


def _text_array() -> Any:
    return ARRAY(Text)


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


# --- Équipe -----------------------------------------------------------------


class Person(Base):
    __tablename__ = "person"
    __table_args__ = (
        CheckConstraint("planning_rate > 0 AND planning_rate <= 1", name="planning_rate"),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    job_role: Mapped[str] = mapped_column(String(200), default="")
    app_role: Mapped[enums.AppRole] = mapped_column(_enum(enums.AppRole, "app_role"))
    # Jour (mon…sun) → heures disponibles
    weekly_pattern: Mapped[dict[str, float]] = mapped_column(JSONB, default=dict)
    planning_rate: Mapped[float] = mapped_column(Float, default=0.8)
    notes: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    role_skill_id: Mapped[int | None] = mapped_column(ForeignKey("role_skill.id"))


class PersonSkill(Base):
    __tablename__ = "person_skill"
    __table_args__ = (CheckConstraint("level BETWEEN 1 AND 3", name="level"),)

    person_id: Mapped[int] = mapped_column(
        ForeignKey("person.id", ondelete="CASCADE"), primary_key=True
    )
    skill_tag: Mapped[str] = mapped_column(String(50), primary_key=True)
    level: Mapped[int] = mapped_column(SmallInteger)
    preference: Mapped[enums.SkillPreference] = mapped_column(
        _enum(enums.SkillPreference, "preference"), default=enums.SkillPreference.neutral
    )


class Absence(Base):
    __tablename__ = "absence"
    __table_args__ = (
        CheckConstraint('"end" >= start', name="period"),
        CheckConstraint("hours IS NULL OR (hours > 0 AND hours <= 24)", name="hours"),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    person_id: Mapped[int] = mapped_column(ForeignKey("person.id", ondelete="CASCADE"))
    start: Mapped[date] = mapped_column(Date)
    end: Mapped[date] = mapped_column(Date)
    kind: Mapped[enums.AbsenceKind] = mapped_column(_enum(enums.AbsenceKind, "kind"))
    hours: Mapped[float | None] = mapped_column(Float)  # pour extra_day
    note: Mapped[str] = mapped_column(Text, default="")


# --- Sociétés et actifs -------------------------------------------------------


class Company(Base):
    __tablename__ = "company"
    __table_args__ = (CheckConstraint("criticality BETWEEN 0.5 AND 1.5", name="criticality"),)

    code: Mapped[str] = mapped_column(String(8), primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    criticality: Mapped[float] = mapped_column(Float, default=1.0)


class AssetRule(Base):
    __tablename__ = "asset_rule"
    __table_args__ = (
        UniqueConstraint("source", "match_type", "pattern"),
        CheckConstraint(
            "asset_criticality IS NULL OR asset_criticality BETWEEN 0.5 AND 1.5",
            name="asset_criticality",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    source: Mapped[str] = mapped_column(String(64))
    match_type: Mapped[enums.MatchType] = mapped_column(_enum(enums.MatchType, "match_type"))
    pattern: Mapped[str] = mapped_column(String(200))
    # Facultatif : une règle peut ne porter que la criticité de l'actif.
    company_code: Mapped[str | None] = mapped_column(ForeignKey("company.code"))
    asset_criticality: Mapped[float | None] = mapped_column(Float)
    tags: Mapped[list[str]] = mapped_column(_text_array(), default=list)


# --- Politique IT -----------------------------------------------------------


class PolicyAxis(Base):
    __tablename__ = "policy_axis"
    __table_args__ = (
        CheckConstraint("weight BETWEEN 1 AND 5", name="weight"),
        CheckConstraint(
            "valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from", name="validity"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    title: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    weight: Mapped[int] = mapped_column(SmallInteger)
    valid_from: Mapped[date | None] = mapped_column(Date)
    valid_to: Mapped[date | None] = mapped_column(Date)
    keywords: Mapped[list[str]] = mapped_column(_text_array(), default=list)
    categories: Mapped[list[str]] = mapped_column(_text_array(), default=list)


class PolicyRule(Base):
    __tablename__ = "policy_rule"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    text: Mapped[str] = mapped_column(Text, unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)


# --- Projets ----------------------------------------------------------------


class Project(Base):
    __tablename__ = "project"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    sponsor: Mapped[str] = mapped_column(String(100), default="")
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("person.id"))
    priority: Mapped[enums.ProjectPriority] = mapped_column(
        _enum(enums.ProjectPriority, "priority"), default=enums.ProjectPriority.medium
    )
    status: Mapped[enums.ProjectStatus] = mapped_column(
        _enum(enums.ProjectStatus, "status"), default=enums.ProjectStatus.proposed
    )
    start: Mapped[date | None] = mapped_column(Date)
    end: Mapped[date | None] = mapped_column(Date)


class ProjectCompany(Base):
    __tablename__ = "project_company"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("project.id", ondelete="CASCADE"), primary_key=True
    )
    company_code: Mapped[str] = mapped_column(ForeignKey("company.code"), primary_key=True)


class ProjectAxis(Base):
    __tablename__ = "project_axis"

    project_id: Mapped[int] = mapped_column(
        ForeignKey("project.id", ondelete="CASCADE"), primary_key=True
    )
    axis_id: Mapped[int] = mapped_column(
        ForeignKey("policy_axis.id", ondelete="CASCADE"), primary_key=True
    )


class Milestone(Base):
    __tablename__ = "milestone"
    __table_args__ = (
        UniqueConstraint("project_id", "title"),
        CheckConstraint("effort_h >= 0 AND remaining_h >= 0", name="effort"),
    )

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("project.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(200))
    due: Mapped[date] = mapped_column(Date)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("person.id"))
    effort_h: Mapped[float] = mapped_column(Float, default=0)
    remaining_h: Mapped[float] = mapped_column(Float, default=0)
    skill_tags: Mapped[list[str]] = mapped_column(_text_array(), default=list)
    status: Mapped[enums.MilestoneStatus] = mapped_column(
        _enum(enums.MilestoneStatus, "status"), default=enums.MilestoneStatus.planned
    )


class MilestoneDependency(Base):
    __tablename__ = "milestone_dependency"
    __table_args__ = (CheckConstraint("milestone_id <> depends_on_id", name="not_self"),)

    milestone_id: Mapped[int] = mapped_column(
        ForeignKey("milestone.id", ondelete="CASCADE"), primary_key=True
    )
    depends_on_id: Mapped[int] = mapped_column(
        ForeignKey("milestone.id", ondelete="CASCADE"), primary_key=True
    )


# --- Skills de rôle -----------------------------------------------------------


class RoleSkill(Base):
    __tablename__ = "role_skill"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    body_md: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str] = mapped_column(String(100))
    updated_at: Mapped[datetime] = _created_at()


class RoleSkillVersion(Base):
    __tablename__ = "role_skill_version"
    __table_args__ = (UniqueConstraint("role_skill_id", "version"),)

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    role_skill_id: Mapped[int] = mapped_column(ForeignKey("role_skill.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text, default="")
    body_md: Mapped[str] = mapped_column(Text)
    updated_by: Mapped[str] = mapped_column(String(100))
    updated_at: Mapped[datetime] = _created_at()


# --- Sources, signaux, incidents ------------------------------------------------


class Source(Base):
    __tablename__ = "source"

    # « zabbix », ou « veeam:vbr-main » pour une source multi-instance
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    interval_min: Mapped[int] = mapped_column(Integer, default=15)
    filters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    base_url: Mapped[str] = mapped_column(String(500), default="")
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Signal(Base):
    __tablename__ = "signal"
    __table_args__ = (
        UniqueConstraint("source", "external_id"),
        CheckConstraint("severity BETWEEN 0 AND 5", name="severity"),
        CheckConstraint("char_length(details) <= 1000", name="details_length"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    source: Mapped[str] = mapped_column(ForeignKey("source.name"))
    external_id: Mapped[str] = mapped_column(String(200))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    company_code: Mapped[str | None] = mapped_column(ForeignKey("company.code"))
    asset: Mapped[str] = mapped_column(String(200), default="")
    category: Mapped[enums.Category] = mapped_column(_enum(enums.Category, "category"))
    severity: Mapped[int] = mapped_column(SmallInteger)
    title: Mapped[str] = mapped_column(String(300))
    details: Mapped[str] = mapped_column(Text, default="")
    url_template_params: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    raw_hash: Mapped[str] = mapped_column(String(64))


class Incident(Base):
    __tablename__ = "incident"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    fingerprint_group: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[enums.Category] = mapped_column(_enum(enums.Category, "category"))
    company_code: Mapped[str | None] = mapped_column(ForeignKey("company.code"))
    asset: Mapped[str] = mapped_column(String(200), default="")
    score: Mapped[float] = mapped_column(Float, default=0)
    priority: Mapped[enums.Priority] = mapped_column(_enum(enums.Priority, "priority"))
    priority_reason: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[enums.IncidentStatus] = mapped_column(
        _enum(enums.IncidentStatus, "status"), default=enums.IncidentStatus.open
    )
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _created_at()


class IncidentSignal(Base):
    __tablename__ = "incident_signal"

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incident.id", ondelete="CASCADE"), primary_key=True
    )
    signal_id: Mapped[int] = mapped_column(
        ForeignKey("signal.id", ondelete="CASCADE"), primary_key=True
    )


# --- Plans et tâches ----------------------------------------------------------


class LLMCall(Base):
    __tablename__ = "llm_call"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    at: Mapped[datetime] = _created_at()
    model: Mapped[str] = mapped_column(String(100))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cached_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(10, 4), default=Decimal(0))
    prompt_hash: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[enums.LLMOutcome] = mapped_column(_enum(enums.LLMOutcome, "outcome"))
    error: Mapped[str | None] = mapped_column(Text)


class Plan(Base):
    __tablename__ = "plan"
    __table_args__ = (CheckConstraint("period_end >= period_start", name="period"),)

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    kind: Mapped[enums.PlanKind] = mapped_column(_enum(enums.PlanKind, "kind"))
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    status: Mapped[enums.PlanStatus] = mapped_column(
        _enum(enums.PlanStatus, "status"), default=enums.PlanStatus.draft
    )
    summary_md: Mapped[str] = mapped_column(Text, default="")
    # Données structurées pour le web (synthèses IA, capacité/charge, jalons à risque…).
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    generated_by: Mapped[enums.GeneratedBy] = mapped_column(
        _enum(enums.GeneratedBy, "generated_by")
    )
    llm_call_id: Mapped[int | None] = mapped_column(ForeignKey("llm_call.id"))
    created_at: Mapped[datetime] = _created_at()
    validated_by: Mapped[int | None] = mapped_column(ForeignKey("person.id"))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Task(Base):
    __tablename__ = "task"
    __table_args__ = (
        CheckConstraint("estimate_h >= 0 AND estimate_h <= 16", name="estimate"),
        CheckConstraint("carry_count >= 0", name="carry_count"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("plan.id", ondelete="CASCADE"))
    milestone_id: Mapped[int | None] = mapped_column(ForeignKey("milestone.id"))
    title: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    actions: Mapped[list[str]] = mapped_column(_text_array(), default=list)
    category: Mapped[enums.Category] = mapped_column(_enum(enums.Category, "category"))
    priority: Mapped[enums.Priority] = mapped_column(_enum(enums.Priority, "priority"))
    score: Mapped[float | None] = mapped_column(Float)
    estimate_h: Mapped[float] = mapped_column(Float, default=1)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("person.id"))
    due: Mapped[date | None] = mapped_column(Date)
    not_before: Mapped[date | None] = mapped_column(Date)
    status: Mapped[enums.TaskStatus] = mapped_column(
        _enum(enums.TaskStatus, "status"), default=enums.TaskStatus.todo
    )
    status_reason: Mapped[str] = mapped_column(Text, default="")
    carry_count: Mapped[int] = mapped_column(Integer, default=0)
    rationale: Mapped[str] = mapped_column(Text, default="")
    origin: Mapped[enums.TaskOrigin] = mapped_column(_enum(enums.TaskOrigin, "origin"))
    created_at: Mapped[datetime] = _created_at()


class TaskIncident(Base):
    __tablename__ = "task_incident"

    task_id: Mapped[int] = mapped_column(
        ForeignKey("task.id", ondelete="CASCADE"), primary_key=True
    )
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incident.id", ondelete="CASCADE"), primary_key=True
    )


class TaskComment(Base):
    __tablename__ = "task_comment"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("task.id", ondelete="CASCADE"))
    author_id: Mapped[int] = mapped_column(ForeignKey("person.id"))
    at: Mapped[datetime] = _created_at()
    body: Mapped[str] = mapped_column(Text)


class TaskReview(Base):
    """Jugement du coordinateur pendant le rodage (phase 9) : une ligne par tâche."""

    __tablename__ = "task_review"

    task_id: Mapped[int] = mapped_column(
        ForeignKey("task.id", ondelete="CASCADE"), primary_key=True
    )
    relevant: Mapped[bool] = mapped_column(Boolean)
    well_assigned: Mapped[bool] = mapped_column(Boolean)
    note: Mapped[str] = mapped_column(String(300), default="")
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("person.id"))
    at: Mapped[datetime] = _created_at()


class PlanReview(Base):
    """Ce qui manquait au plan selon le coordinateur (rodage)."""

    __tablename__ = "plan_review"

    plan_id: Mapped[int] = mapped_column(
        ForeignKey("plan.id", ondelete="CASCADE"), primary_key=True
    )
    missing: Mapped[str] = mapped_column(String(1000), default="")
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("person.id"))
    at: Mapped[datetime] = _created_at()


# --- Administration -----------------------------------------------------------


class AuditLog(Base):
    """Append-only : triggers de la migration 0002 (UPDATE/TRUNCATE interdits, DELETE > 1 an)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    at: Mapped[datetime] = _created_at()
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    object: Mapped[str] = mapped_column(String(200), default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class Setting(Base):
    __tablename__ = "setting"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB)


class JobRequest(Base):
    """Demande du web exécutée par le worker (le web n'a ni secret ni accès aux sources).

    `payload` est validé par `vigie.db.jobs.validate_payload` ; la base borne sa taille.
    """

    __tablename__ = "job_request"
    __table_args__ = (
        CheckConstraint(f"octet_length(payload::text) <= {MAX_PAYLOAD_BYTES}", name="payload_size"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    kind: Mapped[enums.JobKind] = mapped_column(_enum(enums.JobKind, "kind"))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    requested_by: Mapped[str] = mapped_column(String(100))
    requested_at: Mapped[datetime] = _created_at()
    status: Mapped[enums.JobStatus] = mapped_column(
        _enum(enums.JobStatus, "status"), default=enums.JobStatus.pending
    )
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
