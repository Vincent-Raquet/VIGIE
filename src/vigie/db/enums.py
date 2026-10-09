"""Énumérations du domaine, stockées en VARCHAR + CHECK (pas de type PostgreSQL natif)."""

from enum import StrEnum


class AppRole(StrEnum):
    admin = "admin"
    manager = "manager"
    tech = "tech"
    viewer = "viewer"


class SkillPreference(StrEnum):
    likes = "likes"
    neutral = "neutral"
    avoid = "avoid"


class AbsenceKind(StrEnum):
    leave = "leave"
    sick = "sick"
    training = "training"
    other = "other"
    extra_day = "extra_day"  # jour de présence supplémentaire


class Category(StrEnum):
    network = "network"
    firewall = "firewall"
    security = "security"
    vulnerability = "vulnerability"
    backup = "backup"
    server = "server"
    endpoint = "endpoint"
    user_support = "user_support"
    m365 = "m365"
    monitoring = "monitoring"
    project = "project"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class MatchType(StrEnum):
    hostgroup_prefix = "hostgroup_prefix"
    hostgroup_suffix = "hostgroup_suffix"
    org_id = "org_id"
    adom = "adom"
    devname_prefix = "devname_prefix"
    job_prefix = "job_prefix"
    agent_group = "agent_group"
    hostname_contains = "hostname_contains"  # type d'actif d'après le nom (caméra, antenne…)


class ProjectStatus(StrEnum):
    proposed = "proposed"
    active = "active"
    paused = "paused"
    done = "done"


class ProjectPriority(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class MilestoneStatus(StrEnum):
    planned = "planned"
    in_progress = "in_progress"
    done = "done"
    cancelled = "cancelled"


class IncidentStatus(StrEnum):
    open = "open"
    resolved = "resolved"


class TaskStatus(StrEnum):
    todo = "todo"
    in_progress = "in_progress"
    blocked = "blocked"
    pending_done = "pending_done"  # « done? » : signaux résolus, confirmation attendue
    done = "done"
    wont_do = "wont_do"


class TaskOrigin(StrEnum):
    engine = "engine"
    llm = "llm"
    human = "human"


class PlanKind(StrEnum):
    daily = "daily"
    weekly = "weekly"


class PlanStatus(StrEnum):
    draft = "draft"
    validated = "validated"
    published = "published"


class GeneratedBy(StrEnum):
    rules = "rules"
    llm = "llm"


class LLMOutcome(StrEnum):
    ok = "ok"
    invalid = "invalid"
    error = "error"
    budget_exceeded = "budget_exceeded"


class JobKind(StrEnum):
    source_test = "source_test"


class JobStatus(StrEnum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"
