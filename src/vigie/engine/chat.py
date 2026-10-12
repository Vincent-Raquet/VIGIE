"""Discussion avec l'IA sur les priorités (service `vigie chat-worker`, SECURITY.md C3 à C5, C8).

- Le web n'a pas la clé : il dépose une question (`chat_message` en attente) ; ce module,
  exécuté par le service `vigie-chat` (compte vigie-worker, clé Anthropic seule), y répond.
- **Aucun outil** : sortie structurée (`output_config.format`) = une réponse en Markdown et des
  propositions déclaratives. Une proposition est enregistrée telle quelle (`chat_proposal`)
  après validation ; seul un admin l'applique, par un clic, dans l'interface.
- Données des sources : instantané nettoyé (`clean_untrusted`), tickets masqués selon
  `[llm] send_ticket_text`, sérialisé en JSON aux chevrons échappés dans `<source_data>`.
- Plafonds : budget mensuel commun avec les plans (avant l'appel, majorant), jetons par
  conversation et par utilisateur et par jour ; chaque appel est journalisé dans `llm_call`.
- Cache de prompt : instructions + skills, puis organisation (politique, barème), puis le
  contexte figé de la conversation, puis l'historique déjà échangé.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from importlib.resources import files
from typing import Any, Literal

import anthropic
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vigie.config import ChatConfig, LLMConfig
from vigie.db import enums, models
from vigie.db.enums import ChatRole, ChatStatus, LLMOutcome, Priority, ProposalKind
from vigie.engine.context import ROLE_SKILLS, TICKET_MASK, _json
from vigie.engine.llm import (
    CACHE_WRITE_FACTOR,
    FALLBACK_BETA,
    LLMClient,
    month_spend,
    price_of,
    record_call,
)
from vigie.engine.rules import OverrideRule
from vigie.engine.settings import load_scoring
from vigie.redact import clean_untrusted

logger = logging.getLogger("vigie.chat")

MAX_PLAN_TASKS = 80
MAX_INCIDENT_SIGNALS = 20
MAX_MENTIONED = 5
MAX_PROPOSALS = 3
DETAIL_MAX = 300
TITLE_MAX = 200
ANSWER_MAX = 8000
_MENTION_RE = re.compile(r"(?:#|\bincident\s*(?:n[°o]\s*)?)(\d{1,12})\b", re.IGNORECASE)
_URL_SCHEME_RE = re.compile(r"(?i)\b(https?|ftp|file)://")
_WWW_RE = re.compile(r"(?i)\bwww\.")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


# --- Sortie structurée ----------------------------------------------------------------------


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConditionOut(_Out):
    field: str
    op: Literal["eq", "ne", "gt", "ge", "lt", "le", "in", "contains_any"]
    value: str | int | float | bool | list[str] | None


class ProposalOut(_Out):
    kind: ProposalKind
    incident_id: int | None = None
    priority: Priority
    rule_id: str | None = None
    reason: str | None = None
    conditions: list[ConditionOut] | None = None
    rationale: str = Field(default="", max_length=600)


class ChatAnswer(_Out):
    answer: str = Field(max_length=ANSWER_MAX)
    proposals: list[ProposalOut] = Field(default_factory=list, max_length=MAX_PROPOSALS)


def _obj(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_STR = {"type": "string"}
_NULL = {"type": "null"}
_SCALAR = {
    "anyOf": [
        _STR,
        {"type": "number"},
        {"type": "boolean"},
        {"type": "array", "items": _STR},
        _NULL,
    ]
}
CHAT_SCHEMA: dict[str, Any] = _obj(
    {
        "answer": _STR,
        "proposals": {
            "type": "array",
            "items": _obj(
                {
                    "kind": {"type": "string", "enum": [k.value for k in ProposalKind]},
                    "incident_id": {"anyOf": [{"type": "integer"}, _NULL]},
                    "priority": {"type": "string", "enum": [p.value for p in Priority]},
                    "rule_id": {"anyOf": [_STR, _NULL]},
                    "reason": {"anyOf": [_STR, _NULL]},
                    "conditions": {
                        "anyOf": [
                            {
                                "type": "array",
                                "items": _obj(
                                    {
                                        "field": _STR,
                                        "op": {
                                            "type": "string",
                                            "enum": [
                                                "eq",
                                                "ne",
                                                "gt",
                                                "ge",
                                                "lt",
                                                "le",
                                                "in",
                                                "contains_any",
                                            ],
                                        },
                                        "value": _SCALAR,
                                    },
                                    ["field", "op", "value"],
                                ),
                            },
                            _NULL,
                        ]
                    },
                    "rationale": _STR,
                },
                ["kind", "incident_id", "priority", "rule_id", "reason", "conditions", "rationale"],
            ),
        },
    },
    ["answer", "proposals"],
)


@dataclass(frozen=True)
class ValidProposal:
    kind: ProposalKind
    payload: dict[str, Any]
    rationale: str


def validate_proposals(
    proposals: Iterable[ProposalOut], known_incidents: set[int]
) -> list[ValidProposal]:
    """Ne garde que les propositions applicables telles quelles : incident présent dans le
    contexte, règle d'override valide (mêmes contrôles que scoring.yaml)."""
    out: list[ValidProposal] = []
    for p in proposals:
        rationale = defang(clean_untrusted(p.rationale, 600))
        if p.kind is ProposalKind.incident_priority:
            if p.incident_id is None or p.incident_id not in known_incidents:
                continue
            out.append(
                ValidProposal(
                    p.kind, {"incident_id": p.incident_id, "priority": p.priority.value}, rationale
                )
            )
        else:
            try:
                rule = OverrideRule.model_validate(
                    {
                        "id": p.rule_id or "",
                        "priority": p.priority.value,
                        "reason": defang(clean_untrusted(p.reason or "", 200)),
                        "all": [c.model_dump() for c in p.conditions or []],
                    }
                )
            except ValidationError:
                continue
            out.append(ValidProposal(p.kind, {"rule": rule.model_dump(mode="json")}, rationale))
    return out[:MAX_PROPOSALS]


def defang(text: str) -> str:
    """Aucun lien ni adresse ne vient du modèle (C4) : URL désarmées, e-mails masqués."""
    text = _URL_SCHEME_RE.sub(r"\1[:]//", text)
    text = _WWW_RE.sub("www[.]", text)
    return _EMAIL_RE.sub("<email>", text)


# --- Contexte ---------------------------------------------------------------------------


def _prompt(name: str) -> str:
    return (files("vigie.engine") / "prompts" / f"{name}.md").read_text(encoding="utf-8")


def _block(text: str, cached: bool) -> dict[str, Any]:
    block: dict[str, Any] = {"type": "text", "text": text}
    if cached:
        block["cache_control"] = {"type": "ephemeral"}
    return block


def system_blocks(session: Session) -> list[dict[str, Any]]:
    """Blocs stables, mis en cache : instructions + skills, puis politique et barème."""
    skills = {
        s.name: s.body_md
        for s in session.scalars(
            select(models.RoleSkill).where(models.RoleSkill.name.in_(ROLE_SKILLS))
        )
    }
    parts = [_prompt("chat")]
    for name in ROLE_SKILLS:
        if name in skills:
            parts.append(f'<role_skill name="{name}">\n{skills[name].strip()}\n</role_skill>')
    scoring = load_scoring(session)
    axes = [
        {"title": a.title, "weight": a.weight, "categories": sorted(a.categories),
         "keywords": sorted(a.keywords)}
        for a in session.scalars(select(models.PolicyAxis).order_by(models.PolicyAxis.title))
    ]  # fmt: skip
    rules = list(
        session.scalars(
            select(models.PolicyRule.text)
            .where(models.PolicyRule.active.is_(True))
            .order_by(models.PolicyRule.text)
        )
    )
    companies = {
        c.code: {"name": c.name, "criticality": c.criticality}
        for c in session.scalars(select(models.Company).order_by(models.Company.code))
    }
    organisation = {
        "policy_axes": axes,
        "policy_rules": rules,
        "companies": companies,
        "scoring": scoring.model_dump(mode="json"),
    }
    return [
        _block("\n\n".join(parts), cached=True),
        _block("# Politique IT et barème (configuration)\n\n" + _json(organisation), cached=True),
    ]


def _ticket_id(signal: models.Signal) -> str | None:
    attrs = signal.attributes or {}
    return str(attrs.get("ticket_id")) if attrs.get("kind") == "ticket" else None


def incident_facts(
    session: Session, incident_ids: Iterable[int], now: datetime, *, send_ticket_text: bool
) -> dict[int, dict[str, Any]]:
    """Faits des incidents : priorité, raison exacte (règles appliquées), signaux nettoyés."""
    ids = sorted(set(incident_ids))
    if not ids:
        return {}
    incidents = {i.id: i for i in session.scalars(select(models.Incident).where(
        models.Incident.id.in_(ids)))}  # fmt: skip
    rows = session.execute(
        select(models.IncidentSignal.incident_id, models.Signal)
        .join(models.Signal, models.Signal.id == models.IncidentSignal.signal_id)
        .where(models.IncidentSignal.incident_id.in_(ids))
        .order_by(models.Signal.severity.desc(), models.Signal.id)
    ).all()
    signals: dict[int, list[models.Signal]] = {}
    for incident_id, s in rows:
        signals.setdefault(incident_id, []).append(s)
    out: dict[int, dict[str, Any]] = {}
    for incident_id, inc in incidents.items():
        items = []
        for s in signals.get(incident_id, [])[:MAX_INCIDENT_SIGNALS]:
            ticket = _ticket_id(s)
            masked = ticket is not None and not send_ticket_text
            items.append(
                {
                    "source": s.source,
                    "severity": s.severity,
                    "title": f"Ticket n° {ticket}"
                    if masked
                    else clean_untrusted(s.title, TITLE_MAX),
                    "detail": TICKET_MASK if masked else clean_untrusted(s.details, DETAIL_MAX),
                    "age_days": round((now - s.first_seen).total_seconds() / 86400, 1),
                    "occurrences": s.occurrences,
                    "resolved": s.resolved_at is not None,
                }
            )
        out[incident_id] = {
            "incident_id": incident_id,
            "asset": clean_untrusted(inc.asset, TITLE_MAX),
            "category": inc.category.value,
            "company": inc.company_code,
            "status": inc.status.value,
            "priority": inc.priority.value,
            "score": round(inc.score, 1),
            "priority_reason": clean_untrusted(inc.priority_reason, 1000),
            "manual_priority": inc.manual_priority.value if inc.manual_priority else None,
            "signals": items,
        }
    return out


def _plan_context(
    session: Session, plan: models.Plan, now: datetime, *, send_ticket_text: bool
) -> dict[str, Any]:
    tasks = list(
        session.scalars(
            select(models.Task)
            .where(models.Task.plan_id == plan.id)
            .order_by(models.Task.priority, models.Task.score.desc().nulls_last(), models.Task.id)
            .limit(MAX_PLAN_TASKS)
        )
    )
    links = session.execute(
        select(models.TaskIncident.task_id, models.TaskIncident.incident_id).where(
            models.TaskIncident.task_id.in_([t.id for t in tasks])
        )
    ).all()
    by_task: dict[int, list[int]] = {}
    for task_id, incident_id in links:
        by_task.setdefault(task_id, []).append(incident_id)
    people = {p.id: p.name for p in session.scalars(select(models.Person))}
    facts = incident_facts(
        session, [i for ids in by_task.values() for i in ids], now,
        send_ticket_text=send_ticket_text,
    )  # fmt: skip
    return {
        "plan": {
            "plan_id": plan.id,
            "kind": plan.kind.value,
            "period_start": plan.period_start.isoformat(),
            "period_end": plan.period_end.isoformat(),
            "status": plan.status.value,
        },
        "tasks": [
            {
                "task_id": t.id,
                "title": clean_untrusted(t.title, TITLE_MAX),
                "priority": t.priority.value,
                "category": t.category.value,
                "status": t.status.value,
                "assignee": people.get(t.assignee_id) if t.assignee_id else None,
                "estimate_h": t.estimate_h,
                "due": t.due.isoformat() if t.due else None,
                "incident_ids": sorted(by_task.get(t.id, [])),
                "rationale": clean_untrusted(t.rationale, DETAIL_MAX),
            }
            for t in tasks
        ],
        "incidents": [facts[i] for i in sorted(facts)],
    }


def build_context(
    session: Session, conversation: models.ChatConversation, now: datetime, llm: LLMConfig
) -> dict[str, Any]:
    """Instantané figé à la première question (et refait après « Réinitialiser »)."""
    if conversation.anchor is enums.ChatAnchor.plan:
        plan = session.get(models.Plan, conversation.anchor_id)
        if plan is None:
            return {"error": "plan introuvable"}
        return _plan_context(session, plan, now, send_ticket_text=llm.send_ticket_text)
    facts = incident_facts(
        session, [conversation.anchor_id], now, send_ticket_text=llm.send_ticket_text
    )
    tasks = session.scalars(
        select(models.Task)
        .join(models.TaskIncident, models.TaskIncident.task_id == models.Task.id)
        .where(models.TaskIncident.incident_id == conversation.anchor_id)
        .order_by(models.Task.id.desc())
        .limit(10)
    )
    return {
        "incidents": list(facts.values()),
        "tasks": [
            {
                "task_id": t.id,
                "title": clean_untrusted(t.title, TITLE_MAX),
                "priority": t.priority.value,
                "status": t.status.value,
            }
            for t in tasks
        ],
    }


def known_incident_ids(context: dict[str, Any]) -> set[int]:
    return {int(i["incident_id"]) for i in context.get("incidents", []) if "incident_id" in i}


def mentioned_ids(text: str) -> list[int]:
    seen: list[int] = []
    for m in _MENTION_RE.finditer(text):
        value = int(m.group(1))
        if value not in seen:
            seen.append(value)
    return seen[:MAX_MENTIONED]


# --- Plafonds ---------------------------------------------------------------------------


def conversation_tokens(session: Session, conversation_id: int) -> int:
    return int(
        session.scalar(
            select(func.coalesce(func.sum(models.ChatMessage.tokens), 0)).where(
                models.ChatMessage.conversation_id == conversation_id
            )
        )
        or 0
    )


def user_tokens_today(session: Session, owner: str, now: datetime) -> int:
    start = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(
        session.scalar(
            select(func.coalesce(func.sum(models.ChatMessage.tokens), 0))
            .join(
                models.ChatConversation,
                models.ChatConversation.id == models.ChatMessage.conversation_id,
            )
            .where(models.ChatConversation.owner == owner, models.ChatMessage.created_at >= start)
        )
        or 0
    )


def quota_refusal(
    session: Session, conversation: models.ChatConversation, chat: ChatConfig, now: datetime
) -> str | None:
    if user_tokens_today(session, conversation.owner, now) >= chat.max_user_daily_tokens:
        return (
            f"Limite quotidienne de discussion atteinte ({chat.max_user_daily_tokens} jetons) : "
            "réessayez demain."
        )
    if conversation_tokens(session, conversation.id) >= chat.max_conversation_tokens:
        return (
            "Limite de cette conversation atteinte "
            f"({chat.max_conversation_tokens} jetons) : utilisez « Réinitialiser le contexte »."
        )
    return None


# --- Appel ------------------------------------------------------------------------------


@dataclass(frozen=True)
class ChatRequest:
    system: list[dict[str, Any]]
    messages: list[dict[str, Any]]
    known_incidents: set[int]
    prompt_hash: str


def build_request(
    session: Session,
    conversation: models.ChatConversation,
    question: models.ChatMessage,
    chat: ChatConfig,
    llm: LLMConfig,
    now: datetime,
) -> ChatRequest:
    if conversation.context_json is None:
        conversation.context_json = _json(build_context(session, conversation, now, llm))
    context = json.loads(conversation.context_json)
    known = known_incident_ids(context)
    history = list(
        session.scalars(
            select(models.ChatMessage)
            .where(
                models.ChatMessage.conversation_id == conversation.id,
                models.ChatMessage.id < question.id,
                models.ChatMessage.status == ChatStatus.done,
            )
            .order_by(models.ChatMessage.id.desc())
            .limit(chat.history_messages)
        )
    )[::-1]
    # Paires question → réponse complètes seulement (alternance user/assistant).
    while history and history[0].role is not ChatRole.user:
        history.pop(0)
    turns: list[dict[str, Any]] = []
    for m in history:
        role = "user" if m.role is ChatRole.user else "assistant"
        if turns and turns[-1]["role"] == role:
            continue
        turns.append({"role": role, "content": [{"type": "text", "text": m.content}]})
    if turns and turns[-1]["role"] == "user":
        turns.pop()
    # Incidents cités dans la question (#123) : ajoutés pour la comparaison.
    extra_ids = [i for i in mentioned_ids(question.content) if i not in known]
    extra = incident_facts(session, extra_ids, now, send_ticket_text=llm.send_ticket_text)
    known |= set(extra)
    question_blocks: list[dict[str, Any]] = []
    if extra:
        question_blocks.append(
            {
                "type": "text",
                "text": "Incidents cités dans la question :\n<source_data>\n"
                + _json(list(extra.values()))
                + "\n</source_data>",
            }
        )
    question_blocks.append(
        {"type": "text", "text": "Question de l'utilisateur :\n" + question.content}
    )
    context_block = {
        "type": "text",
        "text": "Contexte de la discussion (données figées à son ouverture) :\n<source_data>\n"
        + conversation.context_json
        + "\n</source_data>",
        "cache_control": {"type": "ephemeral"},
    }
    if turns:
        turns[0]["content"].insert(0, context_block)
        turns[-1]["content"][-1]["cache_control"] = {"type": "ephemeral"}
        messages = [*turns, {"role": "user", "content": question_blocks}]
    else:
        messages = [{"role": "user", "content": [context_block, *question_blocks]}]
    system = system_blocks(session)
    digest = hashlib.sha256(
        json.dumps({"system": system, "messages": messages}, sort_keys=True).encode()
    ).hexdigest()
    return ChatRequest(system, messages, known, digest)


def estimate_max_cost(request: ChatRequest, chat: ChatConfig, model: str) -> Decimal:
    p = price_of(model)
    chars = sum(len(b["text"]) for b in request.system) + len(
        json.dumps(request.messages, ensure_ascii=False)
    )
    input_tokens = Decimal(chars) / 4 * Decimal("1.5")
    return (
        input_tokens * p.input * CACHE_WRITE_FACTOR + Decimal(chat.max_output_tokens) * p.output
    ) / Decimal(1_000_000)


@dataclass(frozen=True)
class Reply:
    ok: bool
    text: str
    proposals: list[ValidProposal]
    tokens: int
    call_id: int | None


def _usage_tokens(usage: Any) -> int:
    return sum(
        int(getattr(usage, k, 0) or 0)
        for k in (
            "input_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
            "output_tokens",
        )
    )


def ask(
    session: Session,
    client: LLMClient,
    request: ChatRequest,
    chat: ChatConfig,
    llm: LLMConfig,
    now: datetime,
) -> Reply:
    spent = month_spend(session, now)
    budget = Decimal(str(llm.monthly_budget_usd))
    if spent + estimate_max_cost(request, chat, llm.model) > budget:
        detail = f"budget mensuel ({spent:.2f} $ dépensés sur {budget:.2f} $)"
        call = record_call(
            session, request.prompt_hash, LLMOutcome.budget_exceeded, model=llm.model,
            error=detail, now=now,
        )  # fmt: skip
        return Reply(False, f"Budget IA du mois atteint : {detail}.", [], 0, call.id)
    payload: dict[str, Any] = {
        "model": llm.model,
        "max_tokens": chat.max_output_tokens,
        "system": request.system,
        "messages": request.messages,
        "thinking": {"type": "adaptive"},
        "output_config": {
            "effort": chat.effort,
            "format": {"type": "json_schema", "schema": CHAT_SCHEMA},
        },
    }
    if llm.fallback:
        payload["betas"] = [FALLBACK_BETA]
        payload["fallbacks"] = "default"
    try:
        response = client.beta.messages.create(**payload)
    except anthropic.APIError as exc:
        name = type(exc).__name__
        status = getattr(exc, "status_code", None)
        detail = f"{name} (HTTP {status})" if status else name
        call = record_call(
            session, request.prompt_hash, LLMOutcome.error, model=llm.model, error=detail, now=now
        )
        return Reply(False, f"L'IA n'a pas pu répondre ({detail}).", [], 0, call.id)
    model = str(getattr(response, "model", None) or llm.model)
    usage = getattr(response, "usage", None)
    tokens = _usage_tokens(usage)
    stop = getattr(response, "stop_reason", None)
    try:
        if stop != "end_turn":
            raise ValueError(f"arrêt « {stop} »")
        texts = [b.text for b in response.content if getattr(b, "type", None) == "text"]
        answer = ChatAnswer.model_validate(json.loads("".join(texts)))
    except (ValueError, ValidationError) as exc:
        detail = (
            str(exc)
            if isinstance(exc, ValueError) and "arrêt" in str(exc)
            else (f"sortie invalide ({type(exc).__name__})")
        )
        call = record_call(
            session, request.prompt_hash, LLMOutcome.invalid, model=model, usage=usage,
            error=detail, now=now,
        )  # fmt: skip
        return Reply(False, f"Réponse de l'IA inutilisable ({detail}).", [], tokens, call.id)
    call = record_call(
        session, request.prompt_hash, LLMOutcome.ok, model=model, usage=usage, now=now
    )
    text = defang(answer.answer.strip())[:ANSWER_MAX] or "(réponse vide)"
    proposals = validate_proposals(answer.proposals, request.known_incidents)
    return Reply(True, text, proposals, tokens, call.id)


# --- File d'attente ---------------------------------------------------------------------

ClientFactory = Callable[[], LLMClient]


def process_pending(
    session: Session,
    client_factory: ClientFactory,
    chat: ChatConfig,
    llm: LLMConfig,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    *,
    limit: int = 5,
) -> int:
    """Répond aux questions en attente (les plus anciennes d'abord) ; renvoie leur nombre."""
    done = 0
    for _ in range(limit):
        question = session.scalars(
            select(models.ChatMessage)
            .where(
                models.ChatMessage.role == ChatRole.user,
                models.ChatMessage.status == ChatStatus.pending,
            )
            .order_by(models.ChatMessage.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        ).first()
        if question is None:
            break
        question.status = ChatStatus.running
        session.commit()
        conversation = session.get(models.ChatConversation, question.conversation_id)
        at = now()
        reply = _answer(session, client_factory, conversation, question, chat, llm, at)
        answer = models.ChatMessage(
            conversation_id=question.conversation_id,
            role=ChatRole.assistant,
            content=reply.text[:ANSWER_MAX],
            status=ChatStatus.done if reply.ok else ChatStatus.failed,
            error=None if reply.ok else reply.text[:300],
            llm_call_id=reply.call_id,
            tokens=reply.tokens,
            done_at=at,
        )
        session.add(answer)
        session.flush()
        for p in reply.proposals:
            session.add(
                models.ChatProposal(
                    message_id=answer.id, kind=p.kind, payload=p.payload, rationale=p.rationale
                )
            )
        # Une question sans réponse utilisable n'entre pas dans l'historique renvoyé.
        question.status = ChatStatus.done if reply.ok else ChatStatus.failed
        question.done_at = at
        session.commit()
        done += 1
    return done


def _answer(
    session: Session,
    client_factory: ClientFactory,
    conversation: models.ChatConversation | None,
    question: models.ChatMessage,
    chat: ChatConfig,
    llm: LLMConfig,
    now: datetime,
) -> Reply:
    if conversation is None or conversation.status is not enums.ConversationStatus.active:
        return Reply(False, "Conversation archivée : posez la question dans la nouvelle.", [], 0,
                     None)  # fmt: skip
    if not chat.enabled or not llm.enabled:
        return Reply(False, "La discussion avec l'IA est désactivée dans la configuration.", [],
                     0, None)  # fmt: skip
    refusal = quota_refusal(session, conversation, chat, now)
    if refusal is not None:
        return Reply(False, refusal, [], 0, None)
    request = build_request(session, conversation, question, chat, llm, now)
    try:
        client = client_factory()
    except Exception as exc:  # clé absente : type seulement
        return Reply(False, f"Clé API Anthropic indisponible ({type(exc).__name__}).", [], 0, None)
    return ask(session, client, request, chat, llm, now)


def stale_running(session: Session, now: datetime, after: timedelta = timedelta(minutes=10)) -> int:
    """Questions restées « en cours » (service arrêté pendant l'appel) : remises en attente."""
    rows = session.scalars(
        select(models.ChatMessage).where(
            models.ChatMessage.status == ChatStatus.running,
            models.ChatMessage.created_at < now - after,
        )
    ).all()
    for row in rows:
        row.status = ChatStatus.pending
    session.commit()
    return len(rows)
