"""Discussion avec l'IA sur les priorités (panneau du plan du jour et de la fiche incident).

Le web n'a pas la clé Anthropic (SECURITY.md C8) : il dépose la question en base et le service
`vigie-chat` y répond ; le panneau se rafraîchit tant qu'une réponse est attendue.

Droits : admin, manager et tech posent des questions dans leurs propres conversations ;
tout le monde (viewer compris) peut relire les discussions, en lecture seule ; seul un admin
applique ou rejette une proposition de l'IA, et chaque décision est tracée dans `audit_log`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.db import models
from vigie.db.enums import (
    AppRole,
    ChatAnchor,
    ChatRole,
    ChatStatus,
    ConversationStatus,
    IncidentStatus,
    Priority,
    ProposalKind,
    ProposalStatus,
)
from vigie.engine.settings import ScoringConfig
from vigie.web.auth import User, audit, require_role
from vigie.web.deps import ADMIN, ALL, DB, STAFF, render
from vigie.web.markdown import render_markdown_safe

router = APIRouter()
Anyone = Annotated[User, Depends(require_role(*ALL))]
Staff = Annotated[User, Depends(require_role(*STAFF))]
Admin = Annotated[User, Depends(require_role(*ADMIN))]

MAX_LIST = 100


def _anchor_exists(session: Session, anchor: ChatAnchor, anchor_id: int) -> bool:
    model = models.Plan if anchor is ChatAnchor.plan else models.Incident
    return session.get(model, anchor_id) is not None


def _active(
    session: Session, owner: str, anchor: ChatAnchor, anchor_id: int
) -> models.ChatConversation | None:
    return session.scalars(
        select(models.ChatConversation)
        .where(
            models.ChatConversation.owner == owner,
            models.ChatConversation.anchor == anchor,
            models.ChatConversation.anchor_id == anchor_id,
            models.ChatConversation.status == ConversationStatus.active,
        )
        .order_by(models.ChatConversation.id.desc())
        .limit(1)
    ).first()


def _view(session: Session, conversation: models.ChatConversation) -> dict[str, Any]:
    messages = list(
        session.scalars(
            select(models.ChatMessage)
            .where(models.ChatMessage.conversation_id == conversation.id)
            .order_by(models.ChatMessage.id)
        )
    )
    proposals: dict[int, list[models.ChatProposal]] = {}
    for p in session.scalars(
        select(models.ChatProposal)
        .where(models.ChatProposal.message_id.in_([m.id for m in messages]))
        .order_by(models.ChatProposal.id)
    ):
        proposals.setdefault(p.message_id, []).append(p)
    return {
        "conversation": conversation,
        "messages": [
            {
                "m": m,
                # Réponse de l'IA : Markdown filtré (nh3), sans lien ni HTML (C4).
                "html": render_markdown_safe(m.content)
                if m.role is ChatRole.assistant and m.status is ChatStatus.done
                else None,
                "proposals": proposals.get(m.id, []),
            }
            for m in messages
        ],
        "waiting": any(
            m.role is ChatRole.user and m.status in (ChatStatus.pending, ChatStatus.running)
            for m in messages
        ),
        "tokens": sum(m.tokens for m in messages),
    }


def _panel(
    request: Request,
    user: User,
    session: Session,
    anchor: ChatAnchor,
    anchor_id: int,
    *,
    error: str | None = None,
) -> Response:
    conversation = _active(session, user.email, anchor, anchor_id)
    others = list(
        session.scalars(
            select(models.ChatConversation)
            .where(
                models.ChatConversation.anchor == anchor,
                models.ChatConversation.anchor_id == anchor_id,
                models.ChatConversation.id != (conversation.id if conversation else 0),
            )
            .order_by(models.ChatConversation.id.desc())
            .limit(20)
        )
    )
    cfg = request.app.state.cfg
    return render(
        request,
        "_chat_panel.html",
        {
            "anchor": anchor.value,
            "anchor_id": anchor_id,
            "can_ask": user.role in STAFF and cfg.chat.enabled,
            "chat_enabled": cfg.chat.enabled and cfg.llm.enabled,
            "max_chars": cfg.chat.max_question_chars,
            "max_tokens": cfg.chat.max_conversation_tokens,
            "others": others,
            "error": error,
            **(_view(session, conversation) if conversation else {"conversation": None}),
        },
    )


def _anchor(value: str) -> ChatAnchor:
    try:
        return ChatAnchor(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Ancre de discussion inconnue.") from exc


@router.get("/chat/panneau")
def panel(
    request: Request,
    user: Anyone,
    session: DB,
    anchor: Annotated[str, Query(max_length=16)],
    anchor_id: Annotated[int, Query(ge=1)],
) -> Response:
    kind = _anchor(anchor)
    if not _anchor_exists(session, kind, anchor_id):
        raise HTTPException(status_code=404, detail="Plan ou incident introuvable.")
    return _panel(request, user, session, kind, anchor_id)


@router.post("/chat/questions")
def ask(
    request: Request,
    user: Staff,
    session: DB,
    anchor: Annotated[str, Form(max_length=16)],
    anchor_id: Annotated[int, Form(ge=1)],
    content: Annotated[str, Form(max_length=5000)],
) -> Response:
    kind = _anchor(anchor)
    cfg = request.app.state.cfg
    if not _anchor_exists(session, kind, anchor_id):
        raise HTTPException(status_code=404, detail="Plan ou incident introuvable.")
    text = content.strip()
    if not cfg.chat.enabled:
        return _panel(request, user, session, kind, anchor_id, error="Discussion désactivée.")
    if not text or len(text) > cfg.chat.max_question_chars:
        return _panel(
            request, user, session, kind, anchor_id,
            error=f"Question vide ou trop longue ({cfg.chat.max_question_chars} car. au plus).",
        )  # fmt: skip
    conversation = _active(session, user.email, kind, anchor_id)
    if conversation is None:
        conversation = models.ChatConversation(owner=user.email, anchor=kind, anchor_id=anchor_id)
        session.add(conversation)
        session.flush()
    elif _view(session, conversation)["waiting"]:
        return _panel(
            request, user, session, kind, anchor_id,
            error="Une réponse est déjà attendue : patientez avant la question suivante.",
        )  # fmt: skip
    session.add(
        models.ChatMessage(
            conversation_id=conversation.id,
            role=ChatRole.user,
            content=text,
            status=ChatStatus.pending,
        )
    )
    session.commit()
    return _panel(request, user, session, kind, anchor_id)


@router.post("/chat/conversations/{conversation_id}/reinitialiser")
def reset(request: Request, user: Staff, session: DB, conversation_id: int) -> Response:
    """Archive la conversation (lecture seule, jamais supprimée) ; la question suivante en
    ouvre une nouvelle, avec un contexte refait et sans l'historique précédent."""
    conversation = session.get(models.ChatConversation, conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation introuvable.")
    if conversation.owner != user.email and user.role is not AppRole.admin:
        raise HTTPException(status_code=403, detail="Seul l'auteur ou un admin peut réinitialiser.")
    if conversation.status is ConversationStatus.active:
        conversation.status = ConversationStatus.archived
        conversation.archived_at = datetime.now(UTC)
        conversation.archived_by = user.email
        audit(
            session, user.email, "chat_reset", f"chat_conversation:{conversation.id}",
            anchor=conversation.anchor.value, anchor_id=conversation.anchor_id,
        )  # fmt: skip
        session.commit()
    return _panel(request, user, session, conversation.anchor, conversation.anchor_id)


@router.get("/chat")
def conversations(request: Request, user: Anyone, session: DB) -> Response:
    rows = list(
        session.scalars(
            select(models.ChatConversation)
            .order_by(models.ChatConversation.id.desc())
            .limit(MAX_LIST)
        )
    )
    return render(request, "chat.html", {"conversations": rows})


@router.get("/chat/conversations/{conversation_id}")
def conversation(request: Request, user: Anyone, session: DB, conversation_id: int) -> Response:
    row = session.get(models.ChatConversation, conversation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Conversation introuvable.")
    return render(
        request,
        "chat_conversation.html",
        {**_view(session, row), "flash": request.session.pop("flash", None)},
    )


# --- Propositions de l'IA : appliquées seulement par un admin, par un clic -----------------


def _proposal_or_404(session: Session, proposal_id: int) -> models.ChatProposal:
    proposal = session.get(models.ChatProposal, proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail="Proposition introuvable.")
    return proposal


def _back(session: Session, proposal: models.ChatProposal, next_: str | None) -> Response:
    message = session.get(models.ChatMessage, proposal.message_id)
    target = f"/chat/conversations/{message.conversation_id}" if message else "/chat"
    if next_ and next_.startswith("/") and not next_.startswith("//"):
        target = next_
    return RedirectResponse(target, status_code=303)


def apply_proposal(session: Session, user: User, proposal: models.ChatProposal) -> str:
    """Applique une proposition encore ouverte ; renvoie le message affiché. Lève ValueError
    si elle n'est plus applicable (incident résolu, règle devenue invalide)."""
    if proposal.status is not ProposalStatus.proposed:
        raise ValueError("proposition déjà traitée")
    now = datetime.now(UTC)
    if proposal.kind is ProposalKind.incident_priority:
        incident = session.get(models.Incident, int(proposal.payload["incident_id"]))
        if incident is None or incident.status is not IncidentStatus.open:
            raise ValueError("incident introuvable ou résolu")
        priority = Priority(proposal.payload["priority"])
        before = incident.manual_priority.value if incident.manual_priority else None
        incident.manual_priority = priority
        incident.manual_reason = f"proposition n° {proposal.id} de la discussion IA"
        incident.manual_by = user.email
        incident.manual_at = now
        details: dict[str, Any] = {
            "incident_id": incident.id,
            "avant": {"calculée": incident.priority.value, "manuelle": before},
            "après": priority.value,
        }
        message = (
            f"Priorité de l'incident {incident.id} fixée à {priority.value} "
            "(prise en compte au prochain calcul du moteur)."
        )
    else:
        rule = proposal.payload["rule"]
        row = session.get(models.Setting, "scoring")
        raw: dict[str, Any] = dict(row.value) if row is not None else {}
        current = ScoringConfig.model_validate(raw)
        overrides = [r.model_dump(mode="json") for r in current.overrides]
        before_rule = next((r for r in overrides if r["id"] == rule["id"]), None)
        overrides = [r for r in overrides if r["id"] != rule["id"]] + [rule]
        raw["overrides"] = overrides
        try:
            ScoringConfig.model_validate(raw)
        except ValidationError as exc:
            raise ValueError("règle invalide pour le barème actuel") from exc
        if row is None:
            session.add(models.Setting(key="scoring", value=raw))
        else:
            row.value = json.loads(json.dumps(raw))
        details = {"règle": rule["id"], "avant": before_rule, "après": rule}
        message = (
            f"Règle d'override « {rule['id']} » enregistrée : elle s'applique au prochain plan."
        )
    proposal.status = ProposalStatus.applied
    proposal.decided_by = user.email
    proposal.decided_at = now
    audit(session, user.email, "chat_proposal_applied", f"chat_proposal:{proposal.id}",
          kind=proposal.kind.value, **details)  # fmt: skip
    return message


@router.post("/chat/propositions/{proposal_id}/appliquer")
def apply(
    request: Request,
    user: Admin,
    session: DB,
    proposal_id: int,
    next_: Annotated[str | None, Form(alias="next", max_length=200)] = None,
) -> Response:
    proposal = _proposal_or_404(session, proposal_id)
    try:
        request.session["flash"] = apply_proposal(session, user, proposal)
        session.commit()
    except ValueError as exc:
        session.rollback()
        request.session["flash"] = f"Proposition non appliquée : {exc}."
    return _back(session, proposal, next_)


@router.post("/chat/propositions/{proposal_id}/rejeter")
def reject(
    request: Request,
    user: Admin,
    session: DB,
    proposal_id: int,
    next_: Annotated[str | None, Form(alias="next", max_length=200)] = None,
) -> Response:
    proposal = _proposal_or_404(session, proposal_id)
    if proposal.status is ProposalStatus.proposed:
        proposal.status = ProposalStatus.rejected
        proposal.decided_by = user.email
        proposal.decided_at = datetime.now(UTC)
        audit(session, user.email, "chat_proposal_rejected", f"chat_proposal:{proposal.id}",
              kind=proposal.kind.value)  # fmt: skip
        session.commit()
        request.session["flash"] = "Proposition rejetée."
    return _back(session, proposal, next_)


@router.post("/signaux/incidents/{incident_id}/priorite-manuelle/retirer")
def clear_manual(request: Request, user: Admin, session: DB, incident_id: int) -> Response:
    incident = session.get(models.Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident introuvable.")
    if incident.manual_priority is not None:
        audit(session, user.email, "incident_manual_priority_cleared", f"incident:{incident.id}",
              avant=incident.manual_priority.value)  # fmt: skip
        incident.manual_priority = None
        incident.manual_reason = ""
        incident.manual_by = None
        incident.manual_at = None
        session.commit()
        request.session["flash"] = "Priorité manuelle retirée : le calcul du moteur reprend."
    return RedirectResponse(f"/signaux/incidents/{incident.id}", status_code=303)
