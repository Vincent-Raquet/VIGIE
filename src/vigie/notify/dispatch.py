"""Diffusion d'un plan : sélection, destinataires autorisés, envoi par canal, publication.

- Destinataires : uniquement les personnes **actives** de la table `person` (allowlist,
  SECURITY.md C4) ; une adresse hors liste n'est jamais servie.
- Rodage (`draft_only`) : chaque message part au seul coordinateur, sujet préfixé.
- Un canal en échec n'empêche pas l'autre ; le plan est publié si au moins un canal a
  fonctionné (ou en simulation, jamais).
- Audit : canaux, nombres et issue — jamais d'adresse ni de contenu.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from vigie.config import VigieConfig
from vigie.db import models
from vigie.db.enums import PlanKind, PlanStatus
from vigie.notify.render import Bundle, Message, build, coordinator

logger = logging.getLogger("vigie.notify")
LATEST = {"latest-daily": PlanKind.daily, "latest-weekly": PlanKind.weekly}


class NotifyError(Exception):
    """Plan introuvable, déjà diffusé, ou configuration incomplète."""


class Mailer(Protocol):
    def send(self, to: str, name: str, subject: str, html: str) -> None: ...


class Teams(Protocol):
    def send(self, payload: dict[str, object]) -> None: ...


@dataclass
class Report:
    plan_id: int
    mails: int = 0
    mail_errors: list[str] = field(default_factory=list)
    skipped: int = 0  # destinataires hors allowlist
    teams: str = "désactivé"
    published: bool = False
    written: list[Path] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mail_errors and not self.teams.startswith("erreur")


def select_plan(session: Session, ref: str) -> models.Plan:
    if ref in LATEST:
        plan = session.scalar(
            select(models.Plan)
            .where(models.Plan.kind == LATEST[ref])
            .order_by(models.Plan.created_at.desc(), models.Plan.id.desc())
            .limit(1)
        )
    elif ref.isdigit():
        plan = session.get(models.Plan, int(ref))
    else:
        raise NotifyError("--plan : identifiant numérique, latest-daily ou latest-weekly")
    if plan is None:
        raise NotifyError(f"plan introuvable : {ref}")
    return plan


def allowed_recipients(session: Session) -> dict[str, models.Person]:
    people = session.scalars(select(models.Person).where(models.Person.active.is_(True)))
    return {p.email.strip().lower(): p for p in people}


def _audience(session: Session, bundle: Bundle, draft_only: bool) -> tuple[list[Message], int]:
    allowed = allowed_recipients(session)
    messages = [*bundle.messages, *([bundle.recap] if bundle.recap else [])]
    kept = [m for m in messages if m.to.strip().lower() in allowed]
    skipped = len(messages) - len(kept)
    if draft_only:
        lead = coordinator(session)
        if lead is None:
            raise NotifyError("mode rodage : aucun coordinateur actif pour recevoir les messages")
        kept = [
            m
            if m.person_id == lead.id
            else replace(m, to=lead.email, name=lead.name, subject=f"[pour {m.name}] {m.subject}")
            for m in kept
        ]
    return kept, skipped


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "message"


def write_files(
    out_dir: Path, messages: list[Message], teams: dict[str, object], sender: str
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for n, m in enumerate(messages, start=1):
        stem = out_dir / f"{n:02d}-{m.kind}-{_slug(m.name)}"
        mail = EmailMessage()
        mail["From"] = sender or "vigie@localhost"
        mail["To"] = m.to
        mail["Subject"] = m.subject
        mail.set_content(m.text)
        mail.add_alternative(m.html, subtype="html")
        for suffix, content in ((".eml", mail.as_string()), (".html", m.html), (".txt", m.text)):
            path = stem.with_suffix(suffix)
            path.write_text(content, encoding="utf-8")
            written.append(path)
    path = out_dir / "teams.json"
    path.write_text(json.dumps(teams, ensure_ascii=False, indent=2), encoding="utf-8")
    written.append(path)
    return written


def dispatch(
    session: Session,
    plan: models.Plan,
    cfg: VigieConfig,
    *,
    mailer: Mailer | None = None,
    teams: Teams | None = None,
    out_dir: Path | None = None,
    force: bool = False,
    now: datetime | None = None,
) -> Report:
    data = dict(plan.data or {})
    if data.get("notified_at") and not force and out_dir is None:
        raise NotifyError(
            f"plan {plan.id} déjà diffusé le {data['notified_at']} (--force pour renvoyer)"
        )
    bundle = build(session, plan, cfg.general.base_url)
    messages, skipped = _audience(session, bundle, cfg.notify.draft_only)
    report = Report(plan_id=plan.id, skipped=skipped)
    if skipped:
        logger.warning("destinataires hors allowlist ignorés", extra={"count": skipped})

    if out_dir is not None:
        report.written = write_files(out_dir, messages, bundle.teams, cfg.notify.mail_sender)
        report.mails = len(messages)
        report.teams = "écrit (simulation)"
        return report

    if cfg.notify.mail_enabled:
        if mailer is None:
            raise NotifyError("e-mail activé mais Graph non configuré")
        for m in messages:
            try:
                mailer.send(m.to, m.name, m.subject, m.html)
                report.mails += 1
            except Exception as exc:  # un destinataire en échec n'arrête pas les autres
                report.mail_errors.append(f"{m.name} : {type(exc).__name__} ({exc})"[:300])
    if cfg.notify.teams_enabled:
        if teams is None:
            raise NotifyError("Teams activé mais webhook non configuré")
        try:
            teams.send(bundle.teams)
            report.teams = "envoyé"
        except Exception as exc:
            report.teams = f"erreur : {type(exc).__name__} ({exc})"[:300]

    delivered = report.mails > 0 or report.teams == "envoyé"
    when = now or datetime.now(UTC)
    if delivered:
        if plan.status is not PlanStatus.published:
            plan.status = PlanStatus.published
            plan.published_at = when
            report.published = True
        plan.data = {**data, "notified_at": when.isoformat()}
    session.add(
        models.AuditLog(
            actor="vigie-worker",
            action="notify_sent",
            object=f"plan:{plan.id}",
            details={
                "mails": report.mails,
                "mail_errors": len(report.mail_errors),
                "skipped": skipped,
                "teams": report.teams.split(" ")[0],
                "draft_only": cfg.notify.draft_only,
                "validated": plan.validated_at is not None,
            },
        )
    )
    session.flush()
    return report
