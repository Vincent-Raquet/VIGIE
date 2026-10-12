"""Discussion avec l'IA dans l'interface : droits par rôle, propositions, réinitialisation."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.webfixtures import login
from vigie.db import models
from vigie.db.enums import (
    AppRole,
    ChatAnchor,
    ChatRole,
    ChatStatus,
    ConversationStatus,
    Priority,
    ProposalKind,
    ProposalStatus,
)

pytestmark = pytest.mark.db


def incident(session: Session) -> models.Incident:
    row = session.scalars(select(models.Incident).order_by(models.Incident.id)).first()
    assert row is not None
    return row


def panel(client: TestClient, inc: models.Incident) -> str:
    r = client.get(f"/chat/panneau?anchor=incident&anchor_id={inc.id}")
    assert r.status_code == 200, r.text
    return r.text


def post_question(client: TestClient, token: str, inc_id: int, text: str) -> int:
    r = client.post(
        "/chat/questions",
        data={"anchor": "incident", "anchor_id": str(inc_id), "content": text},
        headers={"X-CSRF-Token": token},
    )
    return r.status_code


def messages(session: Session) -> list[models.ChatMessage]:
    session.expire_all()
    return list(session.scalars(select(models.ChatMessage).order_by(models.ChatMessage.id)))


def proposal_for(
    session: Session,
    inc: models.Incident,
    owner: str = "x@example.test",
    kind: ProposalKind = ProposalKind.incident_priority,
) -> models.ChatProposal:
    conv = models.ChatConversation(owner=owner, anchor=ChatAnchor.incident, anchor_id=inc.id)
    session.add(conv)
    session.flush()
    msg = models.ChatMessage(conversation_id=conv.id, role=ChatRole.assistant, content="ok")
    session.add(msg)
    session.flush()
    payload = (
        {"incident_id": inc.id, "priority": "P1"}
        if kind is ProposalKind.incident_priority
        else {"rule": {"id": "chat_rule", "priority": "P2", "reason": "test",
                       "all": [{"field": "category", "op": "eq", "value": "network"}]}}
    )  # fmt: skip
    p = models.ChatProposal(message_id=msg.id, kind=kind, payload=payload, rationale="r")
    session.add(p)
    session.commit()
    return p


def test_viewer_reads_but_cannot_ask(client: TestClient, plans: dict, seeded: Session) -> None:
    inc = incident(seeded)
    token = login(client, seeded, "Angelo", AppRole.viewer)
    page = panel(client, inc)
    assert "Lecture seule." in page and 'name="content"' not in page
    assert post_question(client, token, inc.id, "Pourquoi ?") == 403
    assert client.get("/chat").status_code == 200
    assert not messages(seeded)


@pytest.mark.parametrize("role", [AppRole.tech, AppRole.manager, AppRole.admin])
def test_staff_asks_and_question_is_queued(
    client: TestClient, plans: dict, seeded: Session, role: AppRole
) -> None:
    inc = incident(seeded)
    token = login(client, seeded, "Giovanni", role)
    assert 'name="content"' in panel(client, inc)
    assert post_question(client, token, inc.id, "<b>Pourquoi</b> ce P2 ?") == 200
    [m] = messages(seeded)
    assert (m.role, m.status, m.tokens, m.llm_call_id) == (
        ChatRole.user,
        ChatStatus.pending,
        0,
        None,
    )
    page = panel(client, inc)
    assert "L'IA réfléchit" in page and 'hx-trigger="every 2s"' in page
    assert "&lt;b&gt;Pourquoi&lt;/b&gt;" in page  # question échappée
    # Une seule question en attente à la fois.
    assert post_question(client, token, inc.id, "Encore ?") == 200
    assert len(messages(seeded)) == 1


def test_question_limits(client: TestClient, plans: dict, seeded: Session) -> None:
    inc = incident(seeded)
    token = login(client, seeded, "Giovanni", AppRole.tech)
    assert post_question(client, token, inc.id, "   ") == 200
    assert post_question(client, token, inc.id, "x" * 2001) == 200
    assert not messages(seeded)
    assert post_question(client, token, 99999999, "x") == 404
    r = client.get("/chat/panneau?anchor=autre&anchor_id=1")
    assert r.status_code == 422


def test_answer_rendered_without_links(client: TestClient, plans: dict, seeded: Session) -> None:
    inc = incident(seeded)
    token = login(client, seeded, "Giovanni", AppRole.tech)
    post_question(client, token, inc.id, "x")
    conv = seeded.scalars(select(models.ChatConversation)).one()
    seeded.add(
        models.ChatMessage(
            conversation_id=conv.id,
            role=ChatRole.assistant,
            content="**gras** [lien](http://evil.test) <script>x</script>",
        )
    )
    for m in seeded.scalars(
        select(models.ChatMessage).where(models.ChatMessage.role == ChatRole.user)
    ):
        m.status = ChatStatus.done
    seeded.commit()
    page = panel(client, inc)
    assert "<strong>gras</strong>" in page
    assert 'href="http://evil.test"' not in page and "<script>x" not in page


def test_reset_archives_and_is_audited(client: TestClient, plans: dict, seeded: Session) -> None:
    inc = incident(seeded)
    token = login(client, seeded, "Giovanni", AppRole.tech)
    post_question(client, token, inc.id, "première")
    conv = seeded.scalars(select(models.ChatConversation)).one()
    conv_id = conv.id
    # Un autre tech ne peut pas réinitialiser la conversation de Giovanni.
    other = login(client, seeded, "Cédric", AppRole.tech)
    r = client.post(f"/chat/conversations/{conv_id}/reinitialiser", headers={"X-CSRF-Token": other})
    assert r.status_code == 403
    token = login(client, seeded, "Giovanni", AppRole.tech)
    r = client.post(f"/chat/conversations/{conv_id}/reinitialiser", headers={"X-CSRF-Token": token})
    assert r.status_code == 200
    seeded.expire_all()
    archived = seeded.get(models.ChatConversation, conv_id)
    assert archived is not None and archived.status is ConversationStatus.archived
    assert seeded.scalars(select(models.ChatMessage).where(
        models.ChatMessage.conversation_id == conv_id)).all()  # fmt: skip
    assert seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "chat_reset")
    ).one()
    post_question(client, token, inc.id, "nouvelle")
    convs = seeded.scalars(
        select(models.ChatConversation).order_by(models.ChatConversation.id)
    ).all()
    assert [c.status for c in convs] == [ConversationStatus.archived, ConversationStatus.active]
    page = client.get(f"/chat/conversations/{conv_id}").text
    assert "lecture seule" in page and "première" in page


@pytest.mark.parametrize("role", [AppRole.tech, AppRole.manager, AppRole.viewer])
def test_only_admin_applies(
    client: TestClient, plans: dict, seeded: Session, role: AppRole
) -> None:
    inc = incident(seeded)
    p = proposal_for(seeded, inc)
    token = login(client, seeded, "Giovanni", role)
    for action in ("appliquer", "rejeter"):
        r = client.post(f"/chat/propositions/{p.id}/{action}", headers={"X-CSRF-Token": token})
        assert r.status_code == 403
    seeded.expire_all()
    assert seeded.get(models.ChatProposal, p.id).status is ProposalStatus.proposed
    assert seeded.get(models.Incident, inc.id).manual_priority is None


def test_admin_applies_incident_priority(client: TestClient, plans: dict, seeded: Session) -> None:
    inc = incident(seeded)
    p = proposal_for(seeded, inc)
    assert seeded.get(models.Incident, inc.id).manual_priority is None  # rien sans clic
    token = login(client, seeded, "Vincent", AppRole.admin)
    r = client.post(f"/chat/propositions/{p.id}/appliquer", headers={"X-CSRF-Token": token})
    assert r.status_code == 303
    seeded.expire_all()
    row = seeded.get(models.Incident, inc.id)
    assert row.manual_priority is Priority.P1 and row.manual_by
    assert seeded.get(models.ChatProposal, p.id).status is ProposalStatus.applied
    entry = seeded.scalars(
        select(models.AuditLog).where(models.AuditLog.action == "chat_proposal_applied")
    ).one()
    assert entry.details["après"] == "P1"
    # Déjà traitée : un second clic ne refait rien.
    client.post(f"/chat/propositions/{p.id}/appliquer", headers={"X-CSRF-Token": token})
    assert len(seeded.scalars(select(models.AuditLog).where(
        models.AuditLog.action == "chat_proposal_applied")).all()) == 1  # fmt: skip
    # Retrait par l'admin depuis la fiche incident.
    r = client.post(f"/signaux/incidents/{inc.id}/priorite-manuelle/retirer",
                    headers={"X-CSRF-Token": token})  # fmt: skip
    assert r.status_code == 303
    seeded.expire_all()
    assert seeded.get(models.Incident, inc.id).manual_priority is None


def test_admin_applies_scoring_override(client: TestClient, plans: dict, seeded: Session) -> None:
    from vigie.engine.settings import load_scoring

    inc = incident(seeded)
    p = proposal_for(seeded, inc, kind=ProposalKind.scoring_override)
    token = login(client, seeded, "Vincent", AppRole.admin)
    client.post(f"/chat/propositions/{p.id}/appliquer", headers={"X-CSRF-Token": token})
    seeded.expire_all()
    ids = [r.id for r in load_scoring(seeded).overrides]
    assert "chat_rule" in ids and "cert_7d" in ids


def test_admin_rejects(client: TestClient, plans: dict, seeded: Session) -> None:
    inc = incident(seeded)
    p = proposal_for(seeded, inc)
    token = login(client, seeded, "Vincent", AppRole.admin)
    client.post(f"/chat/propositions/{p.id}/rejeter", headers={"X-CSRF-Token": token})
    seeded.expire_all()
    assert seeded.get(models.ChatProposal, p.id).status is ProposalStatus.rejected
    assert seeded.get(models.Incident, inc.id).manual_priority is None


def test_panels_on_today_and_incident_pages(
    client: TestClient, plans: dict, seeded: Session
) -> None:
    inc = incident(seeded)
    login(client, seeded, "Vincent", AppRole.manager)
    page = client.get(f"/signaux/incidents/{inc.id}").text
    assert f'hx-get="/chat/panneau?anchor=incident&anchor_id={inc.id}"' in page
    page = client.get("/aujourdhui?day=2026-10-09").text
    assert "/chat/panneau?anchor=plan&anchor_id=" in page
