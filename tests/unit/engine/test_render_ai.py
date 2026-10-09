from tests.unit.engine.test_validator import G, draft, plan, task
from vigie.engine.render import render_markdown
from vigie.engine.validator import validate


def test_ai_contributions_are_rendered_and_escaped() -> None:
    d = draft()
    refined = validate(
        d,
        plan(
            task("incident:2", actions=["Appeler l'utilisateur", "Vérifier *le* poste"]),
            task("incident:77"),
            summary_exec="Ligne 1\nLigne 2",
            per_person=[{"person_id": G.id, "summary": "Journée support."}],
            escalations=[{"text": "Capacité système insuffisante.", "to": "manager"}],
        ),
    )
    text = render_markdown(d, refined)
    assert "_Brouillon affiné par l'IA puis validé automatiquement" in text
    assert "## Synthèse exécutive\n\nLigne 1\nLigne 2" in text
    assert "_Journée support._" in text
    assert "    - Appeler l'utilisateur" in text
    assert "Vérifier \\*le\\* poste" in text
    assert "- vers le responsable : Capacité système insuffisante." in text
    assert "## Propositions de l'IA écartées par le validateur" in text
    assert "incident:77 : référence inconnue ignorée" in text


def test_fallback_header_and_no_ai_sections() -> None:
    d = draft()
    refined = validate(d, plan(summary_exec="Ne doit pas paraître"))
    text = render_markdown(d, refined, without_ai="budget mensuel")
    assert "(règles déterministes : budget mensuel)" in text
    assert "Synthèse exécutive" not in text and "Ne doit pas paraître" not in text


def test_many_rejections_are_summarized() -> None:
    d = draft()
    refined = validate(d, plan(*[task(f"incident:{100 + i}") for i in range(12)]))
    text = render_markdown(d, refined)
    assert "… et 2 autre(s)" in text
