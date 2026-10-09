"""Rendu Markdown des plans (CLI, puis corps des notifications et de l'UI).

Tout texte issu des sources (titres, actifs, raisons) est échappé : il ne peut ni créer de
lien, ni de titre, ni casser un tableau. Aucune URL n'est produite ici.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from datetime import date

from vigie.db.enums import PlanKind, Priority
from vigie.engine.assign import Assignment, Candidate
from vigie.engine.calendar import DAY_NAMES_FR
from vigie.engine.planner import PlanDraft
from vigie.engine.validator import RefinedPlan

# Caractères qui créent de la structure (emphase, code, lien, HTML, tableau, titre).
_MD_SPECIAL_RE = re.compile(r"([\\`*_\[\]<>|~#])")
_SPACES_RE = re.compile(r"\s+")
_URL_SCHEME_RE = re.compile(r"(?i)\b(https?|ftp|file)://")


def md(text: str) -> str:
    """Texte non fiable → Markdown inerte : une ligne, structure échappée, URL désarmées
    (« https[:]// ») pour qu'aucun lien ne vienne d'une source (SPEC F9)."""
    flat = _MD_SPECIAL_RE.sub(r"\\\1", _SPACES_RE.sub(" ", text).strip())
    return _URL_SCHEME_RE.sub(r"\1[:]//", flat)


def _num(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".").replace(".", ",")


def _day(d: date) -> str:
    return f"{DAY_NAMES_FR[d.weekday()]} {d:%d/%m}"


def _task_line(a: Assignment, *, with_day: bool = False) -> list[str]:
    c = a.candidate
    flags = []
    if a.escalation:
        flags.append("⚠ escalade")
    if c.carry_count:
        flags.append(f"reportée ×{c.carry_count}")
    when = f" — {_day(a.day)}" if with_day and a.day else ""
    due = f", échéance {c.due:%d/%m}" if c.due else ""
    head = f"**{c.priority.value}** {md(c.title)} — {_num(c.estimate_h)} h{due}{when}"
    if flags:
        head += " — " + ", ".join(flags)
    lines = [head]
    lines += [f"  - {md(action)}" for action in c.actions]
    if a.rationale:
        lines.append(f"  _{md(a.rationale)}_")
    if c.reason and c.reason != a.rationale:
        lines.append(f"  Priorité : {md(c.reason)}")
    return lines


def _by_person(draft: PlanDraft, assignments: Iterable[Assignment]) -> dict[int, list[Assignment]]:
    grouped: dict[int, list[Assignment]] = defaultdict(list)
    for a in assignments:
        if a.person_id is not None:
            grouped[a.person_id].append(a)
    return dict(sorted(grouped.items(), key=lambda kv: draft.members[kv[0]].name))


def _candidate_line(c: Candidate) -> str:
    due = f", échéance {c.due:%d/%m}" if c.due else ""
    return f"- **{c.priority.value}** {md(c.title)}{due}"


def _header(draft: PlanDraft, without_ai: str | None, refined: bool) -> list[str]:
    if draft.kind is PlanKind.daily:
        title = f"# Plan quotidien — {_day(draft.period_start)}/{draft.period_start:%Y}"
    else:
        title = (
            f"# Plan hebdomadaire — semaine du {draft.period_start:%d/%m} "
            f"au {draft.period_end:%d/%m/%Y}"
        )
    when = f"{draft.generated_at:%d/%m/%Y à %H:%M} UTC"
    if refined and without_ai is None:
        origin = f"_Brouillon affiné par l'IA puis validé automatiquement, le {when}._"
    else:
        why = f" : {md(without_ai)}" if without_ai else ""
        origin = f"_Brouillon généré sans IA (règles déterministes{why}) le {when}._"
    return [title, "", origin, ""]


def _section(title: str, lines: list[str], empty: str | None = None) -> list[str]:
    if not lines and empty is None:
        return []
    return [f"## {title}", "", *(lines or [f"_{empty}_"]), ""]


def _new_incidents(draft: PlanDraft) -> list[str]:
    return [
        f"- **{i.priority.value}** {md(i.company_code or '—')} · {md(i.asset or '—')} — "
        f"{md(i.title)} _(score {_num(i.score)})_"
        for i in draft.new_incidents
    ]


def _tasks(
    draft: PlanDraft, *, with_day: bool, summaries: dict[int, str] | None = None
) -> list[str]:
    lines: list[str] = []
    for person_id, items in _by_person(draft, draft.result.assigned).items():
        member = draft.members[person_id]
        load = sum(draft.result.load.get((person_id, d), 0) for d in draft.window)
        cap = sum(draft.result.capacity.get((person_id, d), 0) for d in draft.window)
        lines += [f"### {md(member.name)} — {_num(load)}/{_num(cap)} h", ""]
        if summaries and person_id in summaries:
            lines += [f"_{md(summaries[person_id])}_", ""]
        items = sorted(items, key=lambda a: (a.day or date.max, a.candidate.priority.value))
        for n, a in enumerate(items, start=1):
            first, *rest = _task_line(a, with_day=with_day)
            lines.append(f"{n}. {first}")
            lines.extend(f"  {r}" for r in rest)
        lines.append("")
    return lines


def _later(draft: PlanDraft) -> list[str]:
    out = []
    for a in sorted(draft.result.later, key=lambda a: a.day or date.max):
        who = draft.members[a.person_id].name if a.person_id in draft.members else "—"
        when = _day(a.day) if a.day else "—"
        out.append(
            f"- {when} — {md(who)} : **{a.candidate.priority.value}** {md(a.candidate.title)}"
        )
    return out


def _backlog(draft: PlanDraft, *, urgent_only: bool = False) -> list[str]:
    """Plan quotidien (« light ») : P1/P2 détaillés, le reste résumé."""
    shown = [
        a
        for a in draft.result.backlog
        if not urgent_only or a.candidate.priority in (Priority.P1, Priority.P2)
    ]
    lines = [
        f"- **{a.candidate.priority.value}** {md(a.candidate.title)} — _{md(a.rationale)}_"
        for a in shown
    ]
    hidden = len(draft.result.backlog) - len(shown)
    if hidden:
        lines.append(f"- … et {hidden} tâche(s) P3/P4 non planifiée(s) (voir le plan hebdomadaire)")
    return lines


def _sources(draft: PlanDraft) -> list[str]:
    return [
        f"- {md(s.name)} — dernière collecte réussie : {s.since:%d/%m %H:%M} UTC"
        if s.since
        else f"- {md(s.name)} — jamais collectée"
        for s in draft.sources_down
    ]


def _load_table(draft: PlanDraft) -> list[str]:
    head = "| Personne | " + " | ".join(_day(d) for d in draft.window) + " |"
    sep = "|---|" + "---|" * len(draft.window)
    rows = []
    for member in sorted(draft.members.values(), key=lambda m: m.name):
        cells = []
        for d in draft.window:
            cap = draft.result.capacity.get((member.id, d), 0)
            load = draft.result.load.get((member.id, d), 0)
            cells.append("—" if cap == 0 and load == 0 else f"{_num(load)}/{_num(cap)} h")
        rows.append(f"| {md(member.name)} | " + " | ".join(cells) + " |")
    return [head, sep, *rows]


def _summary(draft: PlanDraft) -> list[str]:
    counts = draft.open_by_priority
    open_line = ", ".join(f"{p} : {counts[p]}" for p in sorted(counts, key=lambda p: p.value))
    escalations = sum(1 for a in draft.result.assigned if a.escalation)
    return [
        f"- Incidents ouverts : {sum(counts.values())} ({open_line or 'aucun'})",
        f"- Tâches planifiées : {len(draft.result.assigned)}, dont {escalations} escalade(s)",
        f"- Prévues plus tard : {len(draft.result.later)} ; non planifiées : "
        f"{len(draft.result.backlog)}",
        f"- Sources en panne : {len(draft.sources_down)} ; jalons à risque : {len(draft.risks)}",
    ]


def _trends(draft: PlanDraft) -> list[str]:
    lines: list[str] = []
    for label, rows in draft.trends.items():
        if not rows:
            continue
        lines += [f"| Par {label} | Cette semaine | Semaine précédente |", "|---|---|---|"]
        lines += [f"| {md(k)} | {now} | {prev} |" for k, now, prev in rows]
        lines.append("")
    return lines


def _milestones(draft: PlanDraft) -> list[str]:
    lines = [_candidate_line(c) for c in draft.milestones]
    lines += [
        f"- ⚠ **À risque** : {md(r.title)} — {_num(r.remaining_h)} h restantes pour "
        f"{_num(r.capacity_h)} h de capacité compétente d'ici le {r.due:%d/%m}"
        for r in draft.risks
    ]
    return lines


REJECTIONS_SHOWN = 10


def _ai_extras(refined: RefinedPlan) -> tuple[list[str], list[str], list[str]]:
    risks = [f"- **{sev}** — {md(text)}" for text, sev in refined.risks]
    target = {"coordinator": "coordinateur", "manager": "responsable"}
    escalations = [f"- vers le {target[to]} : {md(text)}" for text, to in refined.escalations]
    rejected = [f"- {md(r)}" for r in refined.rejections[:REJECTIONS_SHOWN]]
    if len(refined.rejections) > REJECTIONS_SHOWN:
        rejected.append(f"- … et {len(refined.rejections) - REJECTIONS_SHOWN} autre(s)")
    return risks, escalations, rejected


def render_markdown(
    draft: PlanDraft, refined: RefinedPlan | None = None, *, without_ai: str | None = None
) -> str:
    if refined is not None:
        draft = refined.draft
    ai = refined is not None and without_ai is None
    summaries = refined.per_person if refined is not None and ai else None
    lines = _header(draft, without_ai, refined is not None)
    if ai and refined is not None and refined.summary_exec:
        lines += _section(
            "Synthèse exécutive",
            [md(line) for line in refined.summary_exec.splitlines() if line.strip()],
        )
    if draft.kind is PlanKind.daily:
        lines += _section("Nouveautés depuis hier (P1/P2)", _new_incidents(draft), "aucune")
        lines += _section(
            "Tâches du jour", _tasks(draft, with_day=False, summaries=summaries), "aucune tâche"
        )
        lines += _section("Prévu plus tard", _later(draft))
        late = [_candidate_line(c) for c in draft.late]
        blocked = [_candidate_line(c) for c in draft.blocked]
        lines += _section("En retard ou bloquées", late + blocked)
        lines += _section("Sources en panne", _sources(draft))
        lines += _section("Non planifié (backlog)", _backlog(draft, urgent_only=True))
    else:
        lines += _section("Synthèse", _summary(draft))
        lines += _section("Charge par personne et par jour", _load_table(draft))
        lines += _section(
            "Tâches de la semaine",
            _tasks(draft, with_day=True, summaries=summaries),
            "aucune tâche",
        )
        lines += _section("Jalons de projets", _milestones(draft))
        lines += _section("Prévu après la semaine", _later(draft))
        lines += _section("Non planifié (backlog) — arbitrage nécessaire", _backlog(draft))
        lines += _section("Nouveaux incidents P1/P2 de la semaine", _new_incidents(draft))
        lines += _section("Sources en panne", _sources(draft))
        lines += _section("Tendances des signaux", _trends(draft))
    if ai and refined is not None:
        risks, escalations, rejected = _ai_extras(refined)
        lines += _section("Risques signalés par l'IA", risks)
        lines += _section("Escalades proposées par l'IA", escalations)
        lines += _section("Propositions de l'IA écartées par le validateur", rejected)
    return "\n".join(lines).rstrip() + "\n"
