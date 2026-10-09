"""Rodage (phase 9) : règle du jour validé, série de jours consécutifs, coût projeté."""

from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from vigie.rodage import DayStats, cost_projection, streak


def day(n: int, planned: int, reviewed: int, both: int, *, relevant: int | None = None) -> DayStats:
    return DayStats(
        plan_id=n,
        day=date(2026, 10, n),
        planned=planned,
        reviewed=reviewed,
        relevant=both if relevant is None else relevant,
        well_assigned=both,
        both=both,
        cost_usd=Decimal("0.05"),
    )


def test_validated_day_needs_coverage_and_rate() -> None:
    assert day(1, planned=10, reviewed=9, both=8).validated  # 90 % jugées, 8/9 = 89 %
    assert not day(1, planned=10, reviewed=8, both=8).validated  # 80 % jugées seulement
    assert not day(1, planned=10, reviewed=10, both=7).validated  # 70 %
    assert day(1, planned=10, reviewed=10, both=8).validated  # 80 % pile


def test_day_without_tasks_is_never_validated() -> None:
    d = day(1, planned=0, reviewed=0, both=0)
    assert not d.validated
    assert d.coverage == 0 and d.both_rate is None


def test_rates() -> None:
    d = day(1, planned=8, reviewed=4, both=2, relevant=3)
    assert d.coverage == 0.5
    assert d.relevant_rate == 0.75
    assert d.both_rate == 0.5


def test_streak_counts_consecutive_validated_days_newest_first() -> None:
    ok, ko = (10, 10, 9), (10, 10, 5)
    days = [day(9, *ok), day(8, *ok), day(7, *ko), day(6, *ok)]
    assert streak(days) == 2


def test_streak_ignores_days_not_yet_reviewed_at_the_top() -> None:
    # Le plan du jour n'est pas encore relu : il n'interrompt pas la série.
    days = [day(10, 10, 0, 0), day(9, 10, 10, 9), day(8, 10, 10, 9)]
    assert streak(days) == 2


def test_partially_reviewed_day_breaks_the_streak() -> None:
    days = [day(10, 10, 5, 5), day(9, 10, 10, 9)]
    assert streak(days) == 0


def test_unreviewed_day_in_the_middle_breaks_the_streak() -> None:
    days = [day(10, 10, 10, 9), day(9, 10, 0, 0), day(8, 10, 10, 9)]
    assert streak(days) == 1


def test_cost_projection() -> None:
    now = datetime(2026, 10, 11, tzinfo=UTC)  # 10 jours écoulés sur 31
    assert cost_projection(Decimal("1.00"), now) == pytest.approx(Decimal("3.10"))
    assert cost_projection(Decimal(0), now) == Decimal(0)
