from datetime import date

import pytest

from vigie.db.enums import AbsenceKind
from vigie.engine.calendar import (
    AbsenceSpan,
    Availability,
    CalendarError,
    belgian_holidays,
    days,
    easter,
    is_holiday,
    total_capacity,
    week_of,
)


@pytest.mark.parametrize(
    ("year", "expected"),
    [
        (2000, date(2000, 4, 23)),
        (2019, date(2019, 4, 21)),
        (2024, date(2024, 3, 31)),
        (2025, date(2025, 4, 20)),
        (2026, date(2026, 4, 5)),
        (2027, date(2027, 3, 28)),
        (2038, date(2038, 4, 25)),
    ],
)
def test_easter(year: int, expected: date) -> None:
    assert easter(year) == expected


def test_belgian_holidays_2026() -> None:
    holidays = belgian_holidays(2026)
    assert len(holidays) == 10
    assert {date(2026, 4, 6), date(2026, 5, 14), date(2026, 5, 25)} <= holidays
    assert is_holiday(date(2026, 11, 11))
    assert not is_holiday(date(2026, 11, 12))


def test_other_country_is_refused() -> None:
    with pytest.raises(CalendarError):
        is_holiday(date(2026, 1, 1), "FR")


CEDRIC = Availability(person_id=3, weekly_pattern={"thu": 8}, planning_rate=0.8)
VINCENT = Availability(
    person_id=1,
    weekly_pattern={d: 8 for d in ("mon", "tue", "wed", "thu", "fri")},
    planning_rate=0.5,
    absences=(
        AbsenceSpan(date(2026, 10, 19), date(2026, 10, 20), AbsenceKind.leave),
        AbsenceSpan(date(2026, 10, 24), date(2026, 10, 24), AbsenceKind.extra_day, hours=4),
        AbsenceSpan(date(2026, 11, 11), date(2026, 11, 11), AbsenceKind.extra_day, hours=2),
    ),
)


def test_weekly_pattern_and_capacity() -> None:
    thursday, friday = date(2026, 10, 15), date(2026, 10, 16)
    assert (CEDRIC.hours(thursday), CEDRIC.capacity(thursday)) == (8, 6.4)
    assert not CEDRIC.present(friday)
    assert VINCENT.capacity(friday) == 4


def test_absences_extra_days_and_holidays() -> None:
    assert VINCENT.hours(date(2026, 10, 19)) == 0  # congé
    assert VINCENT.hours(date(2026, 10, 24)) == 4  # samedi supplémentaire
    assert VINCENT.hours(date(2026, 11, 11)) == 2  # férié, mais jour supplémentaire déclaré
    assert CEDRIC.hours(date(2026, 5, 14)) == 0  # Ascension (jeudi)


def test_next_presence() -> None:
    assert CEDRIC.next_presence(date(2026, 10, 13)) == date(2026, 10, 15)
    assert CEDRIC.next_presence(date(2026, 10, 15)) == date(2026, 10, 22)
    assert CEDRIC.next_presence(date(2026, 10, 13), horizon_days=1) is None


def test_week_helpers() -> None:
    assert week_of(date(2026, 10, 15)) == (date(2026, 10, 12), date(2026, 10, 16))
    week = days(*week_of(date(2026, 10, 15)))
    assert len(week) == 5
    assert total_capacity([CEDRIC, VINCENT], week) == 6.4 + 5 * 4
