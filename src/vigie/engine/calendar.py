"""Disponibilités de l'équipe (SPEC F1, §7.5) : heures par personne et par jour.

heures(jour) = weekly_pattern[jour de semaine], sauf jour férié ou absence (congé, maladie,
formation) ; un `extra_day` ajoute ses heures (jour de présence supplémentaire).
capacité planifiable = heures × planning_rate.

Jours fériés : calculés ici pour la Belgique (pas de dépendance externe).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from functools import cache

from vigie.db.enums import AbsenceKind

WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DAY_NAMES_FR = ("lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche")


class CalendarError(ValueError):
    """Pays de jours fériés non pris en charge."""


def easter(year: int) -> date:
    """Dimanche de Pâques (calendrier grégorien, algorithme anonyme de Meeus/Jones/Butcher)."""
    a = year % 19
    b, c = divmod(year, 100)
    d, e = divmod(b, 4)
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    ell = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * ell) // 451
    month, day = divmod(h + ell - 7 * m + 114, 31)
    return date(year, month, day + 1)


@cache
def belgian_holidays(year: int) -> frozenset[date]:
    paques = easter(year)
    return frozenset(
        {
            date(year, 1, 1),  # Nouvel An
            paques + timedelta(days=1),  # lundi de Pâques
            date(year, 5, 1),  # fête du Travail
            paques + timedelta(days=39),  # Ascension
            paques + timedelta(days=50),  # lundi de Pentecôte
            date(year, 7, 21),  # fête nationale
            date(year, 8, 15),  # Assomption
            date(year, 11, 1),  # Toussaint
            date(year, 11, 11),  # Armistice
            date(year, 12, 25),  # Noël
        }
    )


def is_holiday(day: date, country: str = "BE") -> bool:
    if country != "BE":
        raise CalendarError(f"jours fériés non pris en charge pour le pays {country!r}")
    return day in belgian_holidays(day.year)


@dataclass(frozen=True)
class AbsenceSpan:
    start: date
    end: date
    kind: AbsenceKind
    hours: float | None = None

    def covers(self, day: date) -> bool:
        return self.start <= day <= self.end


@dataclass(frozen=True)
class Availability:
    person_id: int
    weekly_pattern: dict[str, float]
    planning_rate: float
    absences: tuple[AbsenceSpan, ...] = ()

    def hours(self, day: date, country: str = "BE") -> float:
        extra = sum(
            a.hours or 0 for a in self.absences if a.kind is AbsenceKind.extra_day and a.covers(day)
        )
        if is_holiday(day, country):
            return extra
        if any(a.kind is not AbsenceKind.extra_day and a.covers(day) for a in self.absences):
            return 0.0
        return float(self.weekly_pattern.get(WEEKDAYS[day.weekday()], 0)) + extra

    def capacity(self, day: date, country: str = "BE") -> float:
        return round(self.hours(day, country) * self.planning_rate, 2)

    def present(self, day: date, country: str = "BE") -> bool:
        return self.hours(day, country) > 0

    def next_presence(
        self, after: date, horizon_days: int = 28, country: str = "BE"
    ) -> date | None:
        """Premier jour de présence strictement après `after`, dans l'horizon."""
        for offset in range(1, horizon_days + 1):
            day = after + timedelta(days=offset)
            if self.present(day, country):
                return day
        return None


def days(start: date, end: date) -> list[date]:
    return [start + timedelta(days=n) for n in range((end - start).days + 1)]


def week_of(day: date) -> tuple[date, date]:
    """Lundi et vendredi de la semaine de `day`."""
    monday = day - timedelta(days=day.weekday())
    return monday, monday + timedelta(days=4)


def total_capacity(
    people: Iterable[Availability], window: Sequence[date], country: str = "BE"
) -> float:
    return round(sum(p.capacity(d, country) for p in people for d in window), 2)
