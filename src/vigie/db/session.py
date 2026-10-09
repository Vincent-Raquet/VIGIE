"""Connexion PostgreSQL (socket unix, authentification peer : aucun mot de passe en dev)."""

from __future__ import annotations

from sqlalchemy import Engine, create_engine


def make_engine(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True)
