"""Vigie : veille des systèmes de supervision IT et plans de tâches de l'équipe."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("vigie")
except PackageNotFoundError:  # pragma: no cover - paquet non installé
    __version__ = "0.0.0"
