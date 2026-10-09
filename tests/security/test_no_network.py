"""Garde-fou : aucun test ne peut ouvrir de connexion réseau (CLAUDE.md, SECURITY.md §3)."""

import socket  # noqa: TID251 - on vérifie justement que le réseau est bloqué

import pytest
from pytest_socket import SocketBlockedError


def test_tcp_socket_is_blocked() -> None:
    with pytest.raises(SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
