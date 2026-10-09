"""Masquage des données sensibles (SECURITY.md C5/C7, SPEC §7.2).

Utilisé par les journaux, la normalisation des signaux et la préparation du prompt LLM.
Le masquage est volontairement large : mieux vaut masquer un faux positif que laisser
passer un secret.
"""

from __future__ import annotations

import re

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}")
_KEY_VALUE_RE = re.compile(
    r"""(?ix)
    (["']?\b(?:password|passwd|pwd|secret|client_secret|token|access_token|refresh_token|
       api[_-]?key|apikey|authorization|psk|private_key)\b["']?\s*[:=]\s*)
    ("[^"]*"|'[^']*'|[^\s,;&}\]]+)
    """
)
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
# Premier chiffre de 2 à 6 (réseaux de cartes) ; un point final de phrase est accepté.
_CARD_RE = re.compile(r"(?<![\w.])[2-6](?:[ -]?\d){12,18}(?!\w|\.\d)")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<![\w.:/-])(?:(?:\+|00)[1-9]\d{0,2}[ .\-/]?(?:\(0\)[ .\-/]?)?|0(?=[1-9]))"
    r"\d{1,4}(?:[ .\-/]?\d{2,4}){2,4}"
    r"(?![\w.:/-])"
)

REDACTED = "<redacted>"


def _mask_value(m: re.Match[str]) -> str:
    value = m.group(2)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return f"{m.group(1)}{value[0]}{REDACTED}{value[0]}"
    return f"{m.group(1)}{REDACTED}"


def _iban_valid(candidate: str) -> bool:
    s = candidate.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    return int(digits) % 97 == 1


def _luhn_valid(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _phone(m: re.Match[str]) -> str:
    digits = sum(c.isdigit() for c in m.group(0))
    return "<phone>" if 9 <= digits <= 15 else m.group(0)


def redact(text: str, *, emails: bool = True, phones: bool = True) -> str:
    """Retourne `text` avec secrets et données personnelles remplacés par des marqueurs."""
    text = _PRIVATE_KEY_RE.sub("<private-key>", text)
    text = _JWT_RE.sub("<jwt>", text)
    text = _AUTH_SCHEME_RE.sub(rf"\1 {REDACTED}", text)
    text = _KEY_VALUE_RE.sub(_mask_value, text)
    text = _IBAN_RE.sub(lambda m: "<iban>" if _iban_valid(m.group(0)) else m.group(0), text)
    text = _CARD_RE.sub(lambda m: "<card>" if _luhn_valid(m.group(0)) else m.group(0), text)
    if emails:
        text = _EMAIL_RE.sub("<email>", text)
    if phones:
        text = _PHONE_RE.sub(_phone, text)
    return text


_TAG_RE = re.compile(r"<[^<>]{0,200}>")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
_SPACES_RE = re.compile(r"[ \t]+")


def clean_untrusted(text: str, max_len: int) -> str:
    """Texte venu d'une source (non fiable) : balises et caractères de contrôle retirés,
    espaces réduits, secrets masqués, tronqué à `max_len` caractères (SPEC §7.2)."""
    text = _CONTROL_RE.sub("", _TAG_RE.sub("", text.replace("\r", "")))
    text = "\n".join(_SPACES_RE.sub(" ", line).strip() for line in text.split("\n")).strip()
    text = redact(text)
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text
