import pytest

from vigie.redact import redact

SECRET = "S3cr3t-Value-42"


@pytest.mark.parametrize(
    "text",
    [
        f"password={SECRET}",
        f"Password: {SECRET}",
        f'{{"password": "{SECRET}"}}',
        f"pwd={SECRET}&user=x",
        f"api_key={SECRET}",
        f"apiKey: {SECRET}",
        f"client_secret='{SECRET}'",
        f"token={SECRET}",
        f'"access_token":"{SECRET}"',
        f"Authorization: Bearer {SECRET}",
        f"Authorization: Basic {SECRET}",
        f"psk: {SECRET}",
    ],
)
def test_key_value_secrets(text: str) -> None:
    assert SECRET not in redact(text)


def test_bearer_without_key() -> None:
    assert redact(f"header Bearer {SECRET}") == "header Bearer <redacted>"


def test_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    assert redact(f"jeton {jwt} fin") == "jeton <jwt> fin"


def test_private_key_block() -> None:
    # Marqueurs assemblés à l'exécution : aucun faux secret littéral dans le dépôt (gitleaks).
    kind = "RSA " + "PRIVATE KEY"
    block = f"-----BEGIN {kind}-----\nMIIEow\nabc\n-----END {kind}-----"
    assert redact(f"cle:\n{block}\nsuite") == "cle:\n<private-key>\nsuite"


@pytest.mark.parametrize(
    "iban", ["BE68 5390 0754 7034", "BE68539007547034", "FR14 2004 1010 0505 0001 3M02 606"]
)
def test_iban(iban: str) -> None:
    assert redact(f"IBAN {iban} ok") == "IBAN <iban> ok"


@pytest.mark.parametrize("card", ["4111 1111 1111 1111", "4111-1111-1111-1111", "5555555555554444"])
def test_card(card: str) -> None:
    assert redact(f"carte {card}.") == "carte <card>."


def test_email() -> None:
    assert redact("contact jean.dupont@wallglass.be svp") == "contact <email> svp"
    assert redact("contact a@b.be", emails=False) == "contact a@b.be"


@pytest.mark.parametrize(
    "phone",
    ["+32 470 12 34 56", "0470 12 34 56", "02/123.45.67", "+32 (0)2 123 45 67", "0032470123456"],
)
def test_phone(phone: str) -> None:
    assert redact(f"appeler {phone} demain") == "appeler <phone> demain"
    assert phone in redact(f"appeler {phone}", phones=False)


@pytest.mark.parametrize(
    "text",
    [
        "2026-10-09T07:15:00Z",
        "eventid 1234567890 triggerid 98765",
        "serial SN-ABC12345 version 7.4.2",
        "hôte 192.168.10.17 port 9419",
        "Job SPL-FS01 failed",
        "4111111111111112",  # Luhn invalide
        "BE00 0000 0000 0000",  # IBAN invalide
        "Tokens: 5 restants",
        "durée 12 34 56",
    ],
)
def test_no_false_positive(text: str) -> None:
    assert redact(text) == text


def test_clean_untrusted() -> None:
    from vigie.redact import clean_untrusted

    raw = "<b>Disque</b>‮ plein\x00 \t sur  srv\r\npassword=hunter2 <script>x</script>"
    assert clean_untrusted(raw, 200) == "Disque plein sur srv\npassword=<redacted> x"
    assert clean_untrusted("a" * 50, 10) == "a" * 9 + "…"
    assert len(clean_untrusted("a" * 50, 10)) == 10
