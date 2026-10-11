"""Expiration des certificats de source : selfcheck et `vigie check`."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from vigie.certs import source_certificates
from vigie.cli import app
from vigie.config import SourceConfig, VigieConfig
from vigie.connectors.base import RecordingTransport

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=UTC)


def cert(path: Path, days: int) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vigie-test")])
    now = datetime.now(UTC)
    built = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now + timedelta(days=days, hours=1))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(built.public_bytes(serialization.Encoding.PEM))
    return path


def test_source_certificates(tmp_path: Path) -> None:
    cfg = VigieConfig(
        sources={
            "defender": SourceConfig(enabled=True, certificate=str(cert(tmp_path / "d.crt", 20))),
            "broken": SourceConfig(enabled=True, certificate=str(tmp_path / "absent.crt")),
            "off": SourceConfig(enabled=False, certificate=str(tmp_path / "d.crt")),
            "zabbix": SourceConfig(enabled=True),
        }
    )
    assert source_certificates(cfg, datetime.now(UTC)) == {"defender": 20, "broken": None}


def test_check_warns_before_expiry(tmp_path: Path) -> None:
    def run(days: int) -> str:
        path = tmp_path / f"vigie-{days}.toml"
        crt = cert(tmp_path / f"{days}.crt", days)
        path.write_text(
            '[database]\nurl = "postgresql+psycopg://x@/absent"\n'
            f'[sources.defender]\nenabled = true\ncertificate = "{crt}"\n'
        )
        return CliRunner().invoke(app, ["--config", str(path), "check"]).output

    assert "Attention : certificat de la source defender expire dans 12 j" in run(12)
    assert "expiré depuis 3 j" in run(-3)
    assert "certificat de la source defender : 200 j restants" in run(200)


def test_entra_token_is_never_recorded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "VRAI-JETON-ENTRA"})
        skip = int(request.url.params.get("$skip", "0"))
        page = {"value": [{"id": skip}]}
        if skip == 0:
            page["@odata.nextLink"] = "https://graph.microsoft.com/next"
        return httpx.Response(200, json=page)

    recorder = RecordingTransport(None, inner=httpx.MockTransport(handler))
    tenant = "00000000-0000-0000-0000-000000000000"
    with httpx.Client(transport=recorder) as client:
        client.post(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
        client.get("https://eu.api.security.microsoft.com/api/machines", params={"$skip": 0})
        client.get("https://eu.api.security.microsoft.com/api/machines", params={"$skip": 1})
    assert "VRAI-JETON-ENTRA" not in str(recorder.saved)
    assert recorder.saved["GET_api_machines.json"] == {"value": [{"id": 0}, {"id": 1}]}
