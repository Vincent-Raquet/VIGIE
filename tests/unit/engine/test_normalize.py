from datetime import UTC, datetime

from vigie.connectors.base import Signal
from vigie.db.enums import Category
from vigie.engine.normalize import fingerprint, normalize_asset, normalize_title, raw_hash

T0 = datetime(2026, 10, 9, tzinfo=UTC)


def sig(**kw: object) -> Signal:
    base: dict[str, object] = {
        "source": "zabbix",
        "external_id": "1",
        "company_code": "WI",
        "asset": "srv-wi-01",
        "category": Category.server,
        "severity": 3,
        "title": "Free disk space is less than 10% on volume C:",
        "details": "",
        "first_seen": T0,
        "last_seen": T0,
    }
    base.update(kw)
    return Signal(**base)  # type: ignore[arg-type]


def test_normalize_title_removes_variable_numbers() -> None:
    assert normalize_title("24 problèmes ouverts sur  SRV-01") == "# problemes ouverts sur srv-#"
    assert normalize_title("Free: 42.808 %, total: 47 GB") == "free: # %, total: # gb"


def test_normalize_asset() -> None:
    assert normalize_asset("SRV-WI-01.corp.example.test") == "srv-wi-01"
    assert normalize_asset("192.0.2.10") == "192.0.2.10"
    assert normalize_asset(" Réseau ") == "reseau"


def test_fingerprint_stable_across_variable_parts() -> None:
    a = sig(external_id="1", title="Disk 91% full", details="x")
    b = sig(external_id="2", title="Disk 95% full", details="y", severity=4)
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(sig(company_code="SPL"))
    assert fingerprint(a) != fingerprint(sig(asset="srv-wi-02"))
    assert fingerprint(a) != fingerprint(sig(category=Category.backup))
    assert len(fingerprint(a)) == 64


def test_raw_hash_tracks_displayed_fields() -> None:
    a = sig()
    assert raw_hash(a) == raw_hash(sig(last_seen=datetime(2027, 1, 1, tzinfo=UTC)))
    assert raw_hash(a) != raw_hash(sig(details="nouveau"))
    assert raw_hash(a) != raw_hash(sig(attributes={"maintenance": True}))
