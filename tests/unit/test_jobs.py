import pytest
from sqlalchemy import Connection

from tests.dbhelpers import denied
from vigie.db.enums import JobKind
from vigie.db.jobs import (
    MAX_PAYLOAD_BYTES,
    PAYLOAD_SCHEMAS,
    JobPayloadError,
    new_job_request,
    validate_payload,
)


def test_every_kind_has_a_schema() -> None:
    assert set(PAYLOAD_SCHEMAS) == set(JobKind)


@pytest.mark.parametrize("source", ["zabbix", "veeam:vbr-main"])
def test_valid_source_test(source: str) -> None:
    assert validate_payload("source_test", {"source": source}) == {"source": source}


def test_unknown_kind_rejected() -> None:
    with pytest.raises(JobPayloadError, match="inconnu"):
        validate_payload("run_command", {"source": "zabbix"})


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"source": "zabbix", "token": "x"},  # champ en trop : jamais de secret
        {"source": "zabbix", "password": "x"},
        {"source": "../etc"},
        {"source": "Zabbix"},
        {"source": 42},
        {"source": "zabbix; DROP TABLE x"},
    ],
)
def test_invalid_payload_rejected(payload: dict[str, object]) -> None:
    with pytest.raises(JobPayloadError):
        validate_payload("source_test", payload)


def test_oversized_payload_rejected_before_parsing() -> None:
    with pytest.raises(JobPayloadError, match="volumineux"):
        validate_payload("source_test", {"source": "x" * (MAX_PAYLOAD_BYTES + 1)})


def test_unserializable_payload_rejected() -> None:
    with pytest.raises(JobPayloadError, match="sérialisable"):
        validate_payload("source_test", {"source": object()})


def test_new_job_request_validates() -> None:
    job = new_job_request("source_test", {"source": "zabbix"}, requested_by="alice")
    assert job.kind is JobKind.source_test
    assert job.payload == {"source": "zabbix"}
    with pytest.raises(JobPayloadError):
        new_job_request("source_test", {"source": "zabbix", "secret": "x"}, requested_by="a")


@pytest.mark.db
def test_database_bounds_payload_size(db_conn: Connection) -> None:
    big = '{"source": "' + "x" * MAX_PAYLOAD_BYTES + '"}'
    error = denied(
        db_conn,
        "INSERT INTO job_request (kind, payload, requested_by, status) "
        "VALUES ('source_test', CAST(:p AS jsonb), 'x', 'pending')",
        {"p": big},
    )
    assert "payload_size" in error


@pytest.mark.db
def test_database_rejects_unknown_kind(db_conn: Connection) -> None:
    error = denied(
        db_conn,
        "INSERT INTO job_request (kind, payload, requested_by, status) "
        "VALUES ('run_command', '{}', 'x', 'pending')",
    )
    assert "ck_job_request_kind" in error
