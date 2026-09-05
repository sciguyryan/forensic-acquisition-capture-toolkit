"""Persistence-boundary tests for confidential FACT note material."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import sqlite3
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fact import identity
from fact.core import authority, catalogue, notes, packaging
from fact.core.authority import (
    accept_contributor,
    accept_ownership_transfer,
    establish_project_genesis,
    invite_contributor,
    propose_ownership_transfer,
)
from fact.core.catalogue import catalogue_path
from fact.core.notes import create_note, revise_note, set_note_disclosure
from fact.core.project import _initialise_project as initialise_project
from fact.errors import ToolkitError
from fact.identity import OperatorIdentity

SENTINEL = "FACT-CONFIDENTIAL-PLAINTEXT-SENTINEL-7e8f0b6a"
SENTINEL_BYTES = SENTINEL.encode("utf-8")


def _operator(operator_id: str, marker: str) -> OperatorIdentity:
    return OperatorIdentity(
        1,
        operator_id,
        operator_id.title(),
        None,
        None,
        None,
        marker * 40,
        marker.lower() * 40,
    )


@pytest.fixture
def confidential_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, OperatorIdentity, OperatorIdentity, OperatorIdentity]:
    def sign(operator_identity: OperatorIdentity, payload: bytes) -> str:
        return f"SIG:{operator_identity.operator_id}:{hashlib.sha256(payload).hexdigest()}"

    monkeypatch.setattr(authority, "sign_operator_payload", sign)
    monkeypatch.setattr(authority, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(catalogue, "verify_operator_payload", lambda *args: None)
    monkeypatch.setattr(notes, "encrypt_for_project_keys", lambda payload, keys: b"ENC:" + bytes(payload)[::-1])
    monkeypatch.setattr(notes, "decrypt_confidential_payload", lambda payload: bytes(payload).removeprefix(b"ENC:")[::-1])

    project = tmp_path / "project"
    owner = _operator("owner", "A")
    author = _operator("author", "B")
    incoming = _operator("incoming", "C")
    initialise_project(project, "P-CONFIDENTIAL", "Confidential persistence")
    establish_project_genesis(project, owner, "PUBLIC OWNER")
    invite_contributor(project, owner, author, "PUBLIC AUTHOR")
    accept_contributor(project, author)
    invite_contributor(project, owner, incoming, "PUBLIC INCOMING")
    accept_contributor(project, incoming)
    return project, owner, author, incoming


def _contains_plaintext(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return SENTINEL in value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return SENTINEL_BYTES in bytes(value)
    if isinstance(value, dict):
        return any(_contains_plaintext(item) for pair in value.items() for item in pair)
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(_contains_plaintext(item) for item in value)
    return SENTINEL in repr(value)


class _GuardedConnection:
    """Proxy a SQLite connection and reject confidential plaintext parameters."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def execute(self, sql: str, parameters: Any = ()) -> Any:
        assert not _contains_plaintext(sql), "confidential plaintext entered SQL text"
        assert not _contains_plaintext(parameters), "confidential plaintext crossed the SQLite parameter boundary"
        return self._connection.execute(sql, parameters)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


@contextlib.contextmanager
def _guard_transaction(original, project_root: Path) -> Iterator[_GuardedConnection]:
    with original(project_root) as connection:
        yield _GuardedConnection(connection)


def _scan_files(root: Path) -> list[Path]:
    matches: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                if SENTINEL_BYTES in path.read_bytes():
                    matches.append(path)
            except OSError:
                continue
    return matches


def test_confidential_plaintext_never_crosses_sqlite_parameters(
    confidential_project: tuple[Path, OperatorIdentity, OperatorIdentity, OperatorIdentity],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, owner, author, incoming = confidential_project
    original_notes_transaction = notes._write_transaction
    original_authority_transaction = authority._write_transaction
    monkeypatch.setattr(
        notes,
        "_write_transaction",
        lambda root: _guard_transaction(original_notes_transaction, root),
    )
    monkeypatch.setattr(
        authority,
        "_write_transaction",
        lambda root: _guard_transaction(original_authority_transaction, root),
    )

    note_id = create_note(project, author, "Confidential", SENTINEL, visibility="confidential")
    revise_note(project, author, note_id, "Confidential", SENTINEL + " revised", "Correction")
    propose_ownership_transfer(project, owner, incoming.operator_id, "Responsibility change")
    accept_ownership_transfer(project, incoming)


def test_confidential_plaintext_absent_from_project_and_package_files(
    confidential_project: tuple[Path, OperatorIdentity, OperatorIdentity, OperatorIdentity],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, owner, author, incoming = confidential_project
    note_id = create_note(project, author, "Confidential", SENTINEL, visibility="confidential")
    revise_note(project, author, note_id, "Confidential", SENTINEL + " revised", "Correction")
    propose_ownership_transfer(project, owner, incoming.operator_id, "Responsibility change")
    accept_ownership_transfer(project, incoming)

    assert _scan_files(project) == []
    database_bytes = catalogue_path(project).read_bytes()
    assert SENTINEL_BYTES not in database_bytes

    # Explicitly disclose the confidential note to exercise the harder package
    # path. Disclosure may include ciphertext, never decrypted note material.
    set_note_disclosure(project, incoming, note_id, True)

    # Packaging crypto is unrelated to note confidentiality and is isolated here.
    monkeypatch.setattr(packaging, "prepare_gnupg", lambda *args, **kwargs: {})
    monkeypatch.setattr(packaging, "fingerprint", lambda *args, **kwargs: "A" * 40)
    monkeypatch.setattr(packaging, "_export_public_key", lambda *args, **kwargs: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nTEST\n-----END PGP PUBLIC KEY BLOCK-----\n")
    monkeypatch.setattr(packaging, "sign", lambda home, payload, signature, fpr: signature.write_text("signature", encoding="ascii"))
    monkeypatch.setattr(packaging, "_verify_signature", lambda *args, **kwargs: None)
    output = tmp_path / "confidential.fact.tar.gz"
    packaging.create_project_package(project, tmp_path, output)
    assert SENTINEL_BYTES not in output.read_bytes()
    import tarfile

    with tarfile.open(output, "r:gz") as archive:
        for member in archive.getmembers():
            if member.isfile():
                handle = archive.extractfile(member)
                assert handle is not None
                assert SENTINEL_BYTES not in handle.read(), member.name
    assert _scan_files(tmp_path) == []


def test_confidential_plaintext_not_disclosed_by_errors_or_logs(
    confidential_project: tuple[Path, OperatorIdentity, OperatorIdentity, OperatorIdentity],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    project, _, author, _ = confidential_project

    def fail_encryption(payload: bytes, keys: list[str]) -> bytes:
        assert SENTINEL_BYTES in bytes(payload)
        raise ToolkitError("synthetic confidential encryption failure")

    monkeypatch.setattr(notes, "encrypt_for_project_keys", fail_encryption)
    with caplog.at_level(logging.DEBUG), pytest.raises(ToolkitError) as excinfo:
        create_note(project, author, "Confidential", SENTINEL, visibility="confidential")
    assert SENTINEL not in str(excinfo.value)
    assert SENTINEL not in caplog.text
    assert _scan_files(project) == []


def test_gnupg_encryption_receives_plaintext_only_through_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    monkeypatch.setattr(
        identity,
        "_import_encryption_fingerprints",
        lambda public_key, home, env: ["0123456789ABCDEF0123456789ABCDEF01234567"],
    )

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        calls.append((list(argv), dict(kwargs)))
        assert not _contains_plaintext(argv)
        assert not _contains_plaintext(kwargs.get("env"))
        assert "--output" not in argv
        if "--encrypt" in argv:
            assert kwargs.get("input") == SENTINEL_BYTES
            assert kwargs.get("capture_output") is True
            return subprocess.CompletedProcess(argv, 0, b"CIPHERTEXT", b"")
        raise AssertionError(f"Unexpected GnuPG command: {argv}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    ciphertext = identity.encrypt_for_project_keys(SENTINEL_BYTES, ["PUBLIC KEY MATERIAL"])
    assert ciphertext == b"CIPHERTEXT"
    assert not any(_contains_plaintext(argv) for argv, _ in calls)
    assert _scan_files(tmp_path) == []


def test_gnupg_decryption_returns_plaintext_only_through_captured_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ciphertext = b"CIPHERTEXT-ONLY"

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        assert argv == ["gpg", "--decrypt"]
        assert "--output" not in argv
        assert kwargs.get("input") == ciphertext
        assert kwargs.get("capture_output") is True
        return subprocess.CompletedProcess(argv, 0, SENTINEL_BYTES, b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert identity.decrypt_confidential_payload(ciphertext) == SENTINEL_BYTES
    assert _scan_files(tmp_path) == []
