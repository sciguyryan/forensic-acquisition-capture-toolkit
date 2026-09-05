"""Tests for FACT project package creation and confidentiality wrapping."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tarfile
from pathlib import Path

import pytest

from fact.core import packaging
from fact.core.project import _initialise_project as initialise_project
from fact.core.project import create_case
from fact.errors import ToolkitError
from fact.services.commands import ToolResult

PUBLIC_KEY = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nTEST\n-----END PGP PUBLIC KEY BLOCK-----\n"
)


def _mock_crypto(monkeypatch) -> None:
    monkeypatch.setattr(packaging, "prepare_gnupg", lambda *args, **kwargs: {})
    monkeypatch.setattr(packaging, "fingerprint", lambda *args, **kwargs: "A" * 40)
    monkeypatch.setattr(
        packaging, "_export_public_key", lambda *args, **kwargs: PUBLIC_KEY
    )
    monkeypatch.setattr(
        packaging,
        "sign",
        lambda home, payload, signature, fpr: signature.write_text(
            "signature", encoding="ascii"
        ),
    )
    monkeypatch.setattr(packaging, "_verify_signature", lambda *args, **kwargs: None)


def test_project_package_contains_allowlisted_state_and_catalogue_anchor(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test project")
    case_id = create_case(project, "Evidence")
    acquisition = project / "cases" / case_id / "acquisitions" / "sample.txt"
    acquisition.write_text("captured", encoding="utf-8")
    (project / "secret.txt").write_text("must not be packaged", encoding="utf-8")
    _mock_crypto(monkeypatch)

    output = tmp_path / "package.fact.tar.gz"
    result = packaging.create_project_package(project, tmp_path, output)

    assert result["archive"] == output
    assert result["checksum"].exists()
    assert result["signature"].exists()
    assert result["public_key"].read_text(encoding="utf-8") == PUBLIC_KEY
    with tarfile.open(output, "r:gz") as archive:
        names = archive.getnames()
        assert "PROJECT.toml" in names
        assert ".fact/catalogue.sqlite" in names
        assert f"cases/{case_id}/CASE.toml" in names
        assert "secret.txt" not in names
        descriptor_file = archive.extractfile("FACT-PACKAGE/PACKAGE.json")
        assert descriptor_file is not None
        descriptor = json.load(descriptor_file)
    assert descriptor["project_id"] == "P-1"
    assert descriptor["catalogue_event_count"] == 1
    assert len(descriptor["catalogue_chain_head"]) == 64
    assert descriptor["catalogue_checkpoint_status"] == "absent"


def test_project_package_is_reproducible_for_unchanged_state(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test")
    create_case(project)
    _mock_crypto(monkeypatch)

    first = tmp_path / "first.fact.tar.gz"
    second = tmp_path / "second.fact.tar.gz"
    packaging.create_project_package(project, tmp_path, first)
    packaging.create_project_package(project, tmp_path, second)

    assert (
        hashlib.sha256(first.read_bytes()).digest()
        == hashlib.sha256(second.read_bytes()).digest()
    )


def test_packaging_refuses_tampered_catalogue(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test")
    create_case(project)
    _mock_crypto(monkeypatch)
    connection = sqlite3.connect(project / ".fact" / "catalogue.sqlite")
    connection.execute(
        "UPDATE counters SET next_sequence = 99 WHERE namespace = 'case'"
    )
    connection.commit()
    connection.close()

    with pytest.raises(ToolkitError, match="counter does not match"):
        packaging.create_project_package(
            project, tmp_path, tmp_path / "bad.fact.tar.gz"
        )


def test_packaging_rejects_symlinks_in_included_project_state(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test")
    case_id = create_case(project)
    target = project / "target.txt"
    target.write_text("target", encoding="utf-8")
    (project / "cases" / case_id / "acquisitions" / "link").symlink_to(target)
    _mock_crypto(monkeypatch)

    with pytest.raises(ToolkitError, match="symbolic links"):
        packaging.create_project_package(
            project, tmp_path, tmp_path / "bad.fact.tar.gz"
        )


def test_package_encryption_is_optional_outer_envelope(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test")
    _mock_crypto(monkeypatch)
    commands: list[list[str]] = []

    def fake_run(argv, **kwargs):
        commands.append(argv)
        if "--encrypt" in argv:
            output = Path(argv[argv.index("--output") + 1])
            output.write_bytes(b"encrypted")
        return ToolResult(argv, 0, "", "")

    monkeypatch.setattr(packaging, "run", fake_run)
    output = tmp_path / "package.fact.tar.gz"
    result = packaging.create_project_package(
        project,
        tmp_path,
        output,
        encrypt_to=["RECIPIENT-A", "RECIPIENT-B"],
    )

    assert output.exists()
    assert result["encrypted"].read_bytes() == b"encrypted"
    encrypt_command = next(command for command in commands if "--encrypt" in command)
    assert encrypt_command.count("--recipient") == 2
    assert "RECIPIENT-A" in encrypt_command
    assert "RECIPIENT-B" in encrypt_command


def test_packaging_refuses_existing_outputs_without_force(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test")
    _mock_crypto(monkeypatch)
    output = tmp_path / "package.fact.tar.gz"
    output.write_bytes(b"existing")

    with pytest.raises(ToolkitError, match="already exists"):
        packaging.create_project_package(project, tmp_path, output)


def test_package_lock_blocks_catalogue_mutation(tmp_path: Path) -> None:
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test")
    lock = project / ".fact" / "package.lock"
    lock.write_text("test", encoding="ascii")

    with pytest.raises(ToolkitError, match="currently being packaged"):
        create_case(project)


def test_project_package_validates_project_metadata_and_existing_lock(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(ToolkitError, match="project file does not exist"):
        packaging.create_project_package(project, tmp_path)

    initialise_project(project, "P-1", "Test")
    _mock_crypto(monkeypatch)
    lock = project / ".fact" / "package.lock"
    lock.write_text("stale", encoding="ascii")
    with pytest.raises(ToolkitError, match="stale package lock"):
        packaging.create_project_package(
            project, tmp_path, tmp_path / "locked.fact.tar.gz"
        )


def test_encryption_failure_is_reported(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test")
    _mock_crypto(monkeypatch)

    def fake_run(argv, **kwargs):
        if "--encrypt" in argv:
            return ToolResult(argv, 1, "", "recipient unavailable")
        return ToolResult(argv, 0, "", "")

    monkeypatch.setattr(packaging, "run", fake_run)
    with pytest.raises(ToolkitError, match="Package encryption failed"):
        packaging.create_project_package(
            project,
            tmp_path,
            tmp_path / "encrypted.fact.tar.gz",
            encrypt_to=["MISSING"],
        )


def test_project_package_excludes_acquisition_working_and_legacy_archive_state(
    tmp_path: Path, monkeypatch
) -> None:
    """Package only authoritative catalogue/file state, not acquisition duplicates."""
    project = tmp_path / "project"
    initialise_project(project, "P-1", "Test")
    archived = project / "archived"
    archived.mkdir()
    (archived / "legacy.7z").write_bytes(b"legacy duplicate")
    staging = project / ".fact" / "staging" / "acquisitions" / ".staging-CASE-1-ACQ-1"
    staging.mkdir(parents=True)
    (staging / "raw.png").write_bytes(b"working state")
    _mock_crypto(monkeypatch)

    output = tmp_path / "package.fact.tar.gz"
    packaging.create_project_package(project, tmp_path, output)
    with tarfile.open(output, "r:gz") as package:
        names = package.getnames()
    assert not any(name.startswith("archived/") for name in names)
    assert not any("staging" in name for name in names)
    assert ".fact/catalogue.sqlite" in names
