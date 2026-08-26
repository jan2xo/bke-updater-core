from pathlib import Path

import pytest

from bke_updater_core.authority import AuthorizedUpdate
from bke_updater_core.helper.composition import HelperCompositionError, compose_helper_plan


def authorized(install_root: Path, entry_point: Path | None = None) -> AuthorizedUpdate:
    return AuthorizedUpdate(
        product_id="bke-air-stack",
        current_version="1.0.0",
        target_version="2.0.0",
        platform="windows",
        architecture="x64",
        install_root=install_root,
        entry_point=entry_point or Path("BKE AirStack.exe"),
        artifact_sha256="a" * 64,
        artifact_size=123,
    )


def test_helper_plan_derives_install_identity_from_authorized_update(tmp_path: Path):
    install = tmp_path / "install"
    stage = tmp_path / "stage"
    backup = tmp_path / "backup"
    install.mkdir()
    stage.mkdir()
    (stage / "BKE AirStack.exe").write_text("new")

    plan = compose_helper_plan(authorized(install), staged_root=stage, backup_root=backup)

    assert plan.install_root == install.resolve()
    assert plan.executable == (install / "BKE AirStack.exe").resolve()
    assert plan.staged_root == stage.resolve()
    assert plan.backup_root == backup.resolve()


def test_helper_plan_rejects_authorized_entry_point_escape(tmp_path: Path):
    install = tmp_path / "install"
    stage = tmp_path / "stage"
    backup = tmp_path / "backup"
    install.mkdir()
    stage.mkdir()
    (tmp_path / "evil.exe").write_text("evil")

    with pytest.raises(HelperCompositionError, match="entry point"):
        compose_helper_plan(
            authorized(install, Path("..") / "evil.exe"),
            staged_root=stage,
            backup_root=backup,
        )


def test_helper_plan_rejects_missing_authorized_staged_executable(tmp_path: Path):
    install = tmp_path / "install"
    stage = tmp_path / "stage"
    backup = tmp_path / "backup"
    install.mkdir()
    stage.mkdir()

    with pytest.raises(HelperCompositionError, match="staged executable is missing"):
        compose_helper_plan(authorized(install), staged_root=stage, backup_root=backup)


def test_helper_plan_rejects_overlapping_helper_owned_roots(tmp_path: Path):
    install = tmp_path / "install"
    stage = tmp_path / "stage"
    install.mkdir()
    stage.mkdir()
    (stage / "BKE AirStack.exe").write_text("new")

    with pytest.raises(HelperCompositionError, match="overlap"):
        compose_helper_plan(
            authorized(install),
            staged_root=stage,
            backup_root=stage / "backup",
        )
