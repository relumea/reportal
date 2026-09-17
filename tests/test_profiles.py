from pathlib import Path

import pytest

from reportal import auth, profiles


@pytest.fixture(autouse=True)
def isolated_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(profiles.PROFILE_ENV, raising=False)
    monkeypatch.delenv(auth.REQUIRED_ENV, raising=False)
    (tmp_path / "reportal.toml").write_text("", encoding="utf-8")


def test_default_profile() -> None:
    assert profiles.current() == profiles.PROFILE_PERSONAL
    assert not profiles.is_saas()
    assert not auth.required()


def test_profile_without_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_workspace() -> Path:
        raise profiles.WorkspaceNotFound("no workspace")

    monkeypatch.setattr(profiles, "project_root", missing_workspace)
    assert profiles.current() == profiles.PROFILE_PERSONAL


@pytest.mark.parametrize("profile", ["personal", "saas"])
def test_workspace_profile(tmp_path: Path, profile: str) -> None:
    (tmp_path / "reportal.toml").write_text(
        f'[deployment]\nprofile = "{profile}"\n', encoding="utf-8"
    )
    assert profiles.current() == profile
    assert profiles.is_saas() == (profile == "saas")
    assert auth.required() == (profile == "saas")


def test_environment_overrides_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "reportal.toml").write_text(
        '[deployment]\nprofile = "personal"\n', encoding="utf-8"
    )
    monkeypatch.setenv(profiles.PROFILE_ENV, " SAAS ")
    monkeypatch.setenv(auth.REQUIRED_ENV, "off")
    assert profiles.current() == profiles.PROFILE_SAAS
    assert auth.required()
    monkeypatch.setenv(profiles.PROFILE_ENV, "personal")
    assert profiles.current() == profiles.PROFILE_PERSONAL


def test_blank_environment_uses_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "reportal.toml").write_text('[deployment]\nprofile = "saas"\n', encoding="utf-8")
    monkeypatch.setenv(profiles.PROFILE_ENV, " ")
    assert profiles.is_saas()


def test_unknown_environment_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(profiles.PROFILE_ENV, "saass")
    with pytest.raises(ValueError, match="deployment profile"):
        profiles.current()


@pytest.mark.parametrize(
    "document",
    [
        '[deployment]\nprofile = "saass"\n',
        "[deployment]\nprofile = true\n",
        'deployment = "saas"\n',
    ],
)
def test_invalid_workspace_profile(tmp_path: Path, document: str) -> None:
    (tmp_path / "reportal.toml").write_text(document, encoding="utf-8")
    with pytest.raises(ValueError):
        profiles.current()
