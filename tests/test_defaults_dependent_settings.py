"""The settings.yaml keys written only when they differ from the default (#319).

``security_profile`` and the ``login.*`` keys are omitted from the file while
they hold the model's default, and written when they do not. Two shapes, one
rule: a top-level key, and a key in a section that disappears with its last
entry.

Written before the refactor that moves these keys into ``OWNED_SETTINGS`` and
run against the implementation being replaced, so what it pins is the
behaviour rather than the shape of the code underneath.
"""

import pytest

from nanoidp.config_documents import document_defaults
from nanoidp.models import Settings
from nanoidp.serialization import apply_settings_document

DEFAULTS = document_defaults()


def _document(**document):
    """A settings document as the loader hands it over, with the keys these
    tests are about left to the caller."""
    return document


def _applied(document, **settings_values):
    """The document after the settings have been merged into it."""
    return apply_settings_document(document, Settings(**settings_values), DEFAULTS)


class TestATopLevelKey:
    """``security_profile``: absent means the default."""

    def test_absent_and_at_the_default_stays_absent(self):
        document = _applied(_document(), security_profile="dev")

        assert "security_profile" not in document

    def test_present_and_back_at_the_default_is_removed(self):
        document = _applied(
            _document(security_profile="oauth21"), security_profile="dev"
        )

        assert "security_profile" not in document

    def test_absent_and_not_the_default_is_written(self):
        document = _applied(_document(), security_profile="oauth21")

        assert document["security_profile"] == "oauth21"

    def test_present_and_changed_is_rewritten(self):
        document = _applied(
            _document(security_profile="oauth21"), security_profile="stricter-dev"
        )

        assert document["security_profile"] == "stricter-dev"

    def test_a_placeholder_that_expands_to_the_same_value_is_left_alone(self, monkeypatch):
        """The raw text - placeholder, comments, quoting - survives a save
        that did not change this field (#127)."""
        monkeypatch.setenv("PROFILE", "oauth21")

        document = _applied(
            _document(security_profile="${PROFILE}"), security_profile="oauth21"
        )

        assert document["security_profile"] == "${PROFILE}"


class TestAKeyInAnOmittedSection:
    """``login.*``: the section is absent while every key in it is default."""

    @pytest.mark.parametrize(
        ("attribute", "key", "value"),
        [
            ("login_mode", "mode", "persona"),
            ("auto_login", "auto_login", True),
            ("two_step", "two_step", True),
            ("totp", "totp", True),
        ],
    )
    def test_absent_and_at_the_default_stays_absent(self, attribute, key, value):
        document = _applied(_document())

        assert "login" not in document

    @pytest.mark.parametrize(
        ("attribute", "key", "value"),
        [
            ("login_mode", "mode", "persona"),
            ("auto_login", "auto_login", True),
            ("two_step", "two_step", True),
            ("totp", "totp", True),
        ],
    )
    def test_not_the_default_is_written_into_the_section(self, attribute, key, value):
        document = _applied(_document(), **{attribute: value})

        assert document["login"][key] == value

    @pytest.mark.parametrize(
        ("attribute", "key", "value"),
        [
            ("login_mode", "mode", "persona"),
            ("auto_login", "auto_login", True),
            ("two_step", "two_step", True),
            ("totp", "totp", True),
        ],
    )
    def test_back_at_the_default_removes_the_key_and_the_empty_section(
        self, attribute, key, value
    ):
        document = _applied(_document(login={key: value}))

        assert "login" not in document

    def test_the_section_survives_while_another_key_is_set(self):
        document = _applied(
            _document(login={"mode": "persona", "totp": True}),
            login_mode="persona",
            totp=False,
        )

        assert document["login"] == {"mode": "persona"}

    def test_a_placeholder_that_expands_to_the_same_value_is_left_alone(self, monkeypatch):
        monkeypatch.setenv("LOGIN_MODE", "persona")

        document = _applied(
            _document(login={"mode": "${LOGIN_MODE}"}), login_mode="persona"
        )

        assert document["login"]["mode"] == "${LOGIN_MODE}"

    def test_a_bare_section_line_is_not_a_missing_section(self):
        """``login:`` with nothing under it parses to ``{"login": None}``."""
        document = _applied(_document(login=None), login_mode="persona")

        assert document["login"]["mode"] == "persona"


class TestTheWritersOwnSemantics:
    """What the writer decides to apply at all, which is its API and not
    the persistence rule (#131/#250): a blank mode and an absent checkbox
    mean "leave it alone", and an explicit False is applied like any value.
    """

    def _writer(self, tmp_path):
        import shutil
        from pathlib import Path

        from nanoidp.config import ConfigManager
        from nanoidp.services.yaml_writer import YamlWriter

        repo_config = Path(__file__).resolve().parent.parent / "config"
        for name in ("settings.yaml", "users.yaml"):
            shutil.copy(repo_config / name, tmp_path / name)
        ConfigManager(str(tmp_path))
        return YamlWriter(str(tmp_path))

    def _login(self, tmp_path):
        import yaml

        return yaml.safe_load((tmp_path / "settings.yaml").read_text()).get("login")

    def test_a_blank_mode_leaves_the_file_alone(self, tmp_path):
        """There is no sensible cleared login mode, so blank is not "write
        an empty one": it means unchanged."""
        writer = self._writer(tmp_path)
        writer.update_login_settings(mode="persona")

        writer.update_login_settings(mode="")

        assert self._login(tmp_path) == {"mode": "persona"}

    def test_an_absent_checkbox_leaves_the_file_alone(self, tmp_path):
        writer = self._writer(tmp_path)
        writer.update_login_settings(totp=True)

        writer.update_login_settings(mode="persona")

        assert self._login(tmp_path) == {"mode": "persona", "totp": True}

    def test_an_explicit_false_removes_the_key(self, tmp_path):
        writer = self._writer(tmp_path)
        writer.update_login_settings(mode="persona", totp=True)

        writer.update_login_settings(totp=False)

        assert self._login(tmp_path) == {"mode": "persona"}

    def test_the_last_key_takes_the_section_with_it(self, tmp_path):
        writer = self._writer(tmp_path)
        writer.update_login_settings(totp=True)

        writer.update_login_settings(totp=False)

        assert self._login(tmp_path) is None


class TestTheKeysAreTheOnesTheLoaderKnows:
    def test_every_defaults_dependent_key_has_a_default(self):
        for key in ("security_profile", "login.mode", "login.auto_login", "login.two_step", "login.totp"):
            assert key in DEFAULTS
