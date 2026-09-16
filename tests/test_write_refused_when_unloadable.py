"""A write whose result would not load is refused, not written (#366).

``compare_and_replace`` replaces the file and the runtime reloads after, so
a document the models reject used to reach disk first and be discovered
second, leaving a settings.yaml no process could start from. The same parse
the loader runs, one step earlier, turns that into a refusal with nothing
written.

What makes this worth a boundary rather than a guard per field: the value
does not have to be blank, and the rule does not have to be a field
constraint. ``oauth.issuer`` is refused by a validator, which no schema can
advertise, and MCP's update_settings writes onto a model without
validate_assignment.
"""

import shutil
from pathlib import Path

import pytest
import yaml

from nanoidp.config import ConfigManager
from nanoidp.config_documents import DocumentRejected
from nanoidp.services.yaml_writer import YamlWriter

_REPO = Path(__file__).resolve().parent.parent


def _seed(tmp_path):
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, tmp_path / name)
    ConfigManager(str(tmp_path))
    return YamlWriter(str(tmp_path))


def _settings(tmp_path):
    return yaml.safe_load((tmp_path / "settings.yaml").read_text())


class TestTheWriterRefuses:
    @pytest.mark.parametrize(
        "field, value",
        [
            ("audience", ""),
            ("issuer", ""),
            ("issuer", "not-a-url"),
        ],
    )
    def test_a_value_the_models_reject_never_reaches_the_file(self, tmp_path, field, value):
        writer = _seed(tmp_path)
        before = (tmp_path / "settings.yaml").read_text()

        with pytest.raises(DocumentRejected):
            writer.update_oauth_settings(**{field: value})

        assert (tmp_path / "settings.yaml").read_text() == before

    def test_the_refusal_names_the_file_and_the_key(self, tmp_path):
        writer = _seed(tmp_path)

        with pytest.raises(DocumentRejected) as refused:
            writer.update_oauth_settings(audience="")

        assert "settings.yaml" in refused.value.message
        assert "audience" in refused.value.message

    def test_a_good_write_still_lands(self, tmp_path):
        writer = _seed(tmp_path)

        writer.update_oauth_settings(audience="something-valid")

        assert _settings(tmp_path)["oauth"]["audience"] == "something-valid"


class TestWhatARefusalDoesNotDo:
    """The boundary is loadability of the document, and nothing further."""

    def test_the_check_does_not_activate_anything(self, tmp_path, monkeypatch):
        """It parses a candidate; it does not ask whether nanoidp could
        start from it. Bringing activation in would make the write
        primitive depend on the whole runtime, and #359 already owns the
        question of a configuration whose signing service cannot be built.
        """
        import nanoidp.services.crypto as crypto

        writer = _seed(tmp_path)
        monkeypatch.setattr(
            crypto,
            "prepare_crypto_service",
            lambda *a, **k: pytest.fail("the pre-write check must not activate"),
        )

        writer.update_oauth_settings(audience="still-fine")

        assert _settings(tmp_path)["oauth"]["audience"] == "still-fine"

    def test_the_refusal_leaves_the_running_configuration_alone(self, tmp_path):
        """The file is untouched and so is what the process is serving."""
        _seed(tmp_path)
        config = ConfigManager(str(tmp_path))
        serving = config.settings.audience

        with pytest.raises(DocumentRejected):
            YamlWriter(str(tmp_path)).update_oauth_settings(audience="")

        assert config.settings.audience == serving

    def test_a_directly_mutated_settings_object_is_not_rolled_back(self, tmp_path):
        """Deliberate, and worth stating: ``config.settings.x = ...``
        followed by a refused ``save()`` leaves the object as the caller
        left it. Undoing it would mean this call quietly reverting a
        mutation it did not make, and the surfaces that matter (the
        settings form, MCP update_settings) hand values in rather than
        keeping them here. The refusal is about the file.
        """
        _seed(tmp_path)
        config = ConfigManager(str(tmp_path))
        config.settings.token_expiry_minutes = -5

        with pytest.raises(DocumentRejected):
            config.save()

        assert config.settings.token_expiry_minutes == -5


class TestEveryWriterGoesThroughIt:
    """One boundary, not one per caller."""

    def test_the_single_file_save_helpers_refuse_too(self, tmp_path):
        """They exist for callers that want one file written and notified,
        not for a second contract in the same class."""
        _seed(tmp_path)
        config = ConfigManager(str(tmp_path))
        before = (tmp_path / "settings.yaml").read_text()
        config.settings.token_expiry_minutes = -5

        with pytest.raises(DocumentRejected):
            config._save_settings()

        assert (tmp_path / "settings.yaml").read_text() == before

    def test_every_save_path_hands_the_primitive_the_check(self, tmp_path, monkeypatch):
        """_save_users writes from User objects, which validate on
        assignment, so no value reaches it that the models would refuse:
        the check there is defence, and a behavioural test cannot tell
        whether it is passed. The rule is structural - one contract for the
        class, not one per method - so it is pinned structurally.
        """
        import nanoidp.config as config_module

        _seed(tmp_path)
        config = ConfigManager(str(tmp_path))
        seen = []
        real = config_module.compare_and_replace

        def recording(file_path, expected, mutate, validate=None):
            seen.append((file_path.name, validate))
            return real(file_path, expected, mutate, validate)

        monkeypatch.setattr(config_module, "compare_and_replace", recording)

        config._save_users()
        config._save_settings()

        assert [name for name, _ in seen] == ["users.yaml", "settings.yaml"]
        assert all(validate is not None for _name, validate in seen), seen

    def test_the_wizard_refuses_and_leaves_no_directory_behind(self, tmp_path):
        """``nanoidp init`` asks for an issuer as free text, and a document
        model accepts a string that is not a URL: the wizard used to finish
        by writing a directory the server it just configured cannot start
        from."""
        from nanoidp import wizard

        config_dir = tmp_path / "fresh"

        with pytest.raises(DocumentRejected):
            wizard._create_config(
                str(config_dir), "127.0.0.1", "8000", "localhost:8000", "my-app",
                "demo", "secret", "Demo", "admin", "admin", "a@example.org", "60",
            )

        assert list(config_dir.glob("*.yaml")) == []

    def test_a_good_wizard_run_produces_a_directory_that_loads(self, tmp_path):
        from nanoidp import wizard

        config_dir = tmp_path / "fresh"
        wizard._create_config(
            str(config_dir), "127.0.0.1", "8000", "http://localhost:8000", "my-app",
            "demo", "secret", "Demo", "admin", "admin", "a@example.org", "60",
        )

        assert ConfigManager(str(config_dir)).settings.issuer == "http://localhost:8000"


class TestTheCheckItself:
    """``reject_unloadable`` directly, for the halves no writer reaches on
    its own today but that must not regress silently."""

    def test_a_users_document_the_models_refuse_is_rejected(self, tmp_path):
        from nanoidp.config_documents import reject_unloadable

        with pytest.raises(DocumentRejected) as refused:
            reject_unloadable(
                [(tmp_path / "users.yaml", {"users": {"admin": {"email": "not-an-email"}}})]
            )

        assert "users.yaml" in refused.value.message

    def test_the_message_does_not_carry_the_server_directory(self, tmp_path):
        """The caller has been told the file name; the absolute path the
        server happens to run from is not theirs to see."""
        from nanoidp.config_documents import reject_unloadable

        settings = tmp_path / "settings.yaml"
        with pytest.raises(DocumentRejected) as refused:
            reject_unloadable([(settings, {"oauth": {"token_expiry_minutes": "not a number"}})])

        assert str(settings) not in refused.value.message
        assert refused.value.message.count("settings.yaml") == 1

    def test_the_declared_mode_is_read_before_the_placeholders_are_expanded(
        self, tmp_path, monkeypatch
    ):
        """The loader reads config_validation literally, so a placeholder
        there means "warn" to it. Reading it after expansion would refuse a
        write the load would have accepted."""
        from nanoidp.config_documents import reject_unloadable

        monkeypatch.setenv("NANOIDP_TEST_MODE", "strict")
        document = {
            "config_validation": "${NANOIDP_TEST_MODE}",
            "oauth": {"issuer": "http://localhost:8000"},
            "not_a_key_anyone_knows": True,
        }

        reject_unloadable([(tmp_path / "settings.yaml", document)])


class TestPlaceholdersAreNotTheValidatedValue:
    """The loader expands ``${VAR}`` before the models see it, so the check
    has to expand a copy: what is written keeps the placeholder, what is
    validated is what the next load will actually read."""

    def test_an_unrelated_write_leaves_a_placeholder_alone(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NANOIDP_TEST_AUD", "from-the-environment")
        for name in ("settings.yaml", "users.yaml"):
            shutil.copy(_REPO / "config" / name, tmp_path / name)
        document = _settings(tmp_path)
        document["oauth"]["audience"] = "${NANOIDP_TEST_AUD}"
        (tmp_path / "settings.yaml").write_text(yaml.safe_dump(document))
        ConfigManager(str(tmp_path))
        writer = YamlWriter(str(tmp_path))

        writer.update_oauth_settings(token_expiry_minutes=45)

        raw = (tmp_path / "settings.yaml").read_text()
        assert "${NANOIDP_TEST_AUD}" in raw
        assert _settings(tmp_path)["oauth"]["token_expiry_minutes"] == 45

    def test_a_placeholder_whose_value_the_models_reject_is_refused(self, tmp_path, monkeypatch):
        """The question is whether the file would load in this environment,
        which is the one the next process starts in."""
        monkeypatch.setenv("NANOIDP_TEST_AUD", "")
        writer = _seed(tmp_path)
        before = (tmp_path / "settings.yaml").read_text()

        with pytest.raises(DocumentRejected):
            writer.update_oauth_settings(audience="${NANOIDP_TEST_AUD}")

        assert (tmp_path / "settings.yaml").read_text() == before


class TestTheWholeSaveOrNoneOfIt:
    """``ConfigManager.save()`` composes both files and the check sees both
    before either is written, so one unacceptable document stops the save
    rather than half of it.

    The reachable half is settings.yaml: ``User`` sets
    ``validate_assignment``, so a bad user value raises where it is
    assigned and never becomes a document. ``Settings`` does not, which is
    the asymmetry this whole boundary exists for.
    """

    def test_a_user_change_does_not_land_when_the_settings_are_refused(self, tmp_path):
        _seed(tmp_path)
        config = ConfigManager(str(tmp_path))
        users_before = (tmp_path / "users.yaml").read_text()
        config.users["admin"].email = "changed@example.org"
        config.settings.token_expiry_minutes = -5

        with pytest.raises(DocumentRejected):
            config.save()

        assert (tmp_path / "users.yaml").read_text() == users_before

    def test_both_land_when_both_are_acceptable(self, tmp_path):
        _seed(tmp_path)
        config = ConfigManager(str(tmp_path))
        config.users["admin"].email = "changed@example.org"
        config.settings.audience = "also-changed"

        config.save()

        users = yaml.safe_load((tmp_path / "users.yaml").read_text())
        assert users["users"]["admin"]["email"] == "changed@example.org"
        assert _settings(tmp_path)["oauth"]["audience"] == "also-changed"

    def test_a_bad_user_value_never_gets_as_far_as_a_document(self, tmp_path):
        """Not this boundary's doing, and worth pinning so a future change
        to User's model_config does not quietly move that rule here."""
        _seed(tmp_path)
        config = ConfigManager(str(tmp_path))

        with pytest.raises(ValueError):
            config.users["admin"].email = "not-an-email"
