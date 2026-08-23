"""
Strict validation and ``nanoidp validate-config`` (#175 piece 4).

Covers: the ``--strict-config`` flag, ``config_validation: strict`` in
settings.yaml and the precedence between them; the CLI's exit codes on
clean / warning / error directories including a bootstrap.yaml finding; the
guarantee that validating a directory never executes what its hooks declare;
and the MCP ``validate_config`` tool.
"""

import json
from pathlib import Path

import pytest
import yaml

from nanoidp.config import ConfigManager
from nanoidp.config_validation import (
    ERROR,
    WARNING,
    validate_config_dir,
    validate_config_result,
)


def write_config(directory: Path, settings=None, users=None, bootstrap=None) -> str:
    """A minimal but complete config directory."""
    doc = {"oauth": {"issuer": "http://localhost:8000"}}
    doc.update(settings or {})
    (directory / "settings.yaml").write_text(yaml.safe_dump(doc))
    (directory / "users.yaml").write_text(
        yaml.safe_dump(users or {"users": {"alice": {"password": "x"}}})
    )
    if bootstrap is not None:
        (directory / "bootstrap.yaml").write_text(yaml.safe_dump(bootstrap))
    return str(directory)


def levels(findings):
    return [f.level for f in findings]


class TestStrictLoading:
    def test_unknown_key_warns_by_default(self, tmp_path, caplog):
        config_dir = write_config(tmp_path, {"oauth": {"isuer": "x"}})
        with caplog.at_level("WARNING"):
            manager = ConfigManager(config_dir)
        assert manager.strict_config is False
        assert any("unknown key oauth.isuer" in r.message for r in caplog.records)

    def test_strict_flag_refuses_to_load(self, tmp_path):
        config_dir = write_config(tmp_path, {"oauth": {"isuer": "x"}})
        with pytest.raises(ValueError) as exc:
            ConfigManager(config_dir, strict_config=True)
        assert "unknown key oauth.isuer" in str(exc.value)
        assert "settings.yaml" in str(exc.value)

    def test_strict_from_yaml_refuses_to_load(self, tmp_path):
        config_dir = write_config(
            tmp_path, {"config_validation": "strict", "oauth": {"isuer": "x"}}
        )
        with pytest.raises(ValueError, match="unknown key oauth.isuer"):
            ConfigManager(config_dir)

    def test_flag_wins_over_yaml(self, tmp_path):
        """--strict-config is an override in both directions, like --profile."""
        config_dir = write_config(
            tmp_path, {"config_validation": "strict", "oauth": {"isuer": "x"}}
        )
        manager = ConfigManager(config_dir, strict_config=False)
        assert manager.strict_config is False
        assert manager.settings.issuer == "http://localhost:8000"

        # ... and the other way round: warn in the file, strict on the flag.
        clean = tmp_path / "clean"
        clean.mkdir()
        strict_manager = ConfigManager(write_config(clean), strict_config=True)
        assert strict_manager.strict_config is True

    def test_strict_is_never_persisted(self, tmp_path):
        """The flag is transient: a save must not write config_validation."""
        config_dir = write_config(tmp_path)
        manager = ConfigManager(config_dir, strict_config=True)
        manager.save()
        written = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert "config_validation" not in written

    def test_yaml_value_survives_a_save(self, tmp_path):
        config_dir = write_config(tmp_path, {"config_validation": "strict"})
        manager = ConfigManager(config_dir)
        assert manager.strict_config is True
        manager.save()
        written = yaml.safe_load((tmp_path / "settings.yaml").read_text())
        assert written["config_validation"] == "strict"

    def test_strict_applies_to_users_yaml(self, tmp_path):
        config_dir = write_config(
            tmp_path,
            {"config_validation": "strict"},
            users={"users": {"alice": {"password": "x"}}, "defualt_user": "alice"},
        )
        with pytest.raises(ValueError) as exc:
            ConfigManager(config_dir)
        assert "unknown key defualt_user" in str(exc.value)
        assert "users.yaml" in str(exc.value)

    def test_strict_applies_to_bootstrap_yaml(self, tmp_path):
        """bootstrap.yaml is read before settings.yaml but follows its
        declaration: one contract for the directory."""
        config_dir = write_config(
            tmp_path,
            {"config_validation": "strict"},
            bootstrap={"hooks": {"on_before_load": "true"}, "plugns": {}},
        )
        with pytest.raises(ValueError) as exc:
            ConfigManager(config_dir)
        assert "unknown key plugns" in str(exc.value)
        assert "bootstrap.yaml" in str(exc.value)

    def test_wrong_type_is_an_error_either_way(self, tmp_path):
        config_dir = write_config(tmp_path, {"oauth": {"token_expiry_minutes": "soon"}})
        with pytest.raises(ValueError, match="invalid value at oauth.token_expiry_minutes"):
            ConfigManager(config_dir)

    def test_unknown_validation_mode_is_reported_with_its_path(self, tmp_path):
        config_dir = write_config(tmp_path, {"config_validation": "paranoid"})
        with pytest.raises(ValueError, match="invalid value at config_validation"):
            ConfigManager(config_dir)

    def test_strict_survives_a_reload(self, tmp_path):
        config_dir = write_config(tmp_path)
        manager = ConfigManager(config_dir, strict_config=True)
        (tmp_path / "settings.yaml").write_text(
            yaml.safe_dump({"oauth": {"issuer": "http://localhost:8000", "isuer": "x"}})
        )
        with pytest.raises(ValueError, match="unknown key oauth.isuer"):
            manager.reload()

    def test_yaml_strict_takes_effect_on_the_next_reload(self, tmp_path):
        config_dir = write_config(tmp_path)
        manager = ConfigManager(config_dir)
        assert manager.strict_config is False
        (tmp_path / "settings.yaml").write_text(
            yaml.safe_dump(
                {
                    "config_validation": "strict",
                    "oauth": {"issuer": "http://localhost:8000", "isuer": "x"},
                }
            )
        )
        with pytest.raises(ValueError, match="unknown key oauth.isuer"):
            manager.reload()


class TestValidateConfigDir:
    def test_clean_directory_has_no_findings(self, tmp_path):
        assert validate_config_dir(write_config(tmp_path)) == []

    def test_unknown_key_is_a_warning(self, tmp_path):
        findings = validate_config_dir(write_config(tmp_path, {"oauth": {"isuer": "x"}}))
        assert levels(findings) == [WARNING]
        assert "unknown key oauth.isuer" in findings[0].message

    def test_wrong_type_is_an_error(self, tmp_path):
        findings = validate_config_dir(
            write_config(tmp_path, {"oauth": {"token_expiry_minutes": "soon"}})
        )
        assert levels(findings) == [ERROR]
        assert "invalid value at oauth.token_expiry_minutes" in findings[0].message

    def test_bootstrap_finding_is_reported(self, tmp_path):
        findings = validate_config_dir(
            write_config(tmp_path, bootstrap={"hooks": {"stric": True}})
        )
        assert levels(findings) == [WARNING]
        assert "bootstrap.yaml" in findings[0].message
        assert "unknown key hooks.stric" in findings[0].message

    def test_every_file_is_reported_not_just_the_first(self, tmp_path):
        findings = validate_config_dir(
            write_config(
                tmp_path,
                {"oauth": {"isuer": "x"}},
                users={"users": {"alice": {"password": "x"}}, "defualt_user": "a"},
                bootstrap={"plugns": {}},
            )
        )
        assert {f.file for f in findings} == {"settings.yaml", "users.yaml", "bootstrap.yaml"}

    def test_domain_validators_run(self, tmp_path):
        """A file whose shape is fine can still be refused at startup: the
        duplicate client_id rule is not expressible in the document model."""
        findings = validate_config_dir(
            write_config(
                tmp_path,
                {
                    "oauth": {
                        "clients": [
                            {"client_id": "a", "client_secret": "s"},
                            {"client_id": "a", "client_secret": "t"},
                        ]
                    }
                },
            )
        )
        assert levels(findings) == [ERROR]
        assert "Duplicate OAuth client_id" in findings[0].message

    def test_broken_yaml_is_an_error(self, tmp_path):
        write_config(tmp_path)
        (tmp_path / "settings.yaml").write_text("oauth: [unclosed\n")
        findings = validate_config_dir(tmp_path)
        assert levels(findings) == [ERROR]
        assert "not valid YAML" in findings[0].message

    def test_missing_files_are_warnings(self, tmp_path):
        findings = validate_config_dir(tmp_path)
        assert levels(findings) == [WARNING, WARNING]

    def test_missing_directory_is_an_error(self, tmp_path):
        findings = validate_config_dir(tmp_path / "nope")
        assert levels(findings) == [ERROR]

    def test_placeholders_are_expanded_before_validation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NANOIDP_TEST_EXPIRY", "45")
        config_dir = write_config(
            tmp_path, {"oauth": {"token_expiry_minutes": "${NANOIDP_TEST_EXPIRY}"}}
        )
        assert validate_config_dir(config_dir) == []

    def test_version_mismatch_between_files(self, tmp_path):
        write_config(tmp_path, {"config_version": 1}, users={"config_version": 2, "users": {}})
        findings = validate_config_dir(tmp_path)
        assert ERROR in levels(findings)
        assert any("config_version" in f.message for f in findings)


class TestValidateConfigNeverRunsHooks:
    def test_bootstrap_hook_command_is_not_executed(self, tmp_path):
        """The point of validating instead of starting: a directory whose
        bootstrap.yaml names a command must be safe to look at."""
        marker = tmp_path / "hook-ran.txt"
        config_dir = write_config(
            tmp_path,
            bootstrap={"hooks": {"on_before_load": f"touch {marker}"}},
        )
        findings = validate_config_dir(config_dir)
        assert findings == []
        assert not marker.exists(), "validate-config executed a bootstrap hook"

    def test_settings_hook_command_is_not_executed(self, tmp_path):
        marker = tmp_path / "settings-hook-ran.txt"
        config_dir = write_config(
            tmp_path, {"hooks": {"on_before_load": f"touch {marker}"}}
        )
        assert validate_config_dir(config_dir) == []
        assert not marker.exists()

    def test_plugin_is_not_loaded(self, tmp_path):
        """An unknown plugin name is a load failure at startup; validating
        must not even look it up, so it produces no finding."""
        config_dir = write_config(
            tmp_path, {"plugins": {"definitely-not-installed": {"a": 1}}}
        )
        assert validate_config_dir(config_dir) == []

    def test_the_hook_does_run_when_the_server_starts(self, tmp_path):
        """Control for the two tests above: the same file, actually loaded."""
        marker = tmp_path / "hook-ran.txt"
        config_dir = write_config(
            tmp_path, bootstrap={"hooks": {"on_before_load": f"touch {marker}"}}
        )
        ConfigManager(config_dir)
        assert marker.exists()


class TestValidateConfigCli:
    def run(self, capsys, config_dir, strict=False):
        from nanoidp.__main__ import validate_config_command

        code = validate_config_command(str(config_dir), strict)
        return code, capsys.readouterr().out

    def test_clean_exits_zero(self, tmp_path, capsys):
        code, out = self.run(capsys, write_config(tmp_path))
        assert code == 0
        assert "ok: no findings" in out

    def test_warning_exits_zero_without_strict(self, tmp_path, capsys):
        code, out = self.run(capsys, write_config(tmp_path, {"oauth": {"isuer": "x"}}))
        assert code == 0
        assert "warning: " in out
        assert "unknown key oauth.isuer" in out

    def test_warning_exits_one_with_strict(self, tmp_path, capsys):
        code, out = self.run(
            capsys, write_config(tmp_path, {"oauth": {"isuer": "x"}}), strict=True
        )
        assert code == 1
        assert "unknown key oauth.isuer" in out

    def test_error_exits_one(self, tmp_path, capsys):
        code, out = self.run(
            capsys, write_config(tmp_path, {"oauth": {"token_expiry_minutes": "soon"}})
        )
        assert code == 1
        assert "error: " in out

    def test_bootstrap_finding_exits_one_under_strict(self, tmp_path, capsys):
        code, out = self.run(
            capsys, write_config(tmp_path, bootstrap={"hooks": {"stric": True}}), strict=True
        )
        assert code == 1
        assert "bootstrap.yaml" in out

    def test_declared_strict_fails_without_the_flag(self, tmp_path, capsys):
        """A directory the server would refuse to start on cannot lint clean."""
        code, out = self.run(
            capsys,
            write_config(tmp_path, {"config_validation": "strict", "oauth": {"isuer": "x"}}),
        )
        assert code == 1
        assert "(strict)" in out

    def test_one_line_per_finding(self, tmp_path, capsys):
        code, out = self.run(
            capsys,
            write_config(
                tmp_path,
                {"oauth": {"isuer": "x", "audiense": "y"}},
            ),
        )
        assert code == 0
        assert out.count("warning: ") == 2


class TestValidateConfigMcpTool:
    def test_result_shape(self, tmp_path):
        result = validate_config_result(write_config(tmp_path))
        assert result["valid"] is True
        assert result["findings"] == []
        assert result["config_validation"] == "warn"

    def test_warning_is_reported_but_still_valid(self, tmp_path):
        result = validate_config_result(write_config(tmp_path, {"oauth": {"isuer": "x"}}))
        assert result["valid"] is True
        assert result["findings"][0]["level"] == WARNING

    def test_strict_argument_invalidates_a_warning(self, tmp_path):
        result = validate_config_result(
            write_config(tmp_path, {"oauth": {"isuer": "x"}}), strict=True
        )
        assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_tool_call(self, tmp_path, monkeypatch, mcp_call_tool):
        marker = tmp_path / "hook-ran.txt"
        config_dir = write_config(
            tmp_path,
            {"oauth": {"isuer": "x"}},
            bootstrap={"hooks": {"on_config_saved": f"touch {marker}"}},
        )
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", config_dir)
        result = await mcp_call_tool("validate_config", {})
        payload = json.loads(result.content[0].text)
        assert payload["valid"] is True
        assert payload["findings"][0]["level"] == WARNING
        assert "unknown key oauth.isuer" in payload["findings"][0]["message"]
        assert result.is_error is False
        assert not marker.exists()

    @pytest.mark.asyncio
    async def test_tool_call_strict(self, tmp_path, monkeypatch, mcp_call_tool):
        config_dir = write_config(tmp_path, {"oauth": {"isuer": "x"}})
        monkeypatch.setenv("NANOIDP_CONFIG_DIR", config_dir)
        result = await mcp_call_tool("validate_config", {"strict": True})
        payload = json.loads(result.content[0].text)
        assert payload["valid"] is False
        # An invalid config is a truthful answer, not a failed call (#122).
        assert result.is_error is False

    @pytest.mark.asyncio
    async def test_tool_is_listed(self, mcp_list_tools):
        names = {tool.name for tool in await mcp_list_tools()}
        assert "validate_config" in names
