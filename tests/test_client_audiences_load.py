"""
Tests for friendly loading of client ``additional_audiences`` from settings.yaml
(issue #35).

A scalar value is a common single-value footgun; it is coerced to a one-element
list. Unsupported shapes raise a clear, client-scoped error at load time instead
of a raw Pydantic ValidationError that aborts startup with an opaque trace.
"""

import pytest

from nanoidp.config import ConfigManager, _coerce_additional_audiences


def _write_config(tmp_path, audiences_yaml: str):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "settings.yaml").write_text(
        'oauth:\n'
        '  issuer: "http://localhost:8000"\n'
        '  audience: "my-app"\n'
        '  clients:\n'
        '    - client_id: "c1"\n'
        '      client_secret: "s1"\n'
        f'{audiences_yaml}'
    )
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )
    return config_dir


class TestCoerceHelper:
    def test_none_returns_empty(self):
        assert _coerce_additional_audiences(None, "c1") == []

    def test_scalar_string_wrapped(self):
        assert _coerce_additional_audiences("api://x", "c1") == ["api://x"]

    def test_empty_scalar_returns_empty(self):
        assert _coerce_additional_audiences("", "c1") == []

    def test_list_of_strings_passthrough_drops_empty(self):
        assert _coerce_additional_audiences(["a", "", "b"], "c1") == ["a", "b"]

    def test_non_string_item_raises_with_client_name(self):
        with pytest.raises(ValueError, match="c1"):
            _coerce_additional_audiences([123], "c1")

    def test_wrong_type_raises_with_client_name(self):
        with pytest.raises(ValueError, match="c1"):
            _coerce_additional_audiences({"a": 1}, "c1")


class TestLoadFromYaml:
    def test_scalar_additional_audiences_loads_as_list(self, tmp_path):
        config_dir = _write_config(tmp_path, '      additional_audiences: "api://single"\n')
        config = ConfigManager(str(config_dir))
        client = config.get_client("c1")
        assert client.additional_audiences == ["api://single"]

    def test_list_additional_audiences_loads(self, tmp_path):
        config_dir = _write_config(
            tmp_path,
            '      additional_audiences:\n'
            '        - "api://a"\n'
            '        - "api://b"\n',
        )
        config = ConfigManager(str(config_dir))
        assert config.get_client("c1").additional_audiences == ["api://a", "api://b"]

    def test_non_string_item_aborts_with_clear_error(self, tmp_path):
        config_dir = _write_config(
            tmp_path,
            '      additional_audiences:\n'
            '        - 123\n',
        )
        with pytest.raises(ValueError, match="c1"):
            ConfigManager(str(config_dir))
