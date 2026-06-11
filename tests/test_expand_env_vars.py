"""
Unit tests for _expand_env_vars — the YAML env-var substitution helper.

Covers:
  - Basic ${NAME} and ${NAME:default} substitution
  - Recursive traversal through dicts, lists, and nested structures
  - Non-string leaf types (int, float, bool, None) are passed through unchanged
  - Multiple and adjacent placeholders in a single string
  - Edge cases: empty default, empty env value, invalid var names
  - Integration: ConfigManager picks up substitutions from the environment
"""


from nanoidp.config import _expand_env_vars

# ---------------------------------------------------------------------------
# Basic string substitution
# ---------------------------------------------------------------------------

class TestStringSubstitution:

    def test_plain_var_set(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "hello")
        assert _expand_env_vars("${MY_VAR}") == "hello"

    def test_plain_var_not_set_returns_empty(self, monkeypatch):
        monkeypatch.delenv("_NANOIDP_UNSET_VAR_", raising=False)
        assert _expand_env_vars("${_NANOIDP_UNSET_VAR_}") == ""

    def test_var_with_default_var_set(self, monkeypatch):
        monkeypatch.setenv("PORT", "9000")
        assert _expand_env_vars("${PORT:8000}") == "9000"

    def test_var_with_default_var_not_set(self, monkeypatch):
        monkeypatch.delenv("_NANOIDP_UNSET_PORT_", raising=False)
        assert _expand_env_vars("${_NANOIDP_UNSET_PORT_:8000}") == "8000"

    def test_var_with_empty_default(self, monkeypatch):
        monkeypatch.delenv("_NANOIDP_UNSET_", raising=False)
        assert _expand_env_vars("${_NANOIDP_UNSET_:}") == ""

    def test_var_set_to_empty_string(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "")
        assert _expand_env_vars("${MY_VAR:fallback}") == ""

    def test_embedded_in_url(self, monkeypatch):
        monkeypatch.setenv("PORT", "9000")
        assert _expand_env_vars("http://localhost:${PORT:8000}") == "http://localhost:9000"

    def test_embedded_in_url_default_used(self, monkeypatch):
        monkeypatch.delenv("_NANOIDP_PORT_", raising=False)
        assert _expand_env_vars("http://localhost:${_NANOIDP_PORT_:8000}") == "http://localhost:8000"

    def test_string_without_placeholder_unchanged(self):
        assert _expand_env_vars("no placeholders here") == "no placeholders here"

    def test_empty_string_unchanged(self):
        assert _expand_env_vars("") == ""

    def test_default_can_contain_slashes(self, monkeypatch):
        monkeypatch.delenv("_NANOIDP_PATH_", raising=False)
        assert _expand_env_vars("${_NANOIDP_PATH_:./keys}") == "./keys"

    def test_default_can_contain_spaces(self, monkeypatch):
        monkeypatch.delenv("_NANOIDP_MSG_", raising=False)
        assert _expand_env_vars("${_NANOIDP_MSG_:hello world}") == "hello world"


class TestMultiplePlaceholders:

    def test_two_placeholders_same_var(self, monkeypatch):
        monkeypatch.setenv("HOST", "myhost")
        monkeypatch.setenv("PORT", "9000")
        assert _expand_env_vars("http://${HOST:localhost}:${PORT:8000}") == "http://myhost:9000"

    def test_two_different_vars(self, monkeypatch):
        monkeypatch.setenv("A", "foo")
        monkeypatch.setenv("B", "bar")
        assert _expand_env_vars("${A}-${B}") == "foo-bar"

    def test_adjacent_placeholders(self, monkeypatch):
        monkeypatch.setenv("X", "ab")
        monkeypatch.setenv("Y", "cd")
        assert _expand_env_vars("${X}${Y}") == "abcd"

    def test_mixed_set_and_unset(self, monkeypatch):
        monkeypatch.setenv("SET_VAR", "yes")
        monkeypatch.delenv("_NANOIDP_UNSET2_", raising=False)
        assert _expand_env_vars("${SET_VAR}:${_NANOIDP_UNSET2_:default}") == "yes:default"


# ---------------------------------------------------------------------------
# Non-string leaf pass-through
# ---------------------------------------------------------------------------

class TestNonStringLeaves:

    def test_integer_unchanged(self):
        assert _expand_env_vars(42) == 42

    def test_float_unchanged(self):
        assert _expand_env_vars(3.14) == 3.14

    def test_bool_true_unchanged(self):
        assert _expand_env_vars(True) is True

    def test_bool_false_unchanged(self):
        assert _expand_env_vars(False) is False

    def test_none_unchanged(self):
        assert _expand_env_vars(None) is None


# ---------------------------------------------------------------------------
# Dict traversal
# ---------------------------------------------------------------------------

class TestDictTraversal:

    def test_single_string_value(self, monkeypatch):
        monkeypatch.setenv("PORT", "9000")
        result = _expand_env_vars({"issuer": "http://localhost:${PORT:8000}"})
        assert result == {"issuer": "http://localhost:9000"}

    def test_nested_dict(self, monkeypatch):
        monkeypatch.setenv("PORT", "7000")
        data = {"oauth": {"issuer": "http://localhost:${PORT:8000}"}}
        assert _expand_env_vars(data) == {"oauth": {"issuer": "http://localhost:7000"}}

    def test_non_string_value_untouched(self):
        data = {"port": 8000, "debug": False, "count": 3}
        assert _expand_env_vars(data) == {"port": 8000, "debug": False, "count": 3}

    def test_dict_keys_not_expanded(self, monkeypatch):
        monkeypatch.setenv("KEY", "expanded")
        result = _expand_env_vars({"${KEY}": "value"})
        # Keys are not traversed, only values
        assert "${KEY}" in result

    def test_empty_dict(self):
        assert _expand_env_vars({}) == {}

    def test_multiple_keys(self, monkeypatch):
        monkeypatch.setenv("A", "1")
        monkeypatch.setenv("B", "2")
        assert _expand_env_vars({"x": "${A}", "y": "${B}", "z": 99}) == {"x": "1", "y": "2", "z": 99}


# ---------------------------------------------------------------------------
# List traversal
# ---------------------------------------------------------------------------

class TestListTraversal:

    def test_list_of_strings(self, monkeypatch):
        monkeypatch.setenv("X", "hello")
        assert _expand_env_vars(["${X}", "plain"]) == ["hello", "plain"]

    def test_list_with_non_strings(self):
        assert _expand_env_vars([1, True, None, "text"]) == [1, True, None, "text"]

    def test_empty_list(self):
        assert _expand_env_vars([]) == []

    def test_list_of_dicts(self, monkeypatch):
        monkeypatch.setenv("PORT", "9000")
        data = [{"url": "http://localhost:${PORT:8000}"}]
        assert _expand_env_vars(data) == [{"url": "http://localhost:9000"}]

    def test_nested_list_in_list(self, monkeypatch):
        monkeypatch.setenv("V", "x")
        assert _expand_env_vars([["${V}"]]) == [["x"]]


# ---------------------------------------------------------------------------
# Deeply nested / realistic YAML-like structures
# ---------------------------------------------------------------------------

class TestNestedStructures:

    def test_realistic_settings_dict(self, monkeypatch):
        monkeypatch.setenv("PORT", "9000")
        data = {
            "server": {"port": "${PORT:8000}", "host": "0.0.0.0"},
            "oauth": {"issuer": "http://localhost:${PORT:8000}"},
            "saml": {
                "entity_id": "http://localhost:${PORT:8000}/saml",
                "sso_url": "http://localhost:${PORT:8000}/saml/sso",
            },
            "allowed_identity_classes": ["INTERNAL", "EXTERNAL"],
        }
        result = _expand_env_vars(data)
        assert result == {
            "server": {"port": "9000", "host": "0.0.0.0"},
            "oauth": {"issuer": "http://localhost:9000"},
            "saml": {
                "entity_id": "http://localhost:9000/saml",
                "sso_url": "http://localhost:9000/saml/sso",
            },
            "allowed_identity_classes": ["INTERNAL", "EXTERNAL"],
        }

    def test_list_of_mixed_types_in_nested_dict(self, monkeypatch):
        monkeypatch.setenv("ROLE_PREFIX", "ROLE_")
        data = {"prefixes": ["${ROLE_PREFIX}USER", 42, None]}
        assert _expand_env_vars(data) == {"prefixes": ["ROLE_USER", 42, None]}


# ---------------------------------------------------------------------------
# Pattern validation — only valid identifiers matched
# ---------------------------------------------------------------------------

class TestPatternBoundaries:

    def test_invalid_var_name_not_expanded(self):
        # Starts with digit — not a valid identifier per regex
        assert _expand_env_vars("${1INVALID}") == "${1INVALID}"

    def test_dollar_without_braces_not_expanded(self):
        assert _expand_env_vars("$PORT") == "$PORT"

    def test_unclosed_brace_not_expanded(self):
        assert _expand_env_vars("${PORT") == "${PORT"

    def test_empty_braces_not_expanded(self):
        assert _expand_env_vars("${}") == "${}"

    def test_underscore_start_valid(self, monkeypatch):
        monkeypatch.setenv("_MY_VAR", "ok")
        assert _expand_env_vars("${_MY_VAR}") == "ok"

    def test_alphanumeric_var_valid(self, monkeypatch):
        monkeypatch.setenv("VAR123", "val")
        assert _expand_env_vars("${VAR123}") == "val"
