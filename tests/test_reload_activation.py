"""A configuration does not become active if the signing service it needs
cannot be built (#359).

The load prepares the candidate's signing service before it commits
anything, publishes it only once nothing can fail any more, and publishes it
before the settings; readers take the settings first.
"""

import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import jwt
import yaml

import nanoidp.services.token as token_module
from nanoidp.app import create_app
from nanoidp.config import get_config
from nanoidp.services.crypto import get_crypto_service

_REPO = Path(__file__).resolve().parent.parent
_AUTH = {"Authorization": "Basic " + base64.b64encode(b"demo-client:demo-secret").decode()}


def _unusable_keys_dir(tmp_path: Path) -> str:
    """A keys_dir no platform can create: a directory inside a regular file."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    return str(blocker / "keys")


def _config_dir(tmp_path: Path, keys_dir: str) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True)
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    _set_settings(config_dir, lambda doc: doc["jwt"].update(keys_dir=keys_dir))
    return config_dir


def _set_settings(config_dir: Path, mutate) -> None:
    settings = config_dir / "settings.yaml"
    doc = yaml.safe_load(settings.read_text())
    mutate(doc)
    settings.write_text(yaml.safe_dump(doc))


def _app(config_dir: Path):
    app = create_app(str(config_dir))
    app.config["TESTING"] = True
    return app, app.test_client()


def _token(client) -> str:
    response = client.post(
        "/token",
        data={"grant_type": "password", "username": "admin", "password": "admin"},
        headers=_AUTH,
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    return response.get_json()["access_token"]


def _served_kids(client) -> set:
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    return {key["kid"] for key in response.get_json()["keys"]}


class TestReloadRejectsAnUnusableSigningConfiguration:
    def test_http_reload_answers_422_and_the_previous_key_keeps_signing(self, tmp_path):
        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        app, client = _app(config_dir)
        kid_before = jwt.get_unverified_header(_token(client))["kid"]

        unusable = _unusable_keys_dir(tmp_path)
        _set_settings(config_dir, lambda doc: doc["jwt"].update(keys_dir=unusable))
        response = client.post("/api/config/reload")

        assert response.status_code == 422
        body = response.get_json()
        assert body["status"] == "error" and body["kind"] == "activation"
        assert unusable in body["error"]
        assert get_config().settings.keys_dir == str(tmp_path / "keys")
        token = _token(client)
        assert jwt.get_unverified_header(token)["kid"] == kid_before
        assert kid_before in _served_kids(client)
        introspection = client.post("/introspect", data={"token": token}, headers=_AUTH)
        assert introspection.get_json()["active"] is True

    def test_mcp_reload_fails_and_keeps_the_running_configuration(self, tmp_path, mcp_call_tool):
        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        _app(config_dir)
        published = get_crypto_service()

        unusable = _unusable_keys_dir(tmp_path)
        _set_settings(config_dir, lambda doc: doc["jwt"].update(keys_dir=unusable))
        result = json.loads(asyncio.run(mcp_call_tool("reload_config", {})).content[0].text)

        assert result["success"] is False and result["kind"] == "activation"
        assert get_config().settings.keys_dir == str(tmp_path / "keys")
        assert get_crypto_service() is published

    def test_the_refresh_after_a_ui_write_rejects_it_too(self, tmp_path):
        from nanoidp.config import ConfigurationRejected
        from nanoidp.services.yaml_writer import get_yaml_writer

        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        _app(config_dir)
        published = get_crypto_service()
        user = get_config().get_user("admin")
        unusable = _unusable_keys_dir(tmp_path)
        # Edited on disk by someone else; the next UI write refreshes from it.
        _set_settings(config_dir, lambda doc: doc["jwt"].update(keys_dir=unusable))

        try:
            get_yaml_writer().save_user(user)
        except ConfigurationRejected as exc:
            assert exc.kind == "activation"
        else:
            raise AssertionError("the refresh accepted an unusable keys_dir")

        assert get_config().settings.keys_dir == str(tmp_path / "keys")
        assert get_crypto_service() is published

    def test_an_invalid_file_is_rejected_the_same_way(self, tmp_path):
        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        app, client = _app(config_dir)
        (config_dir / "settings.yaml").write_text("jwt: [unclosed\n")

        response = client.post("/api/config/reload")

        assert response.status_code == 422
        assert response.get_json()["kind"] == "invalid"
        _token(client)


class TestActivationOrder:
    def test_a_reload_with_unchanged_key_inputs_keeps_the_signing_service(self, tmp_path):
        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        app, client = _app(config_dir)
        published = get_crypto_service()
        _set_settings(config_dir, lambda doc: doc["oauth"].update(token_expiry_minutes=17))

        assert client.post("/api/config/reload").status_code == 200

        assert get_config().settings.token_expiry_minutes == 17
        assert get_crypto_service() is published

    def test_a_strict_plugin_failure_after_prepare_publishes_nothing(self, tmp_path):
        config_dir = _config_dir(tmp_path, str(tmp_path / "keys-1"))
        app, client = _app(config_dir)
        published = get_crypto_service()

        def mutate(doc):
            doc["jwt"]["keys_dir"] = str(tmp_path / "keys-2")
            doc["hooks"] = {"strict": True}
            doc["plugins"] = {"missing": {}}

        _set_settings(config_dir, mutate)
        response = client.post("/api/config/reload")

        assert response.status_code == 503
        assert response.get_json()["kind"] == "plugin_load"
        # Prepared (the candidate's keys exist), never published.
        assert (tmp_path / "keys-2" / "rsa_private.pem").exists()
        assert get_crypto_service() is published
        assert get_config().settings.keys_dir == str(tmp_path / "keys-1")

    def test_a_reload_right_after_the_settings_read_still_signs_with_a_served_key(
        self, tmp_path, monkeypatch
    ):
        """Pins the read order in create_token(): settings, then the signing
        service. A reload moving keys_dir lands right after the settings read;
        reading the signing service afterwards gets the newly published one,
        which the JWKS serves. Were the service read first, the token would be
        signed with the old key the JWKS no longer serves."""
        config_dir = _config_dir(tmp_path, str(tmp_path / "keys-1"))
        app, client = _app(config_dir)
        _token(client)
        manager = get_config()
        reloaded = []

        class ReloadAfterSettingsRead:
            def __getattr__(self, name):
                return getattr(manager, name)

            @property
            def settings(self):
                snapshot = manager.settings
                if not reloaded:
                    reloaded.append(True)
                    _set_settings(
                        config_dir,
                        lambda doc: doc["jwt"].update(keys_dir=str(tmp_path / "keys-2")),
                    )
                    manager.reload()
                return snapshot

        monkeypatch.setattr(token_module, "get_config", lambda: ReloadAfterSettingsRead())
        token = _token(client)

        assert reloaded
        assert manager.settings.keys_dir == str(tmp_path / "keys-2")
        assert jwt.get_unverified_header(token)["kid"] in _served_kids(client)
        introspection = client.post("/introspect", data={"token": token}, headers=_AUTH)
        assert introspection.get_json()["active"] is True


class TestReadersTakeSettingsBeforeTheSigningService:
    """The rule get_crypto_service() documents, held by every reader.

    The activation publishes the signing service before the settings, so a
    reader that took the service first and the settings after could pair
    newer settings with an older service.
    """

    def test_no_function_reads_settings_after_resolving_the_signing_service(self):
        import ast

        offenders = []
        for path in sorted((_REPO / "src" / "nanoidp").rglob("*.py")):
            tree = ast.parse(path.read_text())
            for fn in ast.walk(tree):
                if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if fn.name in ("get_crypto_service", "crypto"):
                    continue
                resolved = [
                    node.lineno
                    for node in ast.walk(fn)
                    if (
                        isinstance(node, ast.Call)
                        and getattr(node.func, "id", getattr(node.func, "attr", None))
                        == "get_crypto_service"
                    )
                    or (
                        isinstance(node, ast.Attribute)
                        and node.attr == "crypto"
                        and isinstance(node.value, ast.Name)
                        and node.value.id == "self"
                    )
                ]
                if not resolved:
                    continue
                first = min(resolved)
                late = sorted(
                    {
                        node.lineno
                        for node in ast.walk(fn)
                        if isinstance(node, ast.Attribute)
                        and node.attr == "settings"
                        and node.lineno >= first
                    }
                )
                if late:
                    offenders.append(f"{path.relative_to(_REPO)}:{fn.name} reads settings at {late}")
        assert offenders == []

    @staticmethod
    def _reload_audience_after_the_service_is_resolved(monkeypatch, module, config_dir):
        """Wrap the module's get_crypto_service so a reload changing
        oauth.audience lands right after the service is resolved: a reader
        that reads its settings after that sees the new audience."""
        real = module.get_crypto_service
        reloaded = []

        def resolve_then_reload():
            service = real()
            if not reloaded:
                reloaded.append(True)
                _set_settings(config_dir, lambda doc: doc["oauth"].update(audience="moved-audience"))
                get_config().reload()
            return service

        monkeypatch.setattr(module, "get_crypto_service", resolve_then_reload)
        return reloaded

    def test_userinfo_verifies_with_the_settings_it_read_first(self, tmp_path, monkeypatch):
        import nanoidp.routes.oauth as oauth_module

        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        app, client = _app(config_dir)
        token = _token(client)
        reloaded = self._reload_audience_after_the_service_is_resolved(
            monkeypatch, oauth_module, config_dir
        )

        response = client.get("/userinfo", headers={"Authorization": f"Bearer {token}"})

        assert reloaded
        assert response.status_code == 200, response.get_data(as_text=True)

    def test_the_refresh_grant_verifies_with_the_settings_it_read_first(self, tmp_path, monkeypatch):
        import nanoidp.routes.oauth_grants as grants_module

        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        app, client = _app(config_dir)
        issued = client.post(
            "/token",
            data={"grant_type": "password", "username": "admin", "password": "admin"},
            headers=_AUTH,
        ).get_json()
        assert "refresh_token" in issued
        reloaded = self._reload_audience_after_the_service_is_resolved(
            monkeypatch, grants_module, config_dir
        )

        response = client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": issued["refresh_token"]},
            headers=_AUTH,
        )

        assert reloaded
        assert response.status_code == 200, response.get_data(as_text=True)


class TestConcurrentLoads:
    def test_loads_run_one_at_a_time(self, tmp_path):
        """Two concurrent loads moving keys_dir to a fresh directory would each
        generate keys there over the other and could publish a service whose
        private and public keys belong to different pairs."""
        import threading
        import time

        from nanoidp.config import init_config
        from nanoidp.services.crypto import activate_crypto_service

        active = []
        overlap = []

        def slow_activation(settings, config_dir=None):
            active.append(1)
            overlap.append(len(active))
            time.sleep(0.05)
            try:
                return activate_crypto_service(settings)
            finally:
                active.pop()

        config_dir = _config_dir(tmp_path, str(tmp_path / "keys-1"))
        manager = init_config(str(config_dir), activate=slow_activation)
        _set_settings(config_dir, lambda doc: doc["jwt"].update(keys_dir=str(tmp_path / "keys-2")))
        barrier = threading.Barrier(2)

        def reload():
            barrier.wait()
            manager.reload()

        threads = [threading.Thread(target=reload) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert max(overlap) == 1


class TestUnreadableFile:
    def test_an_unreadable_settings_file_is_rejected_as_json(self, tmp_path):
        import pytest

        if sys.platform == "win32" or os.geteuid() == 0:
            pytest.skip("file permissions do not restrict this user")
        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        app, client = _app(config_dir)
        settings = config_dir / "settings.yaml"
        settings.chmod(0)
        try:
            response = client.post("/api/config/reload")
        finally:
            settings.chmod(0o644)

        assert response.status_code == 422
        assert response.get_json()["kind"] == "invalid"
        _token(client)


class TestStartup:
    def _start(self, config_dir: Path) -> subprocess.CompletedProcess:
        env = dict(os.environ, PYTHONPATH=str(_REPO / "src"), PORT="8399")
        return subprocess.run(
            [sys.executable, "-m", "nanoidp", "--config", str(config_dir)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_an_unusable_keys_dir_is_a_configuration_error_not_a_traceback(self, tmp_path):
        unusable = _unusable_keys_dir(tmp_path)
        result = self._start(_config_dir(tmp_path, unusable))

        assert result.returncode == 1
        assert "error: configuration rejected:" in result.stderr
        assert unusable in result.stderr
        assert "Traceback" not in result.stderr

    def test_an_invalid_file_is_a_configuration_error_not_a_traceback(self, tmp_path):
        config_dir = _config_dir(tmp_path, str(tmp_path / "keys"))
        (config_dir / "settings.yaml").write_text("jwt: [unclosed\n")

        result = self._start(config_dir)

        assert result.returncode == 1
        assert "error: configuration rejected:" in result.stderr
        assert "Traceback" not in result.stderr
