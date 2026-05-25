"""
Regression tests: persisting OAuth client `additional_audiences` (issue #32).

Before the fix, the YAML writer and the web-UI client handlers serialized only
client_id/client_secret/description and replaced the whole client entry, so any
save through the UI (edit, regenerate secret) silently dropped a client's
`additional_audiences` from disk — reverting its ID Token `aud` to a plain string.
"""

import pytest

from nanoidp.config import ConfigManager, OAuthClient, get_config
from nanoidp.services.yaml_writer import YamlWriter


def _seed_config(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "settings.yaml").write_text(
        'oauth:\n'
        '  issuer: "http://localhost:8000"\n'
        '  audience: "my-app"\n'
        '  clients:\n'
        '    - client_id: "c1"\n'
        '      client_secret: "s1"\n'
        '      additional_audiences:\n'
        '        - "https://api.example.com"\n'
        '        - "urn:service:billing"\n'
    )
    (config_dir / "users.yaml").write_text(
        'users:\n  admin:\n    password: "admin"\ndefault_user: admin\n'
    )
    return config_dir


class TestYamlWriterRoundTrip:
    """The YAML writer must persist and round-trip additional_audiences."""

    def test_save_client_persists_additional_audiences(self, tmp_path):
        config_dir = _seed_config(tmp_path)
        writer = YamlWriter(str(config_dir))

        writer.save_client(
            OAuthClient(
                client_id="c1",
                client_secret="s1",
                additional_audiences=["https://api.example.com", "urn:service:billing"],
            ),
            is_new=False,
        )

        reloaded = ConfigManager(str(config_dir))
        assert reloaded.get_client("c1").additional_audiences == [
            "https://api.example.com",
            "urn:service:billing",
        ]

    def test_save_client_can_clear_additional_audiences(self, tmp_path):
        """Saving a client with no extra audiences removes the key (no stale data)."""
        config_dir = _seed_config(tmp_path)
        writer = YamlWriter(str(config_dir))

        writer.save_client(
            OAuthClient(client_id="c1", client_secret="s1", additional_audiences=[]),
            is_new=False,
        )

        reloaded = ConfigManager(str(config_dir))
        assert reloaded.get_client("c1").additional_audiences == []


class TestClientUIPreservesAudiences:
    """Web-UI client handlers must not silently wipe additional_audiences.

    These exercise the real routes against the repo config; ``preserve_config_files``
    restores the on-disk config afterwards.
    """

    @pytest.fixture
    def admin_session(self, client):
        with client.session_transaction() as sess:
            sess["user"] = "admin"
        return client

    def test_regenerate_secret_preserves_audiences(self, admin_session, preserve_config_files):
        """Regenerate-secret has no form field, so it must carry over the existing audiences."""
        before = get_config().get_client("multi-aud-client").additional_audiences
        assert before  # sanity: the shipped config has them

        resp = admin_session.post(
            "/clients/multi-aud-client/regenerate-secret", follow_redirects=True
        )
        assert resp.status_code == 200

        after = get_config().get_client("multi-aud-client").additional_audiences
        assert after == before

    def test_edit_preserves_resubmitted_audiences(self, admin_session, preserve_config_files):
        """Editing a client (form re-submits the audiences) keeps them."""
        resp = admin_session.post(
            "/clients/multi-aud-client/edit",
            data={
                "description": "edited via UI",
                "additional_audiences": "https://api.example.com\nurn:service:billing",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200

        client_obj = get_config().get_client("multi-aud-client")
        assert client_obj.description == "edited via UI"
        assert client_obj.additional_audiences == [
            "https://api.example.com",
            "urn:service:billing",
        ]

    def test_edit_can_clear_audiences(self, admin_session, preserve_config_files):
        """Submitting an empty audiences field clears them (explicit user intent)."""
        resp = admin_session.post(
            "/clients/multi-aud-client/edit",
            data={"description": "no auds", "additional_audiences": ""},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert get_config().get_client("multi-aud-client").additional_audiences == []

    def test_create_sets_audiences(self, admin_session, preserve_config_files):
        """Creating a client through the UI persists audiences entered in the form."""
        resp = admin_session.post(
            "/clients/create",
            data={
                "client_id": "ui-created",
                "client_secret": "ui-secret",
                "description": "made in UI",
                "additional_audiences": "aud-a\n  \naud-b\n",  # blank line ignored
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert get_config().get_client("ui-created").additional_audiences == ["aud-a", "aud-b"]
