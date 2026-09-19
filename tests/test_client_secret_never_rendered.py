"""No stored client secret, and no substring of one, is rendered by a read.

The clients page used to show ``secret[:8] + "..." + secret[-4:]``. For a
secret of 12 characters or fewer that is every character of it, and the page
is a read: ``management_secret`` gates mutations only, so with the gate on a
caller who could change nothing could still read a client's secret off the
page and authenticate as that client at ``/token``.

The contract pinned here is the simple one: the cell shows the same fixed
mask for every confidential client, whatever the secret and however long it
is, for the three origins a confidential client can have (declared, created
through ``/api/runtime``, registered through ``/register``). The mask being
constant matters as much as the secret being absent: a mask as long as the
secret would give the length away.
"""

from __future__ import annotations

import pathlib
import shutil

import pytest
import yaml
from lxml import html

from nanoidp.app import create_app

_REPO = pathlib.Path(__file__).resolve().parent.parent
MANAGEMENT_SECRET = "the-reader-does-not-know-this"
_PROOF = {"X-Management-Secret": MANAGEMENT_SECRET}

# 40 distinct characters, mixed so that no run of four reads as a word the
# page could contain by accident; test_the_canary_is_not_vacuous checks that
# rather than trusting it.
_CANARY = "Zq7Xj9Kw3Vy5Rb1Tn8Mc2Ld6Pf4Gs0HhUuWwIiOo"
LENGTHS = range(1, 41)


def _secret(length: int) -> str:
    return _CANARY[:length]


def _grams(secret: str, size: int = 4) -> set[str]:
    return {secret[i:i + size] for i in range(len(secret) - size + 1)}


@pytest.fixture
def ui(tmp_path):
    """An instance with the management gate on and UI login off, which is the
    posture where a read is all the caller has."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for name in ("settings.yaml", "users.yaml"):
        shutil.copy(_REPO / "config" / name, config_dir / name)
    settings = config_dir / "settings.yaml"
    document = yaml.safe_load(settings.read_text())
    document["jwt"]["keys_dir"] = str(tmp_path / "keys")
    document.setdefault("session", {})["management_secret"] = MANAGEMENT_SECRET
    document["oauth"]["dynamic_registration"] = {"enabled": True}
    document["oauth"]["clients"] = [
        {"client_id": f"declared-{n:02d}", "client_secret": _secret(n)} for n in LENGTHS
    ] + [{"client_id": "declared-public", "token_endpoint_auth_method": "none"}]
    settings.write_text(yaml.safe_dump(document))
    app = create_app(str(config_dir))
    app.config["TESTING"] = True
    return app.test_client()


def _cells(page: str) -> dict[str, str]:
    """client_id -> the text of its secret cell, for every row of the table."""
    cells = {}
    for row in html.fromstring(page).xpath("//table//tbody/tr"):
        columns = row.xpath("./td")
        client_id = columns[0].xpath(".//code/text()")[0]
        cells[client_id] = " ".join(columns[2].text_content().split())
    return cells


def _page(ui) -> str:
    response = ui.get("/clients")  # no proof of the management secret
    assert response.status_code == 200
    return response.get_data(as_text=True)


def test_the_gate_is_on_and_the_page_is_still_a_read(ui):
    assert ui.post("/api/audit/clear").status_code == 401
    assert ui.get("/clients").status_code == 200


def test_the_canary_is_not_vacuous(ui):
    """A four-character run of the canary appearing in the page for another
    reason would make the absence checks below flaky, and a page that lost
    its rows would make them pass for nothing. Checked on the page with the
    secret cells cut out, so that this holds before and after the fix."""
    document = html.fromstring(_page(ui))
    rows = document.xpath("//table//tbody/tr")
    assert len(rows) >= len(LENGTHS) + 1
    for row in rows:
        cell = row.xpath("./td")[2]
        cell.getparent().remove(cell)
    rest = html.tostring(document, encoding="unicode")
    assert not {gram for gram in _grams(_CANARY) if gram in rest}


@pytest.mark.parametrize("length", LENGTHS)
def test_a_declared_secret_of_any_length_is_not_in_the_page(ui, length):
    page = _page(ui)
    secret = _secret(length)
    if length >= 4:
        assert not {gram for gram in _grams(secret) if gram in page}
    assert secret not in _cells(page)[f"declared-{length:02d}"]


def test_the_cell_is_one_fixed_mask_whatever_the_secret(ui):
    cells = _cells(_page(ui))
    masks = {cells[f"declared-{n:02d}"] for n in LENGTHS}
    assert len(masks) == 1, masks
    (mask,) = masks
    assert mask and not set(mask) & set(_CANARY)
    assert cells["declared-public"] == "public (none)"


def test_a_runtime_client_gets_the_same_mask(ui):
    declared_mask = _cells(_page(ui))["declared-20"]
    for length in (5, 12, 13, 32):
        created = ui.post(
            "/api/runtime/clients",
            json={"client_id": f"runtime-{length:02d}", "client_secret": _secret(length)[::-1]},
            headers=_PROOF,
        )
        assert created.status_code == 201, created.get_json()

    page = _page(ui)
    cells = _cells(page)
    for length in (5, 12, 13, 32):
        assert cells[f"runtime-{length:02d}"] == declared_mask
        assert not {gram for gram in _grams(_secret(length)[::-1]) if gram in page}


def test_a_dynamically_registered_client_gets_the_same_mask(ui):
    declared_mask = _cells(_page(ui))["declared-20"]
    registered = ui.post(
        "/register",
        json={
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )
    assert registered.status_code == 201, registered.get_json()
    body = registered.get_json()

    page = _page(ui)
    assert _cells(page)[body["client_id"]] == declared_mask
    assert not {gram for gram in _grams(body["client_secret"]) if gram in page}


# What a path argument of a management read is filled with. A read that grows
# an argument this table does not know fails the sweep below, on purpose: the
# new route gets looked at instead of being skipped.
_ARGUMENTS = {
    "client_id": ["declared-12", "declared-40", "runtime-12"],
    "username": ["admin"],
    "format": ["json", "csv"],
    "key_type": ["public_key", "certificate"],
}
_MANAGEMENT_BLUEPRINTS = {"ui", "api", "runtime"}


def _management_reads(app):
    for rule in app.url_map.iter_rules():
        if "GET" not in rule.methods or rule.endpoint.split(".")[0] not in _MANAGEMENT_BLUEPRINTS:
            continue
        unknown = set(rule.arguments) - set(_ARGUMENTS)
        assert not unknown, f"{rule.rule}: no value for {sorted(unknown)} in _ARGUMENTS"
        urls = [rule.rule]
        for argument in rule.arguments:
            converter = next(c for c in ("<path:", "<string:", "<") if f"{c}{argument}>" in rule.rule)
            urls = [u.replace(f"{converter}{argument}>", v) for u in urls for v in _ARGUMENTS[argument]]
        yield from urls


def test_no_management_read_carries_a_stored_client_secret(ui):
    """The clients page was the one place that did, and nothing keeps it the
    only candidate: every GET of the UI, of /api and of /api/runtime is
    fetched without proof and searched for every stored client secret."""
    created = ui.post(
        "/api/runtime/clients",
        json={"client_id": "runtime-12", "client_secret": _secret(12)[::-1]},
        headers=_PROOF,
    )
    assert created.status_code == 201, created.get_json()
    stored = [_secret(n) for n in LENGTHS if n >= 4] + [_secret(12)[::-1]]
    grams = set().union(*(_grams(secret) for secret in stored))

    urls = sorted(set(_management_reads(ui.application)))
    assert len(urls) > 25, urls
    leaks = {}
    for url in urls:
        response = ui.get(url)
        assert response.status_code < 500, url
        found = {gram for gram in grams if gram in response.get_data(as_text=True)}
        if found:
            leaks[url] = sorted(found)[:3]
    assert not leaks
