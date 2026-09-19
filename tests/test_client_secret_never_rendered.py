"""No management read renders material derived from a stored client secret.

The clients page used to show ``secret[:8] + "..." + secret[-4:]``. For a
secret of 12 characters or fewer that is every character of it, and the page
is a read: ``management_secret`` gates mutations only, so with the gate on a
caller who could change nothing could still read a client's secret off the
page and authenticate as that client at ``/token``.

Two properties are pinned here. The strong one is about the cell: it is
independent of both the value and the length of the stored secret, one fixed
mask for the three origins a confidential client can have (declared, created
through ``/api/runtime``, registered through ``/register``). A mask as long
as the secret would hide the value and give the length away.

The other is about every read: none renders material derived from a stored
secret. "No substring" would be the wrong way to say it, since a one-letter
secret is a substring of any page; that is why the checks below use a canary,
runs of four and eight characters, and cut random base64 before the short
search. And it is about reads available without client-specific
authorization: an RFC 7592 read returns that client's own secret to the
holder of its registration access token, which the sweep does not present.
"""

from __future__ import annotations

import itertools
import pathlib
import re
import shutil

import pytest
import yaml
from flask import url_for
from lxml import html

from nanoidp.app import create_app

_REPO = pathlib.Path(__file__).resolve().parent.parent
MANAGEMENT_SECRET = "the-reader-does-not-know-this"
_PROOF = {"X-Management-Secret": MANAGEMENT_SECRET}

# 40 distinct characters, mixed so that no run of four reads as a word the
# page could contain by accident; test_the_canary_is_not_vacuous checks that
# rather than trusting it. The declared secrets are slices of it.
_CANARY = "Zq7Xj9Kw3Vy5Rb1Tn8Mc2Ld6Pf4Gs0HhUuWwIiOo"
# A second canary for the runtime and dynamically-registered secrets. Those
# two are the only secrets the sweep used to search that were not slices of
# _CANARY - the runtime one was reversed, the DCR one was server-generated
# and random - so their 4-grams were outside the canary's vacuity guarantee
# and could coincide with page chrome (the ~2.3%/run false positive this
# change removes). Giving them slices of a second canary puts every searched
# 4-gram back under that guarantee. Its 4-grams are disjoint from _CANARY's
# (test_the_two_canaries_are_distinguishable), so a match stays attributable.
_CANARY2 = "OgZwiYPV0XvzUJrdeBfIbuL3yacFoM2AQDR6Tkp1"
LENGTHS = range(1, 41)

# The runtime and DCR secrets, as disjoint forward slices of _CANARY2.
RUNTIME_SECRET = _CANARY2[:16]
REGISTERED_SECRET = _CANARY2[16:36]


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


@pytest.fixture
def registered_secret(monkeypatch):
    """`POST /register` issues a server-generated secret (`token_urlsafe`).
    Patch the generator at the name `routes/registration.py` resolved it to
    (it imports `new_client_secret` by name), so the sweep searches a
    canary-controlled value rather than a random one whose 4-grams can
    coincide with page chrome. `token_urlsafe` itself is left alone, so the
    client_id and the registration access token stay random."""
    monkeypatch.setattr(
        "nanoidp.routes.registration.new_client_secret", lambda: REGISTERED_SECRET
    )
    return REGISTERED_SECRET


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


def test_the_two_canaries_are_distinguishable(ui):
    """No 4-gram in common, so a fragment found in a page is attributable to
    one canary and the declared/runtime/DCR origins do not blur."""
    assert not (_grams(_CANARY) & _grams(_CANARY2))


def test_the_canary_is_not_vacuous(ui):
    """The whole approach rests on one fact: neither canary's 4-grams occur in
    the page for any reason other than a secret. If they did, the absence
    checks below would flake (a canary gram in chrome reads as a leak) or pass
    for nothing (a page that lost its rows). Checked on the clients page with
    the secret cells cut out - the only page that renders a secret at all - so
    it holds before and after the fix, and for both canaries now that both are
    searched."""
    document = html.fromstring(_page(ui))
    rows = document.xpath("//table//tbody/tr")
    assert len(rows) >= len(LENGTHS) + 1
    for row in rows:
        cell = row.xpath("./td")[2]
        cell.getparent().remove(cell)
    rest = html.tostring(document, encoding="unicode")
    canary_grams = _grams(_CANARY) | _grams(_CANARY2)
    assert not {gram for gram in canary_grams if gram in rest}


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
            json={"client_id": f"runtime-{length:02d}", "client_secret": _CANARY2[:length]},
            headers=_PROOF,
        )
        assert created.status_code == 201, created.get_json()

    page = _page(ui)
    cells = _cells(page)
    for length in (5, 12, 13, 32):
        assert cells[f"runtime-{length:02d}"] == declared_mask
        assert not {gram for gram in _grams(_CANARY2[:length]) if gram in page}


def test_a_dynamically_registered_client_gets_the_same_mask(ui, registered_secret):
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
    # The registration really did carry the controlled secret, so the search
    # below is testing what it claims to.
    assert body["client_secret"] == registered_secret

    page = _page(ui)
    assert _cells(page)[body["client_id"]] == declared_mask
    # The client_id is still random (token_urlsafe is not patched): cut it, or
    # one run in ten thousand it shares four characters with the secret.
    rest = page.replace(body["client_id"], "")
    assert not {gram for gram in _grams(body["client_secret"]) if gram in rest}


# What a path argument of a read is filled with, per blueprint where the
# same name means different things. A read that grows an argument this table
# does not know fails the sweep below, on purpose: the new route gets looked
# at instead of being skipped.
_ARGUMENTS = {
    ("runtime", "client_id"): ["runtime-12", "<registered>"],
    ("runtime", "username"): ["runtime-user"],
    ("registration", "client_id"): ["<registered>"],
    "client_id": ["declared-12", "declared-40", "runtime-12", "<registered>"],
    "username": ["admin"],
    "format": ["json", "csv"],
    "key_type": ["public_key", "certificate"],
}
# The reads that must answer 200 once redirects are followed: a sweep that
# searched a 404 or an unfollowed 302 would prove nothing about the page.
# Every other GET (the protocol endpoints) is swept too, and only has to
# answer; there is no list of blueprints that are swept, only this one of
# blueprints that are held to more, so a new surface is never skipped.
_MUST_RENDER = {"ui", "api", "runtime", "health"}
_NOT_SWEPT = {"static"}
# Key pages, the JWKS and the SAML metadata carry thousands of fresh random
# base64 characters per run: searched for four-character runs they would
# report a "leak" about once in fifty runs. Long runs are cut before the
# short-gram search; whole secrets and eight-character runs are still
# searched in the untouched body.
_LONG_RUN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")


def _reads(app, registered_id):
    with app.test_request_context():
        for rule in app.url_map.iter_rules():
            blueprint = rule.endpoint.split(".")[0]
            if "GET" not in rule.methods or blueprint in _NOT_SWEPT:
                continue
            choices = []
            for argument in sorted(rule.arguments):
                values = _ARGUMENTS.get((blueprint, argument), _ARGUMENTS.get(argument))
                assert values, f"{rule.rule}: no value for {argument!r} in _ARGUMENTS"
                choices.append([(argument, v.replace("<registered>", registered_id)) for v in values])
            for combination in itertools.product(*choices):
                yield blueprint, url_for(rule.endpoint, **dict(combination))


def test_no_read_carries_a_stored_client_secret(ui, registered_secret):
    """The clients page was the one place that did, and nothing keeps it the
    only candidate: every GET the application routes is fetched without proof
    of the management secret and searched for every stored client secret,
    declared, runtime and dynamically registered."""
    assert ui.post(
        "/api/runtime/clients",
        json={"client_id": "runtime-12", "client_secret": RUNTIME_SECRET},
        headers=_PROOF,
    ).status_code == 201
    assert ui.post(
        "/api/runtime/users",
        json={"username": "runtime-user", "password": "irrelevant-here"},
        headers=_PROOF,
    ).status_code == 201
    registered = ui.post(
        "/register",
        json={
            "redirect_uris": ["https://client.example/callback"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    ).get_json()
    assert registered["client_secret"] == registered_secret

    stored = [_secret(n) for n in LENGTHS] + [RUNTIME_SECRET, registered["client_secret"]]
    whole = [secret for secret in stored if len(secret) >= 8]
    long_grams = set().union(*(_grams(secret, 8) for secret in stored))
    short_grams = set().union(*(_grams(secret, 4) for secret in stored))
    # By construction every searched 4-gram is a canary 4-gram, and the two
    # canaries do not occur in chrome (test_the_canary_is_not_vacuous). This
    # is what makes the sweep deterministic rather than flaky: it is why a
    # match is a leak and not a coincidence.
    assert short_grams <= _grams(_CANARY) | _grams(_CANARY2)

    reads = sorted(set(_reads(ui.application, registered["client_id"])))
    assert len(reads) > 40, reads
    leaks = {}
    for blueprint, url in reads:
        response = ui.get(url, follow_redirects=True)
        if blueprint in _MUST_RENDER:
            assert response.status_code == 200, (url, response.status_code)
        assert response.status_code < 500, (url, response.status_code)
        # The registered client's id is random too, and short enough to
        # survive the cut below.
        body = response.get_data(as_text=True).replace(registered["client_id"], "")
        found = {s for s in whole if s in body} | {g for g in long_grams if g in body}
        found |= {g for g in short_grams if g in _LONG_RUN.sub("", body)}
        if found:
            leaks[url] = sorted(found)[:3]
    assert not leaks
