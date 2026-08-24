"""
The JSON Schema of the configuration files, derived from the document models.

``nanoidp config-schema`` renders it; ``docs/schema/config.v1.json`` is the
committed artifact and a test fails when the two diverge (#175 piece 3). The
point of generating it is that it cannot become a seventh restatement of the
contract (see #174): the schema has no content of its own, it is
``SettingsDocument`` / ``UsersDocument`` / ``BootstrapDocument`` rendered by
pydantic, so a field added to a model is in the schema on the next run and a
field invented in the schema is impossible.

The artifact is a container, not itself a schema: it holds the three
schemas under ``settings``, ``users`` and ``bootstrap``, next to the
``config_version`` they describe. Each one is a complete, standalone JSON
Schema with its own ``$schema``, ``$id`` and ``$defs``, so a consumer picks
the one it wants (``.settings`` for ``settings.yaml``) and validates with it
directly, no reference resolution across the container needed. Three
separate files would work too; one file keeps the version and the three
shapes together, which is the whole point of the contract.

One thing the schema cannot express: a ``${VAR}`` placeholder is a string
until it is expanded, and the expansion produces a string too, which
pydantic then coerces to the field's type. A generic JSON Schema tool has
no such coercion, so it reports ``port: ${PORT:8000}`` (and its expansion,
``"8000"``) as a type error against ``"type": "integer"``. Editor
completion and typo detection - what the artifact is for - work either way;
the type check of a placeholder-fed non-string field is what
``nanoidp validate-config`` is for, since it runs the real loader.

Output is deterministic (``sort_keys``, two-space indent, trailing newline):
the artifact is meant to be diffed in review and regenerated in a pre-commit
hook, so a rerun must produce a byte-identical file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Type

from pydantic import BaseModel

from .config_documents import BootstrapDocument, SettingsDocument, UsersDocument
from .serialization import CONFIG_VERSION

# YAML file name (without extension) -> the model that describes it.
SCHEMA_MODELS: Dict[str, Type[BaseModel]] = {
    "settings": SettingsDocument,
    "users": UsersDocument,
    "bootstrap": BootstrapDocument,
}

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
# Identity of the artifact and of the three resources embedded in it. Not a
# URL anything fetches: a JSON Schema $id is a name, and this one is stable
# per config_version so a tool can pin it.
SCHEMA_ID_BASE = f"https://cdelmonte-zg.github.io/nanoidp/schema/config.v{CONFIG_VERSION}"

# Where `--write` puts the artifact, relative to the repository root.
SCHEMA_ARTIFACT = Path("docs") / "schema" / f"config.v{CONFIG_VERSION}.json"


def file_schema(name: str) -> Dict[str, Any]:
    """The complete, standalone JSON Schema of one configuration file."""
    model = SCHEMA_MODELS[name]
    schema = model.model_json_schema(ref_template="#/$defs/{model}")
    return {
        "$schema": JSON_SCHEMA_DIALECT,
        "$id": f"{SCHEMA_ID_BASE}-{name}.json",
        **schema,
    }


def build_schema_document() -> Dict[str, Any]:
    """The full artifact: one schema per file plus the contract version."""
    document: Dict[str, Any] = {
        "title": "NanoIDP configuration directory",
        "description": (
            "One JSON Schema per configuration file, generated from the "
            "document models in nanoidp.config_documents by "
            "`nanoidp config-schema --write`. Do not edit by hand. Each of "
            "settings, users and bootstrap is a standalone schema; validate "
            "a file against the entry of the same name."
        ),
        "config_version": CONFIG_VERSION,
    }
    for name in SCHEMA_MODELS:
        document[name] = file_schema(name)
    return document


def render(document: Dict[str, Any]) -> str:
    """Deterministic JSON text, with the trailing newline a file wants."""
    return json.dumps(document, sort_keys=True, indent=2) + "\n"


def repo_root() -> Path:
    """The checkout this package is running from.

    ``--write`` targets a path inside the repository, so it only makes sense
    from a source checkout: an installed wheel has no ``docs/`` to write to,
    and this returns the directory that would have to contain it.
    """
    return Path(__file__).resolve().parents[2]


def artifact_path() -> Path:
    """Absolute path of the committed schema artifact in this checkout."""
    return repo_root() / SCHEMA_ARTIFACT


def write_artifact() -> Path:
    """Regenerate ``docs/schema/config.v1.json``; raises outside a checkout."""
    root = repo_root()
    if not (root / "pyproject.toml").exists():
        raise RuntimeError(
            f"{root} is not a nanoidp source checkout: config-schema --write "
            "regenerates a file tracked in the repository and works from a "
            "checkout only. Redirect the output instead: "
            "nanoidp config-schema > config.v1.json"
        )
    target = root / SCHEMA_ARTIFACT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(build_schema_document()))
    return target
