"""Field schema fragments derived from the domain models (#297).

A tool argument that carries a domain field's value takes its **shape** from
that field: type, enum, bounds, length, pattern, item type. The tool keeps
what is its own: the description of the argument, and what the operation
requires (``update_user`` takes a partial patch of a model whose full
representation demands more, so ``required`` is never derived).

Before this, every fragment was written by hand next to the model, and the
two drifted in one direction only: the published schema advertised less than
the domain enforced (no `minLength`, no colour pattern, no expiry range), so
a client learned the rule from the tool's answer instead of from the schema.
"""

from typing import Any, Dict, Optional, Type

from pydantic import BaseModel

# The keys that describe a value's shape. Everything else a model's JSON
# schema carries (title, description, default) belongs to the tool, not to
# the domain field.
SHAPE_KEYS = (
    "type",
    "enum",
    "items",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
)


def _first_concrete(fragment: Dict[str, Any], label: str) -> Dict[str, Any]:
    """The value branch of an ``Optional[...]`` field.

    Pydantic renders it as ``anyOf: [<the type>, {"type": "null"}]``; a tool
    argument is optional through ``required``, not through a null branch.

    A field with more than one value branch has no single shape to publish.
    Falling back to the whole ``anyOf`` would leave nothing behind the shape
    filter below and quietly publish an argument with no constraints at all,
    so it raises instead: the first such field should be a decision, not a
    silently wider schema.
    """
    branches = fragment.get("anyOf")
    if not branches:
        return fragment
    concrete = [branch for branch in branches if branch.get("type") != "null"]
    if len(concrete) != 1:
        raise ValueError(f"{label} is a union of {len(concrete)} value types; pick one shape")
    return concrete[0]


def field_shape(model: Type[BaseModel], field: str) -> Dict[str, Any]:
    """The shape of ``model``'s ``field``, as JSON Schema keys."""
    properties = model.model_json_schema(ref_template="#/$defs/{model}")["properties"]
    if field not in properties:
        raise KeyError(f"{model.__name__} has no field {field!r}")
    label = f"{model.__name__}.{field}"
    fragment = _first_concrete(properties[field], label)
    shape = {key: value for key, value in fragment.items() if key in SHAPE_KEYS}
    if not shape:
        raise ValueError(f"{label} has no publishable shape")
    if "items" in shape:
        shape["items"] = {
            key: value for key, value in shape["items"].items() if key in SHAPE_KEYS
        }
    return shape


class DomainProperty(Dict[str, Any]):
    """A tool property built from a domain field, remembering which one.

    The provenance is what the parity test reads: it recomputes the shape
    from the model and compares, so a hand-edit of a derived fragment, or a
    model change the schema no longer reflects, fails the suite.
    """

    def __init__(
        self,
        fragment: Dict[str, Any],
        model: Type[BaseModel],
        field: str,
        overrides: Optional[Dict[str, Any]],
    ) -> None:
        super().__init__(fragment)
        self.model = model
        self.field = field
        self.overrides = dict(overrides or {})


def field_property(
    model: Type[BaseModel],
    field: str,
    description: str,
    *,
    overrides: Optional[Dict[str, Any]] = None,
) -> "DomainProperty":
    """One tool property: the field's shape, the tool's description.

    ``overrides`` is for the few arguments whose vocabulary is not the
    field's: a value of ``None`` drops a derived key, for a tool that accepts
    something the field does not (an empty string meaning "none" or "clear"),
    and any other value replaces it. An override is visible here, next to the
    argument it belongs to, rather than hidden in a hand-written copy.
    """
    shape = {**field_shape(model, field), **(overrides or {})}
    fragment = {
        **{key: value for key, value in shape.items() if value is not None},
        "description": description,
    }
    return DomainProperty(fragment, model, field, overrides)
