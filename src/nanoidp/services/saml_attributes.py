"""
The single home for SAML attribute resolution (#302).

Until 3.0 the two SAML surfaces resolved a user's attributes independently:
``_sso_build_attributes`` for the SSO assertion and an inline block in the
attribute-query route - and they had drifted in five observable ways. Both
now call :func:`resolve_saml_attributes`; the emission side shares
:func:`append_attribute_statement`.

What the unification DELIBERATELY changed (CHANGELOGed, each finishing a
rule the project had already decided):

- The attribute-query surface no longer fabricates ``<user>@example.com``
  when a user has no email (the #275 rule: never invent facts about a
  principal); an absent email is an absent attribute, on both surfaces.
- A custom attribute that is a LIST reaches the XML as one
  ``AttributeValue`` per entry, and a custom attribute that is a STRING is
  never split on commas (the #134 rule; the query surface used to
  ``",".join`` lists and then re-split any comma-bearing string).
- An EMPTY collection is an absent attribute, not an empty ``Attribute``
  element (the SSO surface used to emit one for ``entitlements: []``).

What stays DELIBERATELY different between the surfaces (documented in
book/src/reference/saml.md):

- ``source_acl`` is exported only by the attribute query
  (``include_source_acl=True``): that surface exists for backend
  authorization lookups; the SSO login assertion does not carry
  document-level ACLs.
- The SSO assertion carries AuthnStatement/SubjectConfirmation and an
  AudienceRestriction; the query assertion does not: an attribute lookup
  is not an authentication event (asserting one would be false), and the
  requester's audience is unknown.
"""

from typing import Any, Dict

from lxml import etree

_SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion"


def _add_export_attr(attrs: Dict[str, Any], name: str, values: Any) -> None:
    """Add an exported roles/groups attribute, merging on a name collision.

    ``saml_roles_attr_name`` and ``saml_groups_attr_name`` are configured
    independently, so both exports can target the same attribute (e.g.
    ``memberOf``). Plain assignment would let the second list silently
    replace the first (#134); merging keeps both, roles first, deduplicated.
    Moved verbatim from routes/saml.py (#302).
    """
    existing = attrs.get(name)
    if isinstance(existing, (list, tuple)):
        attrs[name] = list(existing) + [v for v in values if v not in existing]
    else:
        attrs[name] = list(values)


def resolve_saml_attributes(
    settings: Any, user: Any, *, include_source_acl: bool
) -> Dict[str, Any]:
    """The attribute set a SAML surface asserts for ``user``.

    Empty/None values are omitted (an absent fact is an absent attribute);
    roles/groups are opt-in under their configured SP-specific names; custom
    attributes pass through with their real types - the emission helper
    turns lists into one AttributeValue per entry.
    """
    attrs: Dict[str, Any] = {}
    if user.email:
        attrs["email"] = user.email
    if user.identity_class:
        attrs["identity_class"] = user.identity_class
    if user.entitlements:
        attrs["entitlements"] = list(user.entitlements)
    if include_source_acl and user.source_acl:
        attrs["source_acl"] = list(user.source_acl)
    if settings.saml_export_roles and user.roles:
        _add_export_attr(attrs, settings.saml_roles_attr_name, user.roles)
    if settings.saml_export_groups and user.groups:
        _add_export_attr(attrs, settings.saml_groups_attr_name, user.groups)
    if user.attributes:
        for key, value in user.attributes.items():
            if value is None or value == [] or value == "":
                continue
            attrs[key] = value
    return attrs


def append_attribute_statement(
    assertion: "etree._Element", attributes: Dict[str, Any]
) -> None:
    """Emit one AttributeStatement under ``assertion``, shared by both
    builders (#302): None skipped, a list/tuple becomes one AttributeValue
    per entry, anything else ONE value via str() - never comma-split (the
    #134 rule; the query builder used to split comma-bearing strings).
    Emits nothing at all when ``attributes`` is empty.
    """
    if not attributes:
        return
    statement = etree.SubElement(assertion, f"{{{_SAML2_NS}}}AttributeStatement")
    for name, value in attributes.items():
        if value is None:
            continue
        attribute = etree.SubElement(
            statement, f"{{{_SAML2_NS}}}Attribute", Name=name
        )
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            element = etree.SubElement(
                attribute, f"{{{_SAML2_NS}}}AttributeValue"
            )
            element.text = str(item)
