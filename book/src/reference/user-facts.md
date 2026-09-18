# What each surface says about a user

nanoidp asserts facts about a principal over two protocols and several
surfaces, and they do not all say the same thing. Until #316 each surface
documented only itself, so a difference between them existed only as a
consequence of two independently written assemblers, and nothing said which
differences were intended.

This page is that contract, and `tests/test_user_fact_contract.py` holds
it: each row below has a test that fails when the difference it states
appears or disappears. The one thing the tests do not re-derive is the
matrix itself, so a cell can still be written down wrongly - which is how
the `roles`/`groups` columns for the attribute query were wrong when this
page was first written, until a review read them against the resolver.

## The matrix

| Fact | Access token | ID Token | `/userinfo` (`dev`) | `/userinfo` (gated) | SAML SSO | SAML attribute query |
|---|---|---|---|---|---|---|
| `email` | no | no | yes | needs the `email` scope | yes | yes |
| `identity_class` | yes | no | yes | yes | yes | yes |
| `entitlements` | yes | no | no | no | yes | yes |
| `roles` | yes | no | yes | yes | opt-in, under the SP's name | opt-in, under the SP's name |
| `groups` | yes | no | yes | yes | opt-in, under the SP's name | opt-in, under the SP's name |
| `tenant` | yes | no | yes | yes | never | never |
| `source_acl` | yes | no | no | no | no | yes |
| `attributes` | a map | no | a map | a map | one attribute per key | one attribute per key |
| `authorities` | yes | no | no | no | no | no |

The ID Token carries no user fact at all unless the client asks for one
through the [`claims` request parameter](tokens.md).

**Opt-in** means `saml_export_roles` and `saml_export_groups`, which are
**false by default**: out of the box a SAML assertion carries neither roles
nor groups while an access token always carries both. The two settings
govern **both** SAML surfaces, which share one resolver, so turning an
export on adds the attribute to the login assertion and to the attribute
query alike. `source_acl` is the only attribute-level difference between
those two surfaces, as the [SAML reference](saml.md) states.

## Why the differences are what they are

**`tenant` is OIDC-only.** It has been on the access token since the first
commit and has never been exported over SAML. That began as an omission
rather than a decision; it is a decision now, because adding it would
change the assertions every service provider under test already receives.

**`authorities` exists only on the access token.** It is a derived
convenience for resource servers: the roles, groups, identity class,
entitlements and ACL entries of a user flattened into one prefixed list,
plus any custom attribute that has a prefix configured for its name, so
`authority_prefixes: {department: DEPT_}` puts `DEPT_IT` in the list beside
`ROLE_DEV`. See [Configuration](configuration.md) for the prefixes. It is
not an identity claim, and no identity surface offers it.

**`source_acl` is on the access token and the attribute query only.** Both
are read by a backend deciding what a principal may reach. A login
assertion carries no document-level ACLs, and `/userinfo` describes a
person rather than their reach.

**`entitlements` is not in the default `/userinfo` response**, because the
ungated claim list is `roles`, `groups`, `tenant`, `identity_class` and
`attributes` (see [Tokens and claims](tokens.md)). A client that needs it
asks for it through the `claims` parameter, and then gets it.

**`email` is on no OAuth token.** Clients read it from `/userinfo`, which
is what OpenID Connect Core §5.4 expects and what the tokens reference
tells them.

**Custom attributes have two shapes.** On the OIDC surfaces they arrive as
one `attributes` map, a passthrough of what the operator wrote. On the SAML
surfaces each key becomes its own `Attribute` element, because an assertion
has no nested shape to carry a map in.

## `claims_supported` and what is requestable

These are two different lists, and the difference is deliberate.

`claims_supported` in the discovery document is what OpenID Connect Core 3
§3 defines it to be: the claims this provider **may be able to supply
values for** in an ID Token or a UserInfo response. It is not a list of
names the `claims` request parameter accepts.

- `attributes` **is** advertised, because `/userinfo` returns it. It is
  **not** a claim name: a `claims` request asking for `attributes` is
  skipped like any unknown name.
- An **individual** custom attribute **is** a claim name: a user with a
  `department` attribute answers a `claims` request for `department`.
- Consequently `resolve_user_claim("attributes")` succeeds only for a user
  who owns a custom attribute called `attributes`, and what it returns is
  that custom claim, not the UserInfo map. The collision is documented
  rather than fixed: renaming either would break one of the two meanings.
- `source_acl` and `authorities` are **not** advertised, since #316. They
  reach no ID Token and no UserInfo response, so promising them was a
  promise the endpoints could not keep, the same rule #41 applied to
  `response_types_supported`.
