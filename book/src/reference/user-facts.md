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

The ID Token carries `sub`, which is itself a Claim about the End-User. It
carries none of the application and profile facts in this matrix unless the
client asks for one through the [`claims` request
parameter](tokens.md).

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

## An empty value, and the three answers to it (#388)

An attribute the operator declared with an empty value - `""`, `[]`, `{}` or
nothing at all - reaches the three projections differently, and all three
are right:

| Projection | An empty value |
|---|---|
| `attributes` (the OIDC map) | kept |
| `authorities` (the derived list) | dropped |
| SAML attributes | dropped |

> Composite and raw representations preserve explicitly configured empty
> values. Derived projections may omit them when their output
> representation cannot preserve the distinction usefully, or when that
> surface has an established omission policy.

**The map keeps them** because it is lossless about exactly this: `{}`,
`{"x": ""}` and `{"x": []}` are three different documents. For a testing IdP
that is a useful property, since an operator can deliberately simulate an
upstream that supplies an empty claim and watch what the consumer does. The
key existing is itself something they wrote.

**`authorities` drops them** because a flat list of strings cannot say
"present but empty". Keeping an attribute `x: ""` under the prefix `X_`
would emit the bare string `X_`, which reads like an ordinary authority and
loses the distinction it was meant to carry. Representing it properly would
need an encoding invented for the purpose.

**SAML drops them by policy, not by limitation.** SAML 2.0 Core allows
`<Attribute Name="x"/>`, an attribute that exists with no values, and that
is semantically distinct from the attribute being absent. nanoidp could emit
it; [#315 chose otherwise](saml.md), so an absent or empty fact is an absent
attribute on both SAML surfaces.

So the disagreement between `authorities` and `attributes` inside one access
token is not a contradiction. They are two projections with different
representational capacity, and there is deliberately no shared
"is this a fact?" predicate: the answer depends on the projection.

## `claims_supported` and what the resolver addresses

These are two different lists, and the difference is deliberate.

`claims_supported` in the discovery document is what OpenID Connect
Discovery 1.0 §3 defines it to be: the Claim Names this provider **may be
able to supply values for**. It is not a list of names the `claims` request
parameter accepts, and OpenID Connect Core §5.5 does not require a
requested claim to be returned at all.

On top of that definition nanoidp holds **its own invariant**: only a claim
that can appear in an ID Token or a UserInfo response is advertised here.
That is a choice, not something the specification derives, and it is the
rule #41 applied to `response_types_supported`.

- `source_acl` and `authorities` are **not** advertised, since #316. They
  appear in neither an ID Token nor a UserInfo response, so under that
  invariant they do not belong, whatever an access token carries.
- `attributes` **is** advertised, and it **is** a Claim Name: Core §5.6.1
  says that for Normal Claims represented as JSON, the member name is the
  Claim Name, and `/userinfo` returns an `attributes` member. What it is
  not is **resolver-addressable**: `resolve_user_claim` does not know the
  composite map, so a `claims` request for `attributes` is not answered by
  the resolver.
- An **individual** custom attribute **is** resolver-addressable: a user
  with a `department` attribute answers a `claims` request for
  `department`.

### One name, two answers

A user who owns a custom attribute literally called `attributes` shows what
those two lists mean in practice:

```yaml
attributes:
  attributes: "custom"
```

```text
ID Token, with {"id_token": {"attributes": null}}   ->  "custom"
/userinfo                                           ->  {"attributes": "custom"}
```

The ID Token gets the scalar, because the resolver answers a request for
`attributes` from the user's own attribute map. UserInfo sets the composite
member first, and a requested claim never overwrites one already present,
so the map wins there. Both are documented rather than fixed: renaming
either would break one of the two meanings, and a user with such an
attribute is a test fixture, not a deployment.
