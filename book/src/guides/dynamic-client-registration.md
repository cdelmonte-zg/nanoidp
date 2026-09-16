# Dynamic client registration

An MCP host is often given nothing but a server URL. RFC 7591 is how it
turns that into a `client_id`: it posts the metadata it needs, and the
authorization server issues the client. nanoidp implements it so that such a
host can be exercised end to end against a test IdP, together with the
minimum of RFC 7592 needed to read and remove what was registered.

It is **off by default**, because it is an unauthenticated endpoint that
creates clients:

```yaml
oauth:
  dynamic_registration:
    enabled: true
    max_clients: 100      # live registrations at once
```

There is no switch for this in the settings form or in the MCP
`update_settings` tool, on purpose: opening the endpoint is a decision for
the file. The `management_secret` does not gate `/register` either. With the
flag off, `/register` answers 404 and discovery does not advertise it.

## Registering

```bash
curl -X POST http://localhost:8000/register \
  -H 'Content-Type: application/json' \
  -d '{
        "redirect_uris": ["http://localhost:3000/callback"],
        "token_endpoint_auth_method": "none",
        "client_name": "My MCP host",
        "scope": "openid profile"
      }'
```

```json
{
  "client_id": "dcr-8mF1s0T_",
  "client_id_issued_at": 1789600000,
  "redirect_uris": ["http://localhost:3000/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code"],
  "scope": "openid profile",
  "client_name": "My MCP host",
  "registration_access_token": "...",
  "registration_client_uri": "http://localhost:8000/register/dcr-8mF1s0T_"
}
```

The client is usable immediately, on every flow a declared client can use.
Omitting `token_endpoint_auth_method` means `client_secret_basic`, per the
RFC, and the response then also carries `client_secret` and
`client_secret_expires_at: 0`.

**The registration access token is shown once.** It is the credential for
the two management calls below, and the server keeps only its hash.

## Reading and removing

```bash
curl http://localhost:8000/register/dcr-8mF1s0T_ \
  -H "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN"

curl -X DELETE http://localhost:8000/register/dcr-8mF1s0T_ \
  -H "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN"
```

A read returns the registration, the delete removes the client with it. A
wrong credential and an unknown registration answer the same 401, so the
endpoint cannot be used to discover which client ids exist.

## What a registered client is

A runtime client, the same kind `/api/runtime` creates: it lives in the
server's memory, is listed by `GET /api/runtime/clients` with
`"origin": "runtime"` and `"source": "dcr"`, and **is gone when the process
restarts**. It is never written to `settings.yaml` by registering.

An operator who wants to keep one promotes it, with the same call that
promotes any runtime client:

```bash
curl -X POST http://localhost:8000/api/runtime/clients/dcr-8mF1s0T_/promote
```

The client becomes declared configuration, and RFC 7592 management of it
ends there: the registration record is dropped, and its access token stops
working. The same happens when the client is deleted or reset, or when a
reload declares a client of that name.

## What is accepted, and what is only recorded

The metadata nanoidp understands is `redirect_uris`,
`token_endpoint_auth_method`, `grant_types`, `scope` and `client_name`.
Anything else in the request is ignored rather than refused, as RFC 7591
asks of a server for metadata it does not understand.

- `redirect_uris` must be present and must be absolute URIs, whatever the
  grant types say. A declared client may leave the list empty to mean "any
  redirect URI"; a registration may not, since the grant types it sends are
  recorded rather than enforced and would otherwise be a way around the
  requirement. Matching rules are a declared client's.
- `scope` is narrowed to the server's vocabulary and the granted subset is
  echoed back. A `scope` naming nothing the server supports is refused
  rather than registered as "any scope". Asking for no scope at all grants
  the vocabulary as it stands, written out in the registration, so a scope
  added to the server later does not widen a client registered earlier.
- `client_name` becomes the client's description.
- `grant_types` are checked against what the server supports and returned as
  registered, but **they do not restrict the client**: nanoidp has no
  per-client grant enforcement, and registration does not add one.

## Limits and errors

| Case | Answer |
| --- | --- |
| Disabled | `404` |
| Metadata nanoidp cannot use | `400 invalid_client_metadata` |
| Missing, empty or relative `redirect_uris` | `400 invalid_redirect_uri` |
| `max_clients` live registrations reached | `429 registration_limit_reached` |
| Wrong or missing registration access token | `401 invalid_token` |
| Too many requests, with `rate_limit_enabled` | `429 rate_limit_exceeded` |

`registration_limit_reached` is nanoidp's own name: RFC 7591's error codes
describe metadata, and none of them means "no more room". A promotion or a
delete frees a slot straight away.

**The limit does not heal on its own.** Registrations have no expiry, so
slots are freed only by deleting, promoting or resetting the clients that
hold them, or by restarting the process. On an instance anyone can reach,
that means anyone can fill it: with `rate_limit_enabled`, the rate
configured for `/token` applies to `/register` as well, which is what makes
filling it slow rather than instant. `DELETE /api/runtime` clears every
runtime client, registrations included.

The two responses that carry credentials, the registration and the RFC 7592
read, are sent with `Cache-Control: no-store`.
