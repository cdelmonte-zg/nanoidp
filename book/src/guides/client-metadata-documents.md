# Client ID metadata documents

An MCP client can identify itself with an `https` URL instead of a name it
had to register. The URL is the `client_id`, and the document it points at
says what the client is: its redirect URIs, its name, the scopes it wants.
nanoidp reads that document so a developer can exercise the flow against a
test IdP.

It is **off by default**, because turning it on makes this server fetch a
URL a client chose:

```yaml
oauth:
  client_id_metadata_documents:
    enabled: true
    allowed_hosts:
      - client.example
    allow_loopback: false
```

Like dynamic client registration, there is no switch for this in the
settings form or in the MCP tools: it is a decision for the file.

## What happens, and where

```
https client_id at /authorize
        |
  declared? runtime? -> that client is used, nothing is fetched
        |
  neither -> fetch the document, validate it, cache it
        |
  /token, /introspect, /revoke read the cache and never fetch
```

**Only `/authorize` fetches.** Everything else reads what is cached, so a
client whose document has not been fetched is simply unknown at the token
endpoint. That is deliberate: a token request must not wait on somebody
else's web server.

A client an operator declares, or one created through `/api/runtime`, wins
over a document published under the same name, and is answered without the
cache being consulted at all.

## What the document must say

```json
{
  "client_id": "https://client.example/metadata.json",
  "redirect_uris": ["http://localhost:3000/callback"],
  "token_endpoint_auth_method": "none",
  "client_name": "My MCP client",
  "scope": "openid profile"
}
```

- `client_id` must be the URL it was fetched from, compared literally.
- `token_endpoint_auth_method` is `none`, and only `none`: the
  specification forbids every shared-secret method, and of the three
  nanoidp supports two are those. PKCE S256 applies, as for any public
  client.
- `redirect_uris` must be present and are matched exactly, the same rules a
  declared client gets.
- `scope` is narrowed to the server's vocabulary; asking for nothing the
  server supports is refused rather than granted as "any scope".
- Anything else in the document is ignored.

## The URL itself

`https`, no userinfo, no fragment, a path with no `.` or `..` segments. A
query and a bare `/` path are discouraged by the specification rather than
forbidden, so nanoidp accepts them and logs that it did.

## What the fetch will and will not do

This is the only outbound request nanoidp makes, so it is narrow on
purpose:

| | |
| --- | --- |
| Hosts | only those in `allowed_hosts`, matched as exact DNS names, **and only on the port named there** (443 when none is) |
| Addresses | only globally routable ones. Every address the name answers with must be acceptable, or the name is refused |
| Loopback | only with `allow_loopback`, only when nanoidp is itself on loopback, only on the same address family |
| Redirects | never followed |
| Answer | `200` only, and JSON only |
| Size | 5 KiB, enforced while reading |
| Time | 5 seconds for the whole fetch, including DNS and the TLS handshake |
| Retries | none, and no second address after a failed connection |

`allowed_hosts` is empty by default, which means nothing is fetched at all
until an operator names a host. An entry may carry a port
(`client.example:8443`); one that does not means 443 and no other port, so
naming a host does not turn this server into a way to reach every port on
it. The path is the client's, so a host you name is one whose whole URL
space a client may point this server at.

## The cache

A fetched document is kept in memory for what its `Cache-Control` allows,
within this server's own bounds, and at most 100 documents at a time. It is
lost on restart, and it is not shared between nanoidp processes.

Only successes are cached: a failed fetch or an invalid document is never
remembered, so a bad answer cannot stick.

A document whose response says `no-store` or `no-cache` is **refused at the
authorization request**. The cache is the only place such a client exists
between `/authorize` and `/token`, so honouring the header would mean
issuing a code that could never be redeemed. If a client's host sets that
header globally, it cannot be identified this way.

An entry is kept at least as long as any authorization code issued against
it: the document is cached when it is fetched and the code is minted later,
when the login finishes, so a short `max-age` would otherwise leave a valid
code with no client behind it. The same promise holds against the cap: an
entry a live code depends on is not evicted to make room for a new client.
If every one of the 100 entries is holding up a live code, the new
authorization request is refused instead, because breaking a flow already
under way is the worse of the two outcomes.

An operator's **Forget** still drops such an entry, and any code issued
against it stops being redeemable. That is a deliberate administrative act,
and it is not treated as an accident.

The web UI lists cached clients read-only with a `cimd` badge, and a
**Forget** button drops one: that is how a developer re-fetches a document
they have just changed.

## When something is refused

Every refusal answers the authorization request with the same
`invalid_client` / `Unknown client_id` a name nobody knows would get.
Saying which rule refused it would tell whoever chose the URL whether a
host is allowed, whether it resolved, or what it answered. **The reason is
in the server log only**: `GET /api/audit` is readable by anyone who can
reach it, so the audit records that a document was refused and not why.

If the client cannot be held for the code that is about to be minted - it
has stopped resolving, or the cache has no room to promise anything about
it - no code is issued. The authorization request comes back through the
redirect URI with `error=temporarily_unavailable`, since retrying is the
thing that helps.

The body says nothing, but the clock still does: a host that is not allowed
is refused before any I/O and answers at once, while an allowed one costs a
lookup, a handshake and up to the five second budget. If that distinction
matters to you, do not enable this on an instance strangers can reach - it
is a developer tool, not a hardened gateway.
