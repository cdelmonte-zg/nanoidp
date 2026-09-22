# Two processes, one runtime state

A test setup sometimes needs more than one NanoIDP process on one machine:
an app server and a CLI that both talk to the same IdP, a worker beside the
web process, two instances behind a proxy while you try a restart. With the
default store each process has a runtime state of its own, so a code issued
by one is unknown to the other, and a test identity created through one is
invisible to the other.

The SQLite runtime store gives those processes one runtime state. It is
still test state: NanoIDP does not promise to keep it, and nothing here
turns NanoIDP into an identity provider for production.

## Turn it on

```yaml
# settings.yaml, in the configuration directory both processes read
runtime:
  store: sqlite
  path: ../state/nanoidp-runtime.db
```

Start the processes as usual, each with the same configuration directory:

```bash
PORT=8000 NANOIDP_CONFIG_DIR=./config python -m nanoidp &
PORT=8001 NANOIDP_CONFIG_DIR=./config python -m nanoidp &
```

`path` is relative to the configuration directory, not to the working
directory, so both processes name the same store however they were started.
Signing keys are not: `jwt.keys_dir` is relative to the working directory,
so give it an absolute path when the processes start from different places,
or they will sign with different keys.

The store is a family of files, named after the database: `runtime.db`, the
audit in `runtime-audit.db`, and the owner leases in `runtime-owners/`. They
hold what the protocols keep, including runtime users' passwords and client
secrets, so they are created `0600` and must lie outside the configuration
directory, which gets read, copied and committed. The full rules are in the
[configuration reference](../reference/configuration.md).

## What the two processes share, and what they do not

Shared, because it lives in the store:

- runtime users and clients, and promotions of them;
- authorization codes, device codes and user codes, each consumed once for
  both processes;
- refresh token families and revocations;
- the audit, which reads as one from either process.

Not shared, and process-local on purpose: the login session cookie, the rate
limiter's counters, the client metadata fetch budget, and `on_audit_event`
dispatch to plugins, which each process makes for its own events.

The declared configuration is shared because the files are: a process
notices a change another one wrote, and a promotion made through one is
declared for both.

## What it does not promise

With `store: memory` runtime state is process-local and gone at restart.
With `store: sqlite` it outlives a restart technically, but NanoIDP makes no
durability promise about it: treat it as state you can rebuild or throw
away, never as a record you need to keep. It is also a one-host store: the
processes coordinate through file locks on one filesystem, so it is not a
way to run NanoIDP on several machines.

## Start afresh

Stop every process that uses the store first. Removing files under a running
process leaves it holding what is no longer there.

```bash
# with the processes stopped
rm -rf state/nanoidp-runtime.db state/nanoidp-runtime.db-wal state/nanoidp-runtime.db-shm \
       state/nanoidp-runtime-audit.db state/nanoidp-runtime-audit.db-wal \
       state/nanoidp-runtime-audit.db-shm state/nanoidp-runtime-owners
```

Naming another `runtime.path` is the other way, and needs no removal at all:
the processes then share a new, empty store. Changing the path or the store
of a running process is refused on reload, with a message that says to
restart, because processes that share a store may not disagree about which
one it is.

## When it is held

One process at a time writes a decision, and the others wait briefly. A
process that waited longer than it should answers `503` with `Retry-After`
over HTTP, and `MCP_RUNTIME_STORE_UNAVAILABLE` with `retryable: true` in
MCP, rather than making up an answer. Both mean the same thing: ask again.

## See also

- [Disposable test identities](runtime-identities.md), the identities this
  store lets two processes share.
- [Configuration](../reference/configuration.md), for the `runtime:` section
  rule by rule.
