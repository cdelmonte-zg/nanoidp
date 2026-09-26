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

Not shared, and process-local on purpose: the rate limiter's counters, the
client metadata fetch budget, and `on_audit_event` dispatch to plugins,
which each process makes for its own events.

The browser leg follows the store too. The login session is a cookie the
process signs with `secret_key`, which both read from the same
`settings.yaml`, and the transaction behind `/authorize` lives in the store,
so a login begun at one process can be finished at the other and the code
comes out the same. Two instances behind a proxy therefore need no sticky
sessions for it.

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

## Configuration freshness

With a shared runtime store, a request that reads the configuration first
checks whether another process changed the files: a `stat` of the two files,
and a read under the configuration directory's lock only when they changed,
or were changed within the last two seconds. That lock is the writers' lock,
the one a save from the web UI, an MCP `save_config` or a promotion takes.
One freshness check in a process may wait for it, for up to 10 seconds,
while another process holds it; the other requests of that process wait for
that check for up to 0.5 seconds and then answer `503 configuration_unavailable`
(`freshness_in_progress`) with `Retry-After: 1`, and the check that waited
the whole 10 seconds answers the same with `lock_timeout`. A worker with one
thread cannot run those requests alongside the waiting one, so its requests
queue behind it instead. Health and static-file requests do not check.

Orders of magnitude measured on one host, not promises
([#426](https://github.com/cdelmonte-zg/nanoidp/issues/426)): a freshness
read holds the lock for about 0.1 ms, a small write for 7 to 9 ms, a write
of a `users.yaml` with five hundred users for about a third of a second. A
process that finds the lock taken tries again after 1 ms, then 2, 4, and so
on up to 50 ms between tries, within the same 10 seconds.

## See also

- [Disposable test identities](runtime-identities.md), the identities this
  store lets two processes share.
- [Configuration](../reference/configuration.md), for the `runtime:` section
  rule by rule.
