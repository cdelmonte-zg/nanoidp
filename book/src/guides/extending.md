# Extending nanoidp: hooks and plugins

nanoidp reads and writes two YAML files and nothing else. When those files
need to come from, or go to, somewhere else (an S3 bucket per stage, a Vault
path, a git repository, an audit sink), that integration lives outside the
core, behind a small, versioned extension point: **extension points, not
backends**. A hook observes what happens to the files and can provide them
before they are read; it never replaces persistence, never sees an HTTP
request and never touches token issuance, so a broken hook cannot change
what nanoidp advertises or issues.

## The contract (hook API version 1)

Three hooks, called synchronously:

| Hook | When | Arguments | Typical use |
|---|---|---|---|
| `on_before_load` | before `settings.yaml` and `users.yaml` are read: startup and every explicit reload (`POST /api/config/reload`, MCP `reload_config`), never the refresh that follows a local write | plugin: `config_dir`; shell: `{config_dir}` | render the files from a store into the directory |
| `on_config_saved` | after an atomic write of either file (web UI, MCP, `save`) | plugin: `path`, `kind` (`settings` or `users`); shell: `{config_dir}`, `{path}`, `{kind}` | push to a store, `git commit`, notify |
| `on_audit_event` | after an audit entry is recorded | plugin: the event as a mapping; shell: `{config_dir}`, `{event_type}` plus the event as JSON on stdin | ship audit elsewhere |

Two ways to implement it, sharing one dispatcher (shell hook first, then
plugins in declaration order):

**Shell hooks**, declared in `settings.yaml`, zero API:

```yaml
hooks:
  on_before_load: "aws s3 sync s3://idp-config-${STAGE} {config_dir}"
  on_config_saved: "vault kv put secret/idp/{kind} @{path}"
  on_audit_event: "jq -c . >> /var/log/nanoidp-audit.jsonl"   # event JSON on stdin
  strict: false          # see the error policy below
  timeout_seconds: 10    # shell hooks only
```

Placeholders are listed per hook in the table above. They are replaced
textually, so other braces (`${VAR}`, `jq` filters) are left alone. The
command runs through the shell with nanoidp's environment; for
`on_audit_event` the event is also written to the command's stdin as JSON.

A command is stored after `${VAR}` expansion, so it may embed a token. It
is therefore never reported outside the process: `GET /api/config` and the
MCP `get_settings` tool show a hook's name, source and failure counter but
not its command, and the error a caller sees under `strict` names the hook
and its source only. The command and the hook's stderr go to the server
log at WARNING, and `nanoidp plugins`, which runs in your own terminal,
is the one place that prints commands.

**Python plugins**, packaged separately and discovered through the
`nanoidp.plugins` entry-point group:

```yaml
plugins:
  echo:
    record: /tmp/nanoidp-hooks.jsonl   # keys under a plugin's name belong to the plugin
```

`plugins:` is the only section of `settings.yaml` whose inner keys nanoidp
does not validate: the shape is `name -> mapping`, the keys are the plugin's.
A plugin's identity is its entry-point name, which is also that key; the
object itself carries only `hook_api_version` and the hooks it implements.

## Error policy, per hook

The policy is the same for shell hooks and plugins. `timeout_seconds`
applies to shell hooks only, and a timeout is a failure; a Python plugin
must manage its own network timeouts and queueing, nanoidp does not
interrupt it.

| Hook | default | `hooks.strict: true` |
|---|---|---|
| `on_before_load` | log, continue with whatever is in the directory | the load (startup or reload) fails with the hook's error |
| `on_config_saved` | log | the error is propagated to the caller **after** the write. Disk and runtime stay aligned: the file on disk is what was written and the running configuration is reloaded from it before the error is raised, so only the mirror is behind. The web UI says "Settings saved locally; mirror hook failed". That refresh reads the local files only and does not run `on_before_load`: the disk is the newest state right after a write, and pulling a mirror that has not caught up yet would silently roll the write back |
| `on_audit_event` | log | log; never propagates |

`on_before_load` is the only hook that can block an operation, because it
runs before any mutation. `on_config_saved` runs after the atomic write, so
the local save is always committed; under `strict` the web UI, `/api` and
MCP callers surface the failure so the operator learns the mirror did not
happen. `ConfigManager.save()` writes `users.yaml` and `settings.yaml` as
one transaction (#229): both files are written, both hooks then run, and
the runtime is refreshed from disk once before a `strict` failure is
raised - a failing hook on one file does not leave the other unwritten.
The web UI's settings page is a different, older path (`YamlWriter`):
it still writes its sections one atomic write at a time, so under
`strict` a failing hook there leaves the steps after it unsaved (the
flash message says which write failed). Make the hook idempotent: the
next save re-mirrors. `on_audit_event` never fails the request that
produced the event: a token already issued must not turn into a 500 because
an audit sink is down. Failures are counted per hook and shown by
`nanoidp plugins` and `GET /api/config`.

## Bootstrap: hooks that run before `settings.yaml` exists

`on_before_load` runs before `settings.yaml` is read, but `hooks:` is
declared in `settings.yaml`: the main use case, rendering the files from a
store, cannot be configured by the file it fetches. A minimal surface
outside the normal config covers it:

| Surface | What it declares | Runs |
|---|---|---|
| `NANOIDP_BOOTSTRAP_HOOK="<command>"` or `nanoidp --bootstrap-hook "<command>"` | an `on_before_load` shell command | once, before the first load |
| `NANOIDP_BOOTSTRAP_PLUGIN=<name>` with `NANOIDP_PLUGIN_<NAME>_<KEY>=<value>` | a plugin and its settings (name upper-cased, `-` as `_`) | loaded once, then takes part in every hook |
| `bootstrap.yaml` in the configuration directory | `hooks:` and `plugins:` only, same schema and same loader as `settings.yaml`: `${VAR}` placeholders expand, an unknown key is warned with its path and ignored (under `config_validation: strict` it stops startup, like everywhere else), a wrong type stops startup | its `on_before_load` once, its other hooks and plugins always |

Precedence of the policy values (`strict`, `timeout_seconds`): the
bootstrap surface is the baseline; `settings.yaml` overrides a value only
when it declares it explicitly, and a `settings.yaml` that disappears (a
render that failed, a sync that left the directory half written) takes its
hooks, plugins and policy with it on the next reload, leaving the bootstrap
ones in force. A renderer that replaces or syncs the whole configuration
directory must preserve `bootstrap.yaml`, or that deployment should use the
env/CLI bootstrap instead.

After the first load, `settings.yaml` may declare the same hook for reloads
and saves. `nanoidp plugins` shows which surface each entry came from
(`bootstrap-env`, `bootstrap.yaml`, `settings.yaml`). Note that `strict` read
from `settings.yaml` cannot apply to the very first load (the file is not
known yet): to make a failed bootstrap render fatal, set `strict: true` in
`bootstrap.yaml`.

A plugin that cannot be loaded (its package is not installed, it declares
another `hook_api_version`, its `configure()` raises) follows the same
policy as `on_before_load`: logged at ERROR, listed under `plugins_failed`
by `nanoidp plugins`, `GET /api/config` and the MCP `get_settings` tool,
and skipped; under `strict` the load fails. The public `reason` is one of
nanoidp's own diagnoses (`not installed`, `incompatible hook_api_version=N
(expected 1)`, `already loaded`, `initialization failed`); the exception
text itself, which may embed the plugin's settings, goes to the local log
only. A plugin that failed in non-strict mode is retried only when the
`hooks:`/`plugins:` declaration changes or the process restarts: a reload
with an unchanged declaration does not re-apply it.

A failed `on_before_load` or plugin load under `strict` is reported by
`POST /api/config/reload` as a JSON `503` (`kind` names the phase:
`on_before_load` or `plugin_load`) and by the MCP `reload_config` tool as an
error result, never as an HTML error page. Such a reload fails without
commit: the running settings, the profile hardening and the registered
plugins stay exactly as they were until a later reload succeeds.

## Worked example: version every change in git

```yaml
hooks:
  on_config_saved: "git -C {config_dir} add {path} && git -C {config_dir} commit -q -m 'nanoidp: {kind} saved' || true"
```

Every save from the web UI or the MCP server becomes a commit; `git log -p`
is the change history, `git revert` the rollback, branches the stages. The
trailing `|| true` keeps a "nothing to commit" from counting as a failure.

## Worked example: render from a store before the load

With a shell hook, the store stays entirely outside nanoidp:

```bash
NANOIDP_BOOTSTRAP_HOOK='aws s3 sync "s3://idp-config-$STAGE" {config_dir}' \
NANOIDP_CONFIG_DIR=/var/lib/nanoidp/config \
nanoidp
```

and, to mirror changes back:

```yaml
hooks:
  on_config_saved: 'aws s3 cp {path} "s3://idp-config-$STAGE/"'
```

The same result without any hook: an init container (or Vault Agent, or a
`docker compose` dependency) renders the files into the directory before
nanoidp starts, and `POST /api/config/reload` (or the MCP `reload_config`
tool) picks up a later change. Hooks are for when the render must follow
nanoidp's own lifecycle (every reload) or when the mirror must follow every
save.

## Writing a plugin

The reference plugin, `examples/plugins/nanoidp-echo`, logs every hook call
and records it to a file. It is the whole template:

```python
# src/nanoidp_myvault/__init__.py
from pathlib import Path

class VaultPlugin:
    hook_api_version = 1          # nanoidp refuses any other value; the
                                  # plugin's name is its entry-point name

    def configure(self, settings: dict) -> None:   # receives plugins.myvault, optional
        self.path = settings["path"]

    def on_before_load(self, config_dir: Path) -> None:
        ...  # read secret/<path>/settings and users, write them into config_dir

    def on_config_saved(self, path: Path, kind: str) -> None:
        ...  # write the file back

    # on_audit_event(self, event: dict) is optional, like the other two
```

```toml
# pyproject.toml
[project.entry-points."nanoidp.plugins"]
myvault = "nanoidp_myvault:VaultPlugin"
```

Install it next to nanoidp (`pip install nanoidp-myvault`, or `pip install -e
examples/plugins/nanoidp-echo` to try the reference one), declare it under
`plugins:` or through `NANOIDP_BOOTSTRAP_PLUGIN`, and check `nanoidp
plugins`. Any method may raise: nanoidp counts the failure and applies the
policy of that hook. Keep plugins synchronous; if a store call must not
block a save, queue it on the plugin's side.

## What is reported

`nanoidp plugins [--config DIR]`, `GET /api/config` (`hooks` block) and the
MCP `get_settings` tool show the hook API version, `strict`, the timeout,
every shell hook with its source and failure counter (never its command,
see above), and every plugin with its `hook_api_version`, the hooks it
implements, its source and its failure counters per hook. `hooks:` and `plugins:` are YAML-only: the web UI's
settings page and the MCP `update_settings` tool report them but cannot
change them, because a command editable through the surface it observes
would be a remote-execution primitive.

## Security

A Python plugin runs with the process's privileges; installing one is a
trust decision like any dependency. Shell hooks run whatever the YAML says,
with nanoidp's environment: the file is operator-owned by definition, the
same trust boundary as `secret_key` or `management_secret`. Neither surface
is reachable from the web UI or MCP.

Checking a configuration directory is not the same as loading one:
`nanoidp validate-config` and the MCP `validate_config` tool validate the
shape of `hooks:` and `plugins:` without dispatching a hook or importing a
plugin, so linting a directory someone else wrote executes nothing
([Configuration](../reference/configuration.md#validating-your-configuration)).

## What hooks are not

There are no hooks on the protocol path (`on_token_issued`, `on_login` and
the like): that would be a change to what nanoidp is, decided in
[VISION](../project/vision.md), not added by a plugin. And a plugin cannot
replace the YAML files as the source of truth: nanoidp never reads from or
writes to an external store itself.
