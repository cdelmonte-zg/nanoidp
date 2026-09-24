# Run a real OIDC provider in CI with GitHub Actions

Integration tests for an app that logs users in need an identity provider in
the pipeline. A shared cloud tenant makes every job depend on the network
and on state other jobs leave behind; mocking the provider tests your mock.
NanoIDP runs inside the job, as a Python process or a service container,
issues real signed tokens, and lets each test create the users it needs and
remove them afterwards.

This page covers the test environment: starting the instance, knowing it is
ready, an identity per test, isolation between tests and jobs, and cleanup.
For the login flow itself, see
[Test an SPA login with PKCE](spa-login-pkce.md).

Every file on this page is in
[`examples/ci-github-actions/`](https://github.com/cdelmonte-zg/nanoidp/tree/main/examples/ci-github-actions),
and the repository's own CI runs it on every change, both ways shown here.

## 1. Start NanoIDP in the job

Either way, pin the version: the IdP your tests run against should change
when you decide, not when a release comes out.

**As a Python process** (any runner with Python, and the same script works
on a laptop):

```yaml
{{#include ../../../examples/ci-github-actions/workflow-pip.yml}}
```

**As a service container**, from the published image:

```yaml
{{#include ../../../examples/ci-github-actions/workflow-service.yml}}
```

The image starts with its default configuration: the `demo-client` /
`demo-secret` client, the `admin` user, and the issuer
`http://localhost:8000`, which is the address the job's steps reach it at.
Tests that need more users or clients create them at runtime (step 3), so no
configuration file has to be mounted into the container.

## 2. Ready means your instance answered

`/api/health` answers `{"status":"ok"}` once the server is up. Waiting for
it is not enough on its own: if something else already listens on the port,
the new process fails to bind and exits, and the health check is answered
by the other process. The tests then run against an IdP that is not the one
the job configured. The start script refuses a port that is already taken,
and stops waiting as soon as the process exits:

```bash
{{#include ../../../examples/ci-github-actions/start-nanoidp.sh}}
```

On a fresh hosted runner the port is free; on a self-hosted runner or a
laptop, an IdP left over from an earlier run is exactly what the first check
catches.

## 3. One identity per test

`/api/runtime` creates users and clients on the running instance, without
touching its configuration files, and they work on every protocol surface
at once. A pytest fixture gives each test a user of its own:

```python
{{#include ../../../examples/ci-github-actions/tests/conftest.py}}
```

The body of `POST /api/runtime/users` is a `users.yaml` entry plus the
`username`; clients work the same way through `/api/runtime/clients`. The
full API is in [Disposable test identities](../guides/runtime-identities.md).

## 4. Isolation

**Between jobs**, there is nothing to do: each job starts its own instance
on its own runner, and runtime identities live in that process's memory.

**Between tests in one job** is where the care goes, because parallel
workers (`pytest -n 4`) share one instance:

- **Unique names.** Two tests creating `ci-alice` collide: the second
  `POST` answers `409`. A random suffix makes every name unique.
- **Delete by name.** `DELETE /api/runtime` removes every runtime identity,
  including those of tests still running on other workers. With it in the
  teardown, a run of eight parallel tests that each sleep briefly before
  logging in loses one or two of them to a user deleted underneath; deleting
  by name, the same run passes every time.

## 5. Cleanup, and what deleting does not do

The fixture's teardown deletes its user, and the instance itself ends with
the job, taking every runtime identity with it.

Deleting a user does not revoke what it was issued. An access token taken
before the delete stays valid until it expires (introspection still says
`active: true`); only its refresh token is refused. A test that asserts
"the user is gone" has to check a new login, not a token it already holds.
The example's tests pin both behaviours:

```python
{{#include ../../../examples/ci-github-actions/tests/test_identities.py}}
```

## Access to the management API

`/api/runtime`, like the rest of `/api/*`, is open by default: fine for an
instance on the job's loopback or a service container on the job's own
network. When the IdP is reachable from elsewhere, set a
[`management_secret`](../guides/SECURITY.md#management-secret) and send it
as `X-Management-Secret` on the `POST` and `DELETE` calls.

## Takeaways

- Run the IdP inside the job and pin its version; a pip process and a
  service container both work, and neither needs a config file mounted.
- A health check proves that something answers on the port. Make sure it is
  the process the job started.
- Give each test its own identity with a unique name, and delete it by name.
  `DELETE /api/runtime` is for when nothing else is running.
- Deleting an identity stops new logins, not the tokens it already has.
