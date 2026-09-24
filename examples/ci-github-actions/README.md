# NanoIDP in CI (GitHub Actions)

A test environment with a real OIDC provider inside a CI job: NanoIDP
started from PyPI or as a service container, a readiness check that proves
the job's own instance answered, a user per test through `/api/runtime`,
and cleanup that is safe with parallel workers.

| File | What it is |
|---|---|
| `workflow-pip.yml` | a workflow that starts NanoIDP as a Python process |
| `workflow-service.yml` | the same, with NanoIDP as a service container |
| `ci/start-nanoidp.sh` | start and wait, refusing a port another process holds |
| `tests/conftest.py` | the `test_user` fixture: one runtime user per test, deleted by name |
| `tests/test_identities.py` | tests that use it, and pin what deleting a user does and does not do |

The guide explains each part:
[Run a real OIDC provider in CI with GitHub Actions](https://cdelmonte-zg.github.io/nanoidp/use-cases/oidc-provider-in-ci.html).
The layout is the one your repository needs: the workflows call
`ci/start-nanoidp.sh` and `pytest tests`. The repository runs this
directory, with these paths, in `.github/workflows/ci-example.yml`.
