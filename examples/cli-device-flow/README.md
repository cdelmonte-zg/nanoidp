# CLI device flow

A command-line tool logging in with the device authorization grant (RFC
8628): the preset (`settings.yaml`, `users.yaml`) with the CLI as a public
client, the CLI's login code (`cli_login.py`), and tests that run its
polling while a scripted browser step approves or denies (`tests/`).

```bash
# NanoIDP with this preset, on :8000
mkdir -p idp-config && cp settings.yaml users.yaml idp-config/
python -m nanoidp --config ./idp-config

# The CLI (another terminal): open the URL it prints and log in
python cli_login.py

# The tests (another terminal)
pytest tests
```

Test users: `admin` / `admin` (roles `ADMIN`, `USER`) and `user` / `user`
(role `USER`).

The guide explains the polling, the answers a CLI must handle, and refresh
token rotation:
[Test a CLI login with the device authorization flow](https://cdelmonte-zg.github.io/nanoidp/use-cases/cli-device-flow.html).
The repository runs this directory in `.github/workflows/device-flow-example.yml`.
