"""
Entry point for running NanoIDP as a module.

Usage:
    python -m nanoidp
    python -m nanoidp --port 8080
    python -m nanoidp --config /path/to/config
    python -m nanoidp init ./my-config
"""

import argparse
import os
import sys
from typing import Optional

from nanoidp import __version__
from nanoidp.config_schema import SCHEMA_ARTIFACT, SCHEMA_MODELS
from nanoidp.models import SECURITY_PROFILES

# Add src to path for development
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Default configuration templates
DEFAULT_USERS_YAML = """# NanoIDP Users Configuration
# Documentation: https://github.com/cdelmonte-zg/nanoidp

# Config schema version this file follows (absent = 1)
config_version: 1

users:
  admin:
    password: "admin"
    email: "admin@example.org"
    identity_class: "INTERNAL"
    entitlements:
      - "ADMIN_ACCESS"
      - "USER_MANAGEMENT"
    roles:
      - "USER"
      - "ADMIN"
    groups:
      - "ADMINISTRATORS"
    tenant: "default"
    source_acl:
      - "ACL_READ"
      - "ACL_WRITE"

  testuser:
    password: "test123"
    email: "test@example.org"
    roles:
      - "USER"
    tenant: "default"

default_user: "admin"
"""

DEFAULT_SETTINGS_YAML = """# NanoIDP Settings Configuration
# Documentation: https://github.com/cdelmonte-zg/nanoidp

# Config schema version this file follows (absent = 1)
config_version: 1

server:
  host: "127.0.0.1"
  port: 8000

oauth:
  issuer: "http://localhost:8000"
  audience: "my-app"
  token_expiry_minutes: 60
  clients:
    - client_id: "demo-client"
      client_secret: "demo-secret"
      description: "Default demo client"

saml:
  # entity_id / sso_url: absent = derived from the effective issuer as
  # <issuer>/saml and <issuer>/saml/sso (follows issuer_from_request); set
  # them only to pin a fixed value
  # entity_id: "http://localhost:8000/saml"
  # sso_url: "http://localhost:8000/saml/sso"
  default_acs_url: "http://localhost:8080/login/saml2/sso/nanoidp"
  # Roles/groups are not standard SAML attributes; enable and name them here.
  export_roles: false
  export_groups: false
  roles_attr_name: "roles"
  groups_attr_name: "groups"

# Authority prefixes for JWT claims
authority_prefixes:
  roles: "ROLE_"
  groups: "GROUP_"
  identity_class: "IDENTITY_"
  entitlements: "ENT_"
"""


def init_config(config_dir: str) -> None:
    """Initialize a new configuration directory with default files."""
    import os

    # Create directory
    os.makedirs(config_dir, exist_ok=True)

    # Create users.yaml
    users_path = os.path.join(config_dir, "users.yaml")
    if os.path.exists(users_path):
        print(f"  [skip] {users_path} already exists")
    else:
        # Same validate-then-atomic-write path as the wizard (#282): the
        # template is static, but validating it here means a drifted default
        # fails init loudly instead of shipping a directory that will not load.
        from nanoidp.wizard import _validate_and_write

        _validate_and_write(users_path, DEFAULT_USERS_YAML, kind="users")
        print(f"  [created] {users_path}")

    # Create settings.yaml
    settings_path = os.path.join(config_dir, "settings.yaml")
    if os.path.exists(settings_path):
        print(f"  [skip] {settings_path} already exists")
    else:
        from nanoidp.wizard import _validate_and_write

        _validate_and_write(settings_path, DEFAULT_SETTINGS_YAML, kind="settings")
        print(f"  [created] {settings_path}")

    # Create keys directory
    keys_dir = os.path.join(config_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    print(f"  [created] {keys_dir}/ (RSA keys will be auto-generated on startup)")

    print(f"""
Configuration initialized in: {os.path.abspath(config_dir)}

To start NanoIDP with this config:
    nanoidp --config {config_dir}

Or set the environment variable:
    NANOIDP_CONFIG_DIR={config_dir} nanoidp

Default credentials:
    User: admin / admin
    Client: demo-client / demo-secret
""")


def validate_config_command(config_dir: Optional[str], strict: bool) -> int:
    """``nanoidp validate-config``: lint a config directory, print one line
    per finding, return the exit code.

    Nothing is started and nothing is executed: no ConfigManager, no hook
    dispatch, no plugin import (see ``nanoidp.config_validation``). That is
    what makes it safe as a pre-commit or CI step on a directory whose
    bootstrap.yaml names commands.
    """
    from nanoidp.config_validation import effective_strict, report, validate_config_dir

    # Same precedence the server's own discovery uses (ConfigManager).
    directory: str = (
        config_dir
        or os.getenv("NANOIDP_CONFIG_DIR")
        or os.getenv("MOCK_IDP_CONFIG_DIR")
        or "./config"
    )
    strict_run = effective_strict(directory, strict)
    findings = validate_config_dir(directory)
    lines, code = report(findings, strict_run)
    print(f"validate-config: {directory} (strict)" if strict_run else f"validate-config: {directory}")
    for line in lines:
        print(line)
    return code


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NanoIDP - Lightweight Identity Provider for testing OAuth2/OIDC and SAML integrations"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # init subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize a new configuration directory"
    )
    init_parser.add_argument(
        "config_dir",
        nargs="?",
        default="./config",
        help="Path to create configuration directory (default: ./config)",
    )

    # wizard subcommand
    wizard_parser = subparsers.add_parser(
        "wizard",
        help="Interactive configuration wizard"
    )
    wizard_parser.add_argument(
        "config_dir",
        nargs="?",
        default="./config",
        help="Path to create configuration directory (default: ./config)",
    )

    # plugins subcommand (#185)
    plugins_parser = subparsers.add_parser(
        "plugins",
        help="List loaded hooks and plugins (hook API version, implemented hooks, failures, source)",
    )
    plugins_parser.add_argument(
        "--config",
        default=None,
        help="Path to configuration directory",
    )

    # config-schema subcommand (#175 piece 3)
    schema_parser = subparsers.add_parser(
        "config-schema",
        help="Print the JSON Schema of the configuration files, generated from the "
        "document models (settings.yaml, users.yaml, bootstrap.yaml)",
    )
    schema_parser.add_argument(
        "--file",
        choices=sorted(SCHEMA_MODELS),
        default=None,
        help="Print only this file's schema instead of the full document",
    )
    schema_parser.add_argument(
        "--write",
        action="store_true",
        help=f"Write the full document to {SCHEMA_ARTIFACT} in the source checkout "
        "instead of printing it (works from a checkout only)",
    )

    # validate-config subcommand (#175 piece 4)
    validate_parser = subparsers.add_parser(
        "validate-config",
        help="Validate settings.yaml, users.yaml and bootstrap.yaml without starting "
        "the server; no hook is run and no plugin is loaded",
    )
    validate_parser.add_argument(
        "--config",
        default=None,
        help="Path to configuration directory",
    )
    validate_parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on warnings too (what --strict-config does at startup)",
    )

    # Main server arguments (when no subcommand)
    parser.add_argument(
        "--bootstrap-hook",
        default=None,
        help="Shell command run once before the first configuration load, e.g. to "
        "render settings.yaml/users.yaml from an external store into the config "
        "directory (placeholder {config_dir}). Same as NANOIDP_BOOTSTRAP_HOOK.",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Host to bind to (default: from config or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to (default: from config or 8000)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to configuration directory",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )
    parser.add_argument(
        "--profile",
        choices=list(SECURITY_PROFILES),
        default=None,
        help="Security profile: dev, stricter-dev (runtime hardening) or oauth21 "
        "(draft OAuth 2.1 protocol strictness). When given it overrides "
        "settings.yaml's security_profile for this run only; when omitted the "
        "YAML value applies (default: dev)",
    )

    parser.add_argument(
        "--strict-config",
        action="store_true",
        help="Refuse to start when a configuration file contains an unknown key, "
        "instead of logging a warning and ignoring it. Overrides settings.yaml's "
        "config_validation for this run only and is never written back; wrong "
        "types are errors either way",
    )

    args = parser.parse_args()

    # Handle init command
    if args.command == "init":
        print("""
    ╔══════════════════════════════════════════╗
    ║         NanoIDP Configuration Init       ║
    ╚══════════════════════════════════════════╝
        """)
        init_config(args.config_dir)
        return

    # Handle config-schema command
    if args.command == "config-schema":
        from nanoidp.config_schema import build_schema_document, file_schema, render, write_artifact
        if args.write:
            if args.file:
                print(
                    "config-schema --write always writes the full document; "
                    "drop --file (or redirect a single file's schema yourself)",
                    file=sys.stderr,
                )
                sys.exit(1)
            try:
                target = write_artifact()
            except (RuntimeError, OSError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                sys.exit(1)
            print(f"  [written] {target}")
            return
        document = file_schema(args.file) if args.file else build_schema_document()
        print(render(document), end="")
        return

    # Handle validate-config command
    if args.command == "validate-config":
        sys.exit(validate_config_command(args.config, args.strict))

    # Handle plugins command
    if args.command == "plugins":
        from nanoidp.config import ConfigManager
        print(ConfigManager(args.config).hooks.format_report())
        return

    if args.bootstrap_hook:
        os.environ["NANOIDP_BOOTSTRAP_HOOK"] = args.bootstrap_hook

    # Handle wizard command
    if args.command == "wizard":
        from nanoidp.wizard import run_wizard
        success = run_wizard(args.config_dir)
        sys.exit(0 if success else 1)

    # Run server
    from nanoidp.app import run_app

    print(f"""
    ╔══════════════════════════════════════════╗
    ║{f"NanoIDP v{__version__}":^42}║
    ║   Lightweight Identity Provider          ║
    ╚══════════════════════════════════════════╝
    """)

    run_app(
        host=args.host,
        port=args.port,
        debug=args.debug,
        config_dir=args.config,
        profile=args.profile,
        # Only a given flag is an override; without it settings.yaml decides.
        strict_config=True if args.strict_config else None,
    )


if __name__ == "__main__":
    main()
