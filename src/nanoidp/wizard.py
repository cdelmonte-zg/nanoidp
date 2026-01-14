"""
Interactive text-based configuration wizard.
No external dependencies required.
"""

import os
import sys
import getpass


def _prompt(message: str, default: str = "") -> str:
    """Prompt user for input with optional default."""
    if default:
        result = input(f"  {message} [{default}]: ").strip()
        return result if result else default
    else:
        return input(f"  {message}: ").strip()


def _prompt_password(message: str, default: str = "") -> str:
    """Prompt for password (hidden input if possible)."""
    try:
        if default:
            print(f"  {message} [{default}]: ", end="", flush=True)
            result = getpass.getpass("")
            return result if result else default
        else:
            return getpass.getpass(f"  {message}: ")
    except Exception:
        # Fallback to regular input if getpass fails
        return _prompt(message, default)


def _confirm(message: str) -> bool:
    """Ask for yes/no confirmation."""
    while True:
        response = input(f"  {message} [Y/n]: ").strip().lower()
        if response in ("", "y", "yes"):
            return True
        if response in ("n", "no"):
            return False


def _print_header(title: str):
    """Print a section header."""
    print()
    print(f"{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}")


def _print_box(lines: list[str], title: str = ""):
    """Print text in a box."""
    width = max(len(line) for line in lines) + 4
    width = max(width, len(title) + 4)

    print()
    print(f"┌{'─' * width}┐")
    if title:
        print(f"│ {title.center(width - 2)} │")
        print(f"├{'─' * width}┤")
    for line in lines:
        print(f"│ {line.ljust(width - 2)} │")  # noqa: S101 - intentional display in wizard
    print(f"└{'─' * width}┘")


def run_wizard(config_dir: str = "./config") -> bool:
    """Run the interactive configuration wizard."""

    _print_box([
        "",
        "Welcome to NanoIDP Setup!",
        "",
        "This wizard will help you configure",
        "your Identity Provider.",
        "",
    ], "NanoIDP Configuration Wizard")

    print()
    if not _confirm("Continue with setup?"):
        print("\n  Setup cancelled.\n")
        return False

    # Server configuration
    _print_header("Server Configuration")
    host = _prompt("Host", "0.0.0.0")
    port = _prompt("Port", "8000")
    issuer = _prompt("Issuer URL", f"http://localhost:{port}")
    audience = _prompt("Audience", "my-app")

    # OAuth Client
    _print_header("OAuth Client Configuration")
    client_id = _prompt("Client ID", "demo-client")
    client_secret = _prompt("Client Secret", "demo-secret")
    client_desc = _prompt("Description", "Default client")

    # Admin User
    _print_header("Admin User Configuration")
    admin_user = _prompt("Username", "admin")
    admin_pass = _prompt("Password", "admin")
    admin_email = _prompt("Email", f"{admin_user}@example.org")

    # Token Settings
    _print_header("Token Settings")
    token_expiry = _prompt("Token expiry (minutes)", "60")

    # Config Path
    _print_header("Configuration Location")
    config_path = _prompt("Config directory", config_dir)

    # Summary
    _print_box([
        f"Host:          {host}",
        f"Port:          {port}",
        f"Issuer:        {issuer}",
        f"Audience:      {audience}",
        "",
        f"Client ID:     {client_id}",
        f"Client Secret: {'*' * len(client_secret)}",
        "",
        f"Admin User:    {admin_user}",
        f"Admin Pass:    {'*' * len(admin_pass)}",
        f"Admin Email:   {admin_email}",
        "",
        f"Token Expiry:  {token_expiry} minutes",
        f"Config Path:   {config_path}",
    ], "Configuration Summary")

    print()
    if not _confirm("Create this configuration?"):
        print("\n  Setup cancelled.\n")
        return False

    # Create configuration
    try:
        _create_config(
            config_path=config_path,
            host=host,
            port=port,
            issuer=issuer,
            audience=audience,
            client_id=client_id,
            client_secret=client_secret,
            client_desc=client_desc,
            admin_user=admin_user,
            admin_pass=admin_pass,
            admin_email=admin_email,
            token_expiry=token_expiry,
        )

        _print_box([
            "Configuration created successfully!",
            "",
            f"Files: {os.path.abspath(config_path)}",
            "",
            "To start NanoIDP:",
            f"  python -m nanoidp --config {config_path}",
            "",
            "Default credentials:",
            f"  User:   {admin_user} / {admin_pass}",
            f"  Client: {client_id} / {client_secret}",
        ], "Success!")
        print()
        return True

    except Exception as e:
        print(f"\n  Error: {str(e)}\n")
        return False


def _create_config(
    config_path: str,
    host: str,
    port: str,
    issuer: str,
    audience: str,
    client_id: str,
    client_secret: str,
    client_desc: str,
    admin_user: str,
    admin_pass: str,
    admin_email: str,
    token_expiry: str,
) -> None:
    """Create configuration files."""
    os.makedirs(config_path, exist_ok=True)
    os.makedirs(os.path.join(config_path, "keys"), exist_ok=True)

    # users.yaml
    users_yaml = f"""# NanoIDP Users Configuration
# Generated by NanoIDP Wizard

users:
  {admin_user}:
    password: "{admin_pass}"
    email: "{admin_email}"
    identity_class: "INTERNAL"
    entitlements:
      - "ADMIN_ACCESS"
      - "USER_MANAGEMENT"
    roles:
      - "USER"
      - "ADMIN"
    tenant: "default"
    source_acl:
      - "ACL_READ"
      - "ACL_WRITE"

default_user: "{admin_user}"
"""

    with open(os.path.join(config_path, "users.yaml"), "w") as f:
        f.write(users_yaml)

    # settings.yaml
    settings_yaml = f"""# NanoIDP Settings Configuration
# Generated by NanoIDP Wizard

server:
  host: "{host}"
  port: {port}

oauth:
  issuer: "{issuer}"
  audience: "{audience}"
  token_expiry_minutes: {token_expiry}
  clients:
    - client_id: "{client_id}"
      client_secret: "{client_secret}"
      description: "{client_desc}"

saml:
  entity_id: "{issuer}/saml"
  sso_url: "{issuer}/saml/sso"
  default_acs_url: "http://localhost:8080/login/saml2/sso/nanoidp"

authority_prefixes:
  roles: "ROLE_"
  identity_class: "IDENTITY_"
  entitlements: "ENT_"
"""

    # Development tool - credentials stored in plaintext intentionally for ease of use
    with open(os.path.join(config_path, "settings.yaml"), "w") as f:  # noqa: S101
        f.write(settings_yaml)


if __name__ == "__main__":
    run_wizard()
