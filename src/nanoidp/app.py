"""
Flask application factory for NanoIDP.
"""

import logging
import os
from typing import Optional

from flask import Flask, Response, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__
from .config import get_config, init_config
from .routes import api_bp, oauth_bp, saml_bp, ui_bp
from .services import init_crypto_service

# Global limiter instance (initialized in create_app)
limiter: Optional[Limiter] = None


def create_app(
    config_dir: Optional[str] = None,
    profile: Optional[str] = None,
    strict_config: Optional[bool] = None,
) -> Flask:
    """Create and configure the Flask application."""
    global limiter

    # Initialize configuration
    # The CLI --profile (any of the three values, including an explicit
    # "dev") wins over settings.yaml's security_profile and survives every
    # reload(); the stricter-dev runtime hardening is derived from the
    # EFFECTIVE profile inside ConfigManager, so YAML and CLI mean the same
    # thing and neither is lost on the first UI/MCP save (#68 review, #172).
    # --strict-config follows the same contract (#175 piece 4): given, it
    # wins over settings.yaml's config_validation for this run only; omitted
    # (None), the file decides.
    config = init_config(config_dir, profile_override=profile, strict_config=strict_config)
    settings = config.settings

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    # Initialize crypto service with external key support
    init_crypto_service(
        keys_dir=settings.keys_dir,
        external_private_key=settings.external_private_key,
        external_public_key=settings.external_public_key,
        external_key_id=settings.external_key_id,
        max_previous_keys=settings.max_previous_keys,
    )

    # Create Flask app
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )
    app.secret_key = settings.secret_key

    # Trust X-Forwarded-Proto/Host/For from a single reverse-proxy hop, so
    # request.scheme/host_url (and therefore issuer_from_request, rate-limit
    # client IPs) reflect the original client instead of the proxy.
    if settings.issuer_from_proxy_headers:
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1
        )

    # Configure CORS based on security profile
    if settings.security_profile == "stricter-dev":
        # Restricted CORS for stricter-dev profile
        origins = settings.cors_allowed_origins
        if origins == ["*"]:
            # Default to localhost only in stricter-dev
            origins = ["http://localhost:*", "http://127.0.0.1:*"]
        CORS(app, resources={r"/*": {"origins": origins}})
        logger.info(f"  - CORS: restricted to {origins}")
    else:
        # Permissive CORS for dev profile
        CORS(app, resources={r"/*": {"origins": "*"}})
        logger.info("  - CORS: permissive (all origins)")

    # Configure rate limiting
    if settings.rate_limit_enabled:
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=[],  # No default limits
            storage_uri="memory://",
        )
        logger.info(f"  - Rate limiting: enabled ({settings.rate_limit_token_endpoint} on /token)")
    else:
        # Create a no-op limiter for compatibility
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=[],
            enabled=False,
        )

    # Register blueprints
    app.register_blueprint(oauth_bp)
    app.register_blueprint(saml_bp)
    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp)

    # Context processor to inject version into all templates
    @app.context_processor
    def inject_version() -> dict[str, str]:
        return {"app_version": __version__}

    # Health check at root for backward compatibility
    @app.route("/health")
    def health() -> Response:
        return jsonify({"status": "ok"})

    logger.info("NanoIDP initialized")
    logger.info(f"  - Security profile: {settings.security_profile}")
    logger.info(
        f"  - Config validation: {'strict' if config.strict_config else 'warn'}"
    )
    logger.info(f"  - Password hashing: {'bcrypt' if settings.password_hashing else 'plaintext'}")
    logger.info(f"  - Issuer: {settings.issuer}")
    logger.info(f"  - Users: {len(config.users)}")
    logger.info(f"  - OAuth Clients: {len(settings.clients)}")

    return app


def get_limiter() -> Optional[Limiter]:
    """Get the global limiter instance (None before create_app runs)."""
    return limiter


def run_app(
    host: Optional[str] = None,
    port: Optional[int] = None,
    debug: Optional[bool] = None,
    config_dir: Optional[str] = None,
    profile: Optional[str] = None,
    strict_config: Optional[bool] = None,
) -> None:
    """Run the Flask application."""
    app = create_app(config_dir, profile=profile, strict_config=strict_config)
    config = get_config()
    settings = config.settings

    # Block debug mode in stricter-dev profile
    effective_debug = debug if debug is not None else settings.debug
    if settings.security_profile == "stricter-dev" and effective_debug:
        logging.getLogger(__name__).warning(
            "Debug mode blocked in stricter-dev profile for security"
        )
        effective_debug = False

    effective_host = host or settings.host
    # NanoIDP is a dev/test IdP whose management API (/api/*) is unauthenticated
    # by design; binding to all interfaces exposes admin token minting and key
    # rotation to any network-reachable host. The default is 127.0.0.1; warn
    # loudly when that safe default is overridden.
    if effective_host in ("0.0.0.0", "::", ""):
        logging.getLogger(__name__).warning(
            "Binding to %s exposes NanoIDP on all network interfaces. The "
            "/api/* management endpoints are unauthenticated by design, so any "
            "reachable host can mint admin tokens and rotate signing keys. Use "
            "127.0.0.1 unless you intend network exposure (e.g. inside a "
            "container).",
            effective_host,
        )

    app.run(
        host=effective_host,
        port=port or settings.port,
        debug=effective_debug,
    )
