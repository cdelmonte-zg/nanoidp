"""
Flask application factory for NanoIDP.
"""

import logging
import os
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from . import __version__
from .config import init_config, get_config
from .services import init_crypto_service
from .routes import oauth_bp, saml_bp, ui_bp, api_bp

# Global limiter instance (initialized in create_app)
limiter = None


def create_app(config_dir: str = None, profile: str = None) -> Flask:
    """Create and configure the Flask application."""
    global limiter

    # Initialize configuration
    config = init_config(config_dir)
    settings = config.settings

    # Apply profile overrides
    if profile == "stricter-dev":
        settings.security_profile = "stricter-dev"
        settings.rate_limit_enabled = True
        settings.password_hashing = True
        # Block debug mode in stricter-dev
        settings.debug = False

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
    def inject_version():
        return {"app_version": __version__}

    # Health check at root for backward compatibility
    @app.route("/health")
    def health():
        from flask import jsonify
        return jsonify({"status": "ok"})

    logger.info(f"NanoIDP initialized")
    logger.info(f"  - Security profile: {settings.security_profile}")
    logger.info(f"  - Password hashing: {'bcrypt' if settings.password_hashing else 'plaintext'}")
    logger.info(f"  - Issuer: {settings.issuer}")
    logger.info(f"  - Users: {len(config.users)}")
    logger.info(f"  - OAuth Clients: {len(settings.clients)}")

    return app


def get_limiter() -> Limiter:
    """Get the global limiter instance."""
    return limiter


def run_app(
    host: str = None,
    port: int = None,
    debug: bool = None,
    config_dir: str = None,
    profile: str = None,
):
    """Run the Flask application."""
    app = create_app(config_dir, profile=profile)
    config = get_config()
    settings = config.settings

    # Block debug mode in stricter-dev profile
    effective_debug = debug if debug is not None else settings.debug
    if settings.security_profile == "stricter-dev" and effective_debug:
        logging.getLogger(__name__).warning(
            "Debug mode blocked in stricter-dev profile for security"
        )
        effective_debug = False

    app.run(
        host=host or settings.host,
        port=port or settings.port,
        debug=effective_debug,
    )
