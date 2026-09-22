"""
Flask application factory for NanoIDP.
"""

import logging
import os
from typing import Any, Optional

from flask import Flask, Response, jsonify, make_response, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from . import __version__
from .config import ConfigManager, DeclaredConfigurationUnloadable, get_config, init_config
from .config_writer import LockUnavailableError
from .routes import api_bp, oauth_bp, registration_bp, runtime_bp, saml_bp, ui_bp
from .services import activate_services
from .services.dynamic_registration import prune_stale_registrations
from .services.identities import identities_for, reconcile_runtime_identities
from .services.runtime_repository import RuntimeStoreUnavailable
from .services.runtime_store import fresh_configuration

# Global limiter instance (initialized in create_app)
limiter: Optional[Limiter] = None

# Mirrors Settings.secret_key's default (models.py). Session-signing key that
# ships public, in source control - fine when nothing session-based is being
# trusted, not fine once require_ui_login or management_secret's UI leg asks
# the session to hold something meaningful (#163 review).
_DEFAULT_SECRET_KEY = "dev-secret-key-change-in-production"


def _after_load(config: ConfigManager) -> None:
    """What runs after every successful configuration load, in order.

    The reconciliation retires runtime identities the file now declares
    (#235/#192); the sweep then drops the registration records whose runtime
    client that just removed (#190). They are composed here, in the
    composition root, rather than by teaching either side about the other:
    ``services.identities`` knows nothing about registration, and the
    registration service knows nothing about when a load happens.

    The order matters. A promotion is exactly the case where a record would
    otherwise outlive its client without anyone noticing: the lazy checks
    only fire when someone asks for that registration, so until then the
    record would still be there to be inherited by the next client to hold
    the name.

    ``after_load`` runs post-commit and must not raise (config.py), so the
    sweep is best effort, like the reconciliation it follows.
    """
    reconcile_runtime_identities(config)
    try:
        prune_stale_registrations(identities_for(config))
    except Exception:  # pragma: no cover - defensive, same contract as above
        logging.getLogger(__name__).exception(
            "Could not sweep dynamic registration records after a config load"
        )


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
    config = init_config(
        config_dir,
        profile_override=profile,
        strict_config=strict_config,
        activate=activate_services,
        after_load=_after_load,
    )
    settings = config.settings

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger = logging.getLogger(__name__)

    # Create Flask app
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )
    app.secret_key = settings.secret_key
    # Browsers that don't default new cookies to Lax (Firefox, at the time of
    # writing) would otherwise send the session cookie on a cross-site form
    # POST. An unlocked management_secret session authorizes /api/* mutations
    # (see routes/_auth.py:management_secret_required_for_api), not just
    # ui_bp's own forms, so that cross-site surface now covers the management
    # API too; Lax closes it at the cost of not sending the cookie on a
    # cross-site GET navigation's initial request, which this app never
    # relies on. See docs/SECURITY.md, "Session Cookie Trust".
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # secret_key signs the session cookie; a default (public, in source
    # control) value means anyone who knows it can forge session state -
    # including session['user'], bypassing require_ui_login outright.
    # management_secret's own session flag additionally binds to
    # management_secret itself (see routes/_auth.py:_management_verified_marker),
    # so knowing only this default doesn't forge that one - but a real
    # secret_key is still what either gate's session trust rests on. See
    # docs/SECURITY.md.
    if settings.secret_key == _DEFAULT_SECRET_KEY and (
        settings.require_ui_login or settings.management_secret
    ):
        logger.warning(
            "secret_key is left at its public default while require_ui_login "
            "and/or management_secret is configured. Set session.secret_key "
            "in settings.yaml to a real, private value before relying on "
            "either gate beyond a single trusted machine - see docs/SECURITY.md."
        )

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
            headers_enabled=True,  # RateLimit-*/Retry-After on 429 (#304)
        )
        logger.info(
            f"  - Rate limiting: enabled ({settings.rate_limit_token_endpoint} "
            "on /token, and on /register when registration is on)"
        )
    else:
        # Create a no-op limiter for compatibility
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=[],
            enabled=False,
        )

    # Register blueprints
    @app.errorhandler(LockUnavailableError)
    def _configuration_unavailable(exc: LockUnavailableError) -> Response:
        """503 for a configuration observation that could not be made (#246).

        Reads join the directory lock since #246, so a request that only
        renders a page can now fail where before it could not: a peer
        process holding the lock past the timeout, or a filesystem with no
        advisory locking at all. Without this it reaches the catch-all and
        answers 500 with a traceback, which says nothing true - the service
        is fine, it could not observe the configuration right now.

        Terminal rather than a redirect with a flash: the page it redirected
        to would have to read the configuration too, and would wait again or
        loop. How each surface phrases this is PR B's question; what belongs
        here is that no surface answers it with a stack trace.
        """
        app.logger.warning("Configuration observation unavailable: %s", exc)
        wants_json = request.path.startswith("/api/") or "application/json" in (
            request.headers.get("Accept", "")
        )
        if wants_json:
            response = jsonify({"error": "configuration_unavailable", "kind": exc.kind})
        else:
            response = make_response(
                "<h1>Configuration temporarily unavailable</h1>"
                "<p>The configuration directory could not be read consistently "
                "right now. Another process may be writing it. Try again.</p>"
            )
        response.status_code = 503
        return response

    @app.errorhandler(DeclaredConfigurationUnloadable)
    def _declaration_unloadable(exc: DeclaredConfigurationUnloadable) -> Response:
        """503 for a mutation checked against configuration files that
        changed and do not load (#354, step 4a): refused, not a fault of the
        request, and nothing coming back resolves until the files are fixed,
        so no Retry-After."""
        app.logger.warning("Refused against a configuration that does not load: %s", exc)
        response = jsonify({"error": "configuration_unloadable", "error_description": str(exc)})
        response.status_code = 503
        return response

    @app.errorhandler(RuntimeStoreUnavailable)
    def _runtime_store_unavailable(exc: RuntimeStoreUnavailable) -> Response:
        """503 with Retry-After for a runtime store held by another process
        for longer than it waits (#354): contention, which coming back
        resolves, and not a fault, which a 500 would say. Only contention
        is this; a store that is broken is an error of its own."""
        app.logger.warning("Runtime store unavailable: %s", exc)
        response = jsonify({"error": "runtime_store_unavailable", "error_description": str(exc)})
        response.status_code = 503
        response.headers["Retry-After"] = "1"
        return response

    # Before any blueprint's guard, which reads the configuration: an app
    # before_request runs first. With a store shared by other processes the
    # files are looked at here, once per request, not in get_config() (#354,
    # step 4a). LockUnavailableError is the 503 above.
    app.before_request(fresh_configuration)

    app.register_blueprint(oauth_bp)
    app.register_blueprint(saml_bp)
    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(runtime_bp)
    app.register_blueprint(registration_bp)

    # Actually APPLY the /token rate limit (#304). Until 3.0 the limiter
    # was created with default_limits=[] and no view ever decorated, so
    # rate_limit_enabled: true logged "enabled" while enforcing nothing -
    # a "metadata never lies" violation. The wrap must happen after the
    # blueprint registration above, which is what puts oauth.token into
    # app.view_functions.
    if settings.rate_limit_enabled:
        def _token_rate_limited(request_limit: Any) -> Response:
            # on_breach on THIS limit, not a global 429 handler (#314
            # review): /token's throttle response is a protocol-shaped
            # JSON, and scoping it here means a future limit on some other
            # endpoint does not inherit an OAuth-flavored body. RFC 6749
            # defines no error code for throttling; flask-limiter's
            # Retry-After/X-RateLimit-* headers (headers_enabled above)
            # carry the machine-readable part.
            response = jsonify(
                {
                    "error": "rate_limit_exceeded",
                    "error_description": (
                        "Too many token requests; retry after the "
                        "interval in the Retry-After header"
                    ),
                }
            )
            response.status_code = 429
            return response

        # The rate string was validated at the config boundary
        # (Settings.validate_rate_limit_notation): flask-limiter would not
        # raise on a malformed one - it logs and falls back to the default
        # limits, which are [] here, silently disabling the throttle.
        # flask-limiter's decorator returns the same callable it received;
        # the ignore covers werkzeug's wide view-function union.
        app.view_functions["oauth.token"] = limiter.limit(  # type: ignore[assignment]
            settings.rate_limit_token_endpoint,
            on_breach=_token_rate_limited,
        )(app.view_functions["oauth.token"])

        # /register is unauthenticated by design when it is on (#190), and
        # its only other bound is max_clients, which does not heal by
        # itself: a script can spend every slot in seconds and leave the
        # endpoint useless for the life of the process. The operator's own
        # rate applies here too rather than a second setting for the same
        # intent.
        def _registration_rate_limited(request_limit: Any) -> Response:
            response = jsonify(
                {
                    "error": "rate_limit_exceeded",
                    "error_description": (
                        "Too many registration requests; retry after the "
                        "interval in the Retry-After header"
                    ),
                }
            )
            response.status_code = 429
            return response

        app.view_functions["registration.register"] = limiter.limit(  # type: ignore[assignment]
            settings.rate_limit_token_endpoint,
            on_breach=_registration_rate_limited,
        )(app.view_functions["registration.register"])

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
    # loudly when that safe default is overridden. management_secret (#163)
    # gates mutations but not reads, so the warning still applies, just less
    # severely, when it's configured.
    if effective_host in ("0.0.0.0", "::", ""):
        if settings.management_secret:
            logging.getLogger(__name__).warning(
                "Binding to %s exposes NanoIDP on all network interfaces. "
                "management_secret is configured, so /api/* mutations "
                "(minting admin tokens, rotating signing keys, creating runtime "
                "users and clients under /api/runtime, etc.) require "
                "it - but reads and the UI dashboard remain open to any "
                "reachable host. Use 127.0.0.1 unless you intend network "
                "exposure (e.g. inside a container).",
                effective_host,
            )
        else:
            logging.getLogger(__name__).warning(
                "Binding to %s exposes NanoIDP on all network interfaces. The "
                "/api/* management endpoints are unauthenticated by design, so any "
                "reachable host can mint admin tokens, rotate signing keys and "
                "create runtime users and clients under /api/runtime. Use "
                "127.0.0.1 unless you intend network exposure (e.g. inside a "
                "container), or set management_secret to require a shared secret "
                "for mutations.",
                effective_host,
            )

    app.run(
        host=effective_host,
        port=port or settings.port,
        debug=effective_debug,
    )
