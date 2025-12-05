"""Routes module for NanoIDP."""

from .oauth import oauth_bp
from .saml import saml_bp
from .ui import ui_bp
from .api import api_bp

__all__ = ["oauth_bp", "saml_bp", "ui_bp", "api_bp"]
