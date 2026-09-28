"""Standalone TradeDeck Shield API.

Run:  gunicorn --chdir shield app:app
Dev:  FLASK_DEBUG=1 python shield/app.py
"""
import logging
import os

import stripe
from flask import Flask, g, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from db import client
from routes import bp
from tenant_api import bp as tenant_bp

log = logging.getLogger(__name__)


def create_app():
    config.configure_logging()
    config.validate()

    app = Flask(__name__)
    stripe.api_key = config.get("STRIPE_SECRET_KEY")

    # Werkzeug only raises 413 when this is set. Without it the 413 handler
    # below was unreachable and the size check in upload_photo ran AFTER the
    # whole body was already in memory — a few multi-GB POSTs from any
    # authenticated contractor would spool to disk and then OOM the worker.
    app.config["MAX_CONTENT_LENGTH"] = config.get_int("MAX_UPLOAD_BYTES")

    # Trust exactly one proxy hop (Render's). Without this, request.remote_addr
    # is the proxy and X-Forwarded-For parsing is left to each call site.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    CORS(app, origins=config.allowed_origins(), supports_credentials=False,
         allow_headers=["Authorization", "Content-Type"],
         methods=["GET", "POST", "OPTIONS"])

    @app.before_request
    def attach():
        g.supabase = client()

    @app.after_request
    def harden(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"error": "File too large"}), 413

    @app.errorhandler(500)
    def server_error(exc):
        log.exception("Unhandled error", exc_info=exc)
        return jsonify({"error": "Internal error"}), 500

    # The legacy blueprint, on TradeDeck's tables through TradeDeck's identity.
    # It keeps serving until its last caller leaves.
    app.register_blueprint(bp)
    # The sellable one: tenant-scoped, on Shield's own schema. Separate
    # blueprint rather than a port in place, so neither speaks two dialects.
    app.register_blueprint(tenant_bp)

    @app.route("/")
    def index():
        return jsonify({"service": "tradedeck-shield", "status": "ok"})

    # The trailing slash is load-bearing. Without it the browser resolves
    # `console.css` against the site root, both assets 404, and the page
    # renders its own markup and then does nothing -- which looks like a
    # working console until you click something. Flask redirects /console to
    # /console/ for a rule written this way. Caught by the browser test.
    @app.route("/console/")
    @app.route("/console/<path:asset>")
    def console(asset="index.html"):
        """The tenant console.

        Served from the API origin on purpose: the page's connect-src is
        'self', so it can only ever talk back to the service that served it.
        A console hosted elsewhere would need a wider policy and a CORS
        allowance, and both are things an attacker would rather we had.
        """
        return send_from_directory(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "console"),
            asset)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "model": config.get("ANTHROPIC_MODEL")})

    return app


app = create_app() if __name__ != "__main__" else None

if __name__ == "__main__":
    create_app().run(port=5001, debug=os.environ.get("FLASK_DEBUG") == "1")
