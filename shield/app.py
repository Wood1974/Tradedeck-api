"""Standalone TradeDeck Shield API.

Run:  gunicorn --chdir shield app:app
Dev:  FLASK_DEBUG=1 python shield/app.py
"""
import logging

import stripe
from flask import Flask, g, jsonify
from flask_cors import CORS

import config
from db import client
from routes import bp

log = logging.getLogger(__name__)


def create_app():
    config.configure_logging()
    config.validate()

    app = Flask(__name__)
    stripe.api_key = config.get("STRIPE_SECRET_KEY")

    CORS(app, origins=config.allowed_origins(), supports_credentials=True,
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

    app.register_blueprint(bp)

    @app.route("/")
    def index():
        return jsonify({"service": "tradedeck-shield", "status": "ok"})

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "model": config.get("ANTHROPIC_MODEL")})

    return app


app = create_app() if __name__ != "__main__" else None

if __name__ == "__main__":
    create_app().run(port=5001, debug=True)
