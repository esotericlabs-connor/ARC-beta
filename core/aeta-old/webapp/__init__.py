"""Minimal Flask web UI for running AETA analyses locally."""
from __future__ import annotations

import hmac
import json
import os
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

from dataclasses import asdict

from flask import Blueprint, Flask, Request, abort, current_app, jsonify, render_template, request

from ..core import analyze_email
from ..models import SentryReport, SignalContribution, VerificationResult
from ..utils.community_intel import get_community_hub


BASE_DIR = Path(__file__).resolve().parent


def create_app() -> Flask:
    """Create and configure the AETA web application."""

    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    _initialise_osint_config(app)
    app.register_blueprint(_create_osint_api_blueprint())  # 16 MB upload limit
    _initialise_osint_config(app)
    app.register_blueprint(_create_osint_api_blueprint())

    @app.route("/", methods=["GET", "POST"])
    def index() -> str:
        error: str | None = None
        context: Dict[str, Any] | None = None

        if request.method == "POST":
            error, context = _handle_upload(request)

        return render_template("index.html", error=error, report=context)

    @app.route("/threat-intel", methods=["GET"])
    def threat_intel() -> str:
        hub = get_community_hub()
        snapshot = hub.snapshot()
        return render_template("threat_intel.html", snapshot=asdict(snapshot))

    @app.route("/api/threat-intel", methods=["GET"])
    def threat_intel_api():  # type: ignore[return-type]
        hub = get_community_hub()
        snapshot = hub.snapshot()
        payload = asdict(snapshot)
        return jsonify(payload)

    return app
def _initialise_osint_config(app: Flask) -> None:
    """Load secure API defaults from environment variables."""

    if not app.config.get("OSINT_API_TOKEN"):
        token = os.environ.get("OSINT_API_TOKEN")
        if token:
            app.config["OSINT_API_TOKEN"] = token

    allow_origins = app.config.get("OSINT_API_ALLOW_ORIGINS")
    if allow_origins is None:
        env_origins = os.environ.get("OSINT_API_ALLOW_ORIGINS", "")
        origins = [origin.strip() for origin in env_origins.split(",") if origin.strip()]
        app.config["OSINT_API_ALLOW_ORIGINS"] = origins
    elif isinstance(allow_origins, str):
        origins = [origin.strip() for origin in allow_origins.split(",") if origin.strip()]
        app.config["OSINT_API_ALLOW_ORIGINS"] = origins
    else:
        app.config.setdefault("OSINT_API_ALLOW_ORIGINS", [])


def _create_osint_api_blueprint() -> Blueprint:
    bp = Blueprint("osint_api", __name__, url_prefix="/api/v1")

    @bp.route("/health", methods=["GET"])
    def health_check():
        expected = _expected_api_token()
        if expected:
            _require_api_token()
            return jsonify({"status": "ok"})
        return jsonify({"status": "degraded", "reason": "OSINT_API_TOKEN not configured"}), 503

    @bp.route("/intel/snapshot", methods=["GET"])
    def intel_snapshot():
        _require_api_token()
        hub = get_community_hub()
        snapshot = hub.snapshot()
        return jsonify(asdict(snapshot))

    @bp.route("/intel/events", methods=["POST"])
    def ingest_intel_event():
        _require_api_token()
        payload = request.get_json(silent=True)
        if not isinstance(payload, Mapping):
            abort(400, description="Expected a JSON object body")
        event_payload = {str(key): value for key, value in payload.items()}
        hub = get_community_hub()
        hub.ingest_external_event(event_payload)
        return jsonify({"status": "accepted"}), 202

    @bp.route("/intel/events", methods=["OPTIONS"])
    @bp.route("/intel/snapshot", methods=["OPTIONS"])
    def osint_options():
        return current_app.response_class(status=204)

    @bp.after_request
    def _apply_cors_headers(response):  # type: ignore[override]
        origins = current_app.config.get("OSINT_API_ALLOW_ORIGINS") or []
        if isinstance(origins, str):
            origins = [origin.strip() for origin in origins.split(",") if origin.strip()]
            current_app.config["OSINT_API_ALLOW_ORIGINS"] = origins
        origin_header = request.headers.get("Origin")
        if origins:
            if "*" in origins:
                response.headers["Access-Control-Allow-Origin"] = "*"
            elif origin_header and origin_header in origins:
                response.headers["Access-Control-Allow-Origin"] = origin_header
            if response.headers.get("Access-Control-Allow-Origin"):
                existing_vary = response.headers.get("Vary")
                if existing_vary and "Origin" not in existing_vary:
                    response.headers["Vary"] = f"{existing_vary}, Origin"
                elif not existing_vary:
                    response.headers["Vary"] = "Origin"
                response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Key"
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    return bp

def _expected_api_token() -> str | None:
    token = current_app.config.get("OSINT_API_TOKEN")
    if isinstance(token, str) and token.strip():
        return token.strip()
    env_token = os.environ.get("OSINT_API_TOKEN")
    if env_token and env_token.strip():
        current_app.config["OSINT_API_TOKEN"] = env_token.strip()
        return env_token.strip()
    return None


def _extract_api_token(req: Request) -> str | None:
    auth_header = req.headers.get("Authorization", "")
    if auth_header:
        scheme, _, value = auth_header.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            return value.strip()
    api_key_header = req.headers.get("X-API-Key")
    if api_key_header and api_key_header.strip():
        return api_key_header.strip()
    api_key_param = req.args.get("api_key")
    if api_key_param and api_key_param.strip():
        return api_key_param.strip()
    return None


def _require_api_token() -> None:
    expected = _expected_api_token()
    if not expected:
        abort(503, description="OSINT API token is not configured")
    provided = _extract_api_token(request)
    if not provided or not hmac.compare_digest(expected, provided):
        abort(401, description="Invalid or missing API token")




def _initialise_osint_config(app: Flask) -> None:
    """Load secure API defaults from environment variables."""

    if not app.config.get("OSINT_API_TOKEN"):
        token = os.environ.get("OSINT_API_TOKEN")
        if token:
            app.config["OSINT_API_TOKEN"] = token

    allow_origins = app.config.get("OSINT_API_ALLOW_ORIGINS")
    if allow_origins is None:
        env_origins = os.environ.get("OSINT_API_ALLOW_ORIGINS", "")
        origins = [origin.strip() for origin in env_origins.split(",") if origin.strip()]
        app.config["OSINT_API_ALLOW_ORIGINS"] = origins
    elif isinstance(allow_origins, str):
        origins = [origin.strip() for origin in allow_origins.split(",") if origin.strip()]
        app.config["OSINT_API_ALLOW_ORIGINS"] = origins
    else:
        app.config.setdefault("OSINT_API_ALLOW_ORIGINS", [])


def _create_osint_api_blueprint() -> Blueprint:
    bp = Blueprint("osint_api", __name__, url_prefix="/api/v1")

    @bp.route("/health", methods=["GET"])
    def health_check():
        expected = _expected_api_token()
        if expected:
            _require_api_token()
            return jsonify({"status": "ok"})
        return jsonify({"status": "degraded", "reason": "OSINT_API_TOKEN not configured"}), 503

    @bp.route("/intel/snapshot", methods=["GET"])
    def intel_snapshot():
        _require_api_token()
        hub = get_community_hub()
        snapshot = hub.snapshot()
        return jsonify(asdict(snapshot))

    @bp.route("/intel/events", methods=["POST"])
    def ingest_intel_event():
        _require_api_token()
        payload = request.get_json(silent=True)
        if not isinstance(payload, Mapping):
            abort(400, description="Expected a JSON object body")
        event_payload = {str(key): value for key, value in payload.items()}
        hub = get_community_hub()
        hub.ingest_external_event(event_payload)
        return jsonify({"status": "accepted"}), 202

    @bp.route("/intel/events", methods=["OPTIONS"])
    @bp.route("/intel/snapshot", methods=["OPTIONS"])
    def osint_options():
        return current_app.response_class(status=204)

    @bp.after_request
    def _apply_cors_headers(response):  # type: ignore[override]
        origins = current_app.config.get("OSINT_API_ALLOW_ORIGINS") or []
        if isinstance(origins, str):
            origins = [origin.strip() for origin in origins.split(",") if origin.strip()]
            current_app.config["OSINT_API_ALLOW_ORIGINS"] = origins
        origin_header = request.headers.get("Origin")
        if origins:
            if "*" in origins:
                response.headers["Access-Control-Allow-Origin"] = "*"
            elif origin_header and origin_header in origins:
                response.headers["Access-Control-Allow-Origin"] = origin_header
            if response.headers.get("Access-Control-Allow-Origin"):
                existing_vary = response.headers.get("Vary")
                if existing_vary and "Origin" not in existing_vary:
                    response.headers["Vary"] = f"{existing_vary}, Origin"
                elif not existing_vary:
                    response.headers["Vary"] = "Origin"
                response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Key"
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    return bp


def _expected_api_token() -> str | None:
    token = current_app.config.get("OSINT_API_TOKEN")
    if isinstance(token, str) and token.strip():
        return token.strip()
    env_token = os.environ.get("OSINT_API_TOKEN")
    if env_token and env_token.strip():
        current_app.config["OSINT_API_TOKEN"] = env_token.strip()
        return env_token.strip()
    return None


def _extract_api_token(req: Request) -> str | None:
    auth_header = req.headers.get("Authorization", "")
    if auth_header:
        scheme, _, value = auth_header.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            return value.strip()
    api_key_header = req.headers.get("X-API-Key")
    if api_key_header and api_key_header.strip():
        return api_key_header.strip()
    api_key_param = req.args.get("api_key")
    if api_key_param and api_key_param.strip():
        return api_key_param.strip()
    return None


def _require_api_token() -> None:
    expected = _expected_api_token()
    if not expected:
        abort(503, description="OSINT API token is not configured")
    provided = _extract_api_token(request)
    if not provided or not hmac.compare_digest(expected, provided):
        abort(401, description="Invalid or missing API token")
def _handle_upload(req: Request) -> Tuple[str | None, Dict[str, Any] | None]:
    """Process an uploaded EML file and return template context."""

    uploaded = req.files.get("eml_file")
    if uploaded is None or uploaded.filename == "":
        return "Please choose an .eml file to analyze.", None

    filename = uploaded.filename
    if not filename.lower().endswith(".eml"):
        return "Unsupported file type. Please upload a .eml message.", None

    contents = uploaded.read()
    if not contents:
        return "Uploaded file is empty.", None

    try:
        report = analyze_email(contents)
    except Exception as exc:  # pragma: no cover - safety net for UI feedback
        return f"Analysis failed: {exc}", None

    return None, _build_report_context(report, original_filename=filename)


def _build_report_context(report: SentryReport, *, original_filename: str) -> Dict[str, Any]:
    """Transform a :class:`SentryReport` into template-friendly data."""
@@ -176,26 +292,26 @@ def main(
    # wildcard address directly (which does not resolve on some platforms).
    loopback_url = f"http://127.0.0.1:{bind_port}"

    if open_browser:
        url = loopback_url

        def _launch_browser() -> None:
            # Give the server a moment to start before opening the browser
            time.sleep(1.0)
            webbrowser.open(url)

        threading.Thread(target=_launch_browser, daemon=True).start()

    if bind_host in {"0.0.0.0", "::", "::0"}:
        print(
            "AETA web analyzer listening on all interfaces. "
            f"Local access: {loopback_url}"
        )
    else:
        print(f"AETA web analyzer running on http://{bind_host}:{bind_port}")

    print("Upload an .eml file to generate the interactive report.")
    app.run(host=bind_host, port=bind_port)


__all__ = ["create_app", "main"]