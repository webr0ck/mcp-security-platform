#!/usr/bin/env python3
"""Small dependency-free policy API server for local MCP testing."""

from __future__ import annotations

import argparse
import json
import re
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


DEFAULT_HOST = "127.0.0.1"
READ_PORT = 9191
RW_PORT = 9292
DEFAULT_BEARER_TOKEN = "security-token"


def create_policy_documents() -> dict[str, dict[str, Any]]:
    policies = [
        {
            "id": "app-sec-review",
            "title": "Application Security Review",
            "type": "application-security",
            "department": "Engineering",
            "lines": [
                "All internet-facing applications must complete a security review before production release.",
                "Threat modeling is required for new authentication, payment, and administrative workflows.",
                "Critical and high findings must be fixed or formally risk-accepted before launch.",
            ],
        },
        {
            "id": "secure-code-review",
            "title": "Secure Code Review",
            "type": "application-security",
            "department": "Engineering",
            "lines": [
                "Code handling secrets, user input, or authorization decisions requires peer review.",
                "Static analysis findings must be triaged before merging to the main branch.",
                "Developers must not commit credentials, tokens, or private keys to source control.",
            ],
        },
        {
            "id": "network-segmentation",
            "title": "Network Segmentation",
            "type": "network",
            "department": "IT Operations",
            "lines": [
                "Production, corporate, and guest networks must be segmented with explicit firewall rules.",
                "Inbound administrative access is limited to approved management networks.",
                "Firewall changes require documented business justification and review.",
            ],
        },
        {
            "id": "remote-access",
            "title": "Remote Access",
            "type": "network",
            "department": "IT Operations",
            "lines": [
                "Remote access must use company-approved VPN or zero-trust access services.",
                "Multi-factor authentication is required for all remote administrative sessions.",
                "Split tunneling may only be enabled for approved low-risk use cases.",
            ],
        },
        {
            "id": "windows-endpoint-hardening",
            "title": "Windows Endpoint Hardening",
            "type": "endpoint-windows",
            "department": "Workplace Technology",
            "lines": [
                "Windows endpoints must run supported operating system versions with automatic updates enabled.",
                "Local administrator rights are restricted to approved support and engineering cases.",
                "Endpoint protection must remain active and report telemetry to the central console.",
            ],
        },
        {
            "id": "linux-server-hardening",
            "title": "Linux Server Hardening",
            "type": "endpoint-linux",
            "department": "Infrastructure",
            "lines": [
                "Linux servers must disable password-based SSH access for privileged accounts.",
                "Security updates must be applied according to the vulnerability remediation SLA.",
                "Unneeded services and packages must be removed from production server images.",
            ],
        },
        {
            "id": "compliance-evidence",
            "title": "Compliance Evidence",
            "type": "compliance",
            "department": "Compliance",
            "lines": [
                "Control owners must provide audit evidence within five business days of request.",
                "Evidence must be traceable to the system, control, date, and responsible owner.",
                "Exceptions must include compensating controls and an expiration date.",
            ],
        },
        {
            "id": "data-retention",
            "title": "Data Retention",
            "type": "compliance",
            "department": "Legal",
            "lines": [
                "Business records must be retained according to the approved retention schedule.",
                "Security logs must be retained for at least 180 days unless a stricter rule applies.",
                "Data marked for legal hold must not be deleted until the hold is released.",
            ],
        },
        {
            "id": "incident-response",
            "title": "Incident Response",
            "type": "incident-response",
            "department": "Security",
            "lines": [
                "Suspected security incidents must be reported to the security department immediately.",
                "The incident commander owns coordination, status updates, and escalation decisions.",
                "Post-incident review actions must be tracked to closure with accountable owners.",
            ],
        },
        {
            "id": "security-monitoring",
            "title": "Security Monitoring",
            "type": "incident-response",
            "department": "Security",
            "lines": [
                "Critical security alerts require triage within the agreed response SLA.",
                "Detection rules must include owner, purpose, data source, and tuning history.",
                "Monitoring gaps for critical systems must be documented and prioritized.",
            ],
        },
    ]

    return {policy["id"]: policy for policy in policies}


def make_handler(access_mode: str, bearer_token: str) -> type["TestApiHandler"]:
    class ConfiguredPolicyHandler(TestApiHandler):
        pass

    ConfiguredPolicyHandler.required_access_mode = access_mode
    ConfiguredPolicyHandler.bearer_token = bearer_token

    return ConfiguredPolicyHandler


class TestApiHandler(BaseHTTPRequestHandler):
    server_version = "PolicyApiServer/0.2"
    required_access_mode = "rw"
    bearer_token = DEFAULT_BEARER_TOKEN

    def do_GET(self) -> None:
        path, query = self._path_and_query()

        if path == "/":
            self._send_json(
                {
                    "name": "policy-api-server",
                    "access": self._access_mode(),
                    "endpoints": [
                        "GET /health",
                        "GET /policies?type=network&department=IT%20Operations&q=firewall",
                        "GET /policies/{policy_id}",
                        "POST /policies/{policy_id}/lines",
                        "PATCH /policies/{policy_id}/lines/{line_number}",
                    ],
                }
            )
            return

        if path == "/health":
            self._send_json({"status": "ok"})
            return

        if path == "/policies":
            self._send_json({"policies": self._search_policies(query)})
            return

        match = re.fullmatch(r"/policies/([a-z0-9-]+)", path)
        if match:
            policy = self._policy(match.group(1))
            if policy is None:
                self._send_error(HTTPStatus.NOT_FOUND, "Policy not found")
                return

            self._send_json({"policy": policy})
            return

        self._send_error(HTTPStatus.NOT_FOUND, "Route not found")

    def do_POST(self) -> None:
        path, _query = self._path_and_query()

        match = re.fullmatch(r"/policies/([a-z0-9-]+)/lines", path)
        if match:
            if not self._require_write_access():
                return

            body = self._read_json_body()
            if body is None:
                return

            text = body.get("text") if isinstance(body, dict) else None
            if not isinstance(text, str) or not text.strip():
                self._send_error(HTTPStatus.BAD_REQUEST, "Body must include a non-empty text string")
                return

            policy = self._policy(match.group(1))
            if policy is None:
                self._send_error(HTTPStatus.NOT_FOUND, "Policy not found")
                return

            policy["lines"].append(text.strip())
            self._send_json({"policy": policy}, HTTPStatus.CREATED)
            return

        self._send_error(HTTPStatus.NOT_FOUND, "Route not found")

    def do_PATCH(self) -> None:
        path, _query = self._path_and_query()

        match = re.fullmatch(r"/policies/([a-z0-9-]+)/lines/(\d+)", path)
        if match:
            if not self._require_write_access():
                return

            body = self._read_json_body()
            if body is None:
                return

            text = body.get("text") if isinstance(body, dict) else None
            if not isinstance(text, str) or not text.strip():
                self._send_error(HTTPStatus.BAD_REQUEST, "Body must include a non-empty text string")
                return

            policy = self._policy(match.group(1))
            if policy is None:
                self._send_error(HTTPStatus.NOT_FOUND, "Policy not found")
                return

            line_number = int(match.group(2))
            if line_number < 1 or line_number > len(policy["lines"]):
                self._send_error(HTTPStatus.NOT_FOUND, "Policy line not found")
                return

            policy["lines"][line_number - 1] = text.strip()
            self._send_json({"policy": policy})
            return

        self._send_error(HTTPStatus.NOT_FOUND, "Route not found")

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def _path_and_query(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)

    def _policy_store(self) -> dict[str, dict[str, Any]]:
        if not hasattr(self.server, "policy_documents"):
            self.server.policy_documents = create_policy_documents()
        return self.server.policy_documents

    def _policy(self, policy_id: str) -> dict[str, Any] | None:
        return self._policy_store().get(policy_id)

    def _search_policies(self, query: dict[str, list[str]]) -> list[dict[str, Any]]:
        policy_type = self._query_value(query, "type")
        department = self._query_value(query, "department")
        search = self._query_value(query, "q") or self._query_value(query, "search")

        results = list(self._policy_store().values())
        if policy_type:
            results = [policy for policy in results if policy["type"].lower() == policy_type.lower()]
        if department:
            results = [policy for policy in results if policy["department"].lower() == department.lower()]
        if search:
            needle = search.lower()
            results = [
                policy
                for policy in results
                if needle in policy["title"].lower()
                or needle in policy["type"].lower()
                or needle in policy["department"].lower()
                or any(needle in line.lower() for line in policy["lines"])
            ]

        return results

    def _query_value(self, query: dict[str, list[str]], name: str) -> str | None:
        values = query.get(name)
        if not values:
            return None
        value = values[0].strip()
        return value or None

    def _access_mode(self) -> str:
        return getattr(self, "required_access_mode", "rw")

    def _require_write_access(self) -> bool:
        if self._access_mode() != "rw":
            self._send_error(HTTPStatus.FORBIDDEN, "Read-only listener does not allow writes")
            return False

        if self._has_valid_bearer_token() or self._has_valid_basic_auth():
            return True

        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("www-authenticate", 'Bearer realm="security-department"')
        payload = json.dumps({"error": "Bearer token or Basic credentials required", "status": HTTPStatus.UNAUTHORIZED.value}).encode("utf-8")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        return False

    def _has_valid_bearer_token(self) -> bool:
        header = self.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            return False

        token = header.removeprefix("Bearer ").strip()
        return token == self.bearer_token

    def _has_valid_basic_auth(self) -> bool:
        # Added for mcp-security-platform onboarding acceptance test (2026-07-14):
        # lets the MCP wrapper exercise the platform's basic_auth injection mode
        # against the same write endpoint, alongside the original Bearer scheme.
        import base64

        header = self.headers.get("authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header.removeprefix("Basic ").strip()).decode("utf-8")
            username, _, password = decoded.partition(":")
        except Exception:
            return False
        return username == getattr(self, "basic_username", "security-department") and password == self.bearer_token

    def _read_json_body(self) -> Any | None:
        raw_length = self.headers.get("content-length", "0")
        try:
            length = int(raw_length)
        except ValueError:
            self._send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length header")
            return None

        raw = self.rfile.read(length)
        if not raw:
            return {}

        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Request body must be valid JSON")
            return None

    def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json({"error": message, "status": status.value}, status)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the local policy API server.")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Host to bind. Default: {DEFAULT_HOST}")
    parser.add_argument("--read-port", default=READ_PORT, type=int, help=f"Read-only port. Default: {READ_PORT}")
    parser.add_argument("--rw-port", default=RW_PORT, type=int, help=f"Read/write port. Default: {RW_PORT}")
    parser.add_argument(
        "--bearer-token",
        default=DEFAULT_BEARER_TOKEN,
        help=f"RW bearer token. Default: {DEFAULT_BEARER_TOKEN}",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    documents = create_policy_documents()
    read_server = ThreadingHTTPServer((args.host, args.read_port), make_handler("read", args.bearer_token))
    read_server.policy_documents = documents
    rw_server = ThreadingHTTPServer((args.host, args.rw_port), make_handler("rw", args.bearer_token))
    rw_server.policy_documents = documents

    read_thread = threading.Thread(target=read_server.serve_forever, daemon=True)
    rw_thread = threading.Thread(target=rw_server.serve_forever, daemon=True)
    read_thread.start()
    rw_thread.start()

    print(f"Read-only policy API at http://{args.host}:{args.read_port}")
    print(f"Security RW policy API at http://{args.host}:{args.rw_port}")
    try:
        read_thread.join()
        rw_thread.join()
    except KeyboardInterrupt:
        print("\nShutting down")
    finally:
        read_server.shutdown()
        rw_server.shutdown()
        read_server.server_close()
        rw_server.server_close()


if __name__ == "__main__":
    main()
