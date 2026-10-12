"""A bounded HEAD-only demo against a fixture this process starts on loopback."""

from contextlib import contextmanager
import copy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
import time

from .ledger import Refused

HEADERS = ("content-security-policy", "x-content-type-options", "referrer-policy")
CASES = {"header_presence": "headers", "anonymous_denial": "restricted"}
PATHS = tuple(f"/{role}/{suffix}" for role in ("candidate", "clean_control") for suffix in CASES.values())
ORIGIN = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def source_digest():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) != {"schema", "candidate", "clean_control"} or policy["schema"] != "cyber-review.fixture.v1":
        raise Refused("Exact local fixture policy required.")
    for role in ("candidate", "clean_control"):
        profile = policy[role]
        if not isinstance(profile, dict) or set(profile) != {"security_headers", "unauthenticated_status"} or type(profile["security_headers"]) is not bool or profile["unauthenticated_status"] not in (200, 401, 403):
            raise Refused("Invalid local fixture profile.")
    if policy["clean_control"] != {"security_headers": True, "unauthenticated_status": 403}:
        raise Refused("Known-good synthetic control must remain fixed.")


@contextmanager
def local_fixture(policy):
    validate_policy(policy)
    profile = copy.deepcopy(policy)

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            if self.path not in PATHS:
                self.send_response(404)
                self.end_headers()
                return
            role, suffix = self.path.strip("/").split("/")
            status = profile[role]["unauthenticated_status"] if suffix == "restricted" else 200
            self.send_response(status)
            self.send_header("X-Local-Fixture", "cyber-review-workbench")
            if profile[role]["security_headers"]:
                self.send_header("Content-Security-Policy", "default-src 'none'")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def make_scope(origin, policy, now):
    return {"schema": "cyber-review.scope.v1", "origin": origin, "method": "HEAD", "paths": list(PATHS),
            "fixture_source_sha256": source_digest(), "profile_sha256": digest(policy),
            "expires_at": now + 600, "request_credentials": False, "response_body_retained": False,
            "automatic_replay_allowed": False}


def make_grant(scope, approved, now):
    if approved is not True:
        raise Refused("Explicit --approve-local-fixture operator action required.")
    return {"schema": "cyber-review.authorization.v1", "scope_sha256": digest(scope),
            "intent": "observe_included_local_fixture", "approved_at": now,
            "authorization_source": "explicit_local_fixture_cli_flag"}


def validate_scope(scope, grant, expected_scope, policy, now):
    scope_keys = {"schema", "origin", "method", "paths", "fixture_source_sha256", "profile_sha256", "expires_at", "request_credentials", "response_body_retained", "automatic_replay_allowed"}
    grant_keys = {"schema", "scope_sha256", "intent", "approved_at", "authorization_source"}
    if not isinstance(scope, dict) or set(scope) != scope_keys or not isinstance(grant, dict) or set(grant) != grant_keys:
        raise Refused("Exact scope and operator authorization required.")
    match = ORIGIN.fullmatch(scope["origin"]) if isinstance(scope["origin"], str) else None
    if match is None or int(match[1]) > 65535 or scope["schema"] != "cyber-review.scope.v1" or scope["method"] != "HEAD" or scope["paths"] != list(PATHS):
        raise Refused("Only the included loopback HEAD fixture paths are permitted.")
    if any(scope[key] is not False for key in ("request_credentials", "response_body_retained", "automatic_replay_allowed")):
        raise Refused("Credentials, bodies and replay are outside the local fixture scope.")
    if grant["schema"] != "cyber-review.authorization.v1" or grant["intent"] != "observe_included_local_fixture" or grant["authorization_source"] != "explicit_local_fixture_cli_flag":
        raise Refused("Explicit local fixture authorization required.")
    if type(grant["approved_at"]) is not int or type(scope["expires_at"]) is not int or not grant["approved_at"] <= now < scope["expires_at"] or scope["expires_at"] - grant["approved_at"] != 600:
        raise Refused("Local fixture authorization expired or invalid.")
    if grant["scope_sha256"] != expected_scope or digest(scope) != expected_scope or scope["fixture_source_sha256"] != source_digest() or scope["profile_sha256"] != digest(policy):
        raise Refused("Reviewed local scope or fixture bytes changed.")
    validate_policy(policy)
    return int(match[1])


def observe(scope, grant, expected_scope, policy, path, ledger, now=None):
    now = int(time.time()) if now is None else now
    port = validate_scope(scope, grant, expected_scope, policy, now)
    if path not in PATHS:
        raise Refused("Path is outside the reviewed fixture scope.")
    action_id = "head:" + path
    ledger.claim(action_id, expected_scope, {"name": "observe_local_fixture", "arguments": {"path": path}})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    started = time.monotonic()
    try:
        connection.request("HEAD", path, headers={"Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        if sum(len(key) + len(value) for key, value in response.getheaders()) > 16384:
            raise Refused("Response header budget exceeded.")
        if response.getheader("X-Local-Fixture") != "cyber-review-workbench":
            raise Refused("Included fixture marker missing.")
        evidence = {"schema": "cyber-review.observation.v1", "path": path, "http_status": response.status,
                    "security_headers_present": {header: response.getheader(header) is not None for header in HEADERS},
                    "redirect_observed": response.status in (301, 302, 303, 307, 308), "redirect_followed": False,
                    "response_body_retained": False, "request_credentials": False,
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "complete": True, "findings_status": "operator_review_required"}
        # No response body, header values, cookies, banners or exception messages are saved.
        ledger.complete(action_id, evidence, success=response.status < 500)
        return evidence
    except (OSError, http.client.HTTPException, Refused):
        evidence = {"schema": "cyber-review.observation.v1", "path": path, "complete": False,
                    "reason": "transport_marker_or_header_budget_failure", "automatic_replay_allowed": False}
        try:
            ledger.complete(action_id, evidence, success=False, complete=False)
        except (OSError, Refused):
            pass
        return evidence
    finally:
        connection.close()
