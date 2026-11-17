"""Serve a same-origin dashboard and proxy predefined simulation requests."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
import os
from secrets import token_hex
from pathlib import Path
from threading import Event, Lock
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from attacks.scenarios import SCENARIOS

ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}

def lab_host(value):
    if not value or any(character.isspace() for character in value):
        return False
    try:
        url = urlsplit(f"//{value}")
        if not url.hostname or url.username is not None or url.path or url.query or url.fragment:
            return False
        port = url.port  # Validate the port if one was supplied.
        if port == 0:
            return False
        return url.hostname == "localhost" or bool(ip_address(url.hostname))
    except ValueError:
        return False


class Dashboard(ThreadingHTTPServer):
    def __init__(self, telemetry, assets: Path, port):
        missing = {rule for _, _, expected in SCENARIOS.values() for rule in expected} - telemetry.rules.keys()
        if missing:
            raise ValueError(f"Simulation rules are missing: {', '.join(sorted(missing))}")
        self.telemetry = telemetry
        self.assets = assets
        self.simulator_url = os.getenv("SIMULATOR_URL", "")
        self.simulation_lock = Lock()
        super().__init__(("0.0.0.0", port), Handler)

    def run_scenario(self, name):
        if not self.simulator_url:
            return {"error": "Browser simulations are disabled."}, 503
        if not self.simulation_lock.acquire(blocking=False):
            return {"error": "A simulation is already running."}, 409
        tag = "lab-" + token_hex(5)
        expected = SCENARIOS[name][2]
        telemetry = self.telemetry
        drill = {"expected": expected, "alerts": {}, "events": {}, "observed": Event()}
        with telemetry.lock:
            telemetry.drills[tag] = drill
        try:
            request = Request(f"{self.simulator_url}/run/{name}", method="POST", headers={"X-Lab-Process": tag})
            try:
                with urlopen(request, timeout=11) as response:
                    result = json.load(response)
            except (URLError, OSError, ValueError):
                return {"error": "The simulation container did not return a result. Check its Compose logs."}, 502
            drill["observed"].wait(timeout=2.5)
            with telemetry.lock:
                return {
                    **result, "scenario": name, "process": tag, "session": telemetry.session, "expected_rules": expected,
                    "detections": [drill["alerts"][rule] for rule in expected if rule in drill["alerts"]],
                    "events": list(drill["events"].values()),
                }, 200
        finally:
            with telemetry.lock:
                del telemetry.drills[tag]
            self.simulation_lock.release()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def log_message(self, fmt, *args):
        pass

    def send_body(self, body, content_type, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload, status=200):
        self.send_body(json.dumps(payload).encode(), "application/json", status)

    def do_GET(self):
        if not lab_host(self.headers.get("Host")):
            self.send_json({"error": "Open the dashboard with the Ubuntu VM IP address or localhost."}, 403)
            return
        path = self.path.split("?", 1)[0]
        telemetry = self.server.telemetry
        if path in ASSETS:
            filename, content_type = ASSETS[path]
            self.send_body((self.server.assets / filename).read_bytes(), content_type)
        elif path == "/api/health":
            stats = telemetry.snapshot()
            self.send_json({"ready": stats["ready"], "probes": stats["probes"]}, 200 if stats["ready"] else 503)
        elif path == "/api/stats":
            self.send_json(telemetry.snapshot())
        elif path == "/api/rules":
            self.send_json(list(telemetry.rules.values()))
        elif path in ("/api/alerts", "/api/events", "/api/snapshot"):
            snapshot = telemetry.snapshot(include_records=True)
            self.send_json(snapshot if path == "/api/snapshot" else snapshot[path.split("/")[-1]])
        elif path == "/api/simulations":
            self.send_json({
                "enabled": bool(self.server.simulator_url),
                "scenarios": [
                    {"id": name, "title": title, "description": description, "rules": rules,
                     "mitre": telemetry.rules[rules[-1]]["mitre"], "severity": telemetry.rules[rules[-1]]["severity"]}
                    for name, (title, description, rules) in SCENARIOS.items()
                ],
            })
        else:
            self.send_json({"error": "Route not found."}, 404)

    def do_POST(self):
        if not lab_host(self.headers.get("Host")):
            self.send_json({"error": "Open the dashboard with the Ubuntu VM IP address or localhost."}, 403)
            return
        name = self.path.removeprefix("/api/attack/")
        if self.path != f"/api/attack/{name}" or name not in SCENARIOS:
            self.send_json({"error": "Unknown simulation."}, 404)
            return
        if self.headers.get("X-Lab-Action") != "simulate" or self.headers.get("Sec-Fetch-Site") in ("cross-site", "same-site"):
            self.send_json({"error": "Use the dashboard to launch a simulation."}, 403)
            return
        payload, status = self.server.run_scenario(name)
        self.send_json(payload, status)
