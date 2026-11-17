"""Internal HTTP service for the dashboard's predefined drills."""

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

from attacks.scenarios import SCENARIOS, launch


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def do_POST(self):
        scenario = self.path.removeprefix("/run/")
        tag = self.headers.get("X-Lab-Process", "")
        if self.path != f"/run/{scenario}" or scenario not in SCENARIOS or not re.fullmatch(r"lab-[0-9a-f]{10}", tag):
            self.send_error(400)
            return
        body = json.dumps(launch(scenario, tag)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    with HTTPServer(("0.0.0.0", 8081), Handler) as server:
        server.serve_forever()
