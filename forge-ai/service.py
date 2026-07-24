from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

from agent.planner import build_plan
from agent.reasoning import ReasoningState, prioritize_next_action


class ForgeAIHandler(BaseHTTPRequestHandler):
    def _write_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._write_json(200, {"status": "ok", "component": "forge-ai"})
            return
        self._write_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/plan":
            payload = self._read_json()
            target = str(payload.get("target", "")).strip()
            if not target:
                self._write_json(400, {"error": "target is required"})
                return
            plan = build_plan(target)
            self._write_json(
                200,
                {
                    "target": plan.target,
                    "steps": [step.__dict__ for step in plan.steps],
                },
            )
            return

        if self.path == "/reason":
            payload = self._read_json()
            state = ReasoningState(
                objective=str(payload.get("objective", "")),
                previous_actions=list(payload.get("previous_actions", [])),
                discoveries=list(payload.get("discoveries", [])),
                confidence=float(payload.get("confidence", 0.5)),
            )
            next_action = prioritize_next_action(state)
            self._write_json(200, {"next_action": next_action})
            return

        self._write_json(404, {"error": "not found"})


def run() -> None:
    server = HTTPServer(("127.0.0.1", 8090), ForgeAIHandler)
    print("forge-ai service listening on 127.0.0.1:8090")
    server.serve_forever()


if __name__ == "__main__":
    run()
