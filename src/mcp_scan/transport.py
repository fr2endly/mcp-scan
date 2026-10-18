"""
Two ways to reach an MCP server:
1. stdio - a local server we start as a subprocess
2. http  - Streamable HTTP, for a remote server

The protocol is JSON-RPC 2.0. Three methods are enough here:
  initialize, tools/list, resources/list, prompts/list
"""

import json
import os
import subprocess
import sys
import uuid
from typing import Any

import httpx

PROTOCOL_VERSION = "2025-06-18"

CLIENT_INFO = {
    "name": "mcp-scan",
    "version": "0.1.0",
}


class MCPError(Exception):
    pass


class MCPClient:
    """Base client. Subclasses implement _send."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._id_counter = 0

    def _next_id(self) -> str:
        self._id_counter += 1
        return f"mcp-scan-{self._id_counter}-{uuid.uuid4().hex[:8]}"

    def _request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        return self._send(payload)

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload, expect_response=False)

    def _send(self, payload: dict, expect_response: bool = True) -> Any:
        raise NotImplementedError

    # --- Public API ---

    def initialize(self) -> dict:
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        # The spec requires confirming initialization with a notification
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        result = self._request("tools/list", {})
        return result.get("tools", []) if isinstance(result, dict) else []

    def list_resources(self) -> list[dict]:
        try:
            result = self._request("resources/list", {})
            return result.get("resources", []) if isinstance(result, dict) else []
        except MCPError:
            return []

    def list_prompts(self) -> list[dict]:
        try:
            result = self._request("prompts/list", {})
            return result.get("prompts", []) if isinstance(result, dict) else []
        except MCPError:
            return []

    def close(self) -> None:
        pass


class StdioClient(MCPClient):
    """A local server: start it with a command, talk over stdin/stdout."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None,
                 timeout: float = 30.0):
        super().__init__(timeout)
        self.command = command
        merged_env = dict(os.environ)
        if env:
            merged_env.update(env)
        try:
            self.proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=merged_env,
            )
        except FileNotFoundError as exc:
            raise MCPError(f"could not start the server: {exc}") from exc

    def _send(self, payload: dict, expect_response: bool = True) -> Any:
        if self.proc.poll() is not None:
            raise MCPError("the server exited before answering")
        line = json.dumps(payload) + "\n"
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

        if not expect_response:
            return None

        # Read until the first line whose id matches ours
        deadline_lines = 200  # in case the server floods stdout with junk
        for _ in range(deadline_lines):
            raw = self.proc.stdout.readline()
            if not raw:
                raise MCPError("the server closed stdout")
            raw = raw.strip()
            if not raw:
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue  # the server logs to stdout; skip it
            if msg.get("id") != payload.get("id"):
                continue  # a notification, or a response to somebody else
            if "error" in msg:
                err = msg["error"]
                raise MCPError(f"{err.get('code')}: {err.get('message')}")
            return msg.get("result")
        raise MCPError("gave up waiting for a response after the line limit")

    def close(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


class HttpClient(MCPClient):
    """A remote server over Streamable HTTP."""

    def __init__(self, url: str, headers: dict[str, str] | None = None,
                 timeout: float = 30.0):
        super().__init__(timeout)
        self.url = url
        self.session_id: str | None = None
        self.client = httpx.Client(
            timeout=timeout,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **(headers or {}),
            },
        )

    def _send(self, payload: dict, expect_response: bool = True) -> Any:
        headers = {}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        resp = self.client.post(self.url, json=payload, headers=headers)

        # The server may hand back a session id; keep it for later requests
        if "mcp-session-id" in resp.headers:
            self.session_id = resp.headers["mcp-session-id"]

        if resp.status_code == 202:  # accepted, no body coming (a notification)
            return None
        if resp.status_code >= 400:
            raise MCPError(f"HTTP {resp.status_code}: {resp.text[:200]}")

        if not expect_response:
            return None

        ctype = resp.headers.get("content-type", "")

        # Case A: plain JSON
        if "application/json" in ctype:
            msg = resp.json()
            if "error" in msg:
                err = msg["error"]
                raise MCPError(f"{err.get('code')}: {err.get('message')}")
            return msg.get("result")

        # Case B: Server-Sent Events, so parse the data: lines
        if "text/event-stream" in ctype:
            for line in resp.text.splitlines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data:
                    continue
                try:
                    msg = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if msg.get("id") != payload.get("id"):
                    continue
                if "error" in msg:
                    err = msg["error"]
                    raise MCPError(f"{err.get('code')}: {err.get('message')}")
                return msg.get("result")
            raise MCPError("the SSE stream carried no response to our request")

        raise MCPError(f"unrecognised content-type: {ctype}")

    def close(self) -> None:
        self.client.close()


def make_client(target: str, headers: dict[str, str] | None = None) -> MCPClient:
    """
    Factory. target is either a URL (http/https) or a command line to run
    (for example "npx -y @some/mcp-server").
    """
    if target.startswith("http://") or target.startswith("https://"):
        return HttpClient(target, headers=headers)

    import shlex
    parts = shlex.split(target)

    # Guard against a common mistake: a path to a .py file with no interpreter
    # in front of it. Without this, subprocess dies with an unreadable
    # PermissionError.
    if (
        parts
        and parts[0].endswith(".py")
        and os.path.sep in parts[0]
        and not os.access(parts[0], os.X_OK)
    ):
        parts = [sys.executable, *parts]

    return StdioClient(parts)
