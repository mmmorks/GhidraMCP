"""Tests for bridge_mcp_ghidra.py."""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch

import httpx
import pytest

from bridge_mcp_ghidra import (
    _handle_response,
    _serialize_query_value,
    _parse_args,
    _fetch_tool_definitions,
    _call_tool,
)


# ---------------------------------------------------------------------------
# _serialize_query_value
# ---------------------------------------------------------------------------

class TestSerializeQueryValue:
    def test_string_passthrough(self):
        assert _serialize_query_value("hello") == "hello"

    def test_empty_string(self):
        assert _serialize_query_value("") == ""

    def test_bool_true(self):
        assert _serialize_query_value(True) == "true"

    def test_bool_false(self):
        assert _serialize_query_value(False) == "false"

    def test_int(self):
        assert _serialize_query_value(42) == "42"

    def test_float(self):
        assert _serialize_query_value(3.14) == "3.14"

    def test_none(self):
        assert _serialize_query_value(None) == "null"

    def test_list(self):
        assert _serialize_query_value([1, 2]) == "[1, 2]"


# ---------------------------------------------------------------------------
# _parse_args
# ---------------------------------------------------------------------------

class TestParseArgs:
    def test_defaults(self):
        with patch.object(sys, "argv", ["bridge_mcp_ghidra.py"]):
            args = _parse_args()
        assert args.server_url == "http://127.0.0.1:8080"
        assert args.timeout == 30

    def test_positional_server_url(self):
        with patch.object(sys, "argv", ["bridge_mcp_ghidra.py", "http://localhost:9090"]):
            args = _parse_args()
        assert args.server_url == "http://localhost:9090"

    def test_timeout_arg(self):
        with patch.object(sys, "argv", ["bridge_mcp_ghidra.py", "--timeout", "60"]):
            args = _parse_args()
        assert args.timeout == 60


# ---------------------------------------------------------------------------
# _handle_response
# ---------------------------------------------------------------------------

class TestHandleResponse:
    def test_success_envelope(self):
        body = json.dumps({"status": "success", "text": "OK", "data": {"key": "val"}})
        display, data, is_error = _handle_response(body)
        assert display == "OK"
        assert data == {"key": "val"}
        assert not is_error

    def test_success_envelope_list_data(self):
        body = json.dumps({"status": "success", "text": "OK", "data": [1, 2, 3]})
        display, data, is_error = _handle_response(body)
        assert data == [1, 2, 3]
        assert not is_error

    def test_success_envelope_scalar_data(self):
        body = json.dumps({"status": "success", "text": "OK", "data": 42})
        display, data, is_error = _handle_response(body)
        assert data is None  # scalar data not returned as structured
        assert not is_error

    def test_success_envelope_no_text(self):
        body = json.dumps({"status": "success", "data": {"x": 1}})
        display, data, is_error = _handle_response(body)
        assert display == ""
        assert not is_error

    def test_error_envelope(self):
        body = json.dumps({"status": "error", "error": "boom"})
        display, data, is_error = _handle_response(body)
        assert "boom" in display
        assert data is None
        assert is_error

    def test_error_envelope_no_message(self):
        body = json.dumps({"status": "error"})
        display, _, is_error = _handle_response(body)
        assert "Unknown error" in display
        assert is_error

    def test_missing_status_key_is_error(self):
        body = json.dumps({"foo": "bar"})
        display, data, is_error = _handle_response(body)
        assert is_error
        assert "missing 'status' key" in display

    def test_non_json_is_error(self):
        display, data, is_error = _handle_response("plain text")
        assert is_error
        assert "not valid JSON" in display

    def test_whitespace_stripped(self):
        body = json.dumps({"status": "success", "text": "hi", "data": {}})
        display, _, _ = _handle_response(f"  {body}  ")
        assert display == "hi"


# ---------------------------------------------------------------------------
# _fetch_tool_definitions (with real HTTP server)
# ---------------------------------------------------------------------------

class _ToolHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for testing _fetch_tool_definitions."""
    response_body = b"[]"

    def do_GET(self, *_):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, *_):
        pass


@pytest.fixture()
def _http_server():
    """Start a local HTTP server, yield its base URL."""
    server = HTTPServer(("127.0.0.1", 0), _ToolHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestFetchToolDefinitions:
    @pytest.mark.anyio
    async def test_returns_tools(self, _http_server):
        tools = [{"name": "foo", "method": "GET"}]
        _ToolHandler.response_body = json.dumps(tools).encode()
        async with httpx.AsyncClient() as client:
            result = await _fetch_tool_definitions(client, _http_server)
        assert result == tools

    @pytest.mark.anyio
    async def test_returns_empty_on_connection_refused(self):
        async with httpx.AsyncClient() as client:
            result = await _fetch_tool_definitions(client, "http://127.0.0.1:1")
        assert result == []

    @pytest.mark.anyio
    async def test_returns_empty_on_invalid_json(self, _http_server):
        _ToolHandler.response_body = b"not json"
        async with httpx.AsyncClient() as client:
            result = await _fetch_tool_definitions(client, _http_server)
        assert result == []


# ---------------------------------------------------------------------------
# _call_tool (with real HTTP server)
# ---------------------------------------------------------------------------

class _EchoHandler(BaseHTTPRequestHandler):
    """Echoes request details back in the standard envelope format."""

    def _respond(self, data: dict):
        body = json.dumps({"status": "success", "text": "ok", "data": data})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self, *_):
        parsed = urlparse(self.path)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        self._respond({"method": "GET", "path": parsed.path, "params": params})

    def do_POST(self, *_):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        self._respond({"method": "POST", "path": self.path, "body": json.loads(raw)})

    def log_message(self, *_):
        pass


@pytest.fixture()
def _echo_server():
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestCallTool:
    @pytest.mark.anyio
    async def test_get_request(self, _echo_server):
        tool_def = {"name": "my_tool", "method": "GET"}
        async with httpx.AsyncClient() as client:
            display, data, is_error = await _call_tool(client, _echo_server, tool_def, {"key": "value"})
        assert not is_error
        assert data["method"] == "GET"
        assert data["params"]["key"] == "value"

    @pytest.mark.anyio
    async def test_post_request(self, _echo_server):
        tool_def = {"name": "my_tool", "method": "POST"}
        async with httpx.AsyncClient() as client:
            display, data, is_error = await _call_tool(client, _echo_server, tool_def, {"key": "value"})
        assert not is_error
        assert data["method"] == "POST"
        assert data["body"]["key"] == "value"

    @pytest.mark.anyio
    async def test_get_boolean_serialization(self, _echo_server):
        tool_def = {"name": "my_tool", "method": "GET"}
        async with httpx.AsyncClient() as client:
            _, data, _ = await _call_tool(client, _echo_server, tool_def, {"flag": True})
        assert data["params"]["flag"] == "true"

    @pytest.mark.anyio
    async def test_get_filters_none(self, _echo_server):
        tool_def = {"name": "my_tool", "method": "GET"}
        async with httpx.AsyncClient() as client:
            _, data, _ = await _call_tool(client, _echo_server, tool_def, {"keep": "yes", "drop": None})
        assert "keep" in data["params"]
        assert "drop" not in data["params"]

    @pytest.mark.anyio
    async def test_post_filters_none(self, _echo_server):
        tool_def = {"name": "my_tool", "method": "POST"}
        async with httpx.AsyncClient() as client:
            _, data, _ = await _call_tool(client, _echo_server, tool_def, {"keep": "yes", "drop": None})
        assert "keep" in data["body"]
        assert "drop" not in data["body"]

    @pytest.mark.anyio
    async def test_connection_refused(self):
        tool_def = {"name": "my_tool", "method": "GET"}
        async with httpx.AsyncClient() as client:
            display, data, is_error = await _call_tool(client, "http://127.0.0.1:1", tool_def, {})
        assert is_error
        assert "Request failed" in display

    @pytest.mark.anyio
    async def test_default_method_is_get(self, _echo_server):
        tool_def = {"name": "my_tool"}  # no method key
        async with httpx.AsyncClient() as client:
            _, data, _ = await _call_tool(client, _echo_server, tool_def, {})
        assert data["method"] == "GET"
