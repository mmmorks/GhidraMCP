# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "httpx>=0.27",
#     "mcp>=1.26.0",
# ]
# ///

"""
Generic MCP bridge for GhidraMCP.

Fetches tool definitions from the Java plugin's /mcp/tools endpoint at startup
and dynamically registers them as MCP tools. No per-tool code needed.
"""

import argparse
import asyncio
import json
import logging
import os
import re
import signal
import sys

import httpx
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, Tool, TextContent, ToolAnnotations, CallToolResult
import mcp.server.stdio

logger = logging.getLogger("ghidra-mcp-bridge")

_VALID_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MCP bridge for GhidraMCP")
    parser.add_argument(
        "server_url",
        nargs="?",
        default="http://127.0.0.1:8080",
        help="Ghidra HTTP server URL (default: http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP request timeout in seconds (default: 30)",
    )
    return parser.parse_args()


def _serialize_query_value(v):
    """Serialize a value for use as an HTTP query parameter.

    Strings pass through unchanged; everything else (booleans, numbers, etc.)
    is serialized via json.dumps so that e.g. True becomes "true".
    """
    if isinstance(v, str):
        return v
    return json.dumps(v)


def _handle_response(body: str) -> tuple[str, dict | None, bool]:
    """Process HTTP response into (display_text, structured_data, is_error) tuple.

    Expects a JSON envelope with a 'status' key. Returns an error if the
    response is not valid JSON or lacks the expected envelope format.
    """
    text = body.strip()
    try:
        envelope = json.loads(text)
        if isinstance(envelope, dict) and "status" in envelope:
            if envelope["status"] == "success":
                data = envelope.get("data")
                display = envelope.get("text", "")
                return display, data if isinstance(data, (dict, list)) else None, False
            else:
                msg = f"Error: {envelope.get('error', 'Unknown error')}"
                return msg, None, True
        else:
            return "Error: unexpected JSON response format (missing 'status' key)", None, True
    except json.JSONDecodeError:
        return "Error: response is not valid JSON", None, True


async def _fetch_tool_definitions(client: httpx.AsyncClient, server_url: str) -> list[dict]:
    """Fetch tool schemas from the Ghidra plugin's /mcp/tools endpoint."""
    try:
        resp = await client.get(f"{server_url}/mcp/tools")
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
        logger.warning("Failed to fetch tool definitions from %s/mcp/tools: %s", server_url, e)
        return []


async def _call_tool(client: httpx.AsyncClient, server_url: str, tool_def: dict, arguments: dict) -> tuple[str, dict | None, bool]:
    """Dispatch a tool call as GET or POST to the Ghidra plugin."""
    endpoint = tool_def["name"]
    if not _VALID_TOOL_NAME.match(endpoint):
        return f"Invalid tool name: {endpoint!r}", None, True
    method = tool_def.get("method", "GET").upper()
    url = f"{server_url}/{endpoint}"

    try:
        if method == "POST":
            filtered = {k: v for k, v in arguments.items() if v is not None}
            resp = await client.post(url, content=json.dumps(filtered),
                                     headers={"Content-Type": "application/json"})
        else:
            params = {k: _serialize_query_value(v) for k, v in arguments.items() if v is not None}
            resp = await client.get(url, params=params)
        resp.raise_for_status()
        return _handle_response(resp.text)
    except httpx.HTTPStatusError as e:
        return _handle_response(e.response.text)
    except httpx.HTTPError as e:
        return f"Request failed: {e}", None, True
    except Exception as e:
        logger.error("Unexpected error calling tool %s: %s", endpoint, e)
        return f"Request failed: {e}", None, True


async def main():
    args = _parse_args()
    server_url = args.server_url

    logging.basicConfig(level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO")), format="%(name)s %(levelname)s: %(message)s")

    async with httpx.AsyncClient(timeout=args.timeout) as client:
        tools = await _fetch_tool_definitions(client, server_url)
        if not tools:
            sys.exit(f"Fatal: no tools fetched from {server_url}/mcp/tools — "
                     "is Ghidra running with the GhidraMCP plugin?")

        tool_lookup = {t["name"]: t for t in tools}
        _refresh_lock = asyncio.Lock()

        async def _refresh_tools():
            """Re-fetch tool definitions from the Ghidra plugin."""
            nonlocal tools, tool_lookup
            async with _refresh_lock:
                new_tools = await _fetch_tool_definitions(client, server_url)
                if new_tools:
                    tools = new_tools
                    tool_lookup = {t["name"]: t for t in tools}
                    logger.debug("Refreshed %d tools from %s", len(tools), server_url)
                elif tools:
                    logger.debug("Tool refresh returned empty list; keeping %d existing tools", len(tools))

        server = Server("ghidra-mcp")

        @server.list_tools()
        async def list_tools() -> list[Tool]:
            await _refresh_tools()

            result = []
            for t in tools:
                is_read_only = t.get("method", "GET").upper() == "GET"
                annotations = ToolAnnotations(readOnlyHint=is_read_only)

                tool_kwargs: dict = dict(
                    name=t["name"],
                    description=t["description"],
                    inputSchema=t["inputSchema"],
                    annotations=annotations,
                )
                if "outputSchema" in t:
                    tool_kwargs["outputSchema"] = t["outputSchema"]

                result.append(Tool(**tool_kwargs))
            return result

        @server.call_tool()
        async def call_tool(name: str, arguments: dict) -> CallToolResult:
            tool_def = tool_lookup.get(name)
            if tool_def is None:
                raise McpError(ErrorData(
                    code=-32602,
                    message=f"Unknown tool: {name}",
                ))
            display_text, structured_data, is_error = await _call_tool(
                client, server_url, tool_def, arguments or {}
            )
            return CallToolResult(
                content=[TextContent(type="text", text=display_text)],
                structuredContent=structured_data,
                isError=is_error,
            )

        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))
    asyncio.run(main())
