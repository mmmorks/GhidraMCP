# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2",
#     "mcp>=1.26.0",
# ]
# ///

"""
Generic MCP bridge for GhidraMCP.

Fetches tool definitions from the Java plugin's /mcp/tools endpoint at startup
and dynamically registers them as MCP tools. No per-tool code needed.
"""

import sys
import json
import logging

import requests
from mcp.server.lowlevel import Server
from mcp.types import Tool, TextContent, ToolAnnotations, CallToolResult
import mcp.server.stdio

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT = 30

ghidra_server_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GHIDRA_SERVER

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s: %(message)s")
logger = logging.getLogger("ghidra-mcp-bridge")

# Fetch tool definitions from the Java plugin
_tools: list[dict] = []


def _fetch_tool_definitions() -> list[dict]:
    """Fetch tool schemas from the Ghidra plugin's /mcp/tools endpoint."""
    try:
        resp = requests.get(f"{ghidra_server_url}/mcp/tools", timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning("Failed to fetch tool definitions from %s/mcp/tools: %s", ghidra_server_url, e)
        return []


def _handle_response(response: requests.Response) -> tuple[str, dict | None]:
    """Process HTTP response into (display_text, structured_data) tuple.

    Parses the JSON envelope and extracts the 'data' field.
    Falls back gracefully for old-format responses.
    """
    text = response.content.decode("utf-8").strip()
    try:
        envelope = json.loads(text)
        if isinstance(envelope, dict) and "status" in envelope:
            if envelope["status"] == "success":
                data = envelope.get("data")
                if isinstance(data, (dict, list)):
                    display = json.dumps(data, indent=2)
                else:
                    display = str(data) if data is not None else ""
                return display, data if isinstance(data, (dict, list)) else None
            else:
                msg = f"Error: {envelope.get('error', 'Unknown error')}"
                return msg, None
    except (json.JSONDecodeError, KeyError):
        pass
    if response.ok:
        return text, None
    return f"Error {response.status_code}: {text}", None


def _call_tool(tool_def: dict, arguments: dict) -> tuple[str, dict | None]:
    """Dispatch a tool call as GET or POST to the Ghidra plugin."""
    endpoint = tool_def["name"]
    method = tool_def.get("method", "GET").upper()

    try:
        if method == "POST":
            # Filter out None values to avoid sending null fields
            filtered = {k: v for k, v in arguments.items() if v is not None}
            response = requests.post(
                f"{ghidra_server_url}/{endpoint}",
                data=json.dumps(filtered),
                headers={"Content-Type": "application/json"},
                timeout=DEFAULT_TIMEOUT,
            )
        else:
            # Convert all values to strings for query params, filtering out None
            params = {k: str(v) if not isinstance(v, str) else v for k, v in arguments.items() if v is not None}
            response = requests.get(
                f"{ghidra_server_url}/{endpoint}",
                params=params,
                timeout=DEFAULT_TIMEOUT,
            )
        return _handle_response(response)
    except Exception as e:
        return f"Request failed: {e}", None


async def main():
    global _tools
    _tools = _fetch_tool_definitions()
    if not _tools:
        logger.warning("No tools fetched — bridge will start with zero tools. "
                       "Ensure Ghidra is running with GhidraMCP plugin on %s", ghidra_server_url)

    # Build lookup by name
    tool_lookup = {t["name"]: t for t in _tools}

    server = Server("ghidra-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tools = []
        for t in _tools:
            # Derive readOnlyHint from HTTP method (GET = read-only, POST = mutation)
            is_read_only = t.get("method", "GET").upper() == "GET"
            annotations = ToolAnnotations(readOnlyHint=is_read_only)

            tool_kwargs: dict = dict(
                name=t["name"],
                description=t.get("description", ""),
                inputSchema=t.get("inputSchema", {"type": "object"}),
                annotations=annotations,
            )
            # Pass outputSchema if present
            if "outputSchema" in t:
                tool_kwargs["outputSchema"] = t["outputSchema"]

            tools.append(Tool(**tool_kwargs))
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> CallToolResult:
        tool_def = tool_lookup.get(name)
        if tool_def is None:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Unknown tool: {name}")],
                isError=True,
            )
        display_text, structured_data = _call_tool(tool_def, arguments or {})
        return CallToolResult(
            content=[TextContent(type="text", text=display_text)],
            structuredContent=structured_data,
        )

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
