# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GhidraMCP is an MCP (Model Context Protocol) server for Ghidra that enables LLMs to autonomously reverse engineer binaries. It has two components:

1. **Java plugin** (`src/main/java/com/lauriewired/`) — runs inside Ghidra, exposes an HTTP API via `com.sun.net.httpserver`
2. **Python bridge** (`bridge_mcp_ghidra.py`) — translates MCP protocol (stdio) into HTTP calls to the Java plugin

## Build & Test Commands

```bash
# Build the Ghidra extension (JAR + ZIP)
mvn clean package

# Build without tests
mvn package -DskipTests

# Run all tests (generates JaCoCo coverage at target/site/jacoco/)
mvn test

# Run a single test class
mvn test -Dtest=FunctionServiceTest

# Run a single test method
mvn test -Dtest=FunctionServiceTest#testDecompileFunction

# Build and install to local Ghidra (macOS only)
./build_and_install.sh

# Install Python bridge dependencies
pip install -r requirements.txt
```

## Architecture

```
LLM Client → (MCP/stdio) → bridge_mcp_ghidra.py → (HTTP) → GhidraMCPPlugin (inside Ghidra)
```

**Java plugin entrypoint:** `GhidraMCPPlugin` constructs 9 services and passes them to `ApiHandlerRegistry`, which registers ~54 HTTP endpoints on an embedded `HttpServer` (default port 8080).

**Service layer** (all in `com.lauriewired.mcp.services`):
- `ProgramService` — provides current `Program` reference from Ghidra's `PluginTool`; used by all other services
- `FunctionService`, `DataTypeService`, `AnalysisService`, `MemoryService`, `NamespaceService`, `CommentService`, `SearchService`, `VariableService`

**Key utilities:**
- `HttpUtils` — parses query params, reads POST bodies, sends responses
- `GhidraUtils` — address parsing, function lookup helpers
- `TimeoutHandler` — wraps HTTP handlers with configurable request timeouts
- `ProgramTransaction` — wraps Ghidra `program.startTransaction()`/`endTransaction()` for write operations

**Python bridge:** `bridge_mcp_ghidra.py` uses `FastMCP` to expose ~54 `@mcp.tool()` functions, each making HTTP GET/POST to the Java plugin.

## Key Patterns

- **All Ghidra state access goes through `ProgramService.getCurrentProgram()`** — services never cache the Program reference.
- **Write operations** (rename, create struct, set type, etc.) must use `ProgramTransaction` or manual `startTransaction`/`endTransaction`.
- **No Gson or external JSON libraries** — JSON is built manually with string concatenation/formatting to avoid classpath issues in Ghidra's plugin environment.
- **Pagination** — list endpoints accept `offset`/`limit` query params and return LLM-friendly pagination hints in the response text.
- **Telemetry** — `TelemetryInterceptor` wraps handlers; logs go to `~/.ghidra_mcp/telemetry/`. Uses `ConcurrentHashMap` for thread-safe metrics.

## Dependencies

- **Java 21**, Maven build, Ghidra 11.3.1 JARs in `lib/` (system-scoped)
- **Python 3.10+**, `mcp>=1.2.0`, `requests>=2`
- **Test:** JUnit 5, Mockito 5.21, JaCoCo 0.8.13

## Testing Notes

Tests mock Ghidra internals (`Program`, `FunctionManager`, `Listing`, etc.) via Mockito. The Surefire plugin is configured with `--add-opens` flags for Mockito's reflective access. Test files mirror the main source structure under `src/test/java/`.
