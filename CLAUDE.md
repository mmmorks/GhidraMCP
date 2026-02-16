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

**Java plugin entrypoint:** `GhidraMCPPlugin` constructs 9 services and passes them to `ApiHandlerRegistry`, which uses reflection to discover `@McpTool`-annotated methods on all services and registers 40 HTTP endpoints + a `/mcp/tools` metadata endpoint on an embedded `HttpServer` (default port 8080).

**Annotation-driven tool registry** (in `com.lauriewired.mcp.api`):
- `@McpTool` — marks a service method as an MCP tool (description, POST vs GET)
- `@Param` — annotates each parameter (description, default value)
- `ToolDef` — runtime tool definition built from reflection; handles `camelCase→snake_case` name conversion, JSON Schema generation, and param parsing
- `ParamType` — maps Java types to JSON Schema types (STRING, INTEGER, BOOLEAN, STRING_MAP, LONG_MAP, STRING_PAIR_LIST)
- `ToolParamDef` — parameter definition record
- `OutputSchemas` — compile-time JSON Schema constants for per-tool output schemas; used by `/mcp/tools` to emit `outputSchema` for each tool

**Typed output model** (in `com.lauriewired.mcp.model`):
- `ToolOutput` — sealed interface with `toStructuredJson()` method; permits `TextOutput`, `ListOutput`, `StatusOutput`, `JsonOutput`
- `TextOutput` — free-form text (decompiled code, hex dumps, analysis results)
- `ListOutput` — paginated lists of items with defensive copying
- `StatusOutput` — mutation results (success/failure) with convenience factories
- `JsonOutput` — already-structured JSON outputs

**Service layer** (all in `com.lauriewired.mcp.services`):
- `ProgramService` — provides current `Program` reference from Ghidra's `PluginTool`; used by all other services
- `FunctionService` (8 tools), `DataTypeService` (9 tools), `AnalysisService` (5 tools), `MemoryService` (7 tools), `SearchService` (3 tools), `VariableService` (3 tools), `CommentService` (2 tools), `NamespaceService` (2 tools)

**Key utilities** (in `com.lauriewired.mcp.utils`):
- `HttpUtils` — parses query params, reads POST bodies, sends JSON envelope responses
- `GhidraUtils` — address parsing, function lookup helpers
- `JsonBuilder` — manual JSON string building (no external JSON libraries)
- `TimeoutHandler` — wraps HTTP handlers with configurable request timeouts (GET only)
- `ProgramTransaction` — wraps Ghidra `program.startTransaction()`/`endTransaction()` for write operations

**Telemetry** (in `com.lauriewired.mcp.telemetry`):
- `TelemetryInterceptor` — wraps HTTP handlers; logs go to `~/.ghidra_mcp/telemetry/`
- `TelemetryLogger` — file-based telemetry logging with `ConcurrentHashMap` for thread-safe metrics

**Python bridge:** `bridge_mcp_ghidra.py` is a generic ~156-line MCP proxy. At startup it fetches tool definitions from `GET /mcp/tools` and dynamically registers them as MCP tools. No per-tool code needed — Java is the single source of truth for tool metadata. Supports `outputSchema` and `readOnlyHint` (GET = read-only, POST = mutation).

## Key Patterns

- **Declarative tool registration** — adding a tool means annotating a service method with `@McpTool` + `@Param`. Reflection discovers it, converts Java camelCase names to snake_case, generates JSON Schema, and registers the HTTP handler automatically. The Python bridge picks it up from `/mcp/tools` with zero changes needed.
- **Structured tool outputs** — all tools return a `ToolOutput` subtype. `ApiHandlerRegistry` calls `toStructuredJson()` to produce machine-readable JSON responses. Per-tool `outputSchema` is defined in `OutputSchemas` and served via `/mcp/tools`.
- **All Ghidra state access goes through `ProgramService.getCurrentProgram()`** — services never cache the Program reference.
- **Write operations** (rename, create struct, set type, etc.) must use `ProgramTransaction` or manual `startTransaction`/`endTransaction`.
- **No Gson or external JSON libraries** — JSON is built manually with `JsonBuilder` and string formatting to avoid classpath issues in Ghidra's plugin environment.
- **Pagination** — list endpoints accept `offset`/`limit` query params and return LLM-friendly pagination hints in the response.

## Dependencies

- **Java 24**, Maven build, Ghidra 11.3.1 JARs in `lib/` (system-scoped)
- **Python 3.10+**, `mcp>=1.26.0`, `requests>=2`
- **Test:** JUnit 5.9.2, Mockito 5.21, JaCoCo 0.8.13
- **Static analysis:** SpotBugs 4.9.8.2, PMD 3.28.0 (both run at `verify` phase)

## Testing Notes

Tests mock Ghidra internals (`Program`, `FunctionManager`, `Listing`, etc.) via Mockito. The Surefire plugin is configured with `--add-opens` flags for Mockito's reflective access. Test files mirror the main source structure under `src/test/java/`. Helper classes (`MockablePluginTool`, `TestDataTypeService`, `TestFunctionService`, `TestMemoryService`, `TestProgramService`) provide reusable mock setups.
