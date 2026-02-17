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

**Java plugin entrypoint:** `GhidraMCPPlugin` constructs 9 services and a `McpServerManager`, then passes them to `ApiHandlerRegistry`, which uses reflection to discover `@McpTool`-annotated methods on all services and registers 40 HTTP endpoints + a `/mcp/tools` metadata endpoint.

**Server management** (in `com.lauriewired.mcp`):
- `McpServerManager` — manages the embedded `HttpServer` lifecycle (start/stop), thread pool, and configurable options (port, thread pool size, request timeout) exposed via Ghidra's Tool Options UI. Defaults: port 8080, 10 worker threads, 30s request timeout.

**Annotation-driven tool registry** (in `com.lauriewired.mcp.api`):
- `@McpTool` — marks a service method as an MCP tool (description, POST vs GET, `responseType` for schema generation)
- `@Param` — annotates each parameter (description, default value)
- `ToolDef` — runtime tool definition built from reflection; delegates to `Json.toSnakeCase()` for name conversion, JSON Schema generation, and param parsing
- `ParamType` — maps Java types to JSON Schema types (STRING, INTEGER, LONG, BOOLEAN, STRING_MAP, LONG_MAP, STRING_PAIR_LIST)
- `ToolParamDef` — parameter definition record
- `SchemaGenerator` — generates JSON Schema from Java record types at runtime via victools/jsonschema-generator; used by `/mcp/tools` to emit `outputSchema` for each tool

**Typed output model** (in `com.lauriewired.mcp.model`):
- `ToolOutput` — sealed interface with `toStructuredJson()` and `toDisplayText()` methods; permits `ListOutput`, `StatusOutput`, `JsonOutput`
- `ListOutput` — paginated lists of typed record items with defensive copying; serialized via Jackson
- `StatusOutput` — mutation results (success/failure) with convenience factories
- `JsonOutput` — holds a typed `Object` (typically a response record); serialized via Jackson; delegates `toDisplayText()` to `Displayable` if the data record implements it
- `Displayable` — interface for response records that produce human-readable display text distinct from the structured JSON

**Response records** (in `com.lauriewired.mcp.model.response`):
- Java records representing structured tool outputs (e.g., `ProgramInfoResult`, `ControlFlowResult`, `SearchMemoryResult`)
- Nested records for sub-objects (e.g., `ControlFlowResult.Block`, `CallGraphResult.CallGraphNode`)
- Serialized to snake_case JSON by Jackson's `SNAKE_CASE` naming strategy
- Used by `SchemaGenerator` to derive `outputSchema` at runtime via reflection

**Service layer** (all in `com.lauriewired.mcp.services`):
- `ProgramService` (1 tool) — provides current `Program` reference from Ghidra's `PluginTool`; used by all other services
- `FunctionService` (8 tools), `DataTypeService` (9 tools), `AnalysisService` (5 tools), `MemoryService` (7 tools), `SearchService` (3 tools), `VariableService` (3 tools), `CommentService` (2 tools), `NamespaceService` (2 tools)

**Key utilities** (in `com.lauriewired.mcp.utils`):
- `Json` — shared Jackson `ObjectMapper` singleton (`NON_NULL`, `SNAKE_CASE`); also provides `Json.toSnakeCase()` as the single source of truth for all camelCase→snake_case conversion
- `HttpUtils` — parses query params, reads POST bodies, sends JSON envelope responses
- `GhidraUtils` — address parsing, function lookup helpers
- `TimeoutHandler` — wraps HTTP handlers with configurable request timeouts (GET only)
- `ProgramTransaction` — wraps Ghidra `program.startTransaction()`/`endTransaction()` for write operations

**Telemetry** (in `com.lauriewired.mcp.telemetry`):
- `TelemetryInterceptor` — wraps HTTP handlers; logs go to `~/.ghidra_mcp/telemetry/`
- `TelemetryLogger` — file-based telemetry logging with `ConcurrentHashMap` for thread-safe metrics

**Python bridge:** `bridge_mcp_ghidra.py` is a generic MCP proxy. At startup it fetches tool definitions from `GET /mcp/tools` and dynamically registers them as MCP tools. No per-tool code needed — Java is the single source of truth for tool metadata. Supports `outputSchema` and `readOnlyHint` (GET = read-only, POST = mutation).

## Key Patterns

- **Declarative tool registration** — adding a tool means annotating a service method with `@McpTool` + `@Param`. Reflection discovers it, converts Java camelCase names to snake_case via `Json.toSnakeCase()`, generates JSON Schema, and registers the HTTP handler automatically. The Python bridge picks it up from `/mcp/tools` with zero changes needed.
- **Structured tool outputs** — all tools return a `ToolOutput` subtype. `ApiHandlerRegistry` calls `toStructuredJson()` to produce machine-readable JSON responses. Per-tool `outputSchema` is derived at runtime from response record types by `SchemaGenerator` and served via `/mcp/tools`.
- **Jackson with shaded packages** — Jackson and victools are shaded into `com.lauriewired.shaded.*` via maven-shade-plugin to avoid classpath conflicts in Ghidra's plugin environment. The shared `ObjectMapper` in `Json.java` uses `SNAKE_CASE` naming and `NON_NULL` inclusion.
- **Response records** — service methods return typed Java records (in `com.lauriewired.mcp.model.response`) wrapped in `JsonOutput` or `ListOutput`. Jackson serializes them with snake_case field names. `SchemaGenerator` derives JSON Schema from the same record types.
- **All Ghidra state access goes through `ProgramService.getCurrentProgram()`** — services never cache the Program reference.
- **Write operations** (rename, create struct, set type, etc.) must use `ProgramTransaction` or manual `startTransaction`/`endTransaction`.
- **Pagination** — list endpoints accept `offset`/`limit` query params and return LLM-friendly pagination hints in the response.

## Dependencies

- **Java 24**, Maven build, Ghidra 12.0.3 JARs in `lib/` (system-scoped)
- **Jackson 2.18.2** (shaded), **victools jsonschema-generator 4.37.0** (shaded) — relocated to `com.lauriewired.shaded.*`
- **Python 3.10+**, `mcp>=1.26.0`, `requests>=2`
- **Test:** JUnit 5.9.2, Mockito 5.21, JaCoCo 0.8.13
- **Static analysis:** SpotBugs 4.9.8.2, PMD 3.28.0 (both run at `verify` phase)

## Testing Notes

Tests mock Ghidra internals (`Program`, `FunctionManager`, `Listing`, etc.) via Mockito. The Surefire plugin is configured with `--add-opens` flags for Mockito's reflective access. Test files mirror the main source structure under `src/test/java/`. Helper classes (`MockablePluginTool`, `TestDataTypeService`, `TestFunctionService`, `TestMemoryService`, `TestProgramService`) provide reusable mock setups. 27 test files total, including dedicated tests for `McpServerManager` and `FindDataTypeUsage`.
