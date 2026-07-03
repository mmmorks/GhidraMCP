# Design: Project-level import / list / open / analyze

**Date:** 2026-07-02
**Status:** Approved, pending implementation plan

## Problem

GhidraMCP currently operates only on the single program already open in the
CodeBrowser tool. Every service reaches Ghidra state through
`ProgramService.getCurrentProgram()`, which delegates to the tool's
`ProgramManager`. An agent cannot bring a **new** file into the project,
analyze it, or switch between binaries — it is bound to whatever a human
opened.

The initial hypothesis was that the plugin must be re-parented from the
CodeBrowser tool to the Ghidra front-end process to gain these abilities. That
is **not** required, and it is rejected here (see Rejected Alternatives).

## Key finding (verified against the Ghidra JARs in `lib/`)

A `PluginTool` already exposes everything needed from inside CodeBrowser:

- `tool.getProject()` → `ghidra.framework.model.Project` (the file tree and the
  import target).
- `ghidra.app.util.importer.AutoImporter.importByUsingBestGuess(File, Project,
  String folder, Object consumer, MessageLog, TaskMonitor)` →
  `LoadResults<Program>`, auto-detecting format.
- `ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(Program)`
  → `reAnalyzeAll(null)` + `startAnalysis(TaskMonitor)`.
- `ghidra.app.services.ProgramManager.openProgram(DomainFile)` /
  `setCurrentProgram(Program)` → makes an imported/existing file the current
  program.

Because the imported program becomes the CodeBrowser's current program, all
nine existing services keep working unchanged.

## Decisions

1. **Binding target: work through CodeBrowser.** No re-parenting to
   `FrontEndTool`. Smallest change; existing tools operate on the imported
   program with zero modification. Cost: a CodeBrowser window must be open (it
   already is — that is where the plugin lives).
2. **Scope: all four project operations** — import, list, open, analyze.
3. **Analysis execution: synchronous, block until done.** `reanalyze_program`
   (and `import_program` when `analyze=true`) holds the POST open until Ghidra
   finishes, then returns final counts. Chosen for the simplest agent mental
   model. Consequence handled in Decision 4.

## Architecture

One new service, `ProjectService`, constructed with the existing `PluginTool`,
exactly like the other services.

- Constructed in `GhidraMCPPlugin.initializeServices()`.
- Registered in `ApiHandlerRegistry` alongside the existing services (reflection
  discovers its `@McpTool` methods automatically — no bridge changes for tool
  registration).
- Reaches the project via `tool.getProject()` and the `ProgramManager` service
  the plugin already holds.

### Threading & transactions

- **Import and analysis** run on the HTTP worker thread (already off the
  Swing/EDT thread — correct, they are long-running). Use `TaskMonitor.DUMMY`
  initially.
- **GUI mutations** — `ProgramManager.openProgram(...)`,
  `setCurrentProgram(...)` — are marshalled onto the EDT via
  `ghidra.util.Swing.runNow(...)`.
- **Analysis** runs inside a `ProgramTransaction` (existing util), mirroring
  `GhidraScript.analyzeAll`:
  `AutoAnalysisManager.getAnalysisManager(p)` → `initializeOptions()` →
  `reAnalyzeAll(null)` → `startAnalysis(monitor)` (blocks the worker thread
  until complete) → mark analyzed via
  `ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(p)`.
- **Imported program** is persisted into the project (`LoadResults.save(...)`)
  and the plugin's consumer reference released after the program is opened.

## Tools

| Tool | HTTP | Signature | Output model |
|---|---|---|---|
| `import_program` | POST | `import_program(path, folder="/", analyze=true, open=true)` | `JsonOutput<ImportResult>` |
| `list_program_files` | GET | `list_program_files(folder="/")` | `ListOutput<ProgramFileItem>` |
| `open_program` | POST | `open_program(project_path)` | `JsonOutput<ProgramInfoResult>` |
| `reanalyze_program` | POST | `reanalyze_program()` | `JsonOutput<AnalysisResult>` |

The analysis trigger is named `reanalyze_program` (not `analyze_program`)
deliberately: because `import_program` analyzes by default, any imported or
previously-opened program is normally already analyzed, and the underlying
Ghidra call is `reAnalyzeAll`. The name signals to the agent that analysis is
the expected default state and this tool re-runs it — discouraging a redundant
analysis pass on a freshly imported program.

New response records in `com.lauriewired.mcp.model.response` (Java records,
implementing `Displayable`, serialized snake_case by the shared Jackson mapper),
following the existing `ProgramInfoResult` pattern:

- **`ImportResult`** — program name, project path, executable format, language
  id, function count, analyzed flag, and a list of any additional programs the
  loader produced (archives/containers can yield more than one).
- **`ProgramFileItem`** — project path, name, content type, `open` flag
  (whether it is currently open in the tool). Element type of the `ListOutput`.
- **`AnalysisResult`** — analyzed flag, function count, symbol count, elapsed
  ms.
- `open_program` reuses the existing `ProgramInfoResult` shape.

`import_program` with `analyze=true` calls the same analysis code path as
`reanalyze_program` — one implementation, invoked synchronously.

### Import behavior details

- Loader auto-detection via `importByUsingBestGuess`. Multiple resulting
  programs: open the primary; report the rest by name in `ImportResult`.
- `folder` defaults to project root `/`; created if absent.
- `open=true` (default) opens the primary program and makes it current so
  downstream tools act on it immediately.

## Bridge timeout (required by the synchronous analysis choice)

`bridge_mcp_ghidra.py` applies one `httpx` timeout (default 30s) to every call;
POST is **not** timed out server-side, but a synchronous analysis will exceed
30s and fail on the client.

Add an **optional per-tool timeout hint**:

- `@McpTool(..., timeoutSeconds = 600)` on `import_program` and
  `reanalyze_program`.
- Surface `timeoutSeconds` in the `/mcp/tools` metadata (via `ToolDef`).
- In the bridge, when invoking a tool, use its `timeout_seconds` as the
  per-request `httpx` timeout, falling back to the global `--timeout` default
  when unset.

Keeps Java as the single source of truth; only the long-running tools get the
extended fuse, so ordinary tools still fail fast.

**Residual risk (documented in tool descriptions, not engineered away):** a very
large binary can exceed even 600s, and a proxy can drop a long-held connection.
The synchronous model also means the agent's turn blocks with no progress
visibility for the duration. Accepted for now; async + poll is a small delta if
it becomes a problem.

## Error handling

Return `StatusOutput.error(...)` with actionable messages (the agent must
self-correct) for:

- No active project (`tool.getProject()` is null).
- `path` missing or unreadable.
- Unrecognized format (`LoadException`).
- Name collision in target folder (`DuplicateNameException`).
- `open_program` on a nonexistent project path.
- Any tool call when no program is current where one is required
  (`reanalyze_program`).

## Testing

**Unit-testable with the existing Mockito harness:**

- `list_program_files` over a mocked `ProjectData` / `DomainFolder` /
  `DomainFile` tree, including the `open` flag against mocked
  `ProgramManager.getAllOpenPrograms()`.
- `open_program` via mocked `ProgramManager` + `ProjectData.getFile`.
- All error / validation paths above.
- Response-record `Displayable` output formatting.
- Bridge: per-tool `timeout_seconds` selection logic.

**Not unit-testable with mocks (honest scope):**

- Real `AutoImporter` (needs an on-disk project) — verified manually /
  integration.
- Full auto-analysis — the analysis *invocation* is exercised via a
  `ProgramBuilder` `_X64` program where feasible; genuine end-to-end import is
  flagged as manual verification. No coverage will be claimed that does not
  exist.

## Rejected alternatives

- **Re-parent to `FrontEndTool` (project plugin).** Would let the server run
  with no CodeBrowser open, but every existing program-scoped tool would then
  need to open programs headlessly or spawn a CodeBrowser under the hood — a
  large rearchitecture of the service layer for no benefit to the stated goal.
- **Fully headless (drive a `Project` with no GUI tool).** Most decoupled, most
  work, and it discards the GUI "current program" semantics the whole existing
  tool suite relies on.
- **Async + poll analysis.** More robust for huge binaries, but adds a status
  field and a poll loop; deferred in favor of the simpler synchronous model per
  user decision. Cheap to add later.

## Out of scope (YAGNI)

- Deleting / renaming / moving project files.
- Closing programs.
- Configuring per-analyzer options.
- Raw-bytes upload (import is from a filesystem path on the Ghidra host).
