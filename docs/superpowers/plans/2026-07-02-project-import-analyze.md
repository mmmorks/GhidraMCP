# Project Import / List / Open / Analyze Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an agent import a file into the current Ghidra project, list project files, open any of them, and run analysis — without re-parenting the plugin off the CodeBrowser tool.

**Architecture:** One new service, `ProjectService`, constructed with the existing `PluginTool` (exactly like the other services). It reaches the project via `tool.getProject()` and the `ProgramManager` service the plugin already holds. Imported/opened programs become the CodeBrowser's current program, so every existing service keeps working unchanged. Switching the current program auto-closes the one it replaced (save-first, never discard). A per-tool HTTP timeout hint flows from the `@McpTool` annotation through `/mcp/tools` metadata into the Python bridge so long-running import/analysis calls don't hit the bridge's 30s default.

**Tech Stack:** Java 24, Maven, Ghidra 11.3.1 JARs (`lib/`), JUnit 5 + Mockito, Jackson (shaded), Python 3.10+ bridge with httpx + pytest.

## Global Constraints

- Every `@McpTool` method MUST return `com.lauriewired.mcp.model.ToolOutput` (reflection rejects other return types).
- Tool names are auto-derived from method names via `Json.toSnakeCase()`; `getFoo` → `get_foo`. Do not set `name` unless overriding.
- All Ghidra state access goes through `tool` / `ProgramService.getCurrentProgram()` — services never cache a `Program`.
- Write operations use `ProgramTransaction` (`try (var tx = ProgramTransaction.start(program, "name")) { ...; tx.commit(); }`).
- GUI mutations (`ProgramManager.openProgram/closeProgram/setCurrentProgram`, `DomainFile.save`) run on the EDT via a `runOnSwing(...)` seam that tests override to run inline.
- Response records live in `com.lauriewired.mcp.model.response`, are plain Java records, and are serialized to snake_case JSON by the shared Jackson mapper. Human-readable output comes from implementing `Displayable` or overriding `toString()` (for `ListOutput` items).
- Use `ghidra.util.task.TaskMonitor.DUMMY` for import/analysis monitors.
- Run the Java suite with `mvn test`; a single class with `mvn test -Dtest=ClassName`. Run the bridge tests with `python -m pytest test_bridge.py`.
- Do not pipe test commands through `tail`/`head` without `set -o pipefail` — it masks failures.

**Spec:** `docs/superpowers/specs/2026-07-02-project-import-analyze-design.md`

---

## File Structure

**Create (main):**
- `src/main/java/com/lauriewired/mcp/services/ProjectService.java` — the four new tools + shared helpers (`runOnSwing`, `openAndAutoClose`, `runAnalysis`).
- `src/main/java/com/lauriewired/mcp/model/response/ProgramFileItem.java`
- `src/main/java/com/lauriewired/mcp/model/response/ImportResult.java`
- `src/main/java/com/lauriewired/mcp/model/response/OpenProgramResult.java`
- `src/main/java/com/lauriewired/mcp/model/response/AnalysisResult.java`

**Modify (main):**
- `src/main/java/com/lauriewired/mcp/api/McpTool.java` — add `timeoutSeconds`.
- `src/main/java/com/lauriewired/mcp/api/ToolDef.java` — carry + emit `timeoutSeconds`.
- `src/main/java/com/lauriewired/mcp/model/response/ProgramInfoResult.java` — add static `from(Program)` factory.
- `src/main/java/com/lauriewired/mcp/services/ProgramService.java` — use `ProgramInfoResult.from(...)`.
- `src/main/java/com/lauriewired/GhidraMCPPlugin.java` — construct + wire `ProjectService`.
- `src/main/java/com/lauriewired/mcp/api/ApiHandlerRegistry.java` — accept + register `ProjectService`.
- `bridge_mcp_ghidra.py` — honor per-tool `timeoutSeconds`.

**Modify (test):**
- `src/test/java/com/lauriewired/mcp/api/ToolDefTest.java`
- `src/test/java/com/lauriewired/mcp/api/ApiHandlerRegistryTest.java`
- `src/test/java/com/lauriewired/mcp/api/ApiEndpointIntegrationTest.java`
- `test_bridge.py`

**Create (test):**
- `src/test/java/com/lauriewired/mcp/model/response/ResponseRecordsTest.java`
- `src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java`

---

## Task 1: Add `timeoutSeconds` to `@McpTool` + `ToolDef` metadata

**Files:**
- Modify: `src/main/java/com/lauriewired/mcp/api/McpTool.java`
- Modify: `src/main/java/com/lauriewired/mcp/api/ToolDef.java`
- Test: `src/test/java/com/lauriewired/mcp/api/ToolDefTest.java`

**Interfaces:**
- Produces: `McpTool.timeoutSeconds()` (annotation element, default `0`); `ToolDef.getTimeoutSeconds()` returning `int`; `/mcp/tools` JSON gains a `"timeoutSeconds"` key only when `> 0`.

- [ ] **Step 1: Write the failing test**

Add to `ToolDefTest.java`. Add a tool to the existing `TestTools` inner class and two tests:

```java
// inside static class TestTools:
@McpTool(post = true, timeoutSeconds = 600, description = "A slow tool")
public com.lauriewired.mcp.model.ToolOutput slowTool() { return null; }
```

```java
@Test
void testFromMethod_TimeoutSecondsCaptured() throws Exception {
    Method method = TestTools.class.getDeclaredMethod("slowTool");
    McpTool ann = method.getAnnotation(McpTool.class);
    ToolDef def = ToolDef.fromMethod(method, ann);
    assertEquals(600, def.getTimeoutSeconds());
}

@Test
void testToToolJson_EmitsTimeoutWhenSet() throws Exception {
    Method slow = TestTools.class.getDeclaredMethod("slowTool");
    ToolDef slowDef = ToolDef.fromMethod(slow, slow.getAnnotation(McpTool.class));
    assertTrue(slowDef.toToolJson().contains("\"timeoutSeconds\":600"));

    Method plain = TestTools.class.getDeclaredMethod("getProgramInfo");
    ToolDef plainDef = ToolDef.fromMethod(plain, plain.getAnnotation(McpTool.class));
    assertFalse(plainDef.toToolJson().contains("timeoutSeconds"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=ToolDefTest`
Expected: FAIL — `getTimeoutSeconds()` does not exist / compilation error.

- [ ] **Step 3: Add the annotation element**

In `McpTool.java`, add after `responseType()`:

```java
    /** Per-tool HTTP timeout hint (seconds) surfaced to the bridge. 0 = use bridge default. */
    int timeoutSeconds() default 0;
```

- [ ] **Step 4: Carry it through `ToolDef`**

In `ToolDef.java`:

Add the field near the other finals:
```java
    private final int timeoutSeconds;
```

Add the constructor parameter (append to the signature) and assignment:
```java
    private ToolDef(final String name, final String rawDescription, final boolean post, final List<ToolParamDef> params,
                    final Class<? extends ToolOutput> outputType, final Class<?> responseType, final int timeoutSeconds) {
        this.name = name;
        this.post = post;
        this.params = params;
        this.outputType = outputType;
        this.responseType = responseType;
        this.timeoutSeconds = timeoutSeconds;
        this.hasComplexTypes = params.stream().anyMatch(p ->
            p.type() == ParamType.STRING_MAP || p.type() == ParamType.LONG_MAP || p.type() == ParamType.STRING_PAIR_LIST);
        this.description = buildFullDescription(rawDescription, params);
    }
```

In `fromMethod`, pass it in the `new ToolDef(...)` call (last arg):
```java
        return new ToolDef(toolName, annotation.description(), annotation.post(), paramDefs,
            annotation.outputType(), annotation.responseType(), annotation.timeoutSeconds());
```

Add a getter next to the other getters:
```java
    public int getTimeoutSeconds() { return timeoutSeconds; }
```

In `toToolJson()`, after the `tool.put("inputSchema", ...)` line and before the schema block, add:
```java
        if (timeoutSeconds > 0) {
            tool.put("timeoutSeconds", timeoutSeconds);
        }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `mvn test -Dtest=ToolDefTest`
Expected: PASS (all existing ToolDefTest tests + the two new ones).

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/lauriewired/mcp/api/McpTool.java src/main/java/com/lauriewired/mcp/api/ToolDef.java src/test/java/com/lauriewired/mcp/api/ToolDefTest.java
git commit -m "feat: add per-tool timeoutSeconds hint to @McpTool metadata"
```

---

## Task 2: Bridge honors per-tool `timeoutSeconds`

**Files:**
- Modify: `bridge_mcp_ghidra.py`
- Test: `test_bridge.py`

**Interfaces:**
- Produces: `_effective_timeout(tool_def: dict)` → returns the tool's `timeoutSeconds` (a positive number) or `httpx.USE_CLIENT_DEFAULT`. `_call_tool` passes it as the per-request `timeout=`.

- [ ] **Step 1: Write the failing test**

Add to `test_bridge.py` (import `_effective_timeout` in the existing `from bridge_mcp_ghidra import (...)` block, and `import httpx` already present):

```python
class TestEffectiveTimeout:
    def test_absent_uses_client_default(self):
        assert _effective_timeout({"name": "x"}) is httpx.USE_CLIENT_DEFAULT

    def test_zero_uses_client_default(self):
        assert _effective_timeout({"name": "x", "timeoutSeconds": 0}) is httpx.USE_CLIENT_DEFAULT

    def test_positive_value_used(self):
        assert _effective_timeout({"name": "x", "timeoutSeconds": 600}) == 600
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest test_bridge.py::TestEffectiveTimeout -v`
Expected: FAIL — `ImportError: cannot import name '_effective_timeout'`.

- [ ] **Step 3: Implement `_effective_timeout` and use it**

In `bridge_mcp_ghidra.py`, add this function above `_call_tool`:

```python
def _effective_timeout(tool_def: dict):
    """Per-tool HTTP timeout override, falling back to the client default.

    The Java plugin emits `timeoutSeconds` in /mcp/tools for long-running tools
    (import/analysis). When absent or non-positive, use the AsyncClient's
    configured default via httpx.USE_CLIENT_DEFAULT.
    """
    value = tool_def.get("timeoutSeconds")
    if isinstance(value, (int, float)) and value > 0:
        return value
    return httpx.USE_CLIENT_DEFAULT
```

In `_call_tool`, compute it once and pass to both requests:

```python
    method = tool_def.get("method", "GET").upper()
    url = f"{server_url}/{endpoint}"
    timeout = _effective_timeout(tool_def)

    try:
        if method == "POST":
            filtered = {k: v for k, v in arguments.items() if v is not None}
            resp = await client.post(url, content=json.dumps(filtered),
                                     headers={"Content-Type": "application/json"},
                                     timeout=timeout)
        else:
            params = {k: _serialize_query_value(v) for k, v in arguments.items() if v is not None}
            resp = await client.get(url, params=params, timeout=timeout)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest test_bridge.py -v`
Expected: PASS (new `TestEffectiveTimeout` + all existing bridge tests).

- [ ] **Step 5: Commit**

```bash
git add bridge_mcp_ghidra.py test_bridge.py
git commit -m "feat: bridge honors per-tool timeoutSeconds from /mcp/tools"
```

---

## Task 3: Response records + `ProgramInfoResult.from(Program)`

**Files:**
- Create: `src/main/java/com/lauriewired/mcp/model/response/ProgramFileItem.java`
- Create: `src/main/java/com/lauriewired/mcp/model/response/ImportResult.java`
- Create: `src/main/java/com/lauriewired/mcp/model/response/OpenProgramResult.java`
- Create: `src/main/java/com/lauriewired/mcp/model/response/AnalysisResult.java`
- Modify: `src/main/java/com/lauriewired/mcp/model/response/ProgramInfoResult.java`
- Modify: `src/main/java/com/lauriewired/mcp/services/ProgramService.java`
- Test: `src/test/java/com/lauriewired/mcp/model/response/ResponseRecordsTest.java`

**Interfaces:**
- Produces:
  - `ProgramFileItem(String path, String name, String contentType, boolean open)` — `toString()` yields a clean list line.
  - `ImportResult(String name, String projectPath, String format, String languageId, int functionCount, boolean analyzed, List<String> additionalPrograms, String warning)` implements `Displayable`.
  - `OpenProgramResult(ProgramInfoResult info, String warning)` implements `Displayable`.
  - `AnalysisResult(boolean analyzed, int functionCount, int symbolCount, long elapsedMs)` implements `Displayable`.
  - `ProgramInfoResult.from(ghidra.program.model.listing.Program program)` — static factory building the record from a live program (extracted from `ProgramService.getProgramInfo`).

- [ ] **Step 1: Write the failing test**

Create `src/test/java/com/lauriewired/mcp/model/response/ResponseRecordsTest.java`:

```java
package com.lauriewired.mcp.model.response;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;

class ResponseRecordsTest {

    @Test
    void programFileItem_toStringIncludesPathAndOpenFlag() {
        ProgramFileItem open = new ProgramFileItem("/bin/ls", "ls", "Program", true);
        ProgramFileItem closed = new ProgramFileItem("/bin/cat", "cat", "Program", false);
        assertTrue(open.toString().contains("/bin/ls"));
        assertTrue(open.toString().contains("[open]"));
        assertFalse(closed.toString().contains("[open]"));
    }

    @Test
    void programFileItem_rendersInsideListOutput() {
        ListOutput out = ListOutput.paginate(
            List.of(new ProgramFileItem("/bin/ls", "ls", "Program", false)), 0, 100);
        assertTrue(out.toDisplayText().contains("/bin/ls"));
    }

    @Test
    void importResult_displayShowsNameAnalyzedAndWarning() {
        ImportResult r = new ImportResult("firmware.bin", "/imports/firmware.bin", "ELF",
            "ARM:LE:32:v8", 42, true, List.of("blob.bin"), "prev left open");
        String text = r.toDisplayText();
        assertTrue(text.contains("firmware.bin"));
        assertTrue(text.contains("42"));
        assertTrue(text.contains("blob.bin"));
        assertTrue(text.contains("prev left open"));
        assertTrue(new JsonOutput(r).toStructuredJson().contains("\"analyzed\":true"));
    }

    @Test
    void importResult_noWarningOmitsWarningLine() {
        ImportResult r = new ImportResult("a", "/a", "Raw Binary", "x86:LE:64:default",
            0, false, List.of(), null);
        assertFalse(r.toDisplayText().contains("Warning"));
    }

    @Test
    void analysisResult_displayShowsCounts() {
        AnalysisResult r = new AnalysisResult(true, 10, 20, 1234L);
        String text = r.toDisplayText();
        assertTrue(text.contains("10"));
        assertTrue(text.contains("20"));
        assertTrue(text.contains("1234"));
    }

    @Test
    void openProgramResult_displayIncludesWarningWhenPresent() {
        ProgramInfoResult info = new ProgramInfoResult("p", "ELF", "x86", "x86:LE:64:default",
            "little", 64, "gcc", "0x0", "0x0", "0x100", null, 1, 2);
        OpenProgramResult withWarn = new OpenProgramResult(info, "prev left open");
        OpenProgramResult noWarn = new OpenProgramResult(info, null);
        assertTrue(withWarn.toDisplayText().contains("prev left open"));
        assertTrue(withWarn.toDisplayText().contains("Program: p"));
        assertFalse(noWarn.toDisplayText().contains("Warning"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=ResponseRecordsTest`
Expected: FAIL — the new record classes do not exist (compilation error).

- [ ] **Step 3: Create the records**

`ProgramFileItem.java`:
```java
package com.lauriewired.mcp.model.response;

/** One program file in the project tree, for list_program_files. */
public record ProgramFileItem(String path, String name, String contentType, boolean open) {
    @Override
    public String toString() {
        return path + "  (" + contentType + ")" + (open ? "  [open]" : "");
    }
}
```

`ImportResult.java`:
```java
package com.lauriewired.mcp.model.response;

import java.util.List;
import com.lauriewired.mcp.model.Displayable;

/** Result of import_program. */
public record ImportResult(
    String name,
    String projectPath,
    String format,
    String languageId,
    int functionCount,
    boolean analyzed,
    List<String> additionalPrograms,
    String warning
) implements Displayable {
    public ImportResult {
        additionalPrograms = additionalPrograms == null ? List.of() : List.copyOf(additionalPrograms);
    }

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Imported: ").append(name).append("\n");
        sb.append("Project path: ").append(projectPath).append("\n");
        sb.append("Format: ").append(format).append("\n");
        sb.append("Language: ").append(languageId).append("\n");
        sb.append("Analyzed: ").append(analyzed).append("\n");
        sb.append("Functions: ").append(functionCount);
        if (!additionalPrograms.isEmpty()) {
            sb.append("\nAdditional programs: ").append(String.join(", ", additionalPrograms));
        }
        if (warning != null) {
            sb.append("\nWarning: ").append(warning);
        }
        return sb.toString();
    }
}
```

`OpenProgramResult.java`:
```java
package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

/** Result of open_program: program info for the newly-current program plus an optional warning. */
public record OpenProgramResult(ProgramInfoResult info, String warning) implements Displayable {
    @Override
    public String toDisplayText() {
        final String base = info.toDisplayText();
        return warning == null ? base : base + "\nWarning: " + warning;
    }
}
```

`AnalysisResult.java`:
```java
package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

/** Result of reanalyze_program (and the analysis portion of import_program). */
public record AnalysisResult(boolean analyzed, int functionCount, int symbolCount, long elapsedMs)
        implements Displayable {
    @Override
    public String toDisplayText() {
        return "Analyzed: " + analyzed
            + "\nFunctions: " + functionCount
            + "\nSymbols: " + symbolCount
            + "\nElapsed: " + elapsedMs + " ms";
    }
}
```

- [ ] **Step 4: Extract `ProgramInfoResult.from(Program)` and reuse it**

In `ProgramInfoResult.java`, add these imports at the top:
```java
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
```
Add this static factory inside the record body (above `toDisplayText`):
```java
    /** Build a ProgramInfoResult from a live program. */
    public static ProgramInfoResult from(final Program program) {
        final AddressIterator entryPoints = program.getSymbolTable().getExternalEntryPointIterator();
        final String entryPoint = entryPoints.hasNext() ? entryPoints.next().toString() : null;
        return new ProgramInfoResult(
            program.getName(),
            program.getExecutableFormat(),
            program.getLanguage().getProcessor().toString(),
            program.getLanguageID().toString(),
            program.getLanguage().getLanguageDescription().getEndian().toString(),
            program.getLanguage().getLanguageDescription().getSize(),
            program.getCompilerSpec().getCompilerSpecID().toString(),
            program.getImageBase().toString(),
            program.getMinAddress().toString(),
            program.getMaxAddress().toString(),
            entryPoint,
            program.getFunctionManager().getFunctionCount(),
            program.getSymbolTable().getNumSymbols());
    }
```

In `ProgramService.java`, replace the body of `getProgramInfo()` after the null check with the factory (delete the now-unused `AddressIterator`/entryPoint locals and the inline `new ProgramInfoResult(...)`):
```java
    public ToolOutput getProgramInfo() {
        final Program program = getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        return new JsonOutput(ProgramInfoResult.from(program));
    }
```
Remove the now-unused `import ghidra.program.model.address.AddressIterator;` from `ProgramService.java` if the compiler flags it as unused (PMD/verify).

- [ ] **Step 5: Run tests to verify they pass**

Run: `mvn test -Dtest=ResponseRecordsTest,ProgramServiceTest`
Expected: PASS — new record tests pass and `ProgramServiceTest` still passes (proving the `from(...)` extraction is behavior-preserving).

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/lauriewired/mcp/model/response/ src/main/java/com/lauriewired/mcp/services/ProgramService.java src/test/java/com/lauriewired/mcp/model/response/ResponseRecordsTest.java
git commit -m "feat: add project-tool response records + ProgramInfoResult.from factory"
```

---

## Task 4: Create `ProjectService`, wire it in, implement `list_program_files`

**Files:**
- Create: `src/main/java/com/lauriewired/mcp/services/ProjectService.java`
- Modify: `src/main/java/com/lauriewired/GhidraMCPPlugin.java`
- Modify: `src/main/java/com/lauriewired/mcp/api/ApiHandlerRegistry.java`
- Modify: `src/test/java/com/lauriewired/mcp/api/ApiHandlerRegistryTest.java`
- Modify: `src/test/java/com/lauriewired/mcp/api/ApiEndpointIntegrationTest.java`
- Test: `src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java`

**Interfaces:**
- Consumes: `ProgramInfoResult` (Task 3), `PluginTool`, `ProgramManager`.
- Produces:
  - `ProjectService(PluginTool tool)` constructor.
  - `protected <T> T runOnSwing(java.util.function.Supplier<T> action)` — overridable Swing seam (default `ghidra.util.Swing.runNow(action)`).
  - `@McpTool ToolOutput listProgramFiles(String folder, int offset, int limit)` → `list_program_files` (GET).
  - `ApiHandlerRegistry` constructor now takes a `ProjectService` as its final parameter and registers it.

- [ ] **Step 1: Write the failing test**

Create `src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java`:

```java
package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

class ProjectServiceTest {

    /** ProjectService whose Swing seam runs inline (no EDT) for deterministic tests. */
    static ProjectService inlineService(PluginTool tool) {
        return new ProjectService(tool) {
            @Override
            protected <T> T runOnSwing(java.util.function.Supplier<T> action) {
                return action.get();
            }
        };
    }

    private static DomainFile mockFile(String path, String name, String type) {
        DomainFile f = mock(DomainFile.class);
        when(f.getPathname()).thenReturn(path);
        when(f.getName()).thenReturn(name);
        when(f.getContentType()).thenReturn(type);
        return f;
    }

    @Test
    void listProgramFiles_noProject_returnsError() {
        ProjectService svc = inlineService(null);
        ToolOutput out = svc.listProgramFiles("/", 0, 100);
        assertInstanceOf(StatusOutput.class, out);
        assertTrue(out.toStructuredJson().contains("No active"));
    }

    @Test
    void listProgramFiles_walksTreeAndFlagsOpen() {
        PluginTool tool = mock(PluginTool.class);
        Project project = mock(Project.class);
        ProjectData data = mock(ProjectData.class);
        DomainFolder root = mock(DomainFolder.class);
        DomainFolder sub = mock(DomainFolder.class);
        ProgramManager pm = mock(ProgramManager.class);

        DomainFile lsFile = mockFile("/ls", "ls", "Program");
        DomainFile catFile = mockFile("/sub/cat", "cat", "Program");

        when(tool.getProject()).thenReturn(project);
        when(tool.getService(ProgramManager.class)).thenReturn(pm);
        when(project.getProjectData()).thenReturn(data);
        when(data.getFolder("/")).thenReturn(root);
        when(root.getFiles()).thenReturn(new DomainFile[]{lsFile});
        when(root.getFolders()).thenReturn(new DomainFolder[]{sub});
        when(sub.getFiles()).thenReturn(new DomainFile[]{catFile});
        when(sub.getFolders()).thenReturn(new DomainFolder[]{});

        // "ls" is open, "cat" is not
        Program openProg = mock(Program.class);
        when(openProg.getDomainFile()).thenReturn(lsFile);
        when(pm.getAllOpenPrograms()).thenReturn(new Program[]{openProg});

        ProjectService svc = inlineService(tool);
        ToolOutput out = svc.listProgramFiles("/", 0, 100);
        assertInstanceOf(ListOutput.class, out);
        String text = out.toDisplayText();
        assertTrue(text.contains("/ls"));
        assertTrue(text.contains("[open]"));
        assertTrue(text.contains("/sub/cat"));
    }

    @Test
    void listProgramFiles_missingFolder_returnsError() {
        PluginTool tool = mock(PluginTool.class);
        Project project = mock(Project.class);
        ProjectData data = mock(ProjectData.class);
        when(tool.getProject()).thenReturn(project);
        when(project.getProjectData()).thenReturn(data);
        when(data.getFolder("/nope")).thenReturn(null);

        ProjectService svc = inlineService(tool);
        ToolOutput out = svc.listProgramFiles("/nope", 0, 100);
        assertInstanceOf(StatusOutput.class, out);
        assertTrue(out.toStructuredJson().contains("Folder not found"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=ProjectServiceTest`
Expected: FAIL — `ProjectService` does not exist (compilation error).

- [ ] **Step 3: Create `ProjectService` with the Swing seam + `listProgramFiles`**

Create `src/main/java/com/lauriewired/mcp/services/ProjectService.java`:

```java
package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.ProgramFileItem;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;

/**
 * Project-level tools: import a file into the current project, list project
 * files, open an existing file, and (re-)run analysis. Reaches the project via
 * {@code tool.getProject()} and the tool's {@link ProgramManager}; imported and
 * opened programs become the CodeBrowser's current program.
 */
public class ProjectService {
    private final PluginTool tool;

    public ProjectService(final PluginTool tool) {
        this.tool = tool;
    }

    /**
     * Run an action on the Swing/EDT thread. Overridable so tests run inline.
     */
    protected <T> T runOnSwing(final Supplier<T> action) {
        return Swing.runNow(action);
    }

    private Project getProject() {
        return tool != null ? tool.getProject() : null;
    }

    private ProgramManager getProgramManager() {
        return tool != null ? tool.getService(ProgramManager.class) : null;
    }

    @McpTool(outputType = ListOutput.class, responseType = ProgramFileItem.class, description = """
        List program files in the current Ghidra project.

        Recursively walks the project folder tree starting at the given folder,
        returning each program file's project path, name, content type, and
        whether it is currently open. Use this to discover binaries already
        imported so you can open one with open_program.

        Returns: paginated list of project program files

        Example: list_program_files("/") -> "/imports/firmware.bin  (Program)  [open]" """)
    public ToolOutput listProgramFiles(
            @Param(value = "Project folder path to list (recursive)", defaultValue = "/") final String folder,
            @Param(value = "Pagination offset", defaultValue = "0") final int offset,
            @Param(value = "Maximum items to return", defaultValue = "100") final int limit) {
        final Project project = getProject();
        if (project == null) return StatusOutput.error("No active Ghidra project");

        final String folderPath = (folder == null || folder.isBlank()) ? "/" : folder;
        final ProjectData data = project.getProjectData();
        final DomainFolder start = data.getFolder(folderPath);
        if (start == null) return StatusOutput.error("Folder not found: " + folderPath);

        final Set<String> openPaths = openProgramPaths();
        final List<ProgramFileItem> items = new ArrayList<>();
        collectFiles(start, openPaths, items);
        return ListOutput.paginate(items, offset, limit);
    }

    private Set<String> openProgramPaths() {
        final Set<String> paths = new HashSet<>();
        final ProgramManager pm = getProgramManager();
        if (pm != null) {
            final Program[] open = pm.getAllOpenPrograms();
            if (open != null) {
                for (final Program p : open) {
                    final DomainFile df = p.getDomainFile();
                    if (df != null) paths.add(df.getPathname());
                }
            }
        }
        return paths;
    }

    private void collectFiles(final DomainFolder folder, final Set<String> openPaths,
                              final List<ProgramFileItem> out) {
        for (final DomainFile f : folder.getFiles()) {
            out.add(new ProgramFileItem(f.getPathname(), f.getName(), f.getContentType(),
                openPaths.contains(f.getPathname())));
        }
        for (final DomainFolder sub : folder.getFolders()) {
            collectFiles(sub, openPaths, out);
        }
    }
}
```

- [ ] **Step 4: Wire `ProjectService` into the plugin**

In `GhidraMCPPlugin.java`:

Add the import:
```java
import com.lauriewired.mcp.services.ProjectService;
```
Add the field alongside the other services:
```java
    private ProjectService projectService;
```
In `initializeServices()`, add after `searchService`:
```java
        this.projectService = new ProjectService(tool);
```
In `startServer()`, add `projectService` as the final argument to `new ApiHandlerRegistry(...)`:
```java
            apiHandlerRegistry = new ApiHandlerRegistry(
                serverManager,
                functionService,
                namespaceService,
                dataTypeService,
                analysisService,
                commentService,
                memoryService,
                programService,
                searchService,
                variableService,
                projectService
            );
```

- [ ] **Step 5: Wire `ProjectService` into `ApiHandlerRegistry`**

In `ApiHandlerRegistry.java`:

Add the import:
```java
import com.lauriewired.mcp.services.ProjectService;
```
Add the field:
```java
    private final ProjectService projectService;
```
Add the constructor parameter (append after `variableService`) and assignment:
```java
            final VariableService variableService,
            final ProjectService projectService) {
        ...
        this.variableService = variableService;
        this.projectService = projectService;
```
In `registerAllEndpoints()`, add `projectService` to the `services` array:
```java
        final Object[] services = {
            programService, functionService, namespaceService,
            dataTypeService, analysisService, commentService,
            memoryService, searchService, variableService, projectService
        };
```

- [ ] **Step 6: Fix the other two constructor call sites**

In `src/test/java/com/lauriewired/mcp/api/ApiHandlerRegistryTest.java`, both `new ApiHandlerRegistry(...)` calls (around lines 89 and 107) need a `ProjectService` as the final argument. Add an import `import com.lauriewired.mcp.services.ProjectService;` and pass `new ProjectService(null)` (or the test's mock tool) as the last argument in both calls.

In `src/test/java/com/lauriewired/mcp/api/ApiEndpointIntegrationTest.java` (around line 94), do the same: add the import and pass a `ProjectService` (constructed with the same tool/mocks the other services use) as the final argument.

> Note: read each file's surrounding constructor call first to match how it obtains its `tool`/services, then append the matching `ProjectService`. If the test builds services from a shared mock `PluginTool`, use `new ProjectService(thatTool)`; otherwise `new ProjectService(null)`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `mvn test -Dtest=ProjectServiceTest,ApiHandlerRegistryTest,ApiEndpointIntegrationTest`
Expected: PASS — `ProjectServiceTest` green; the two registry tests compile and pass with the added argument. If `ApiHandlerRegistryTest` asserts a specific tool count, bump the expected count by the number of `@McpTool` methods currently on `ProjectService` (1 so far: `list_program_files`).

- [ ] **Step 8: Commit**

```bash
git add src/main/java/com/lauriewired/mcp/services/ProjectService.java src/main/java/com/lauriewired/GhidraMCPPlugin.java src/main/java/com/lauriewired/mcp/api/ApiHandlerRegistry.java src/test/java/com/lauriewired/mcp/api/ApiHandlerRegistryTest.java src/test/java/com/lauriewired/mcp/api/ApiEndpointIntegrationTest.java src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java
git commit -m "feat: add ProjectService with list_program_files, wired into plugin + registry"
```

---

## Task 5: `open_program` + safe auto-close-previous

**Files:**
- Modify: `src/main/java/com/lauriewired/mcp/services/ProjectService.java`
- Test: `src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java`

**Interfaces:**
- Consumes: `ProgramInfoResult.from(Program)`, `OpenProgramResult`.
- Produces:
  - `@McpTool ToolOutput openProgram(String projectPath)` → `open_program` (POST).
  - Package-private `String autoClosePrevious(ProgramManager pm, Program prev, Program opened)` — the unit-tested core. The public method opens the file and calls this inside a single `runOnSwing(...)`, collecting the returned warning via a one-element `String[]` box.

- [ ] **Step 1: Write the failing test**

Add to `ProjectServiceTest.java`:

```java
    // --- auto-close via the tested core helper ---

    private static Program mockProgram(String name, DomainFile df, boolean changed) {
        Program p = mock(Program.class);
        when(p.getName()).thenReturn(name);
        when(p.getDomainFile()).thenReturn(df);
        when(p.isChanged()).thenReturn(changed);
        return p;
    }

    @org.junit.jupiter.api.Test
    void autoClose_cleanSwitch_savesAndCloses() throws Exception {
        ProgramManager pm = mock(ProgramManager.class);
        DomainFile df = mockFile("/old", "old", "Program");
        when(df.canSave()).thenReturn(true);
        // isChanged: true before save, false after save
        Program prev = mock(Program.class);
        when(prev.getName()).thenReturn("old");
        when(prev.getDomainFile()).thenReturn(df);
        when(prev.isChanged()).thenReturn(true, false);
        Program opened = mock(Program.class);

        ProjectService svc = inlineService(mock(PluginTool.class));
        String warning = svc.autoClosePrevious(pm, prev, opened);

        org.mockito.Mockito.verify(df).save(org.mockito.ArgumentMatchers.any());
        org.mockito.Mockito.verify(pm).closeProgram(prev, false);
        org.junit.jupiter.api.Assertions.assertNull(warning);
    }

    @org.junit.jupiter.api.Test
    void autoClose_saveFails_leavesOpenWithWarning() throws Exception {
        ProgramManager pm = mock(ProgramManager.class);
        DomainFile df = mockFile("/old", "old", "Program");
        when(df.canSave()).thenReturn(true);
        org.mockito.Mockito.doThrow(new java.io.IOException("disk full"))
            .when(df).save(org.mockito.ArgumentMatchers.any());
        Program prev = mockProgram("old", df, true);
        Program opened = mock(Program.class);

        ProjectService svc = inlineService(mock(PluginTool.class));
        String warning = svc.autoClosePrevious(pm, prev, opened);

        assertTrue(warning.contains("old"));
        assertTrue(warning.contains("disk full"));
        org.mockito.Mockito.verify(pm, org.mockito.Mockito.never())
            .closeProgram(org.mockito.ArgumentMatchers.eq(prev), org.mockito.ArgumentMatchers.anyBoolean());
    }

    @org.junit.jupiter.api.Test
    void autoClose_noPrevious_isNoOp() {
        ProgramManager pm = mock(ProgramManager.class);
        Program opened = mock(Program.class);
        ProjectService svc = inlineService(mock(PluginTool.class));
        org.junit.jupiter.api.Assertions.assertNull(svc.autoClosePrevious(pm, null, opened));
        org.junit.jupiter.api.Assertions.assertNull(svc.autoClosePrevious(pm, opened, opened));
    }

    @org.junit.jupiter.api.Test
    void openProgram_missingPath_returnsError() {
        PluginTool tool = mock(PluginTool.class);
        Project project = mock(Project.class);
        ProjectData data = mock(ProjectData.class);
        when(tool.getProject()).thenReturn(project);
        when(project.getProjectData()).thenReturn(data);
        when(data.getFile("/gone")).thenReturn(null);

        ProjectService svc = inlineService(tool);
        ToolOutput out = svc.openProgram("/gone");
        assertInstanceOf(StatusOutput.class, out);
        assertTrue(out.toStructuredJson().contains("not found"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=ProjectServiceTest`
Expected: FAIL — `autoClosePrevious` / `openProgram` do not exist (compilation error).

- [ ] **Step 3: Implement the auto-close core + `open_program`**

Add to `ProjectService.java` these imports:
```java
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.response.OpenProgramResult;
import com.lauriewired.mcp.model.response.ProgramInfoResult;
import ghidra.framework.model.ProjectData;
import ghidra.util.task.TaskMonitor;
```
(`ProjectData` may already be imported from Task 4 — do not duplicate.)

Add the tool method and helpers:

```java
    @McpTool(post = true, outputType = JsonOutput.class, responseType = OpenProgramResult.class, description = """
        Open an already-imported project file and make it the current program.

        Switches the CodeBrowser to the given project file so all other tools
        operate on it. The previously-current program is auto-closed (saved
        first); if that save fails it is left open and a warning is returned.

        Returns: program metadata for the newly-current program (plus optional warning)

        Example: open_program("/imports/firmware.bin") """)
    public ToolOutput openProgram(
            @Param(value = "Project path of the file to open, e.g. /imports/firmware.bin") final String projectPath) {
        final Project project = getProject();
        if (project == null) return StatusOutput.error("No active Ghidra project");
        if (projectPath == null || projectPath.isBlank()) return StatusOutput.error("projectPath is required");

        final DomainFile file = project.getProjectData().getFile(projectPath);
        if (file == null) return StatusOutput.error("Project file not found: " + projectPath);

        final ProgramManager pm = getProgramManager();
        if (pm == null) return StatusOutput.error("No ProgramManager available");

        final String[] warningBox = new String[1];
        final ProgramInfoResult info = runOnSwing(() -> {
            final Program prev = pm.getCurrentProgram();
            final Program opened = pm.openProgram(file);
            if (opened == null) return null;
            warningBox[0] = autoClosePrevious(pm, prev, opened);
            return ProgramInfoResult.from(opened);
        });
        if (info == null) return StatusOutput.error("Failed to open program: " + projectPath);
        return new JsonOutput(new OpenProgramResult(info, warningBox[0]));
    }

    /**
     * Save-then-close the previously-current program when switching. Never
     * discards unsaved work: on save failure (or an unsavable dirty program)
     * the program is left open and a warning string is returned; otherwise
     * returns null. Package-private for unit testing.
     */
    String autoClosePrevious(final ProgramManager pm, final Program prev, final Program opened) {
        if (prev == null || prev == opened) return null;
        final DomainFile df = prev.getDomainFile();
        try {
            if (prev.isChanged() && df != null && df.canSave()) {
                df.save(TaskMonitor.DUMMY);
            }
            if (!prev.isChanged()) {
                pm.closeProgram(prev, false);
                return null;
            }
            return "Previous program '" + prev.getName()
                + "' left open: it has unsaved changes that could not be saved.";
        } catch (Exception e) {
            return "Previous program '" + prev.getName() + "' left open: save failed: " + e.getMessage();
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn test -Dtest=ProjectServiceTest`
Expected: PASS (all Task 4 + Task 5 tests).

- [ ] **Step 5: Update the registry tool-count assertion if present**

If `ApiHandlerRegistryTest` asserts a specific number of registered tools, increase the expected count by 1 (now `list_program_files` + `open_program`).

Run: `mvn test -Dtest=ApiHandlerRegistryTest`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/lauriewired/mcp/services/ProjectService.java src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java src/test/java/com/lauriewired/mcp/api/ApiHandlerRegistryTest.java
git commit -m "feat: add open_program with safe auto-close-previous"
```

---

## Task 6: `reanalyze_program` + shared analysis helper

**Files:**
- Modify: `src/main/java/com/lauriewired/mcp/services/ProjectService.java`
- Test: `src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java`

**Interfaces:**
- Consumes: `AnalysisResult`, `ProgramTransaction`, `AutoAnalysisManager`.
- Produces:
  - `@McpTool ToolOutput reanalyzeProgram()` → `reanalyze_program` (POST, `timeoutSeconds = 600`).
  - Package-private `AnalysisResult runAnalysis(Program program)` — shared with `import_program` (Task 7).

- [ ] **Step 1: Write the failing test**

Add to `ProjectServiceTest.java` a null-program error test plus a real analysis integration test (mirrors `ProgramServiceTest`'s ProgramBuilder pattern; skips gracefully without a Ghidra install):

```java
    @org.junit.jupiter.api.Test
    void reanalyze_noCurrentProgram_returnsError() {
        PluginTool tool = mock(PluginTool.class);
        ProgramManager pm = mock(ProgramManager.class);
        when(tool.getService(ProgramManager.class)).thenReturn(pm);
        when(pm.getCurrentProgram()).thenReturn(null);

        ProjectService svc = inlineService(tool);
        ToolOutput out = svc.reanalyzeProgram();
        assertInstanceOf(StatusOutput.class, out);
        assertTrue(out.toStructuredJson().contains("No program"));
    }

    @org.junit.jupiter.api.Nested
    @org.junit.jupiter.api.DisplayName("reanalyze on a real ProgramBuilder program")
    class ReanalyzeIntegration {
        @org.junit.jupiter.api.Test
        void reanalyze_realProgram_marksAnalyzed() throws Exception {
            GhidraTestEnv.initialize();
            ghidra.program.database.ProgramBuilder builder =
                new ghidra.program.database.ProgramBuilder("t", ghidra.program.database.ProgramBuilder._X64);
            builder.createMemory(".text", "0x401000", 0x200);
            builder.createEmptyFunction("main", "0x401000", 0x40,
                ghidra.program.model.data.DataType.DEFAULT);
            ghidra.program.database.ProgramDB program = builder.getProgram();
            try {
                PluginTool tool = mock(PluginTool.class);
                ProgramManager pm = mock(ProgramManager.class);
                when(tool.getService(ProgramManager.class)).thenReturn(pm);
                when(pm.getCurrentProgram()).thenReturn(program);

                ProjectService svc = inlineService(tool);
                ToolOutput out = svc.reanalyzeProgram();
                assertInstanceOf(com.lauriewired.mcp.model.JsonOutput.class, out);
                com.lauriewired.mcp.model.response.AnalysisResult r =
                    (com.lauriewired.mcp.model.response.AnalysisResult)
                        ((com.lauriewired.mcp.model.JsonOutput) out).data();
                org.junit.jupiter.api.Assertions.assertTrue(r.analyzed());
                org.junit.jupiter.api.Assertions.assertTrue(r.functionCount() >= 1);
            } finally {
                builder.dispose();
            }
        }
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=ProjectServiceTest`
Expected: FAIL — `reanalyzeProgram` does not exist (compilation error).

- [ ] **Step 3: Implement `reanalyze_program` + `runAnalysis`**

Add to `ProjectService.java` these imports:
```java
import com.lauriewired.mcp.model.response.AnalysisResult;
import com.lauriewired.mcp.utils.ProgramTransaction;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.util.GhidraProgramUtilities;
```

Add the tool method and helper:

```java
    @McpTool(post = true, timeoutSeconds = 600, outputType = JsonOutput.class,
             responseType = AnalysisResult.class, description = """
        Re-run Ghidra auto-analysis on the current program.

        Imported programs are analyzed by default, so a program is normally
        already analyzed — use this to redo analysis (e.g. after changing
        settings). This blocks until analysis completes and may take minutes
        on large binaries.

        Returns: analyzed flag with function/symbol counts and elapsed time

        Example: reanalyze_program() """)
    public ToolOutput reanalyzeProgram() {
        final ProgramManager pm = getProgramManager();
        final Program program = pm != null ? pm.getCurrentProgram() : null;
        if (program == null) return StatusOutput.error("No program is currently open");
        return new JsonOutput(runAnalysis(program));
    }

    /**
     * Run auto-analysis on a program within a transaction and return counts.
     * Shared by reanalyze_program and import_program. Package-private for testing.
     */
    AnalysisResult runAnalysis(final Program program) {
        final long start = System.currentTimeMillis();
        final AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        try (var tx = ProgramTransaction.start(program, "Auto-analysis")) {
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(TaskMonitor.DUMMY);
            GhidraProgramUtilities.markProgramAnalyzed(program);
            tx.commit();
        }
        final long elapsed = System.currentTimeMillis() - start;
        return new AnalysisResult(
            true,
            program.getFunctionManager().getFunctionCount(),
            program.getSymbolTable().getNumSymbols(),
            elapsed);
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn test -Dtest=ProjectServiceTest`
Expected: PASS. The `reanalyze_noCurrentProgram` unit test always runs; `ReanalyzeIntegration` runs when a Ghidra install is present (else skipped via `assumeTrue` inside `GhidraTestEnv.initialize()`).

> If the integration test errors because headless auto-analysis needs services unavailable in the test env, downgrade it: keep the null-program unit test as the guaranteed coverage and move the real-analysis check to the Task 8 manual verification. Note the change in the commit message.

- [ ] **Step 5: Bump registry tool-count assertion if present, then commit**

Run: `mvn test -Dtest=ApiHandlerRegistryTest` (bump expected count to include `reanalyze_program` if asserted).

```bash
git add src/main/java/com/lauriewired/mcp/services/ProjectService.java src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java src/test/java/com/lauriewired/mcp/api/ApiHandlerRegistryTest.java
git commit -m "feat: add reanalyze_program with shared runAnalysis helper"
```

---

## Task 7: `import_program`

**Files:**
- Modify: `src/main/java/com/lauriewired/mcp/services/ProjectService.java`
- Test: `src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java`

**Interfaces:**
- Consumes: `AutoImporter`, `LoadResults`, `Loaded`, `ImportResult`, `runAnalysis` (Task 6), `autoClosePrevious` (Task 5).
- Produces: `@McpTool ToolOutput importProgram(String path, String folder, boolean analyze, boolean open)` → `import_program` (POST, `timeoutSeconds = 600`).

- [ ] **Step 1: Write the failing test (validation/error branches — the mock-testable part)**

Add to `ProjectServiceTest.java`:

```java
    @org.junit.jupiter.api.Test
    void importProgram_noProject_returnsError() {
        ProjectService svc = inlineService(null);
        ToolOutput out = svc.importProgram("/tmp/whatever.bin", "/", true, true);
        assertInstanceOf(StatusOutput.class, out);
        assertTrue(out.toStructuredJson().contains("No active"));
    }

    @org.junit.jupiter.api.Test
    void importProgram_missingFile_returnsError() {
        PluginTool tool = mock(PluginTool.class);
        Project project = mock(Project.class);
        when(tool.getProject()).thenReturn(project);

        ProjectService svc = inlineService(tool);
        ToolOutput out = svc.importProgram("/no/such/file-xyz.bin", "/", true, true);
        assertInstanceOf(StatusOutput.class, out);
        assertTrue(out.toStructuredJson().contains("File not found"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=ProjectServiceTest`
Expected: FAIL — `importProgram` does not exist (compilation error).

- [ ] **Step 3: Implement `import_program`**

Add to `ProjectService.java` these imports:
```java
import java.io.File;
import com.lauriewired.mcp.model.response.ImportResult;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoadResults;
```

Add the tool method:

```java
    @McpTool(post = true, timeoutSeconds = 600, outputType = JsonOutput.class,
             responseType = ImportResult.class, description = """
        Import a file from the Ghidra host's filesystem into the current project.

        Ghidra auto-detects the format (ELF, PE, Mach-O, raw, etc.), imports the
        file into the given project folder, optionally runs auto-analysis, and
        optionally opens it as the current program (which auto-closes the program
        it replaced). Blocks until done; large binaries may take minutes.

        Returns: metadata for the imported program (name, project path, format,
        language, function count, analyzed flag, any additional programs, warning)

        Example: import_program("/samples/firmware.bin", "/imports", true, true) """)
    public ToolOutput importProgram(
            @Param(value = "Absolute path to the file on the Ghidra host") final String path,
            @Param(value = "Destination project folder", defaultValue = "/") final String folder,
            @Param(value = "Run auto-analysis after import", defaultValue = "true") final boolean analyze,
            @Param(value = "Open the imported program as current", defaultValue = "true") final boolean open) {
        final Project project = getProject();
        if (project == null) return StatusOutput.error("No active Ghidra project");
        if (path == null || path.isBlank()) return StatusOutput.error("path is required");

        final File file = new File(path);
        if (!file.isFile()) return StatusOutput.error("File not found or not a regular file: " + path);

        final String folderPath = (folder == null || folder.isBlank()) ? "/" : folder;
        final MessageLog log = new MessageLog();
        final Object consumer = this;

        try (LoadResults<Program> results =
                 AutoImporter.importByUsingBestGuess(file, project, folderPath, consumer, log, TaskMonitor.DUMMY)) {
            final Loaded<Program> primary = results.getPrimary();
            final Program program = primary.getDomainObject();

            final boolean analyzed = analyze;
            if (analyze) {
                runAnalysis(program);
            }
            results.save(TaskMonitor.DUMMY);
            final DomainFile savedFile = primary.getSavedDomainFile();

            String warning = null;
            if (open) {
                final ProgramManager pm = getProgramManager();
                if (pm != null) {
                    final String[] warningBox = new String[1];
                    runOnSwing(() -> {
                        final Program prev = pm.getCurrentProgram();
                        final Program opened = pm.openProgram(savedFile);
                        warningBox[0] = autoClosePrevious(pm, prev, opened);
                        return null;
                    });
                    warning = warningBox[0];
                }
            }

            final List<String> extras = new ArrayList<>();
            for (final Loaded<Program> other : results.getNonPrimary()) {
                extras.add(other.getName());
            }

            return new JsonOutput(new ImportResult(
                program.getName(),
                savedFile.getPathname(),
                program.getExecutableFormat(),
                program.getLanguageID().toString(),
                program.getFunctionManager().getFunctionCount(),
                analyzed,
                extras,
                warning));
        } catch (Exception e) {
            return StatusOutput.error("Import failed: " + e.getMessage());
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn test -Dtest=ProjectServiceTest`
Expected: PASS — both `importProgram` error-branch tests pass (plus all earlier tests). The happy path is covered by manual verification in Task 8.

- [ ] **Step 5: Full build + registry count**

Run: `mvn clean test`
Expected: PASS — entire suite green. If `ApiHandlerRegistryTest` asserts a tool count, it now includes all four new tools (`import_program`, `list_program_files`, `open_program`, `reanalyze_program`).

- [ ] **Step 6: Commit**

```bash
git add src/main/java/com/lauriewired/mcp/services/ProjectService.java src/test/java/com/lauriewired/mcp/services/ProjectServiceTest.java src/test/java/com/lauriewired/mcp/api/ApiHandlerRegistryTest.java
git commit -m "feat: add import_program (import + analyze + open with auto-close)"
```

---

## Task 8: End-to-end manual verification + docs

**Files:**
- Modify: `CLAUDE.md` (Service layer list — add `ProjectService`)
- No code changes; this task proves the un-mockable import/analysis path against a real Ghidra.

- [ ] **Step 1: Build and install the extension**

Run: `mvn clean package -DskipTests`
Expected: BUILD SUCCESS; a ZIP is produced under `target/`.

Then install into Ghidra (macOS helper): `./build_and_install.sh` — or install the ZIP via Ghidra's `File > Install Extensions`. Restart Ghidra and open a CodeBrowser tool with the GhidraMCP plugin enabled so the HTTP server is listening on `http://127.0.0.1:8080`.

- [ ] **Step 2: Verify the new tools appear in metadata**

Run: `curl -s http://127.0.0.1:8080/mcp/tools | python -m json.tool | grep -E '"name"|timeoutSeconds'`
Expected: `import_program`, `list_program_files`, `open_program`, `reanalyze_program` all present; `import_program` and `reanalyze_program` show `"timeoutSeconds": 600`.

- [ ] **Step 3: Import a real binary**

Pick a small local binary (e.g. `/bin/ls` on the Ghidra host, copied somewhere readable).

Run:
```bash
curl -s -X POST http://127.0.0.1:8080/import_program \
  -H 'Content-Type: application/json' \
  -d '{"path":"/bin/ls","folder":"/imports","analyze":true,"open":true}'
```
Expected: JSON envelope `status: success` with `data` containing the program name, `project_path` under `/imports`, a non-null `format`/`language_id`, `analyzed: true`, and a `function_count > 0`. In the Ghidra GUI, the imported program is now the current program in CodeBrowser.

- [ ] **Step 4: List, then verify existing tools operate on the import**

Run:
```bash
curl -s "http://127.0.0.1:8080/list_program_files?folder=/imports"
curl -s http://127.0.0.1:8080/get_program_info
```
Expected: `list_program_files` shows the imported file flagged `[open]`; `get_program_info` returns the imported program's metadata (confirming the whole existing tool suite now targets it).

- [ ] **Step 5: Verify auto-close on a second import**

Import a second binary with `open:true` and confirm via `list_program_files` that the first program is no longer flagged `[open]` (it was saved and closed), and no stale program accumulated. Then call `reanalyze_program` and confirm it returns updated counts without a client timeout (proves the 600s hint works through the bridge — run the bridge with default `--timeout` and drive it from an MCP client if verifying end-to-end).

- [ ] **Step 6: Update CLAUDE.md**

In `CLAUDE.md`, in the "Service layer" bullet list, add `ProjectService` — e.g. append to the services line:
`FunctionService, DataTypeService, AnalysisService, MemoryService, SearchService, VariableService, CommentService, NamespaceService, ProjectService` and add a short note: "`ProjectService` — import/list/open project files and (re-)run analysis via `tool.getProject()` + `ProgramManager`; switching the current program auto-closes (save-first) the one it replaced."

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document ProjectService in CLAUDE.md"
```

---

## Self-Review Notes

- **Spec coverage:** timeout hint (T1–T2), response records incl. `OpenProgramResult`/`ImportResult` warnings (T3), `list_program_files` (T4), `open_program` + safe auto-close with `ignoreChanges=false` (T5), `reanalyze_program` + shared analysis (T6), `import_program` with analyze/open defaults (T7), error handling as `StatusOutput.error` (T4–T7), threading via `runOnSwing` seam (T4–T7), honest test scope with manual import/analysis verification (T8). Out-of-scope items (delete/rename, standalone close, per-analyzer options, raw-bytes upload) are not implemented.
- **Naming consistency:** `runOnSwing`, `autoClosePrevious`, `runAnalysis`, `ProgramInfoResult.from`, `getTimeoutSeconds`, `timeoutSeconds` (JSON key + annotation element + bridge lookup) are used identically across tasks.
- **Known soft spot:** the `reanalyze` integration test and the entire real `import_program` happy path depend on a Ghidra install; both are gated/skipped in CI-without-Ghidra and covered by Task 8 manual verification. This is the honest boundary called out in the spec.
