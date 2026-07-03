package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.OpenProgramResult;
import com.lauriewired.mcp.model.response.ProgramFileItem;
import com.lauriewired.mcp.model.response.ProgramInfoResult;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

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
    @SuppressWarnings("PMD.CloseResource")
    // `project` is the tool's shared active AutoCloseable Project (tool.getProject()); it is
    // not owned by this method and must never be closed here.
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

    @McpTool(post = true, outputType = JsonOutput.class, responseType = OpenProgramResult.class, description = """
        Open an already-imported project file and make it the current program.

        Switches the CodeBrowser to the given project file so all other tools
        operate on it. The previously-current program is auto-closed (saved
        first); if that save fails it is left open and a warning is returned.

        Returns: program metadata for the newly-current program (plus optional warning)

        Example: open_program("/imports/firmware.bin") """)
    @SuppressWarnings("PMD.CloseResource")
    // `project` is the tool's shared active AutoCloseable Project (tool.getProject()); it is
    // not owned by this method and must never be closed here.
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
}
