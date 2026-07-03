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
