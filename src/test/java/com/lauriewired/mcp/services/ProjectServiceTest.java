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
}
