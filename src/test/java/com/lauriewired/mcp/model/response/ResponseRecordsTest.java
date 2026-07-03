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
