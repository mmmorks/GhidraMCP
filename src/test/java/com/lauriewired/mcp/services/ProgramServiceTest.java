package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

/**
 * Tests for ProgramService
 */
public class ProgramServiceTest {

    // --- Null-tool tests (no Ghidra needed) ---

    @Test
    @DisplayName("getCurrentProgram returns null when tool is null")
    void testGetCurrentProgram_NullTool() {
        ProgramService service = new ProgramService(null);
        assertNull(service.getCurrentProgram());
    }

    @Test
    @DisplayName("getProgramInfo returns error when no program loaded")
    void testGetProgramInfo_NoProgram() {
        ProgramService service = new ProgramService(null);
        String result = service.getProgramInfo().toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    // --- ProgramBuilder integration test ---

    @Nested
    @DisplayName("ProgramBuilder-based getProgramInfo test")
    class GetProgramInfoIntegrationTest {

        private static ProgramBuilder builder;
        private static ProgramService ps;

        @BeforeAll
        static void setUp() throws Exception {
            GhidraTestEnv.initialize();

            builder = new ProgramBuilder("testBinary", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            builder.createEmptyFunction("main", "0x401000", 0x50, ghidra.program.model.data.DataType.DEFAULT);
            builder.createEmptyFunction("helper", "0x401100", 0x30, ghidra.program.model.data.DataType.DEFAULT);
            builder.createLabel("0x401200", "my_label");

            ProgramDB program = builder.getProgram();
            ps = GhidraTestEnv.programService(program);
        }

        @AfterAll
        static void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        @Test
        @DisplayName("getProgramInfo returns full program details")
        void testGetProgramInfo_Success() {
            com.lauriewired.mcp.model.ToolOutput result = ps.getProgramInfo();
            assertInstanceOf(com.lauriewired.mcp.model.JsonOutput.class, result);

            com.lauriewired.mcp.model.response.ProgramInfoResult info =
                (com.lauriewired.mcp.model.response.ProgramInfoResult) ((com.lauriewired.mcp.model.JsonOutput) result).data();

            assertEquals("testBinary", info.name());
            assertEquals("MIPS", info.processor());
            assertTrue(info.architecture().contains("MIPS"));
            assertTrue(info.endian().equalsIgnoreCase("big"));
            assertEquals(32, info.addressSize());
            assertEquals(2, info.functionCount());
            assertTrue(info.symbolCount() >= 3); // at least main, helper, my_label
            assertNotNull(info.imageBase());
            assertNotNull(info.minAddress());
            assertNotNull(info.maxAddress());
        }
    }
}
