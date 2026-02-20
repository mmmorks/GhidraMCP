package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataType;

/**
 * Unit tests for NamespaceService
 */
public class NamespaceServiceTest {

    private NamespaceService namespaceService;
    private ProgramService programService;

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        namespaceService = new NamespaceService(programService);
    }

    @Test
    @DisplayName("listLabels returns error when no program is loaded")
    void testListLabels_NoProgram() {
        String result = namespaceService.listLabels(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listLabels handles negative offset")
    void testListLabels_NegativeOffset() {
        String result = namespaceService.listLabels(-1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listLabels handles zero limit")
    void testListLabels_ZeroLimit() {
        String result = namespaceService.listLabels(0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress returns error when no program is loaded")
    void testGetSymbolAddress_NoProgram() {
        String result = namespaceService.getSymbolAddress("main").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress returns error for null symbol name")
    void testGetSymbolAddress_NullSymbolName() {
        String result = namespaceService.getSymbolAddress(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress returns error for empty symbol name")
    void testGetSymbolAddress_EmptySymbolName() {
        String result = namespaceService.getSymbolAddress("").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress handles valid symbol name")
    void testGetSymbolAddress_ValidSymbolName() {
        String result = namespaceService.getSymbolAddress("main").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress handles symbol with special characters")
    void testGetSymbolAddress_SpecialCharacters() {
        String result = namespaceService.getSymbolAddress("_start@plt").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new NamespaceService(null));
    }

    // -----------------------------------------------------------------------
    // ProgramBuilder-based happy-path tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("ProgramBuilder-based happy-path tests")
    class HappyPathTests {

        private static ProgramBuilder builder;
        private static NamespaceService svc;

        @BeforeAll
        static void setUp() throws Exception {
            GhidraTestEnv.initialize();

            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            builder.createEmptyFunction("main", "0x401000", 0x50, DataType.DEFAULT);
            builder.createLabel("0x401100", "my_label");

            ProgramDB program = builder.getProgram();
            ProgramService ps = GhidraTestEnv.programService(program);
            svc = new NamespaceService(ps);
        }

        @AfterAll
        static void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        @Test
        @DisplayName("listLabels returns labels but excludes function symbols")
        void testListLabels_Success() {
            ToolOutput result = svc.listLabels(0, 100);
            assertInstanceOf(ListOutput.class, result);

            String json = result.toStructuredJson();
            // my_label should be present (it's a label, not a function)
            assertTrue(json.contains("my_label"));
            // main is a function symbol and should be excluded
            assertFalse(json.contains("\"main\""));
        }

        @Test
        @DisplayName("listLabels respects offset and limit for pagination")
        void testListLabels_Pagination() {
            // Get all labels first to know total count
            ToolOutput allResult = svc.listLabels(0, 100);
            assertInstanceOf(ListOutput.class, allResult);
            ListOutput allOutput = (ListOutput) allResult;
            int totalItems = allOutput.totalItems();
            assertTrue(totalItems >= 1, "Should have at least 1 label (my_label)");

            // Request only 1 item at offset 0
            ToolOutput page1 = svc.listLabels(0, 1);
            assertInstanceOf(ListOutput.class, page1);
            ListOutput page1Output = (ListOutput) page1;
            assertTrue(page1Output.items().size() == 1, "Page should contain exactly 1 item");
        }

        @Test
        @DisplayName("getSymbolAddress finds a function symbol by name")
        void testGetSymbolAddress_FunctionSymbol() {
            ToolOutput result = svc.getSymbolAddress("main");
            assertInstanceOf(JsonOutput.class, result);

            String json = result.toStructuredJson();
            assertTrue(json.contains("main"));
            assertTrue(json.contains("00401000"));
        }

        @Test
        @DisplayName("getSymbolAddress finds a label symbol by name")
        void testGetSymbolAddress_LabelSymbol() {
            ToolOutput result = svc.getSymbolAddress("my_label");
            assertInstanceOf(JsonOutput.class, result);

            String json = result.toStructuredJson();
            assertTrue(json.contains("my_label"));
            assertTrue(json.contains("00401100"));
        }

        @Test
        @DisplayName("getSymbolAddress returns error for nonexistent symbol")
        void testGetSymbolAddress_NotFound() {
            ToolOutput result = svc.getSymbolAddress("nonexistent_symbol");
            assertInstanceOf(StatusOutput.class, result);
            assertTrue(result.toStructuredJson().contains("Symbol not found"));
        }
    }
}
