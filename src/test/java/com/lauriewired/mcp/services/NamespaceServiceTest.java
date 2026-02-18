package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
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
    @DisplayName("listSymbols returns error when no program is loaded")
    void testListSymbols_NoProgram() {
        String result = namespaceService.listSymbols(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listSymbols handles negative offset")
    void testListSymbols_NegativeOffset() {
        String result = namespaceService.listSymbols(-1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listSymbols handles zero limit")
    void testListSymbols_ZeroLimit() {
        String result = namespaceService.listSymbols(0, 0).toStructuredJson();
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

        private ProgramBuilder builder;
        private NamespaceService svc;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @BeforeEach
        void setUp() throws Exception {
            builder = new ProgramBuilder("test", ProgramBuilder._X64);
            builder.createMemory(".text", "0x401000", 0x1000);
            builder.createEmptyFunction("main", "0x401000", 0x50, DataType.DEFAULT);
            builder.createLabel("0x401100", "my_label");

            ProgramDB program = builder.getProgram();
            ProgramService ps = GhidraTestEnv.programService(program);
            svc = new NamespaceService(ps);
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        @Test
        @DisplayName("listSymbols returns symbols including functions and labels")
        void testListSymbols_Success() {
            ToolOutput result = svc.listSymbols(0, 100);
            assertInstanceOf(ListOutput.class, result);

            String json = result.toStructuredJson();
            assertTrue(json.contains("main"));
            assertTrue(json.contains("my_label"));
        }

        @Test
        @DisplayName("listSymbols respects offset and limit for pagination")
        void testListSymbols_Pagination() {
            // Get all symbols first to know total count
            ToolOutput allResult = svc.listSymbols(0, 100);
            assertInstanceOf(ListOutput.class, allResult);
            ListOutput allOutput = (ListOutput) allResult;
            int totalItems = allOutput.totalItems();
            assertTrue(totalItems >= 2, "Should have at least 2 symbols (main + my_label)");

            // Request only 1 item at offset 0
            ToolOutput page1 = svc.listSymbols(0, 1);
            assertInstanceOf(ListOutput.class, page1);
            ListOutput page1Output = (ListOutput) page1;
            assertTrue(page1Output.items().size() == 1, "Page should contain exactly 1 item");
            assertTrue(page1Output.hasMore(), "Should have more pages");

            // Request 1 item at offset 1
            ToolOutput page2 = svc.listSymbols(1, 1);
            assertInstanceOf(ListOutput.class, page2);
            ListOutput page2Output = (ListOutput) page2;
            assertTrue(page2Output.items().size() == 1, "Second page should contain exactly 1 item");

            // The two pages should have different content
            assertFalse(page1Output.toStructuredJson().equals(page2Output.toStructuredJson()),
                "Different pages should have different content");
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
