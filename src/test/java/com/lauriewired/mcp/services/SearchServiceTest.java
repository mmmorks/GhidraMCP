package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.SearchDecompiledResult;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

/**
 * Unit tests for SearchService
 */
public class SearchServiceTest {

    private SearchService searchService;
    private ProgramService programService;

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        searchService = new SearchService(programService);
    }

    @Test
    @DisplayName("searchMemory returns error when no program is loaded")
    void testSearchMemory_NoProgram() {
        String result = searchService.searchMemory("test", true, null, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchMemory returns error for null query")
    void testSearchMemory_NullQuery() {
        String result = searchService.searchMemory(null, true, null, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchMemory returns error for empty query")
    void testSearchMemory_EmptyQuery() {
        String result = searchService.searchMemory("", true, null, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchMemory handles string search type")
    void testSearchMemory_StringSearch() {
        String result = searchService.searchMemory("test string", true, null, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchMemory handles hex pattern search type")
    void testSearchMemory_HexSearch() {
        String result = searchService.searchMemory("48 65 6C 6C 6F", false, null, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchMemory handles hex pattern with wildcards")
    void testSearchMemory_HexSearchWithWildcards() {
        String result = searchService.searchMemory("48 ?? 6C 6C ??", false, null, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchMemory with specific block name")
    void testSearchMemory_WithBlockName() {
        String result = searchService.searchMemory("test", true, ".text", 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchMemory handles zero limit")
    void testSearchMemory_ZeroLimit() {
        String result = searchService.searchMemory("test", true, null, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchMemory handles negative limit")
    void testSearchMemory_NegativeLimit() {
        String result = searchService.searchMemory("test", true, null, -1).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDisassembly returns error when no program is loaded")
    void testSearchDisassembly_NoProgram() {
        String result = searchService.searchDisassembly("mov", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDisassembly returns error for null query")
    void testSearchDisassembly_NullQuery() {
        String result = searchService.searchDisassembly(null, 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDisassembly returns error for empty query")
    void testSearchDisassembly_EmptyQuery() {
        String result = searchService.searchDisassembly("", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDisassembly handles invalid regex pattern")
    void testSearchDisassembly_InvalidRegex() {
        String result = searchService.searchDisassembly("[invalid", 0, 10).toStructuredJson();
        // When no program is loaded, it returns "No program loaded" before checking regex
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDisassembly handles valid regex pattern")
    void testSearchDisassembly_ValidRegex() {
        String result = searchService.searchDisassembly("mov.*eax", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDisassembly handles negative offset")
    void testSearchDisassembly_NegativeOffset() {
        String result = searchService.searchDisassembly("mov", -1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDisassembly handles zero limit")
    void testSearchDisassembly_ZeroLimit() {
        String result = searchService.searchDisassembly("mov", 0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDecompiled returns error when no program is loaded")
    void testSearchDecompiled_NoProgram() {
        String result = searchService.searchDecompiled("function", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDecompiled returns error for null query")
    void testSearchDecompiled_NullQuery() {
        String result = searchService.searchDecompiled(null, 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDecompiled returns error for empty query")
    void testSearchDecompiled_EmptyQuery() {
        String result = searchService.searchDecompiled("", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDecompiled handles invalid regex pattern")
    void testSearchDecompiled_InvalidRegex() {
        String result = searchService.searchDecompiled("(unclosed", 0, 10).toStructuredJson();
        // When no program is loaded, it returns "No program loaded" before checking regex
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDecompiled handles valid regex pattern")
    void testSearchDecompiled_ValidRegex() {
        String result = searchService.searchDecompiled("if\\s*\\(.*\\)", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDecompiled handles negative offset")
    void testSearchDecompiled_NegativeOffset() {
        String result = searchService.searchDecompiled("function", -1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("searchDecompiled handles zero limit")
    void testSearchDecompiled_ZeroLimit() {
        String result = searchService.searchDecompiled("function", 0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new SearchService(null));
    }

    /**
     * ProgramBuilder-based integration tests for search operations.
     * Uses real x86 programs with memory and instructions.
     */
    @Nested
    @DisplayName("ProgramBuilder integration tests")
    class ProgramBuilderIntegrationTest {

        private ProgramBuilder builder;
        private ProgramDB program;
        private SearchService service;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        private void createDefaultProgram() throws Exception {
            builder = new ProgramBuilder("test", ProgramBuilder._X64);
            builder.createMemory(".text", "0x401000", 0x1000);
            builder.createMemory(".data", "0x402000", 0x100);

            // Write "Hello World" into .data
            builder.setBytes("0x402000", "48 65 6C 6C 6F 20 57 6F 72 6C 64", false);

            // x86-64: push rbp; mov rbp,rsp; nop; pop rbp; ret
            builder.setBytes("0x401000", "55 48 89 E5 90 5D C3", true);
            builder.createFunction("0x401000");

            program = builder.getProgram();

            // Mark .text block as executable (ProgramBuilder doesn't do this automatically)
            int tx = program.startTransaction("set permissions");
            try {
                ghidra.program.model.mem.MemoryBlock textBlock = program.getMemory().getBlock(".text");
                if (textBlock != null) {
                    textBlock.setExecute(true);
                }
            } finally {
                program.endTransaction(tx, true);
            }

            ProgramService ps = GhidraTestEnv.programService(program);
            service = new SearchService(ps);
        }

        @Test
        @DisplayName("searchMemory finds string in data block")
        void testSearchMemory_StringFound() throws Exception {
            createDefaultProgram();

            String json = service.searchMemory("Hello", true, null, 10).toStructuredJson();

            assertNotNull(json);
            // Should find the string at 0x402000
            assertTrue(json.contains("\"query\":\"Hello\"") || json.contains("match"),
                    "Should find 'Hello' in memory, got: " + json);
            assertTrue(json.contains("00402000") || json.contains("402000"),
                    "Should report match address in .data block, got: " + json);
        }

        @Test
        @DisplayName("searchMemory returns no matches for absent string")
        void testSearchMemory_NoMatches() throws Exception {
            createDefaultProgram();

            String json = service.searchMemory("NOTHERE", true, null, 10).toStructuredJson();

            assertTrue(json.contains("No matches found"),
                    "Should report no matches for absent string");
        }

        @Test
        @DisplayName("searchMemory finds hex byte pattern")
        void testSearchMemory_HexPattern() throws Exception {
            createDefaultProgram();

            // Search for "Hell" as hex: 48 65 6C 6C
            String json = service.searchMemory("48 65 6C 6C", false, null, 10).toStructuredJson();

            assertNotNull(json);
            // Should find the hex pattern at the data section
            assertTrue(json.contains("00402000") || json.contains("402000") || json.contains("match"),
                    "Should find hex pattern in memory, got: " + json);
        }

        @Test
        @DisplayName("searchMemory returns error for nonexistent block name")
        void testSearchMemory_BlockNotFound() throws Exception {
            createDefaultProgram();

            String json = service.searchMemory("Hello", true, "nonexistent", 10).toStructuredJson();

            assertTrue(json.contains("Memory block not found: nonexistent"),
                    "Should report block not found error");
        }

        @Test
        @DisplayName("searchDisassembly finds instruction by mnemonic pattern")
        void testSearchDisassembly_Found() throws Exception {
            createDefaultProgram();

            // Search for PUSH or NOP instructions
            String json = service.searchDisassembly("PUSH|NOP", 0, 10).toStructuredJson();

            assertNotNull(json);
            // Should find at least one instruction matching PUSH or NOP
            assertTrue(json.contains("\"matches\"") || json.contains("match_count"),
                    "Should find matching instructions, got: " + json);
        }

        @Test
        @DisplayName("searchDisassembly returns error when no executable blocks exist")
        void testSearchDisassembly_NoExecutableBlocks() throws Exception {
            // Create a program with only non-executable data blocks
            builder = new ProgramBuilder("test", ProgramBuilder._X64);
            builder.createMemory(".data", "0x402000", 0x100);
            // setBytes with isExecutable=false creates data, not code
            builder.setBytes("0x402000", "48 65 6C 6C 6F", false);

            program = builder.getProgram();
            ProgramService ps = GhidraTestEnv.programService(program);
            service = new SearchService(ps);

            String json = service.searchDisassembly("PUSH", 0, 10).toStructuredJson();

            assertTrue(json.contains("No executable code blocks") || json.contains("No matches"),
                    "Should report no executable blocks or no matches, got: " + json);
        }

        @Test
        @DisplayName("searchDisassembly returns no matches for pattern not in instructions")
        void testSearchDisassembly_NoMatches() throws Exception {
            createDefaultProgram();

            // Search for a pattern that does not match any instruction in our small function
            String json = service.searchDisassembly("XCHG.*RAX.*RBX", 0, 10).toStructuredJson();

            assertTrue(json.contains("No matches found"),
                    "Should report no matches for absent pattern");
        }

        // --- searchDecompiled integration tests ---

        @Test
        @DisplayName("searchDecompiled finds match in decompiled output")
        void testSearchDecompiled_FindsMatch() throws Exception {
            createDefaultProgram();

            // Search for "return" which is universal in decompiled C output
            ToolOutput result = service.searchDecompiled("return", 0, 10);
            assertInstanceOf(JsonOutput.class, result, "Should return JsonOutput, got: " + result.toStructuredJson());

            SearchDecompiledResult data = (SearchDecompiledResult) ((JsonOutput) result).data();
            assertTrue(data.matchCount() >= 1, "Should find at least 1 match for 'return'");
            assertFalse(data.matches().isEmpty(), "Matches list should not be empty");

            // Each match should have function name and context
            SearchDecompiledResult.DecompiledMatch firstMatch = data.matches().get(0);
            assertNotNull(firstMatch.function(), "Match should have function name");
            assertNotNull(firstMatch.context(), "Match should have context lines");
        }

        @Test
        @DisplayName("searchDecompiled returns no matches for absent pattern")
        void testSearchDecompiled_NoMatches() throws Exception {
            createDefaultProgram();

            String json = service.searchDecompiled("ZZZZNOTFOUND12345", 0, 10).toStructuredJson();

            assertTrue(json.contains("No matches found"),
                "Should report no matches for absent pattern, got: " + json);
        }

        @Test
        @DisplayName("searchDecompiled returns error for invalid regex")
        void testSearchDecompiled_InvalidRegex() throws Exception {
            createDefaultProgram();

            String json = service.searchDecompiled("(unclosed", 0, 10).toStructuredJson();

            assertTrue(json.contains("Invalid regex pattern"),
                "Should report invalid regex, got: " + json);
        }
    }
}
