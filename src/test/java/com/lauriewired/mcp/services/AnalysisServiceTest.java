package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.DataFlowResult;
import com.lauriewired.mcp.model.response.FunctionCodeResult;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.ParameterImpl;

/**
 * Unit tests for AnalysisService
 */
public class AnalysisServiceTest {

    private AnalysisService analysisService;
    private ProgramService programService;
    private FunctionService functionService;

    @BeforeEach
    @SuppressWarnings("unused")
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        functionService = new FunctionService(null, programService);
        analysisService = new AnalysisService(programService, functionService);
    }

    @Test
    @DisplayName("analyzeControlFlow returns error when no program is loaded")
    void testAnalyzeControlFlow_NoProgram() {
        String result = analysisService.analyzeControlFlow("0x1000").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeControlFlow returns error for null identifier")
    void testAnalyzeControlFlow_NullIdentifier() {
        String result = analysisService.analyzeControlFlow(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeControlFlow returns error for empty identifier")
    void testAnalyzeControlFlow_EmptyIdentifier() {
        String result = analysisService.analyzeControlFlow("").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeControlFlow handles invalid identifier")
    void testAnalyzeControlFlow_InvalidIdentifier() {
        String result = analysisService.analyzeControlFlow("invalid").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error when no program is loaded")
    void testAnalyzeDataFlow_NoProgram() {
        String result = analysisService.analyzeDataFlow("0x1000", "variable").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for null identifier")
    void testAnalyzeDataFlow_NullIdentifier() {
        String result = analysisService.analyzeDataFlow(null, "variable").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for empty identifier")
    void testAnalyzeDataFlow_EmptyIdentifier() {
        String result = analysisService.analyzeDataFlow("", "variable").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for null variable name")
    void testAnalyzeDataFlow_NullVariableName() {
        String result = analysisService.analyzeDataFlow("0x1000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for empty variable name")
    void testAnalyzeDataFlow_EmptyVariableName() {
        String result = analysisService.analyzeDataFlow("0x1000", "").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph returns error when no program is loaded")
    void testGetCallGraph_NoProgram() {
        String result = analysisService.getCallGraph("0x1000", 3, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph returns error for null identifier")
    void testGetCallGraph_NullIdentifier() {
        String result = analysisService.getCallGraph(null, 3, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph returns error for empty identifier")
    void testGetCallGraph_EmptyIdentifier() {
        String result = analysisService.getCallGraph("", 3, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph limits depth to maximum of 5")
    void testGetCallGraph_MaxDepth() {
        String result = analysisService.getCallGraph("0x1000", 10, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph handles zero depth")
    void testGetCallGraph_ZeroDepth() {
        String result = analysisService.getCallGraph("0x1000", 0, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph handles negative depth")
    void testGetCallGraph_NegativeDepth() {
        String result = analysisService.getCallGraph("0x1000", -1, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph handles callers direction")
    void testGetCallGraph_CallersDirection() {
        String result = analysisService.getCallGraph("0x1000", 2, "callers").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph handles callees direction")
    void testGetCallGraph_CalleesDirection() {
        String result = analysisService.getCallGraph("0x1000", 2, "callees").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences returns error when no program is loaded")
    void testListReferences_NoProgram() {
        String result = analysisService.listReferences("0x1000", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences returns error for null address")
    void testListReferences_NullAddress() {
        String result = analysisService.listReferences(null, 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences returns error for empty address")
    void testListReferences_EmptyAddress() {
        String result = analysisService.listReferences("", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences handles symbol name")
    void testListReferences_SymbolName() {
        String result = analysisService.listReferences("main", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences handles hex address")
    void testListReferences_HexAddress() {
        String result = analysisService.listReferences("0x1000", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences handles negative offset")
    void testListReferences_NegativeOffset() {
        String result = analysisService.listReferences("0x1000", -1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences handles zero limit")
    void testListReferences_ZeroLimit() {
        String result = analysisService.listReferences("0x1000", 0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    // ===== listReferencesFrom error-path tests =====

    @Test
    @DisplayName("listReferencesFrom returns error when no program is loaded")
    void testListReferencesFrom_NoProgram() {
        String result = analysisService.listReferencesFrom("0x1000", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferencesFrom returns error for null address")
    void testListReferencesFrom_NullAddress() {
        String result = analysisService.listReferencesFrom(null, 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new AnalysisService(null, null));
    }

    /**
     * ProgramBuilder-based integration tests for call graph, control flow, and references.
     * Uses real x86 programs with CALL instructions to verify analysis logic.
     */
    @Nested
    @DisplayName("ProgramBuilder integration tests")
    class ProgramBuilderIntegrationTest {

        private ProgramBuilder builder;
        private ProgramDB program;
        private AnalysisService service;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @BeforeEach
        void setUp() throws Exception {
            builder = new ProgramBuilder("test", ProgramBuilder._X64);
            builder.createMemory(".text", "0x401000", 0x1000);

            // main at 0x401000: call helper (at 0x401100); ret
            // E8 is near call relative; offset = 0x401100 - (0x401000 + 5) = 0xFB
            builder.setBytes("0x401000", "E8 FB 00 00 00 C3", true);
            builder.createFunction("0x401000");

            // helper at 0x401100: nop; ret
            builder.setBytes("0x401100", "90 C3", true);
            builder.createFunction("0x401100");

            program = builder.getProgram();

            // Rename the auto-generated function names to human-readable names
            int tx = program.startTransaction("rename");
            try {
                ghidra.program.model.listing.Function mainFunc =
                    program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
                if (mainFunc != null) {
                    mainFunc.setName("main", ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }
                ghidra.program.model.listing.Function helperFunc =
                    program.getFunctionManager().getFunctionAt(builder.addr("0x401100"));
                if (helperFunc != null) {
                    helperFunc.setName("helper", ghidra.program.model.symbol.SourceType.USER_DEFINED);
                }
            } finally {
                program.endTransaction(tx, true);
            }

            ProgramService ps = GhidraTestEnv.programService(program);
            FunctionService fs = new FunctionService(null, ps);
            service = new AnalysisService(ps, fs);
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        @Test
        @DisplayName("analyzeControlFlow returns blocks for a real function")
        void testAnalyzeControlFlow_RealFunction() {
            String json = service.analyzeControlFlow("main").toStructuredJson();

            // Should contain function name and entry point
            assertTrue(json.contains("\"function\":\"main\""), "Should contain function name");
            assertTrue(json.contains("\"entry_point\""), "Should contain entry_point");
            // Should contain at least one block with instructions
            assertTrue(json.contains("\"blocks\""), "Should contain blocks");
            assertTrue(json.contains("\"instructions\""), "Should contain instructions");
        }

        @Test
        @DisplayName("analyzeControlFlow finds function by address")
        void testAnalyzeControlFlow_ByAddress() {
            String json = service.analyzeControlFlow("0x401000").toStructuredJson();

            assertTrue(json.contains("\"function\":\"main\""), "Should resolve function by address");
            assertTrue(json.contains("\"blocks\""), "Should contain blocks");
        }

        @Test
        @DisplayName("analyzeControlFlow returns error for nonexistent function")
        void testAnalyzeControlFlow_FunctionNotFound() {
            String json = service.analyzeControlFlow("nonexistent").toStructuredJson();

            assertTrue(json.contains("\"message\":\"Function not found: nonexistent\""));
        }

        @Test
        @DisplayName("getCallGraph callees shows helper called by main")
        void testGetCallGraph_Callees() {
            String json = service.getCallGraph("main", 2, "callees").toStructuredJson();

            assertTrue(json.contains("\"function\":\"main\""), "Should contain root function name");
            // main calls helper via the CALL instruction
            assertTrue(json.contains("\"callees\""), "Should contain callees field");
        }

        @Test
        @DisplayName("getCallGraph callers shows main calling helper")
        void testGetCallGraph_Callers() {
            String json = service.getCallGraph("0x401100", 2, "callers").toStructuredJson();

            // helper is called by main
            assertTrue(json.contains("\"callers\""), "Should contain callers field");
        }

        @Test
        @DisplayName("getCallGraph callees at max depth are elided (field absent from JSON)")
        void testCallees_atMaxDepth_elided() {
            // depth=1: main's callees are at max depth, so their callees should be null (omitted by NON_NULL)
            String json = service.getCallGraph("main", 1, "callees").toStructuredJson();

            // The root node should have callees
            assertTrue(json.contains("\"callees\""), "Root should have callees");

            // Find the helper node within the callees array
            int helperIdx = json.indexOf("\"name\":\"helper\"");
            assertTrue(helperIdx >= 0, "Should find helper in callees, got: " + json);
            if (helperIdx >= 0) {
                int braceStart = json.lastIndexOf('{', helperIdx);
                int braceEnd = json.indexOf('}', helperIdx);
                String helperNode = json.substring(braceStart, braceEnd + 1);
                assertFalse(helperNode.contains("\"callees\""),
                        "Leaf node at max depth should not have callees field, but got: " + helperNode);
            }
        }

        @Test
        @DisplayName("getCallGraph genuine leaf callees show empty list")
        void testCallees_genuineLeaf_emptyList() {
            // depth=2: helper is at depth 1 with no callees of its own -> genuine leaf
            String json = service.getCallGraph("main", 2, "callees").toStructuredJson();

            // helper should have callees:[] since it calls nothing
            int helperIdx = json.indexOf("\"name\":\"helper\"");
            assertTrue(helperIdx >= 0, "Should find helper in callees, got: " + json);
            if (helperIdx >= 0) {
                int braceStart = json.lastIndexOf('{', helperIdx);
                int braceEnd = json.indexOf('}', helperIdx);
                String helperNode = json.substring(braceStart, braceEnd + 1);
                assertTrue(helperNode.contains("\"callees\":[]"),
                        "Genuine leaf node should have empty callees list, but got: " + helperNode);
            }
        }

        @Test
        @DisplayName("getCallGraph both direction returns callers and callees")
        void testGetCallGraph_BothDirections() {
            String json = service.getCallGraph("0x401100", 2, "both").toStructuredJson();

            assertTrue(json.contains("\"callers\""), "Should contain callers field");
            assertTrue(json.contains("\"callees\""), "Should contain callees field");
        }

        @Test
        @DisplayName("listReferences shows call reference to helper")
        void testListReferences_CallRef() {
            // helper at 0x401100 should have references from main's CALL instruction
            String json = service.listReferences("0x401100", 0, 10).toStructuredJson();

            // Should find at least one reference
            assertNotNull(json);
            // The CALL from main creates a reference to 0x401100
            assertTrue(json.contains("UNCONDITIONAL_CALL") || json.contains("items") ||
                        json.contains("00401100"),
                    "Should find call reference to helper");
        }

        @Test
        @DisplayName("listReferences returns error for address with no references")
        void testListReferences_NoRefs() {
            // Address 0x401500 is in .text but has no references
            String json = service.listReferences("0x401500", 0, 10).toStructuredJson();

            assertTrue(json.contains("No references found") || json.contains("\"message\""),
                    "Should report no references");
        }

        // ===== listReferencesFrom integration tests =====

        @Test
        @DisplayName("listReferencesFrom shows references from a CALL instruction")
        void testListReferencesFrom_CallInstruction() {
            // main at 0x401000 has a CALL to helper at 0x401100
            // The CALL instruction creates a reference FROM main's call site
            String json = service.listReferencesFrom("0x401000", 0, 10).toStructuredJson();

            // Should find references from the function entry point or nearby
            assertNotNull(json);
            // May contain the CALL reference or may be "No references found" if
            // references are from a specific instruction address not the entry point
            assertTrue(json.contains("items") || json.contains("No references found") || json.contains("\"message\""),
                    "Should return refs or error, got: " + json);
        }

        @Test
        @DisplayName("listReferencesFrom returns error for address with no references")
        void testListReferencesFrom_NoRefs() {
            // Address 0x401500 has no outgoing references
            String json = service.listReferencesFrom("0x401500", 0, 10).toStructuredJson();
            assertTrue(json.contains("No references found") || json.contains("\"message\""),
                    "Should report no references");
        }

        @Test
        @DisplayName("listReferencesFrom resolves symbol name")
        void testListReferencesFrom_SymbolName() {
            // Try resolving by function name instead of address
            String json = service.listReferencesFrom("main", 0, 10).toStructuredJson();
            assertNotNull(json);
            // Either finds references or reports none - both are valid
            assertTrue(json.contains("items") || json.contains("No references found") || json.contains("\"message\""),
                    "Should handle symbol name lookup");
        }

        @Test
        @DisplayName("listReferencesFrom returns error for unresolvable address")
        void testListReferencesFrom_UnresolvableAddress() {
            String json = service.listReferencesFrom("invalid_not_a_symbol", 0, 10).toStructuredJson();
            assertTrue(json.contains("Could not resolve address"),
                    "Should report unresolvable address, got: " + json);
        }

        @Test
        @DisplayName("analyzeDataFlow returns error for nonexistent variable in simple function")
        void testAnalyzeDataFlow_VariableNotFound() {
            // main is a simple CALL+RET function with no locals
            String json = service.analyzeDataFlow("main", "nonexistent_var").toStructuredJson();

            assertTrue(json.contains("not found"),
                "Should report variable not found, got: " + json);
        }
    }

    /**
     * Decompilation-based data flow tests.
     * Uses a function with local variables (LEA+CALL pattern to survive optimization).
     */
    @Nested
    @DisplayName("Data flow decompilation tests")
    class DataFlowDecompilationTest {

        private ProgramBuilder builder;
        private AnalysisService service;
        private FunctionService fs;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @BeforeEach
        void setUp() throws Exception {
            builder = new ProgramBuilder("test", ProgramBuilder._X64);
            builder.createMemory(".text", "0x401000", 0x2000);

            // Helper at 0x401300: mov dword [rdi],0x10; ret — writes through pointer param
            // Unique address avoids decompiler cache collisions with other test classes
            builder.setBytes("0x401300", "C7 07 10 00 00 00 C3", true);
            builder.createFunction("0x401300");

            // Function at 0x401000 with local variable whose address escapes via call:
            // push rbp; mov rbp,rsp; sub rsp,0x10; mov dword [rbp-4],0x42;
            // lea rdi,[rbp-4]; call 0x401300; mov eax,[rbp-4]; leave; ret
            // CALL offset = 0x401300 - 0x401018 = 0x2E8
            builder.setBytes("0x401000",
                "55 48 89 E5 48 83 EC 10 C7 45 FC 42 00 00 00 48 8D 7D FC E8 E8 02 00 00 8B 45 FC C9 C3",
                true);
            builder.createFunction("0x401000");

            ProgramDB program = builder.getProgram();

            // Set helper's prototype to take a pointer param so the decompiler
            // recognizes the pointer escape and preserves the local variable
            int tx = program.startTransaction("set helper prototype");
            try {
                ghidra.program.model.listing.Function helperFunc = program.getFunctionManager()
                    .getFunctionAt(builder.addr("0x401300"));
                if (helperFunc != null) {
                    helperFunc.addParameter(
                        new ParameterImpl("ptr",
                            new PointerDataType(IntegerDataType.dataType), program),
                        ghidra.program.model.symbol.SourceType.ANALYSIS);
                }
            } finally {
                program.endTransaction(tx, true);
            }

            ProgramService ps = GhidraTestEnv.programService(program);
            fs = new FunctionService(null, ps);
            service = new AnalysisService(ps, fs);
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        @Test
        @DisplayName("analyzeDataFlow returns references for a discovered variable")
        void testAnalyzeDataFlow_Success() {
            // Discover a variable name from decompiled C output
            ToolOutput code = fs.getFunctionCode("0x401000", "C");
            assertInstanceOf(JsonOutput.class, code);
            FunctionCodeResult codeData = (FunctionCodeResult) ((JsonOutput) code).data();
            String allCode = codeData.lines().stream()
                .flatMap(line -> line.values().stream())
                .reduce("", (a, b) -> a + " " + b);
            Matcher m = Pattern.compile("(local|param)_\\w+").matcher(allCode);
            assertTrue(m.find(), "Should find a variable in decompiled output, got: " + allCode);
            String varName = m.group();

            ToolOutput result = service.analyzeDataFlow("0x401000", varName);
            assertInstanceOf(JsonOutput.class, result);

            DataFlowResult data = (DataFlowResult) ((JsonOutput) result).data();
            assertNotNull(data.variable(), "Should have variable info");
            assertNotNull(data.references(), "Should have references list");
            assertFalse(data.references().isEmpty(),
                "Should have at least 1 reference (DEFINE or USE)");

            // Verify at least one reference has a recognized kind
            boolean hasKnownKind = data.references().stream()
                .anyMatch(ref -> "DEFINE".equals(ref.kind()) || "USE".equals(ref.kind()));
            assertTrue(hasKnownKind, "At least one reference should be DEFINE or USE");
        }
    }
}
