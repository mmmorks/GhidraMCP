package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
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
import com.lauriewired.mcp.model.response.FunctionCodeResult;
import com.lauriewired.mcp.model.response.RenameVariablesResult;
import com.lauriewired.mcp.model.response.SetVariableTypesResult;
import com.lauriewired.mcp.model.response.SplitVariableResult;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

/**
 * Unit tests for VariableService
 */
public class VariableServiceTest {

    private VariableService variableService;
    private ProgramService programService;
    private FunctionService functionService;

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        functionService = new FunctionService(null, programService);
        variableService = new VariableService(programService, functionService);
    }

    @Test
    @DisplayName("splitVariable returns error when no program is loaded")
    void testSplitVariable_NoProgram() {
        String result = variableService.splitVariable("main", "oldVar", "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for null function name")
    void testSplitVariable_NullFunctionName() {
        String result = variableService.splitVariable(null, "oldVar", "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for empty function name")
    void testSplitVariable_EmptyFunctionName() {
        String result = variableService.splitVariable("", "oldVar", "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for null variable name")
    void testSplitVariable_NullVariableName() {
        String result = variableService.splitVariable("main", null, "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for empty variable name")
    void testSplitVariable_EmptyVariableName() {
        String result = variableService.splitVariable("main", "", "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for null new name (uses default)")
    void testSplitVariable_NullNewName() {
        String result = variableService.splitVariable("main", "oldVar", "00401000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for empty new name (uses default)")
    void testSplitVariable_EmptyNewName() {
        String result = variableService.splitVariable("main", "oldVar", "00401000", "").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable handles usage address")
    void testSplitVariable_WithUsageAddress() {
        String result = variableService.splitVariable("main", "oldVar", "0x1000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable handles invalid usage address")
    void testSplitVariable_InvalidUsageAddress() {
        String result = variableService.splitVariable("main", "oldVar", "invalid", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns JSON response format")
    void testSplitVariable_ResponseFormat() {
        String result = variableService.splitVariable("main", "oldVar", "00401000", "newVar").toStructuredJson();
        // Even with no program loaded, we should get a proper error message
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    // ===== Tests for renameVariables =====

    @Test
    @DisplayName("renameVariables returns error when no program is loaded")
    void testRenameVariables_NoProgram() {
        String result = variableService.renameVariables("main",
            java.util.Map.of("local_10", "buffer_size")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameVariables returns error for null renames")
    void testRenameVariables_NullRenames() {
        String result = variableService.renameVariables("main", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameVariables returns error for empty renames")
    void testRenameVariables_EmptyRenames() {
        String result = variableService.renameVariables("main", java.util.Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null services without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new VariableService(null, null));
    }

    // ===== Tests for setVariableTypes =====

    @Test
    @DisplayName("setVariableTypes returns error when no program is loaded")
    void testSetVariableTypes_NoProgram() {
        String result = variableService.setVariableTypes("0x1000",
            java.util.Map.of("local_10", "int")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("setVariableTypes returns error for null function identifier")
    void testSetVariableTypes_NullIdentifier() {
        String result = variableService.setVariableTypes(null,
            java.util.Map.of("local_10", "int")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setVariableTypes returns error for empty function identifier")
    void testSetVariableTypes_EmptyIdentifier() {
        String result = variableService.setVariableTypes("",
            java.util.Map.of("local_10", "int")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setVariableTypes returns error for null types map")
    void testSetVariableTypes_NullTypes() {
        String result = variableService.setVariableTypes("0x1000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No variable types specified\""));
    }

    @Test
    @DisplayName("setVariableTypes returns error for empty types map")
    void testSetVariableTypes_EmptyTypes() {
        String result = variableService.setVariableTypes("0x1000", java.util.Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No variable types specified\""));
    }

    // ===== ProgramBuilder-based integration tests =====

    @Nested
    @DisplayName("ProgramBuilder integration tests")
    class ProgramBuilderIntegrationTest {

        private ProgramBuilder builder;
        private ProgramDB program;
        private VariableService svc;
        private FunctionService fs;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @BeforeEach
        void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x2000);

            // Helper at 0x401200: writes 0x10 through pointer in $a0 (Pattern B)
            // Unique address avoids decompiler cache collisions with other test classes
            builder.setBytes("0x401200", "34 02 00 10 AC 82 00 00 03 E0 00 08 00 00 00 00", true);
            builder.createFunction("0x401200");

            // Function at 0x401000 with local variable whose address escapes via call (Pattern E)
            // Stores 0x42 to local, passes &local to helper at 0x401200, reads local back
            builder.setBytes("0x401000",
                "27 BD FF F0 AF BF 00 0C 34 02 00 42 AF A2 00 00 27 A4 00 00 0C 10 04 80 00 00 00 00 8F A2 00 00 8F BF 00 0C 27 BD 00 10 03 E0 00 08 00 00 00 00",
                true);
            builder.createFunction("0x401000");

            program = builder.getProgram();

            // Set helper's prototype to take a pointer param so the decompiler
            // recognizes the pointer escape and preserves the local variable
            int tx = program.startTransaction("set helper prototype");
            try {
                Function helperFunc = program.getFunctionManager()
                    .getFunctionAt(builder.addr("0x401200"));
                if (helperFunc != null) {
                    helperFunc.addParameter(
                        new ParameterImpl("ptr",
                            new PointerDataType(IntegerDataType.dataType), program),
                        SourceType.ANALYSIS);
                }
            } finally {
                program.endTransaction(tx, true);
            }

            ProgramService ps = GhidraTestEnv.programService(program);
            fs = new FunctionService(null, ps);
            svc = new VariableService(ps, fs);
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        // --- renameVariables validation with real program ---

        @Test
        @DisplayName("renameVariables returns error for null renames with loaded program")
        void testRenameVariables_NullRenames_ProgramLoaded() {
            String result = svc.renameVariables("main", null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No renames specified\""),
                    "Should return 'No renames specified' with loaded program, got: " + result);
        }

        @Test
        @DisplayName("renameVariables returns error for empty renames with loaded program")
        void testRenameVariables_EmptyRenames_ProgramLoaded() {
            String result = svc.renameVariables("main", java.util.Map.of()).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No renames specified\""),
                    "Should return 'No renames specified' with loaded program, got: " + result);
        }

        @Test
        @DisplayName("renameVariables returns 'Function not found' for unknown function")
        void testRenameVariables_FunctionNotFound() {
            String result = svc.renameVariables("nonexistent",
                java.util.Map.of("local_10", "buffer")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function not found: nonexistent\""),
                    "Should return 'Function not found' error, got: " + result);
        }

        // --- setVariableTypes validation with real program ---

        @Test
        @DisplayName("setVariableTypes returns error for null identifier with loaded program")
        void testSetVariableTypes_NullIdentifier_ProgramLoaded() {
            // Validation happens before getCurrentProgram() is called
            String result = svc.setVariableTypes(null, java.util.Map.of("x", "int")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function identifier is required\""),
                    "Should return 'Function identifier is required', got: " + result);
        }

        @Test
        @DisplayName("setVariableTypes returns error for empty identifier with loaded program")
        void testSetVariableTypes_EmptyIdentifier_ProgramLoaded() {
            String result = svc.setVariableTypes("", java.util.Map.of("x", "int")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function identifier is required\""),
                    "Should return 'Function identifier is required', got: " + result);
        }

        @Test
        @DisplayName("setVariableTypes returns error for null types with loaded program")
        void testSetVariableTypes_NullTypes_ProgramLoaded() {
            String result = svc.setVariableTypes("main", null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No variable types specified\""),
                    "Should return 'No variable types specified', got: " + result);
        }

        @Test
        @DisplayName("setVariableTypes returns error for empty types with loaded program")
        void testSetVariableTypes_EmptyTypes_ProgramLoaded() {
            String result = svc.setVariableTypes("main", java.util.Map.of()).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No variable types specified\""),
                    "Should return 'No variable types specified', got: " + result);
        }

        @Test
        @DisplayName("setVariableTypes returns 'Function not found' for unknown function")
        void testSetVariableTypes_FunctionNotFound() {
            String result = svc.setVariableTypes("nonexistent",
                java.util.Map.of("local_10", "int")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function not found: nonexistent\""),
                    "Should return 'Function not found' error, got: " + result);
        }

        // --- Decompilation integration tests ---

        /** Discover a local_ or param_ variable name from decompiled C output. */
        private String discoverVariable() {
            ToolOutput code = fs.getFunctionCode("0x401000", "C");
            assertInstanceOf(JsonOutput.class, code);
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) code).data();
            String allCode = data.lines().stream()
                .flatMap(line -> line.values().stream())
                .reduce("", (a, b) -> a + " " + b);
            // Try local_ first, fall back to param_
            Matcher m = Pattern.compile("(local|param|[a-z]+Stack)_\\w+").matcher(allCode);
            assertTrue(m.find(), "Decompiled C should contain a decompiler-assigned variable, got: " + allCode);
            return m.group();
        }

        /** Find the first C code line with a non-empty address key. */
        private String discoverUsageAddress() {
            ToolOutput code = fs.getFunctionCode("0x401000", "C");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) code).data();
            return data.lines().stream()
                .flatMap(line -> line.keySet().stream())
                .filter(key -> !key.isEmpty())
                .findFirst()
                .orElseThrow(() -> new AssertionError("No addressed C line found"));
        }

        @Test
        @DisplayName("renameVariables renames a discovered variable")
        void testRenameVariables_Success() {
            String varName = discoverVariable();

            ToolOutput result = svc.renameVariables("0x401000", Map.of(varName, "my_counter"));
            assertInstanceOf(JsonOutput.class, result);

            RenameVariablesResult data = (RenameVariablesResult) ((JsonOutput) result).data();
            assertNotNull(data.status());
            assertEquals(1, data.count());
            assertEquals("my_counter", data.renamed().get(varName));
        }

        @Test
        @DisplayName("renameVariables returns error for nonexistent variable")
        void testRenameVariables_VariableNotFound() {
            String json = svc.renameVariables("0x401000",
                Map.of("nonexistent_var_xyz", "new_name")).toStructuredJson();
            assertTrue(json.contains("Variable not found"),
                "Should report variable not found, got: " + json);
        }

        @Test
        @DisplayName("setVariableTypes sets type on a discovered variable")
        void testSetVariableTypes_Success() {
            String varName = discoverVariable();

            ToolOutput result = svc.setVariableTypes("0x401000", Map.of(varName, "int"));
            assertInstanceOf(JsonOutput.class, result);

            SetVariableTypesResult data = (SetVariableTypesResult) ((JsonOutput) result).data();
            assertNotNull(data.status());
            assertEquals(1, data.count());
            assertEquals("int", data.applied().get(varName));
        }

        @Test
        @DisplayName("setVariableTypes returns error for invalid type name")
        void testSetVariableTypes_InvalidType() {
            String varName = discoverVariable();

            String json = svc.setVariableTypes("0x401000",
                Map.of(varName, "NonExistentType12345")).toStructuredJson();
            assertTrue(json.contains("Could not resolve data type"),
                "Should report unresolvable type, got: " + json);
        }

        @Test
        @DisplayName("splitVariable splits a discovered variable at a usage address")
        void testSplitVariable_Success() {
            String varName = discoverVariable();
            String usageAddr = discoverUsageAddress();

            ToolOutput result = svc.splitVariable("0x401000", varName, usageAddr, "split_var");
            assertInstanceOf(JsonOutput.class, result);

            SplitVariableResult data = (SplitVariableResult) ((JsonOutput) result).data();
            assertNotNull(data.status());
            assertNotNull(data.variables());
            assertNotNull(data.decompiledLines());
        }

        @Test
        @DisplayName("splitVariable returns error for nonexistent variable")
        void testSplitVariable_VariableNotFound() {
            String json = svc.splitVariable("0x401000", "nonexistent_var_xyz", "0x401000", "new_name")
                .toStructuredJson();
            assertTrue(json.contains("Variable not found"),
                "Should report variable not found, got: " + json);
        }
    }

    // ===== SplitVariableResult output format tests =====

    @Nested
    class SplitVariableResultTests {

        @Test
        @DisplayName("SplitVariableResult JSON contains decompiledLines as address-keyed maps")
        void testResultJson_DecompiledLines() {
            var result = new SplitVariableResult(
                "Variable split and renamed",
                "local_10",
                "loop_counter",
                "00401050",
                List.of(new SplitVariableResult.VarInfo("loop_counter", "int", "Stack[-0x10]")),
                List.of(
                    FunctionCodeResult.line(null, "void main(void) {"),
                    FunctionCodeResult.line("00401040", "  int loop_counter;"),
                    FunctionCodeResult.line("00401050", "  loop_counter = 0;"),
                    FunctionCodeResult.line(null, "}")
                ));

            var output = new JsonOutput(result);
            String json = output.toStructuredJson();

            assertTrue(json.contains("\"decompiled_lines\""));
            assertTrue(json.contains("\"\":\"void main(void) {\""));
            assertTrue(json.contains("\"00401040\":\"  int loop_counter;\""));
            assertTrue(json.contains("\"00401050\":\"  loop_counter = 0;\""));
            assertTrue(json.contains("\"\":\"}\""));
        }

        @Test
        @DisplayName("SplitVariableResult displayText renders decompiled lines")
        void testResultDisplayText_DecompiledLines() {
            var result = new SplitVariableResult(
                "Variable split and renamed",
                "local_10",
                "counter",
                "00401050",
                List.of(new SplitVariableResult.VarInfo("counter", "int", null)),
                List.of(
                    FunctionCodeResult.line(null, "void main(void) {"),
                    FunctionCodeResult.line("00401050", "  counter = 0;"),
                    FunctionCodeResult.line(null, "}")
                ));

            String display = result.toDisplayText();

            assertTrue(display.contains("Variable split and renamed"));
            assertTrue(display.contains("Original: local_10"));
            assertTrue(display.contains("New: counter"));
            assertTrue(display.contains("Split address: 00401050"));
            assertTrue(display.contains("\nDecompiled:\n"));
            assertTrue(display.contains("void main(void) {\n"));
            assertTrue(display.contains("00401050:   counter = 0;\n"));
            assertTrue(display.contains("}\n"));
        }

        @Test
        @DisplayName("SplitVariableResult handles null decompiledLines")
        void testResultDisplayText_NullDecompiledLines() {
            var result = new SplitVariableResult(
                "Variable split and renamed",
                "local_10",
                "counter",
                null,
                null,
                null);

            String display = result.toDisplayText();
            assertTrue(display.contains("Variable split and renamed"));
            assertNull(result.decompiledLines());
            assertNull(result.variables());
        }

        @Test
        @DisplayName("SplitVariableResult handles empty decompiledLines")
        void testResultDisplayText_EmptyDecompiledLines() {
            var result = new SplitVariableResult(
                "Variable split and renamed",
                "local_10",
                "counter",
                "00401050",
                List.of(),
                List.of());

            String display = result.toDisplayText();
            assertTrue(display.contains("Variable split and renamed"));
            // No "Decompiled:" section when empty
            assertTrue(!display.contains("Decompiled:"));
            // No "Variables:" section when empty
            assertTrue(!display.contains("Variables:"));
        }

        @Test
        @DisplayName("SplitVariableResult JSON includes all fields")
        void testResultJson_AllFields() {
            var result = new SplitVariableResult(
                "Variable split and renamed",
                "local_10",
                "loop_counter",
                "00401050",
                List.of(
                    new SplitVariableResult.VarInfo("loop_counter", "int", "Stack[-0x10]"),
                    new SplitVariableResult.VarInfo("local_14", "undefined4", null)),
                List.of(FunctionCodeResult.line("00401050", "  loop_counter = 0;")));

            var output = new JsonOutput(result);
            String json = output.toStructuredJson();

            assertTrue(json.contains("\"status\":\"Variable split and renamed\""));
            assertTrue(json.contains("\"original_variable\":\"local_10\""));
            assertTrue(json.contains("\"new_variable\":\"loop_counter\""));
            assertTrue(json.contains("\"split_address\":\"00401050\""));
            assertTrue(json.contains("\"name\":\"loop_counter\""));
            assertTrue(json.contains("\"data_type\":\"int\""));
            assertTrue(json.contains("\"storage\":\"Stack[-0x10]\""));
            assertTrue(json.contains("\"name\":\"local_14\""));
            // null storage should be omitted (NON_NULL)
            assertTrue(!json.contains("\"storage\":null"));
        }

        @Test
        @DisplayName("SplitVariableResult displayText shows variables with storage")
        void testResultDisplayText_VariablesWithStorage() {
            var result = new SplitVariableResult(
                "Variable split and renamed",
                "local_10",
                "counter",
                null,
                List.of(
                    new SplitVariableResult.VarInfo("counter", "int", "EAX"),
                    new SplitVariableResult.VarInfo("local_14", "long", null)),
                null);

            String display = result.toDisplayText();
            assertTrue(display.contains("counter: int (EAX)"));
            assertTrue(display.contains("local_14: long\n"));
            // No split address line when null
            assertTrue(!display.contains("Split address:"));
        }
    }
}
