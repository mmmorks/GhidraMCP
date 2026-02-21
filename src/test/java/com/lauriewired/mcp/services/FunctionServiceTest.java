package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.FunctionCodeResult;
import com.lauriewired.mcp.model.response.RenameFunctionsResult;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

/**
 * Integration tests for FunctionService using ProgramBuilder with real Ghidra programs.
 * Tests are grouped into @Nested classes that share ProgramBuilder instances to
 * minimize the overhead of creating/destroying programs.
 */
public class FunctionServiceTest {

    @BeforeAll
    static void initGhidra() {
        GhidraTestEnv.initialize();
    }

    private static FunctionService serviceFor(ProgramDB program) {
        ProgramService ps = GhidraTestEnv.programService(program);
        return new FunctionService(null, ps, new DataTypeService(ps));
    }

    private static FunctionService nullProgramService() {
        ProgramService ps = new ProgramService(null);
        return new FunctionService(null, ps, new DataTypeService(ps));
    }

    // ===== Tests that need no ProgramBuilder =====

    @Nested
    @DisplayName("No program loaded")
    class NoProgramTests {

        @Test
        @DisplayName("listFunctions returns error when no program is loaded")
        void testGetAllFunctionNames_NoProgram() {
            FunctionService service = nullProgramService();
            String result = service.listFunctions(0, 10).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("getFunctionCode returns error when no program is loaded")
        void testGetFunctionCode_NoProgram() {
            FunctionService service = nullProgramService();
            String result = service.getFunctionCode("testFunction", "C").toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("getFunctionCode returns error for null identifier")
        void testGetFunctionCode_NullIdentifier() {
            FunctionService service = nullProgramService();
            String result = service.getFunctionCode(null, "C").toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("renameFunctions returns error when no program is loaded")
        void testRenameFunctions_NoProgram() {
            FunctionService service = nullProgramService();
            String result = service.renameFunctions(Map.of("oldName", "newName")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("getCurrentAddress returns error when tool is null")
        void testGetCurrentAddress_NullTool() {
            FunctionService service = nullProgramService();
            String result = service.getCurrentAddress().toStructuredJson();
            assertTrue(result.contains("\"message\":\"No tool available\""));
        }

        @Test
        @DisplayName("getCurrentFunction returns error when tool is null")
        void testGetCurrentFunction_NullTool() {
            FunctionService service = nullProgramService();
            String result = service.getCurrentFunction().toStructuredJson();
            assertTrue(result.contains("\"message\":\"No tool available\""));
        }

        @Test
        @DisplayName("setFunctionPrototype returns error when no program loaded")
        void testSetFunctionPrototype_NoProgram() {
            FunctionService service = nullProgramService();
            String result = service.setFunctionPrototype("0x401000", "int test(void)").toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("Constructor accepts null tool without throwing")
        void testConstructor_NullTool() {
            assertDoesNotThrow(() -> new FunctionService(null, new ProgramService(null), null));
        }

        @Test
        @DisplayName("listFunctions handles null tool gracefully")
        void testGetAllFunctionNames_NullTool() {
            FunctionService service = nullProgramService();
            String result = service.listFunctions(0, 10).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("getFunctionCode defaults to C mode for null mode")
        void testGetFunctionCode_NullMode() {
            FunctionService service = nullProgramService();
            String result = service.getFunctionCode("main", null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("getFunctionCode accepts assembly mode alias 'asm'")
        void testGetFunctionCode_AsmAlias() {
            FunctionService service = nullProgramService();
            String result = service.getFunctionCode("main", "asm").toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("resolveFunction returns null for null program")
        void testResolveFunction_NullProgram() {
            FunctionService service = nullProgramService();
            assertNull(service.resolveFunction(null, "main"));
        }

        // --- FunctionCodeResult pure unit tests ---

        @Test
        @DisplayName("toDisplayText includes register assumptions header when present")
        void testFunctionCodeResult_DisplayTextWithAssumptions() {
            List<FunctionCodeResult.RegisterAssumption> assumptions = List.of(
                new FunctionCodeResult.RegisterAssumption("gp", "0x12000"),
                new FunctionCodeResult.RegisterAssumption("tp", "0x3000")
            );
            FunctionCodeResult result = new FunctionCodeResult("entry", "void entry(void)", "assembly", assumptions,
                List.of(FunctionCodeResult.line("00401000", "MOV r1, r2")));

            String display = result.toDisplayText();
            assertTrue(display.contains("Register Assumptions:"));
            assertTrue(display.contains("  assume gp = 0x12000"));
            assertTrue(display.contains("  assume tp = 0x3000"));
            assertTrue(display.contains("00401000: MOV r1, r2"));
        }

        @Test
        @DisplayName("toDisplayText omits register assumptions header when null")
        void testFunctionCodeResult_DisplayTextWithoutAssumptions() {
            FunctionCodeResult result = new FunctionCodeResult("main", "void main(void)", "C", null,
                List.of(FunctionCodeResult.line(null, "void main(void) {")));

            String display = result.toDisplayText();
            assertFalse(display.contains("Register Assumptions:"));
            assertFalse(display.contains("assume"));
            assertTrue(display.contains("void main(void) {"));
        }

        @Test
        @DisplayName("FunctionCodeResult defensive copy prevents mutation of registerAssumptions")
        void testFunctionCodeResult_RegisterAssumptions_DefensiveCopy() {
            List<FunctionCodeResult.RegisterAssumption> mutableAssumptions = new ArrayList<>(List.of(
                new FunctionCodeResult.RegisterAssumption("gp", "0x12000")
            ));
            FunctionCodeResult result = new FunctionCodeResult("entry", "void entry(void)", "assembly",
                mutableAssumptions, List.of(FunctionCodeResult.line("00401000", "NOP")));

            mutableAssumptions.add(new FunctionCodeResult.RegisterAssumption("tp", "0x3000"));
            assertEquals(1, result.registerAssumptions().size(),
                "Modifying original list should not affect record");
        }
    }

    // ===== Prototype parsing unit tests (no Ghidra required) =====

    @Nested
    @DisplayName("Prototype parsing")
    class PrototypeParsingTests {

        @Test
        @DisplayName("parsePrototype parses simple prototype")
        void testParsePrototype_Simple() {
            var parsed = FunctionService.parsePrototype("int process_data(char *buffer, size_t length)");
            assertEquals("int", parsed.returnType);
            assertEquals(2, parsed.params.size());
            assertEquals("char *", parsed.params.get(0).type);
            assertEquals("buffer", parsed.params.get(0).name);
            assertEquals("size_t", parsed.params.get(1).type);
            assertEquals("length", parsed.params.get(1).name);
            assertFalse(parsed.hasVarArgs);
        }

        @Test
        @DisplayName("parsePrototype handles void return and void params")
        void testParsePrototype_VoidVoid() {
            var parsed = FunctionService.parsePrototype("void func(void)");
            assertEquals("void", parsed.returnType);
            assertTrue(parsed.params.isEmpty());
            assertFalse(parsed.hasVarArgs);
        }

        @Test
        @DisplayName("parsePrototype handles empty param list")
        void testParsePrototype_EmptyParams() {
            var parsed = FunctionService.parsePrototype("void func()");
            assertEquals("void", parsed.returnType);
            assertTrue(parsed.params.isEmpty());
        }

        @Test
        @DisplayName("parsePrototype handles pointer return type")
        void testParsePrototype_PointerReturn() {
            var parsed = FunctionService.parsePrototype("char * get_name(int id)");
            assertEquals("char *", parsed.returnType);
            assertEquals(1, parsed.params.size());
            assertEquals("int", parsed.params.get(0).type);
            assertEquals("id", parsed.params.get(0).name);
        }

        @Test
        @DisplayName("parsePrototype handles double pointer param")
        void testParsePrototype_DoublePointer() {
            var parsed = FunctionService.parsePrototype("int main(int argc, char **argv)");
            assertEquals("int", parsed.returnType);
            assertEquals(2, parsed.params.size());
            assertEquals("char **", parsed.params.get(1).type);
            assertEquals("argv", parsed.params.get(1).name);
        }

        @Test
        @DisplayName("parsePrototype handles multi-word types")
        void testParsePrototype_MultiWordTypes() {
            var parsed = FunctionService.parsePrototype("unsigned int compute(unsigned short x)");
            assertEquals("unsigned int", parsed.returnType);
            assertEquals(1, parsed.params.size());
            assertEquals("unsigned short", parsed.params.get(0).type);
            assertEquals("x", parsed.params.get(0).name);
        }

        @Test
        @DisplayName("parsePrototype handles varargs")
        void testParsePrototype_VarArgs() {
            var parsed = FunctionService.parsePrototype("int printf(char *fmt, ...)");
            assertEquals("int", parsed.returnType);
            assertEquals(1, parsed.params.size());
            assertEquals("char *", parsed.params.get(0).type);
            assertEquals("fmt", parsed.params.get(0).name);
            assertTrue(parsed.hasVarArgs);
        }

        @Test
        @DisplayName("parsePrototype handles pointer star attached to name")
        void testParsePrototype_StarAttachedToName() {
            var parsed = FunctionService.parsePrototype("int func(char *buf)");
            assertEquals("int", parsed.returnType);
            assertEquals("char *", parsed.params.get(0).type);
            assertEquals("buf", parsed.params.get(0).name);
        }

        @Test
        @DisplayName("parsePrototype rejects missing parentheses")
        void testParsePrototype_MissingParens() {
            assertThrows(IllegalArgumentException.class,
                () -> FunctionService.parsePrototype("int func"));
        }

        @Test
        @DisplayName("parsePrototype rejects bare type with no function name")
        void testParsePrototype_NoFuncName() {
            assertThrows(IllegalArgumentException.class,
                () -> FunctionService.parsePrototype("int(void)"));
        }

        @Test
        @DisplayName("extractReturnType extracts simple return type")
        void testExtractReturnType_Simple() {
            assertEquals("int", FunctionService.extractReturnType("int func"));
        }

        @Test
        @DisplayName("extractReturnType extracts pointer return type")
        void testExtractReturnType_Pointer() {
            assertEquals("void *", FunctionService.extractReturnType("void * func"));
        }

        @Test
        @DisplayName("parseParam parses type and name")
        void testParseParam_Simple() {
            var param = FunctionService.parseParam("int count");
            assertEquals("int", param.type);
            assertEquals("count", param.name);
        }

        @Test
        @DisplayName("parseParam parses pointer type")
        void testParseParam_Pointer() {
            var param = FunctionService.parseParam("char *buffer");
            assertEquals("char *", param.type);
            assertEquals("buffer", param.name);
        }

        @Test
        @DisplayName("parseParam handles unnamed parameter")
        void testParseParam_Unnamed() {
            var param = FunctionService.parseParam("int");
            assertEquals("int", param.type);
            assertEquals("", param.name);
        }

        @Test
        @DisplayName("splitParams splits by comma respecting parens")
        void testSplitParams_WithParens() {
            String[] parts = FunctionService.splitParams("int a, void (*cb)(int, int), char *c");
            assertEquals(3, parts.length);
            assertEquals("int a", parts[0]);
            assertEquals(" void (*cb)(int, int)", parts[1]);
            assertEquals(" char *c", parts[2]);
        }
    }

    // ===== Tests using a shared empty program (validation / error paths) =====

    @Nested
    @DisplayName("Empty program validation")
    class EmptyProgramTests {

        private static ProgramBuilder builder;
        private static ProgramDB program;
        private static FunctionService service;

        @BeforeAll
        static void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            program = builder.getProgram();
            service = serviceFor(program);
        }

        @AfterAll
        static void tearDown() {
            builder.dispose();
        }

        @Test
        @DisplayName("getFunctionCode returns error for empty identifier")
        void testGetFunctionCode_EmptyIdentifier() {
            String result = service.getFunctionCode("", "C").toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function identifier is required\""));
        }

        @Test
        @DisplayName("renameFunctions returns error for null map")
        void testRenameFunctions_NullMap() {
            String result = service.renameFunctions(null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No renames specified\""));
        }

        @Test
        @DisplayName("renameFunctions returns error for empty map")
        void testRenameFunctions_EmptyMap() {
            String result = service.renameFunctions(Map.of()).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No renames specified\""));
        }

        @Test
        @DisplayName("setFunctionPrototype returns error when function not found")
        void testSetFunctionPrototype_FunctionNotFound() {
            String result = service.setFunctionPrototype("nonexistent", "int test(void)").toStructuredJson();
            assertTrue(result.contains("Failed to set function prototype"),
                "Should report function not found, got: " + result);
        }

        @Test
        @DisplayName("searchFunctionsByName returns error for null query")
        void testSearchFunctionsByName_NullQuery() {
            String result = service.searchFunctionsByName(null, 0, 100).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Search term is required\""));
        }

        @Test
        @DisplayName("searchFunctionsByName returns error for empty query")
        void testSearchFunctionsByName_EmptyQuery() {
            String result = service.searchFunctionsByName("", 0, 100).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Search term is required\""));
        }

        @Test
        @DisplayName("setFunctionPrototype returns error for null identifier")
        void testSetFunctionPrototype_NullIdentifier() {
            String result = service.setFunctionPrototype(null, "int test(void)").toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function identifier is required\""));
        }

        @Test
        @DisplayName("setFunctionPrototype returns error for empty identifier")
        void testSetFunctionPrototype_EmptyIdentifier() {
            String result = service.setFunctionPrototype("", "int test(void)").toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function identifier is required\""));
        }

        @Test
        @DisplayName("setFunctionPrototype returns error for null prototype")
        void testSetFunctionPrototype_NullPrototype() {
            String result = service.setFunctionPrototype("0x401000", null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function prototype is required\""));
        }

        @Test
        @DisplayName("setFunctionPrototype returns error for empty prototype")
        void testSetFunctionPrototype_EmptyPrototype() {
            String result = service.setFunctionPrototype("0x401000", "").toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function prototype is required\""));
        }

        @Test
        @DisplayName("resolveFunction returns null for null identifier")
        void testResolveFunction_NullIdentifier() {
            assertNull(service.resolveFunction(program, null));
        }

        @Test
        @DisplayName("resolveFunction returns null for empty identifier")
        void testResolveFunction_EmptyIdentifier() {
            assertNull(service.resolveFunction(program, ""));
        }

        @Test
        @DisplayName("listFunctions handles empty function list")
        void testGetAllFunctionNames_NoFunctions() {
            String result = service.listFunctions(0, 10).toStructuredJson();
            assertTrue(result.contains("\"remaining\":0"));
        }

        @Test
        @DisplayName("getFunctionCode returns 'Function not found' when function does not exist")
        void testGetFunctionCode_FunctionNotFound() {
            String result = service.getFunctionCode("nonexistent", "C").toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function not found: nonexistent\""));
        }

        @Test
        @DisplayName("resolveFunction returns null for nonexistent function")
        void testResolveFunction_NotFound() {
            assertNull(service.resolveFunction(program, "doesNotExist"));
        }

        @Test
        @DisplayName("renameFunctions returns error when function not found")
        void testRenameFunctions_FunctionNotFound() {
            String result = service.renameFunctions(Map.of("nonexistent", "newName")).toStructuredJson();
            assertTrue(result.contains("Function not found: nonexistent"));
        }
    }

    // ===== Tests sharing a Pattern A MIPS function (read-only) =====

    @Nested
    @DisplayName("Pattern A function output (assembly, C, PCode)")
    class PatternATests {

        private static ProgramBuilder builder;
        private static ProgramDB program;
        private static FunctionService service;

        @BeforeAll
        static void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            // MIPS: simple function (Pattern A)
            builder.setBytes("0x401000",
                "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
                true);
            builder.createFunction("0x401000");
            program = builder.getProgram();
            service = serviceFor(program);
        }

        @AfterAll
        static void tearDown() {
            builder.dispose();
        }

        @Test
        @DisplayName("getFunctionCode assembly mode returns address-keyed line entries")
        void testGetFunctionCode_Assembly_Success() {
            ToolOutput result = service.getFunctionCode("0x401000", "assembly");
            assertTrue(result instanceof JsonOutput);

            String json = result.toStructuredJson();
            assertTrue(json.contains("\"format\":\"assembly\""));

            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();
            assertEquals("assembly", data.format());
            assertNotNull(data.function());
            assertTrue(data.lines().size() >= 7, "Expected at least 7 instructions");

            // Verify the first instruction contains ADDIU (stack frame setup)
            Map<String, String> firstLine = data.lines().get(0);
            String firstCode = firstLine.values().iterator().next();
            assertTrue(firstCode.toUpperCase().contains("ADDIU"), "First instruction should be ADDIU, got: " + firstCode);
        }

        @Test
        @DisplayName("getFunctionCode assembly mode preserves instruction order")
        void testGetFunctionCode_Assembly_PreservesOrder() {
            ToolOutput result = service.getFunctionCode("0x401000", "assembly");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertTrue(data.lines().size() >= 7, "Expected at least 7 instructions");

            // Verify order: ADDIU, SW, NOP, LW, ADDIU, JR, NOP
            String[] expectedMnemonics = {"ADDIU", "SW", "NOP", "LW", "ADDIU", "JR", "NOP"};
            for (int i = 0; i < expectedMnemonics.length; i++) {
                String code = data.lines().get(i).values().iterator().next().toUpperCase();
                assertTrue(code.contains(expectedMnemonics[i]),
                    "Instruction " + i + " should contain " + expectedMnemonics[i] + ", got: " + code);
            }

            // Verify addresses are monotonically increasing
            long prevAddr = -1;
            for (Map<String, String> line : data.lines()) {
                String addrStr = line.keySet().iterator().next();
                long addr = Long.parseUnsignedLong(addrStr, 16);
                assertTrue(addr > prevAddr, "Addresses should be monotonically increasing");
                prevAddr = addr;
            }
        }

        @Test
        @DisplayName("Assembly mode returns null registerAssumptions when no register values are set")
        void testGetFunctionCode_Assembly_NoRegisterAssumptions() {
            ToolOutput result = service.getFunctionCode("0x401000", "assembly");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertEquals("assembly", data.format());
            assertNull(data.registerAssumptions());
        }

        @Test
        @DisplayName("getFunctionCode C mode decompiles a simple function")
        void testGetFunctionCode_C_Success() {
            ToolOutput result = service.getFunctionCode("0x401000", "C");
            assertInstanceOf(JsonOutput.class, result);

            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();
            assertEquals("C", data.format());
            assertNotNull(data.function());
            assertFalse(data.lines().isEmpty(), "Decompiled C output should have at least one line");
        }

        @Test
        @DisplayName("getFunctionCode C mode produces lines with non-empty address keys")
        void testGetFunctionCode_C_HasAddressedLines() {
            ToolOutput result = service.getFunctionCode("0x401000", "C");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            // At least one line should have a non-empty address key (address-mapped code)
            boolean hasAddressedLine = data.lines().stream()
                .anyMatch(line -> line.keySet().stream().anyMatch(key -> !key.isEmpty()));
            assertTrue(hasAddressedLine, "C output should have at least one line with a non-empty address key");

            // Output should contain recognizable C constructs (braces, return, void, etc.)
            String allCode = data.lines().stream()
                .flatMap(line -> line.values().stream())
                .reduce("", (a, b) -> a + " " + b);
            assertTrue(allCode.contains("{") || allCode.contains("}") || allCode.contains("return") || allCode.contains("void"),
                "C output should contain recognizable C constructs, got: " + allCode);
        }

        @Test
        @DisplayName("getFunctionCode PCode mode returns non-empty lines with PCode syntax")
        void testGetFunctionCode_PCode_Success() {
            ToolOutput result = service.getFunctionCode("0x401000", "pcode");
            assertInstanceOf(JsonOutput.class, result);

            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();
            assertEquals("pcode", data.format());
            assertFalse(data.lines().isEmpty(), "PCode output should have at least one line");

            // Every PCode line should have a non-empty address key
            for (Map<String, String> line : data.lines()) {
                String addr = line.keySet().iterator().next();
                assertFalse(addr.isEmpty(), "Every PCode line should have a non-empty address key");
            }

            // PCode lines should contain PCode op syntax (parentheses, e.g., "(register, 0x8, 8)")
            String allCode = data.lines().stream()
                .flatMap(line -> line.values().stream())
                .reduce("", (a, b) -> a + " " + b);
            assertTrue(allCode.contains("("), "PCode output should contain parentheses from PCode syntax, got: " + allCode);
        }
    }

    // ===== Tests sharing a Pattern D function (jr $ra; nop) =====

    @Nested
    @DisplayName("Pattern D function (C/PCode register assumptions)")
    class PatternDTests {

        private static ProgramBuilder builder;
        private static FunctionService service;

        @BeforeAll
        static void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            // Pattern D: jr $ra; nop
            builder.setBytes("0x401000", "03 E0 00 08 00 00 00 00", true);
            builder.createFunction("0x401000");
            service = serviceFor(builder.getProgram());
        }

        @AfterAll
        static void tearDown() {
            builder.dispose();
        }

        @Test
        @DisplayName("C mode returns null registerAssumptions even when register values are set")
        void testGetFunctionCode_C_NoRegisterAssumptions() {
            ToolOutput result = service.getFunctionCode("0x401000", "C");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertEquals("C", data.format());
            assertNull(data.registerAssumptions(), "C mode should not include register assumptions");
        }

        @Test
        @DisplayName("Pcode mode returns null registerAssumptions even when register values are set")
        void testGetFunctionCode_Pcode_NoRegisterAssumptions() {
            ToolOutput result = service.getFunctionCode("0x401000", "pcode");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertEquals("pcode", data.format());
            assertNull(data.registerAssumptions(), "Pcode mode should not include register assumptions");
        }
    }

    // ===== MIPS ISA_MODE register assumption tests =====

    @Nested
    @DisplayName("MIPS ISA_MODE register assumptions")
    class IsaModeTests {

        private static ProgramBuilder builder;
        private static FunctionService service;

        @BeforeAll
        static void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            builder.setRegisterValue("ISA_MODE", "0x401000", "0x401010", 1);
            builder.createEmptyFunction("testFunc", "0x401000", 0x10, DataType.DEFAULT);
            service = serviceFor(builder.getProgram());
        }

        @AfterAll
        static void tearDown() {
            builder.dispose();
        }

        @Test
        @DisplayName("Assembly mode includes register assumptions when non-default register values are set")
        void testGetFunctionCode_Assembly_WithRegisterAssumptions() {
            ToolOutput result = service.getFunctionCode("testFunc", "assembly");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertNotNull(data.registerAssumptions(), "Should have register assumptions");
            assertTrue(data.registerAssumptions().stream()
                    .anyMatch(a -> a.name().equals("ISA_MODE")),
                "Should contain ISA_MODE register assumption");

            FunctionCodeResult.RegisterAssumption isaModeAssumption = data.registerAssumptions().stream()
                    .filter(a -> a.name().equals("ISA_MODE"))
                    .findFirst().orElseThrow();
            assertEquals("0x1", isaModeAssumption.value());
        }

        @Test
        @DisplayName("Register assumptions are sorted alphabetically by name")
        void testGetFunctionCode_Assembly_RegisterAssumptionsSorted() {
            ToolOutput result = service.getFunctionCode("testFunc", "assembly");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertNotNull(data.registerAssumptions());

            // Verify alphabetical ordering of whatever assumptions are present
            List<String> names = data.registerAssumptions().stream()
                    .map(FunctionCodeResult.RegisterAssumption::name)
                    .toList();
            List<String> sorted = new ArrayList<>(names);
            Collections.sort(sorted);
            assertEquals(sorted, names, "Register assumptions should be sorted alphabetically");
        }

        @Test
        @DisplayName("Register assumption hex value is formatted correctly (0x prefix, uppercase)")
        void testGetFunctionCode_Assembly_HexFormatting() {
            ToolOutput result = service.getFunctionCode("testFunc", "assembly");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertNotNull(data.registerAssumptions());
            FunctionCodeResult.RegisterAssumption assumption = data.registerAssumptions().stream()
                    .filter(a -> a.name().equals("ISA_MODE"))
                    .findFirst().orElseThrow();
            assertTrue(assumption.value().startsWith("0x"), "Value should have 0x prefix");
        }
    }

    // ===== V850 register assumption tests =====

    @Nested
    @DisplayName("V850 register assumptions")
    class V850Tests {

        private static ProgramBuilder builder;
        private static FunctionService service;

        @BeforeAll
        static void setUp() throws Exception {
            builder = new ProgramBuilder("test", "V850:LE:32:default");
            builder.createMemory(".text", "0x1000", 0x1000);

            // Function 1: gp only
            builder.setRegisterValue("gp", "0x1000", "0x1010", 0x12000);
            builder.createEmptyFunction("entry_gp", "0x1000", 0x10, DataType.DEFAULT);

            // Function 2: gp with different value (for hex formatting test)
            builder.setRegisterValue("gp", "0x1100", "0x1110", 0xFF00);
            builder.createEmptyFunction("entry_hex", "0x1100", 0x10, DataType.DEFAULT);

            // Function 3: gp + tp (multiple registers)
            builder.setRegisterValue("gp", "0x1200", "0x1210", 0x12000);
            builder.setRegisterValue("tp", "0x1200", "0x1210", 0x3000);
            builder.createEmptyFunction("entry_multi", "0x1200", 0x10, DataType.DEFAULT);

            service = serviceFor(builder.getProgram());
        }

        @AfterAll
        static void tearDown() {
            builder.dispose();
        }

        @Test
        @DisplayName("V850 assembly mode includes gp register assumption")
        void testGetFunctionCode_Assembly_V850_GpAssumption() {
            ToolOutput result = service.getFunctionCode("entry_gp", "assembly");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertNotNull(data.registerAssumptions(), "V850 should have register assumptions when gp is set");

            FunctionCodeResult.RegisterAssumption gpAssumption = data.registerAssumptions().stream()
                    .filter(a -> a.name().equals("gp"))
                    .findFirst()
                    .orElse(null);
            assertNotNull(gpAssumption, "Should contain gp register assumption");
            assertEquals("0x12000", gpAssumption.value());
        }

        @Test
        @DisplayName("V850 assembly mode formats large hex values with uppercase")
        void testGetFunctionCode_Assembly_V850_LargeHexValue() {
            ToolOutput result = service.getFunctionCode("entry_hex", "assembly");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertNotNull(data.registerAssumptions());
            FunctionCodeResult.RegisterAssumption gpAssumption = data.registerAssumptions().stream()
                    .filter(a -> a.name().equals("gp"))
                    .findFirst().orElseThrow();
            assertEquals("0xFF00", gpAssumption.value(), "Hex should be uppercase with 0x prefix");
        }

        @Test
        @DisplayName("V850 assembly mode with multiple register assumptions (gp and tp)")
        void testGetFunctionCode_Assembly_V850_MultipleRegisters() {
            ToolOutput result = service.getFunctionCode("entry_multi", "assembly");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

            assertNotNull(data.registerAssumptions());

            assertTrue(data.registerAssumptions().stream().anyMatch(a -> a.name().equals("gp")),
                "Should contain gp assumption");
            assertTrue(data.registerAssumptions().stream().anyMatch(a -> a.name().equals("tp")),
                "Should contain tp assumption");

            // Verify sorted order (gp before tp)
            List<String> names = data.registerAssumptions().stream()
                    .map(FunctionCodeResult.RegisterAssumption::name)
                    .toList();
            List<String> sorted = new ArrayList<>(names);
            Collections.sort(sorted);
            assertEquals(sorted, names, "Register assumptions should be sorted alphabetically");
        }
    }

    // ===== Tests sharing a program with several named functions =====

    @Nested
    @DisplayName("Function lookup and search")
    class FunctionLookupTests {

        private static ProgramBuilder builder;
        private static ProgramDB program;
        private static FunctionService service;

        @BeforeAll
        static void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x2000);
            builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);
            builder.createEmptyFunction("main", "0x401100", 0x50, DataType.DEFAULT);
            builder.createEmptyFunction("MyFunction", "0x401200", 0x20, DataType.DEFAULT);
            builder.createEmptyFunction("alpha", "0x401300", 0x20, DataType.DEFAULT);
            program = builder.getProgram();
            service = serviceFor(program);
        }

        @AfterAll
        static void tearDown() {
            builder.dispose();
        }

        @Test
        @DisplayName("setFunctionPrototype succeeds without PluginTool (no modal dialogs)")
        void testSetFunctionPrototype_NullTool_Succeeds() {
            String result = service.setFunctionPrototype("myFunc", "int test(void)").toStructuredJson();
            assertTrue(result.contains("Function prototype set successfully"),
                "Should succeed without PluginTool, got: " + result);
        }

        @Test
        @DisplayName("resolveFunction finds function by name")
        void testResolveFunction_ByName() {
            Function resolved = service.resolveFunction(program, "myFunc");
            assertNotNull(resolved);
            assertEquals("myFunc", resolved.getName());
        }

        @Test
        @DisplayName("resolveFunction finds function by address")
        void testResolveFunction_ByAddress() {
            Function resolved = service.resolveFunction(program, "0x401000");
            assertNotNull(resolved);
            assertEquals("myFunc", resolved.getName());
        }

        @Test
        @DisplayName("searchFunctionsByName is case-insensitive")
        void testSearchFunctionsByName_CaseInsensitive() {
            String json = service.searchFunctionsByName("myfunction", 0, 100).toStructuredJson();
            assertTrue(json.contains("MyFunction"));
        }

        @Test
        @DisplayName("searchFunctionsByName returns empty when no matches")
        void testSearchFunctionsByName_NoMatches() {
            String json = service.searchFunctionsByName("zzz_not_found", 0, 100).toStructuredJson();
            assertTrue(json.contains("\"remaining\":0"));
        }
    }

    // ===== Tests requiring per-test ProgramBuilder (mutations or unique setups) =====

    private ProgramBuilder builder;

    @AfterEach
    void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    @DisplayName("getFunctionCode assembly mode includes EOL comments")
    void testGetFunctionCode_Assembly_WithComments() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");
        builder.createComment("0x401000", "save frame pointer", CommentType.EOL);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionCode("0x401000", "asm");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals("assembly", data.format());
        assertTrue(data.lines().size() >= 1);

        // First instruction should include the EOL comment
        Map<String, String> firstLine = data.lines().get(0);
        String firstCode = firstLine.values().iterator().next();
        assertTrue(firstCode.contains("; save frame pointer"),
            "First line should contain EOL comment, got: " + firstCode);
    }

    @Test
    @DisplayName("getFunctionCode assembly mode includes all comment types")
    void testGetFunctionCode_Assembly_AllCommentTypes() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");
        builder.createComment("0x401000", "plate header", CommentType.PLATE);
        builder.createComment("0x401000", "before instruction", CommentType.PRE);
        builder.createComment("0x401000", "end of line", CommentType.EOL);
        builder.createComment("0x401000", "after instruction", CommentType.POST);
        builder.createComment("0x401000", "repeatable note", CommentType.REPEATABLE);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionCode("0x401000", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        List<String> codes = data.lines().stream()
            .map(m -> m.values().iterator().next())
            .toList();

        // Plate and pre comments appear before the instruction
        assertTrue(codes.stream().anyMatch(c -> c.equals("; plate header")),
            "Should contain plate comment, got: " + codes);
        assertTrue(codes.stream().anyMatch(c -> c.equals("; before instruction")),
            "Should contain pre comment, got: " + codes);

        // EOL and repeatable are inlined on the instruction line
        String instrLine = codes.stream()
            .filter(c -> c.contains("; end of line"))
            .findFirst().orElseThrow(() -> new AssertionError("No line with EOL comment in: " + codes));
        assertTrue(instrLine.contains("; repeatable note"),
            "Instruction line should also contain repeatable comment, got: " + instrLine);
        assertFalse(instrLine.startsWith(";"),
            "Instruction line should start with instruction, not comment prefix, got: " + instrLine);

        // Post comment appears after the instruction
        assertTrue(codes.stream().anyMatch(c -> c.equals("; after instruction")),
            "Should contain post comment, got: " + codes);

        // Verify ordering: plate, pre, instruction, post
        int plateIdx = codes.indexOf("; plate header");
        int preIdx = codes.indexOf("; before instruction");
        int instrIdx = codes.indexOf(instrLine);
        int postIdx = codes.indexOf("; after instruction");
        assertTrue(plateIdx < preIdx, "Plate should come before pre");
        assertTrue(preIdx < instrIdx, "Pre should come before instruction");
        assertTrue(instrIdx < postIdx, "Instruction should come before post");
    }

    @Test
    @DisplayName("getFunctionCode assembly mode handles multiline comments")
    void testGetFunctionCode_Assembly_MultilineComments() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");
        builder.createComment("0x401000", "line one\nline two", CommentType.PRE);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionCode("0x401000", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        List<String> codes = data.lines().stream()
            .map(m -> m.values().iterator().next())
            .toList();

        assertTrue(codes.contains("; line one"), "Should contain first line of multiline comment, got: " + codes);
        assertTrue(codes.contains("; line two"), "Should contain second line of multiline comment, got: " + codes);
    }

    @Test
    @DisplayName("getFunctionCode assembly mode toDisplayText reproduces readable format")
    void testGetFunctionCode_Assembly_DisplayText() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");
        builder.createComment("0x401000", "function entry", CommentType.EOL);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionCode("0x401000", "assembly");
        String display = result.toDisplayText();

        // Display text should contain address: instruction format
        assertTrue(display.contains("; function entry"), "Display text should contain the EOL comment");
        // Each line should follow the "address: instruction" pattern
        String[] lines = display.split("\n");
        assertTrue(lines.length >= 5, "Display text should have at least 5 lines");
        for (String line : lines) {
            if (!line.isEmpty()) {
                assertTrue(line.contains(": "), "Each line should have 'address: code' format, got: " + line);
            }
        }
    }

    @Test
    @DisplayName("getFunctionCode assembly mode handles empty function body")
    void testGetFunctionCode_Assembly_EmptyBody() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // Create a function with no bytes (empty body, no instructions)
        builder.createEmptyFunction("emptyFunc", "0x401000", 1, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionCode("emptyFunc", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals("emptyFunc", data.function());
        assertEquals("assembly", data.format());
        assertEquals(0, data.lines().size());
    }

    @Test
    @DisplayName("getFunctionCode C mode with local variables decompiles correctly")
    void testGetFunctionCode_C_WithLocalVariables() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x2000);

        // Helper at 0x401500: writes 0x10 through pointer in $a0 (Pattern B)
        // Unique address avoids decompiler cache collisions with other test classes
        builder.setBytes("0x401500", "34 02 00 10 AC 82 00 00 03 E0 00 08 00 00 00 00", true);
        builder.createFunction("0x401500");

        // Function at 0x401000 with local variable whose address escapes via call (Pattern E)
        // Stores 0x42 to local, passes &local to helper at 0x401500, reads local back
        builder.setBytes("0x401000",
            "27 BD FF F0 AF BF 00 0C 34 02 00 42 AF A2 00 00 27 A4 00 00 0C 10 05 40 00 00 00 00 8F A2 00 00 8F BF 00 0C 27 BD 00 10 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");

        ProgramDB program = builder.getProgram();

        // Set helper's prototype to take a pointer param so the decompiler
        // recognizes the pointer escape and preserves the local variable
        int tx = program.startTransaction("set helper prototype");
        try {
            Function helperFunc = program.getFunctionManager()
                .getFunctionAt(builder.addr("0x401500"));
            if (helperFunc != null) {
                helperFunc.addParameter(
                    new ParameterImpl("ptr",
                        new PointerDataType(IntegerDataType.dataType), program),
                    SourceType.ANALYSIS);
            }
        } finally {
            program.endTransaction(tx, true);
        }

        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionCode("0x401000", "C");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals("C", data.format());
        assertTrue(data.lines().size() >= 3,
            "Function with locals should produce at least 3 lines of C code, got: " + data.lines());

        // The decompiled output should reference the constant 0x42 (66 decimal) or a local variable
        String allCode = data.lines().stream()
            .flatMap(line -> line.values().stream())
            .reduce("", (a, b) -> a + " " + b);
        assertTrue(allCode.contains("0x42") || allCode.contains("66") || allCode.contains("local_"),
            "Decompiled C should contain 0x42, 66, or local_ variable, got: " + allCode);
    }

    // --- renameFunctions happy-path tests (each mutates the program) ---

    @Test
    @DisplayName("renameFunctions renames a single function by name")
    void testRenameFunctions_ByName() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("oldName", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.renameFunctions(Map.of("oldName", "newName"));
        assertInstanceOf(JsonOutput.class, result);

        RenameFunctionsResult data = (RenameFunctionsResult) ((JsonOutput) result).data();
        assertEquals("Renamed successfully", data.status());
        assertEquals(1, data.count());
        assertEquals("newName", data.renamed().get("oldName"));

        // Verify the rename actually took effect on the program
        assertNotNull(program.getFunctionManager().getFunctionAt(builder.addr("0x401000")));
        assertEquals("newName", program.getFunctionManager().getFunctionAt(builder.addr("0x401000")).getName());
    }

    @Test
    @DisplayName("renameFunctions renames multiple functions atomically")
    void testRenameFunctions_Multiple() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("func_a", "0x401000", 0x20, DataType.DEFAULT);
        builder.createEmptyFunction("func_b", "0x401100", 0x20, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        var renames = new java.util.LinkedHashMap<String, String>();
        renames.put("func_a", "process_input");
        renames.put("func_b", "validate_data");

        ToolOutput result = service.renameFunctions(renames);
        RenameFunctionsResult data = (RenameFunctionsResult) ((JsonOutput) result).data();
        assertEquals(2, data.count());
        assertEquals("process_input", data.renamed().get("func_a"));
        assertEquals("validate_data", data.renamed().get("func_b"));
    }

    @Test
    @DisplayName("renameFunctions renames by address")
    void testRenameFunctions_ByAddress() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.renameFunctions(Map.of("0x401000", "renamed_func"));
        RenameFunctionsResult data = (RenameFunctionsResult) ((JsonOutput) result).data();
        assertEquals(1, data.count());
        assertEquals("renamed_func", program.getFunctionManager().getFunctionAt(builder.addr("0x401000")).getName());
    }

    @Test
    @DisplayName("renameFunctions returns error for invalid function name")
    void testRenameFunctions_InvalidName() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("validFunc", "0x401000", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.renameFunctions(Map.of("validFunc", "bad name!")).toStructuredJson();
        assertTrue(result.contains("Failed to rename functions"),
            "Should report rename failure for invalid name, got: " + result);
    }

    // --- listFunctions and searchFunctionsByName tests (unique function sets) ---

    @Test
    @DisplayName("listFunctions returns function names successfully")
    void testGetAllFunctionNames_Success() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("main", "0x401000", 0x50, DataType.DEFAULT);
        builder.createEmptyFunction("helper_function", "0x401100", 0x30, DataType.DEFAULT);
        builder.createEmptyFunction("init", "0x401200", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.listFunctions(0, 10).toStructuredJson();

        assertTrue(result.contains("main"));
        assertTrue(result.contains("helper_function"));
        assertTrue(result.contains("init"));
    }

    @Test
    @DisplayName("listFunctions respects offset and limit parameters")
    void testGetAllFunctionNames_WithPagination() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("function_0", "0x401000", 0x10, DataType.DEFAULT);
        builder.createEmptyFunction("function_1", "0x401020", 0x10, DataType.DEFAULT);
        builder.createEmptyFunction("function_2", "0x401040", 0x10, DataType.DEFAULT);
        builder.createEmptyFunction("function_3", "0x401060", 0x10, DataType.DEFAULT);
        builder.createEmptyFunction("function_4", "0x401080", 0x10, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());

        // Test with offset=2, limit=2 (should get function_2 and function_3)
        String result = service.listFunctions(2, 2).toStructuredJson();

        assertFalse(result.contains("function_0"));
        assertFalse(result.contains("function_1"));
        assertTrue(result.contains("function_2"));
        assertTrue(result.contains("function_3"));
        assertFalse(result.contains("function_4"));
    }

    @Test
    @DisplayName("searchFunctionsByName finds functions matching substring")
    void testSearchFunctionsByName_Success() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("process_input", "0x401000", 0x20, DataType.DEFAULT);
        builder.createEmptyFunction("process_output", "0x401040", 0x20, DataType.DEFAULT);
        builder.createEmptyFunction("validate_data", "0x401080", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.searchFunctionsByName("process", 0, 100);
        assertInstanceOf(ListOutput.class, result);

        String json = result.toStructuredJson();
        assertTrue(json.contains("process_input"));
        assertTrue(json.contains("process_output"));
        assertFalse(json.contains("validate_data"));
    }

    @Test
    @DisplayName("searchFunctionsByName respects pagination")
    void testSearchFunctionsByName_Pagination() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("test_a", "0x401000", 0x10, DataType.DEFAULT);
        builder.createEmptyFunction("test_b", "0x401020", 0x10, DataType.DEFAULT);
        builder.createEmptyFunction("test_c", "0x401040", 0x10, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.searchFunctionsByName("test", 1, 1);
        assertInstanceOf(ListOutput.class, result);

        ListOutput list = (ListOutput) result;
        assertEquals(1, list.items().size());
        assertTrue(list.hasMore());
    }

    // --- setFunctionPrototype with ambiguous types (ushort, uint, etc.) ---

    @Test
    @DisplayName("setFunctionPrototype resolves ushort parameter without modal dialog")
    void testSetFunctionPrototype_UshortParam() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        String result = service.setFunctionPrototype("myFunc", "void myFunc(ushort value)").toStructuredJson();
        assertTrue(result.contains("Function prototype set successfully"),
            "ushort should resolve without modal dialog, got: " + result);

        // Verify the parameter type was applied
        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        assertEquals(1, func.getParameterCount());
        assertEquals("value", func.getParameter(0).getName());
        assertTrue(func.getParameter(0).getDataType().getName().toLowerCase().contains("ushort"),
            "Parameter type should be ushort, got: " + func.getParameter(0).getDataType().getName());
    }

    @Test
    @DisplayName("setFunctionPrototype resolves ushort return type without modal dialog")
    void testSetFunctionPrototype_UshortReturn() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        String result = service.setFunctionPrototype("myFunc", "ushort myFunc(int x)").toStructuredJson();
        assertTrue(result.contains("Function prototype set successfully"),
            "ushort return type should resolve without modal dialog, got: " + result);

        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        assertTrue(func.getReturnType().getName().toLowerCase().contains("ushort"),
            "Return type should be ushort, got: " + func.getReturnType().getName());
    }

    @Test
    @DisplayName("setFunctionPrototype resolves multiple ambiguous types in one prototype")
    void testSetFunctionPrototype_MultipleAmbiguousTypes() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        String result = service.setFunctionPrototype("myFunc",
            "uint myFunc(ushort a, uchar b)").toStructuredJson();
        assertTrue(result.contains("Function prototype set successfully"),
            "Multiple ambiguous types should all resolve, got: " + result);

        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        assertTrue(func.getReturnType().getName().toLowerCase().contains("uint"),
            "Return type should be uint, got: " + func.getReturnType().getName());
        assertEquals(2, func.getParameterCount());
        assertTrue(func.getParameter(0).getDataType().getName().toLowerCase().contains("ushort"),
            "First param should be ushort, got: " + func.getParameter(0).getDataType().getName());
        assertTrue(func.getParameter(1).getDataType().getName().toLowerCase().contains("uchar"),
            "Second param should be uchar, got: " + func.getParameter(1).getDataType().getName());
    }

    @Test
    @DisplayName("setFunctionPrototype resolves category-qualified type path")
    void testSetFunctionPrototype_CategoryQualifiedType() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        // Use explicit built-in path to disambiguate
        String result = service.setFunctionPrototype("myFunc",
            "void myFunc(/ushort value)").toStructuredJson();
        assertTrue(result.contains("Function prototype set successfully"),
            "Category-qualified path should resolve, got: " + result);
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for unresolvable type")
    void testSetFunctionPrototype_UnresolvableType() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        String result = service.setFunctionPrototype("myFunc",
            "void myFunc(nonexistent_type_xyz x)").toStructuredJson();
        assertTrue(result.contains("could not resolve type"),
            "Should report unresolvable type, got: " + result);
    }

    @Test
    @DisplayName("setFunctionPrototype resolves pointer to ushort without modal dialog")
    void testSetFunctionPrototype_PointerToUshort() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        String result = service.setFunctionPrototype("myFunc",
            "void myFunc(ushort *ptr)").toStructuredJson();
        assertTrue(result.contains("Function prototype set successfully"),
            "ushort * should resolve without modal dialog, got: " + result);

        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        assertEquals(1, func.getParameterCount());
        String paramTypeName = func.getParameter(0).getDataType().getName();
        assertTrue(paramTypeName.contains("ushort") && paramTypeName.contains("*"),
            "Parameter type should be ushort *, got: " + paramTypeName);
    }
}
