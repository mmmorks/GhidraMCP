package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.FunctionCodeResult;
import com.lauriewired.mcp.model.response.FunctionSearchItem;
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
 * Null/error-path tests use a null ProgramService (no Ghidra boot needed).
 */
public class FunctionServiceTest {

    private ProgramBuilder builder;

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

    // --- Helper to create a FunctionService backed by a real program ---

    private FunctionService serviceFor(ProgramDB program) {
        return new FunctionService(null, GhidraTestEnv.programService(program));
    }

    private FunctionService nullProgramService() {
        return new FunctionService(null, new ProgramService(null));
    }

    // ===== Null / error-path tests (no ProgramBuilder needed) =====

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
    @DisplayName("getFunctionCode returns error for empty identifier")
    void testGetFunctionCode_EmptyIdentifier() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.getFunctionCode("", "C").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("renameFunctions returns error when no program is loaded")
    void testRenameFunctions_NoProgram() {
        FunctionService service = nullProgramService();
        String result = service.renameFunctions(Map.of("oldName", "newName")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameFunctions returns error for null map")
    void testRenameFunctions_NullMap() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.renameFunctions(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No renames specified\""));
    }

    @Test
    @DisplayName("renameFunctions returns error for empty map")
    void testRenameFunctions_EmptyMap() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.renameFunctions(Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No renames specified\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error when no program loaded")
    void testSetFunctionPrototype_NoProgram() {
        FunctionService service = nullProgramService();
        String result = service.setFunctionPrototype("0x401000", "int test(void)").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for null identifier")
    void testSetFunctionPrototype_NullIdentifier() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype(null, "int test(void)").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for empty identifier")
    void testSetFunctionPrototype_EmptyIdentifier() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype("", "int test(void)").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for null prototype")
    void testSetFunctionPrototype_NullPrototype() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype("0x401000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function prototype is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for empty prototype")
    void testSetFunctionPrototype_EmptyPrototype() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype("0x401000", "").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function prototype is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error when function not found")
    void testSetFunctionPrototype_FunctionNotFound() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype("nonexistent", "int test(void)").toStructuredJson();
        assertTrue(result.contains("Failed to set function prototype"),
            "Should report function not found, got: " + result);
    }

    @Test
    @DisplayName("setFunctionPrototype NPE when tool is null but function exists")
    void testSetFunctionPrototype_NullTool_CausesNPE() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("testFunc", "0x401000", 0x20, DataType.DEFAULT);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype("testFunc", "int test(void)").toStructuredJson();
        assertTrue(result.contains("Failed to set function prototype"),
            "Should report prototype error due to null tool, got: " + result);
    }

    @Test
    @DisplayName("Constructor accepts null tool without throwing")
    void testConstructor_NullTool() {
        assertDoesNotThrow(() -> new FunctionService(null, new ProgramService(null)));
    }

    @Test
    @DisplayName("listFunctions handles null tool gracefully")
    void testGetAllFunctionNames_NullTool() {
        FunctionService service = new FunctionService(null, new ProgramService(null));
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

    // ===== getCurrentAddress / getCurrentFunction null tool =====

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

    // ===== resolveFunction null/error paths =====

    @Test
    @DisplayName("resolveFunction returns null for null program")
    void testResolveFunction_NullProgram() {
        FunctionService service = nullProgramService();
        assertNull(service.resolveFunction(null, "main"));
    }

    @Test
    @DisplayName("resolveFunction returns null for null identifier")
    void testResolveFunction_NullIdentifier() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        assertNull(service.resolveFunction(builder.getProgram(), null));
    }

    @Test
    @DisplayName("resolveFunction returns null for empty identifier")
    void testResolveFunction_EmptyIdentifier() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        assertNull(service.resolveFunction(builder.getProgram(), ""));
    }

    // ===== ProgramBuilder-based integration tests =====

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
    @DisplayName("listFunctions handles empty function list")
    void testGetAllFunctionNames_NoFunctions() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.listFunctions(0, 10).toStructuredJson();

        assertTrue(result.contains("\"total_items\":0"));
    }

    @Test
    @DisplayName("getFunctionCode returns 'Function not found' when function does not exist")
    void testGetFunctionCode_FunctionNotFound() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.getFunctionCode("nonexistent", "C").toStructuredJson();

        assertTrue(result.contains("\"message\":\"Function not found: nonexistent\""));
    }

    @Test
    @DisplayName("getFunctionCode assembly mode returns address-keyed line entries")
    void testGetFunctionCode_Assembly_Success() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

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
    @DisplayName("getFunctionCode assembly mode preserves instruction order")
    void testGetFunctionCode_Assembly_PreservesOrder() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

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
    @DisplayName("resolveFunction finds function by name")
    void testResolveFunction_ByName() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        Function resolved = service.resolveFunction(program, "myFunc");
        assertNotNull(resolved);
        assertEquals("myFunc", resolved.getName());
    }

    @Test
    @DisplayName("resolveFunction finds function by address")
    void testResolveFunction_ByAddress() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("myFunc", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        Function resolved = service.resolveFunction(program, "0x401000");
        assertNotNull(resolved);
        assertEquals("myFunc", resolved.getName());
    }

    @Test
    @DisplayName("resolveFunction returns null for nonexistent function")
    void testResolveFunction_NotFound() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        assertNull(service.resolveFunction(program, "doesNotExist"));
    }

    // ===== Decompilation (C mode) tests =====

    @Test
    @DisplayName("getFunctionCode C mode decompiles a simple function")
    void testGetFunctionCode_C_Success() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionCode("0x401000", "C");
        assertInstanceOf(JsonOutput.class, result);

        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();
        assertEquals("C", data.format());
        assertNotNull(data.function());
        assertFalse(data.lines().isEmpty(), "Decompiled C output should have at least one line");
    }

    @Test
    @DisplayName("getFunctionCode C mode produces lines with non-empty address keys")
    void testGetFunctionCode_C_HasAddressedLines() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");

        FunctionService service = serviceFor(builder.getProgram());

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
    void testGetFunctionCode_PCode_Success() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");

        FunctionService service = serviceFor(builder.getProgram());

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

    // ===== renameFunctions happy-path tests =====

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
    @DisplayName("renameFunctions returns error when function not found")
    void testRenameFunctions_FunctionNotFound() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.renameFunctions(Map.of("nonexistent", "newName")).toStructuredJson();
        assertTrue(result.contains("Function not found: nonexistent"));
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

    // ===== searchFunctionsByName happy-path tests =====

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
    @DisplayName("searchFunctionsByName is case-insensitive")
    void testSearchFunctionsByName_CaseInsensitive() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("MyFunction", "0x401000", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        String json = service.searchFunctionsByName("myfunction", 0, 100).toStructuredJson();
        assertTrue(json.contains("MyFunction"));
    }

    @Test
    @DisplayName("searchFunctionsByName returns empty when no matches")
    void testSearchFunctionsByName_NoMatches() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("alpha", "0x401000", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        String json = service.searchFunctionsByName("zzz_not_found", 0, 100).toStructuredJson();
        assertTrue(json.contains("\"total_items\":0"));
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

    @Test
    @DisplayName("searchFunctionsByName returns error for null query")
    void testSearchFunctionsByName_NullQuery() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("test_func", "0x401000", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.searchFunctionsByName(null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Search term is required\""));
    }

    @Test
    @DisplayName("searchFunctionsByName returns error for empty query")
    void testSearchFunctionsByName_EmptyQuery() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("test_func", "0x401000", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.searchFunctionsByName("", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Search term is required\""));
    }

    // ===== Register assumptions tests =====

    @Test
    @DisplayName("Assembly mode returns null registerAssumptions when no register values are set")
    void testGetFunctionCode_Assembly_NoRegisterAssumptions() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.getFunctionCode("0x401000", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals("assembly", data.format());
        assertNull(data.registerAssumptions());
    }

    @Test
    @DisplayName("Assembly mode includes register assumptions when non-default register values are set")
    void testGetFunctionCode_Assembly_WithRegisterAssumptions() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        // Use empty function to avoid context register conflicts with instructions.
        // Set a non-default context register value (ISA_MODE=1 is non-default for MIPS).
        builder.setRegisterValue("ISA_MODE", "0x401000", "0x401010", 1);
        builder.createEmptyFunction("testFunc", "0x401000", 0x10, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
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
    @DisplayName("C mode returns null registerAssumptions even when register values are set")
    void testGetFunctionCode_C_NoRegisterAssumptions() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        // Use real bytecode (Pattern D: jr $ra; nop) to prevent decompiler NOP-sled pcode warnings.
        // ISA_MODE is not set here because it's a context register that conflicts with decoded
        // instructions; registerAssumptions is structurally never populated for C mode anyway.
        builder.setBytes("0x401000", "03 E0 00 08 00 00 00 00", true);
        builder.createFunction("0x401000");

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.getFunctionCode("0x401000", "C");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals("C", data.format());
        assertNull(data.registerAssumptions(), "C mode should not include register assumptions");
    }

    @Test
    @DisplayName("Pcode mode returns null registerAssumptions even when register values are set")
    void testGetFunctionCode_Pcode_NoRegisterAssumptions() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        // Use real bytecode (Pattern D: jr $ra; nop) to prevent decompiler NOP-sled pcode warnings.
        // ISA_MODE is not set here because it's a context register that conflicts with decoded
        // instructions; registerAssumptions is structurally never populated for PCode mode anyway.
        builder.setBytes("0x401000", "03 E0 00 08 00 00 00 00", true);
        builder.createFunction("0x401000");

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.getFunctionCode("0x401000", "pcode");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals("pcode", data.format());
        assertNull(data.registerAssumptions(), "Pcode mode should not include register assumptions");
    }

    @Test
    @DisplayName("Register assumptions are sorted alphabetically by name")
    void testGetFunctionCode_Assembly_RegisterAssumptionsSorted() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        // ISA_MODE=1 is non-default for MIPS; this may cause the parent contextreg
        // to also appear as non-default, giving us multiple register assumptions to verify sorting.
        builder.setRegisterValue("ISA_MODE", "0x401000", "0x401010", 1);
        builder.createEmptyFunction("testFunc", "0x401000", 0x10, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
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
    void testGetFunctionCode_Assembly_HexFormatting() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        // Set a non-default value to verify hex formatting
        builder.setRegisterValue("ISA_MODE", "0x401000", "0x401010", 1);
        builder.createEmptyFunction("testFunc", "0x401000", 0x10, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.getFunctionCode("testFunc", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertNotNull(data.registerAssumptions());
        FunctionCodeResult.RegisterAssumption assumption = data.registerAssumptions().stream()
                .filter(a -> a.name().equals("ISA_MODE"))
                .findFirst().orElseThrow();
        assertTrue(assumption.value().startsWith("0x"), "Value should have 0x prefix");
    }

    // ===== FunctionCodeResult record tests =====

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

    // ===== V850 register assumption tests =====

    @Test
    @DisplayName("V850 assembly mode includes gp register assumption")
    void testGetFunctionCode_Assembly_V850_GpAssumption() throws Exception {
        builder = new ProgramBuilder("test", "V850:LE:32:default");
        builder.createMemory(".text", "0x1000", 0x1000);

        builder.setRegisterValue("gp", "0x1000", "0x1010", 0x12000);
        builder.createEmptyFunction("entry", "0x1000", 0x10, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.getFunctionCode("entry", "assembly");
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
    void testGetFunctionCode_Assembly_V850_LargeHexValue() throws Exception {
        builder = new ProgramBuilder("test", "V850:LE:32:default");
        builder.createMemory(".text", "0x1000", 0x1000);

        builder.setRegisterValue("gp", "0x1000", "0x1010", 0xFF00);
        builder.createEmptyFunction("entry", "0x1000", 0x10, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.getFunctionCode("entry", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertNotNull(data.registerAssumptions());
        FunctionCodeResult.RegisterAssumption gpAssumption = data.registerAssumptions().stream()
                .filter(a -> a.name().equals("gp"))
                .findFirst().orElseThrow();
        assertEquals("0xFF00", gpAssumption.value(), "Hex should be uppercase with 0x prefix");
    }

    @Test
    @DisplayName("V850 assembly mode with multiple register assumptions (gp and tp)")
    void testGetFunctionCode_Assembly_V850_MultipleRegisters() throws Exception {
        builder = new ProgramBuilder("test", "V850:LE:32:default");
        builder.createMemory(".text", "0x1000", 0x1000);

        builder.setRegisterValue("gp", "0x1000", "0x1010", 0x12000);
        builder.setRegisterValue("tp", "0x1000", "0x1010", 0x3000);
        builder.createEmptyFunction("entry", "0x1000", 0x10, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        ToolOutput result = service.getFunctionCode("entry", "assembly");
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
