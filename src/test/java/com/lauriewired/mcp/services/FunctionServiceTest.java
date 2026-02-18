package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.FunctionByAddressResult;
import com.lauriewired.mcp.model.response.FunctionCodeResult;
import com.lauriewired.mcp.model.response.FunctionSearchItem;
import com.lauriewired.mcp.model.response.RenameFunctionsResult;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;

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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.renameFunctions(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No renames specified\""));
    }

    @Test
    @DisplayName("renameFunctions returns error for empty map")
    void testRenameFunctions_EmptyMap() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.renameFunctions(Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No renames specified\""));
    }

    @Test
    @DisplayName("getFunctionByAddress returns error when no program loaded")
    void testGetFunctionByAddress_NoProgram() {
        FunctionService service = nullProgramService();
        String result = service.getFunctionByAddress("0x401000").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getFunctionByAddress returns error for null address")
    void testGetFunctionByAddress_NullAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.getFunctionByAddress(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Address is required\""));
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype(null, "int test(void)").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for empty identifier")
    void testSetFunctionPrototype_EmptyIdentifier() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype("", "int test(void)").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for null prototype")
    void testSetFunctionPrototype_NullPrototype() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype("0x401000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function prototype is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for empty prototype")
    void testSetFunctionPrototype_EmptyPrototype() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        String result = service.setFunctionPrototype("0x401000", "").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function prototype is required\""));
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        assertNull(service.resolveFunction(builder.getProgram(), null));
    }

    @Test
    @DisplayName("resolveFunction returns null for empty identifier")
    void testResolveFunction_EmptyIdentifier() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        FunctionService service = serviceFor(builder.getProgram());

        assertNull(service.resolveFunction(builder.getProgram(), ""));
    }

    // ===== ProgramBuilder-based integration tests =====

    @Test
    @DisplayName("listFunctions returns function names successfully")
    void testGetAllFunctionNames_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.listFunctions(0, 10).toStructuredJson();

        assertTrue(result.contains("\"total_items\":0"));
    }

    @Test
    @DisplayName("getFunctionCode returns 'Function not found' when function does not exist")
    void testGetFunctionCode_FunctionNotFound() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.getFunctionCode("nonexistent", "C").toStructuredJson();

        assertTrue(result.contains("\"message\":\"Function not found: nonexistent\""));
    }

    @Test
    @DisplayName("getFunctionCode assembly mode returns address-keyed line entries")
    void testGetFunctionCode_Assembly_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        // x86-64: push rbp; mov rbp,rsp; nop; pop rbp; ret
        builder.setBytes("0x401000", "55 48 89 e5 90 5d c3", true);
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
        assertTrue(data.lines().size() >= 5, "Expected at least 5 instructions (push, mov, nop, pop, ret)");

        // Verify the first instruction contains PUSH
        Map<String, String> firstLine = data.lines().get(0);
        String firstCode = firstLine.values().iterator().next();
        assertTrue(firstCode.toUpperCase().contains("PUSH"), "First instruction should be PUSH, got: " + firstCode);
    }

    @Test
    @DisplayName("getFunctionCode assembly mode includes EOL comments")
    void testGetFunctionCode_Assembly_WithComments() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        // x86-64: push rbp; mov rbp,rsp; nop; pop rbp; ret
        builder.setBytes("0x401000", "55 48 89 e5 90 5d c3", true);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        // x86-64: push rbp; mov rbp,rsp; nop; pop rbp; ret
        builder.setBytes("0x401000", "55 48 89 e5 90 5d c3", true);
        builder.createFunction("0x401000");

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionCode("0x401000", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertTrue(data.lines().size() >= 5, "Expected at least 5 instructions");

        // Verify order: PUSH, MOV, NOP, POP, RET
        String[] expectedMnemonics = {"PUSH", "MOV", "NOP", "POP", "RET"};
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        // x86-64: push rbp; mov rbp,rsp; nop; pop rbp; ret
        builder.setBytes("0x401000", "55 48 89 e5 90 5d c3", true);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
    @DisplayName("getFunctionByAddress returns function details successfully")
    void testGetFunctionByAddress_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("main", "0x401000", 0x50, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        ToolOutput result = service.getFunctionByAddress("0x401000");
        assertTrue(result instanceof JsonOutput);

        FunctionByAddressResult data = (FunctionByAddressResult) ((JsonOutput) result).data();
        assertEquals("main", data.name());
        assertNotNull(data.signature());
        assertNotNull(data.entryPoint());
        assertNotNull(data.bodyStart());
        assertNotNull(data.bodyEnd());
    }

    @Test
    @DisplayName("resolveFunction finds function by name")
    void testResolveFunction_ByName() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);

        ProgramDB program = builder.getProgram();
        FunctionService service = serviceFor(program);

        assertNull(service.resolveFunction(program, "doesNotExist"));
    }

    // ===== renameFunctions happy-path tests =====

    @Test
    @DisplayName("renameFunctions renames a single function by name")
    void testRenameFunctions_ByName() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);

        FunctionService service = serviceFor(builder.getProgram());
        String result = service.renameFunctions(Map.of("nonexistent", "newName")).toStructuredJson();
        assertTrue(result.contains("Function not found: nonexistent"));
    }

    // ===== searchFunctionsByName happy-path tests =====

    @Test
    @DisplayName("searchFunctionsByName finds functions matching substring")
    void testSearchFunctionsByName_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("MyFunction", "0x401000", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        String json = service.searchFunctionsByName("myfunction", 0, 100).toStructuredJson();
        assertTrue(json.contains("MyFunction"));
    }

    @Test
    @DisplayName("searchFunctionsByName returns empty when no matches")
    void testSearchFunctionsByName_NoMatches() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createEmptyFunction("alpha", "0x401000", 0x20, DataType.DEFAULT);

        FunctionService service = serviceFor(builder.getProgram());
        String json = service.searchFunctionsByName("zzz_not_found", 0, 100).toStructuredJson();
        assertTrue(json.contains("\"total_items\":0"));
    }

    @Test
    @DisplayName("searchFunctionsByName respects pagination")
    void testSearchFunctionsByName_Pagination() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
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
}
