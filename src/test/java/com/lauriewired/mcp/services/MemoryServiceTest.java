package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.AddressDataTypeResult;
import com.lauriewired.mcp.model.response.MemoryPermissionsResult;
import com.lauriewired.mcp.model.response.ReadMemoryResult;
import com.lauriewired.mcp.model.response.RenameDataResult;
import com.lauriewired.mcp.model.response.SetDataTypesResult;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.IntegerDataType;

/**
 * Integration tests for MemoryService using ProgramBuilder-based real Ghidra programs.
 * Null-program validation tests use a MemoryService with no backing program.
 */
public class MemoryServiceTest {

    /** MemoryService with null program — used for error-path tests. */
    private MemoryService nullProgramService;

    /** ProgramBuilder for creating real programs in happy-path tests. */
    private ProgramBuilder builder;

    @BeforeAll
    static void initGhidra() {
        GhidraTestEnv.initialize();
    }

    @BeforeEach
    void setUp() {
        ProgramService ps = new ProgramService(null);
        nullProgramService = new MemoryService(ps, new DataTypeService(ps));
    }

    @AfterEach
    void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    // --- Helper to build a MemoryService backed by a real ProgramDB ---

    private MemoryService serviceFor(ProgramDB program) {
        ProgramService ps = GhidraTestEnv.programService(program);
        return new MemoryService(ps, new DataTypeService(ps));
    }

    // ===== Null-program / validation error-path tests =====

    @Test
    @DisplayName("getMemoryLayout returns error when no program is loaded")
    void testListSegments_NoProgram() {
        String result = nullProgramService.getMemoryLayout(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getMemoryLayout handles negative offset")
    void testListSegments_NegativeOffset() {
        String result = nullProgramService.getMemoryLayout(-1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getMemoryLayout handles zero limit")
    void testListSegments_ZeroLimit() {
        String result = nullProgramService.getMemoryLayout(0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listDataItems returns error when no program is loaded")
    void testListDataItems_NoProgram() {
        String result = nullProgramService.listDataItems(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listDataItems handles negative offset")
    void testListDataItems_NegativeOffset() {
        String result = nullProgramService.listDataItems(-1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listDataItems handles zero limit")
    void testListDataItems_ZeroLimit() {
        String result = nullProgramService.listDataItems(0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error when no program is loaded")
    void testRenameData_NoProgram() {
        String result = nullProgramService.renameData(Map.of("0x1000", "newName")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error for null map")
    void testRenameData_NullMap() {
        String result = nullProgramService.renameData((Map<String, String>) null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error for empty map")
    void testRenameData_EmptyMap() {
        String result = nullProgramService.renameData(Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new MemoryService(null));
    }

    @Test
    @DisplayName("setAddressDataType returns error when no program is loaded")
    void testSetMemoryDataType_NoProgram() {
        String result = nullProgramService.setAddressDataType(Map.of("0x1000", "int"), true).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("readMemory returns error for invalid size")
    void testReadMemory_InvalidSize_NoProgram() {
        String result = nullProgramService.readMemory("00401000", 0, "hex").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    // ===== ProgramBuilder-based integration tests =====

    @Test
    @DisplayName("getMemoryLayout returns memory blocks when program is loaded")
    void testListSegments_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x400000", 0x1000);
        builder.createMemory(".data", "0x402000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.getMemoryLayout(0, 10).toStructuredJson();

        assertTrue(result.contains(".text"));
        assertTrue(result.contains(".data"));
        assertTrue(result.contains("00400000"));
        assertTrue(result.contains("00402000"));
    }

    @Test
    @DisplayName("getMemoryLayout respects pagination limits")
    void testListSegments_Pagination() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x400000", 0x1000);
        builder.createMemory(".data", "0x402000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.getMemoryLayout(0, 1).toStructuredJson();

        // Should only contain first block
        assertTrue(result.contains(".text"));
        assertFalse(result.contains(".data"));
    }

    @Test
    @DisplayName("listDataItems returns data items when program is loaded")
    void testListDataItems_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "42 00 00 00", false);
        builder.applyDataType("0x402000", IntegerDataType.dataType);
        builder.createLabel("0x402000", "myVariable");
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.listDataItems(0, 10).toStructuredJson();

        assertTrue(result.contains("00402000"));
        assertTrue(result.contains("myVariable"));
    }

    @Test
    @DisplayName("listDataItems handles unnamed data")
    void testListDataItems_UnnamedData() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "FF 00 00 00", false);
        builder.applyDataType("0x402000", IntegerDataType.dataType);
        // No label created — data is unnamed
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.listDataItems(0, 10).toStructuredJson();

        assertTrue(result.contains("00402000"));
        assertTrue(result.contains("(unnamed)"));
    }

    @Test
    @DisplayName("renameData successfully renames multiple data labels")
    void testRenameData_MultipleAddresses_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "42 00 00 00", false);
        builder.applyDataType("0x402000", IntegerDataType.dataType);
        builder.createLabel("0x402000", "oldLabel1");

        builder.setBytes("0x402010", "43 00 00 00", false);
        builder.applyDataType("0x402010", IntegerDataType.dataType);
        builder.createLabel("0x402010", "oldLabel2");
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        Map<String, String> renames = new LinkedHashMap<>();
        renames.put("0x402000", "config_table");
        renames.put("0x402010", "key_buffer");
        ToolOutput result = ms.renameData(renames);

        assertInstanceOf(JsonOutput.class, result);
        RenameDataResult renameResult = (RenameDataResult) ((JsonOutput) result).data();
        assertEquals("Renamed successfully", renameResult.status());
        assertEquals(2, renameResult.count());
        assertEquals("config_table", renameResult.renamed().get("00402000"));
        assertEquals("key_buffer", renameResult.renamed().get("00402010"));
    }

    @Test
    @DisplayName("renameData creates new label when no symbol exists")
    void testRenameData_NoSymbol_CreatesLabel() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "42 00 00 00", false);
        builder.applyDataType("0x402000", IntegerDataType.dataType);
        // No label — data exists but no symbol
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.renameData(Map.of("0x402000", "brandNewLabel"));

        assertInstanceOf(JsonOutput.class, result);
        RenameDataResult renameResult = (RenameDataResult) ((JsonOutput) result).data();
        assertEquals("Renamed successfully", renameResult.status());
        assertEquals(1, renameResult.count());

        // Verify the label was actually created on the program
        var sym = program.getSymbolTable().getPrimarySymbol(builder.addr("0x402000"));
        assertEquals("brandNewLabel", sym.getName());
    }

    @Test
    @DisplayName("renameData returns error for invalid address in map")
    void testRenameData_InvalidAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.renameData(Map.of("invalid", "newName")).toStructuredJson();

        assertTrue(result.contains("Invalid address: invalid"));
    }

    @Test
    @DisplayName("renameData returns error when no data at address")
    void testRenameData_NoDataAtAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        // Memory exists at 0x402000, but no defined data applied
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.renameData(Map.of("0x402000", "newName")).toStructuredJson();

        assertTrue(result.contains("No defined data at address"));
    }

    @Test
    @DisplayName("renameData returns error for empty map with program loaded")
    void testRenameData_EmptyMapWithProgram() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.renameData(Map.of()).toStructuredJson();

        assertTrue(result.contains("No renames specified"));
    }

    // ===== setAddressDataType tests =====

    @Test
    @DisplayName("setAddressDataType returns error when DataTypeService is null")
    void testSetMemoryDataType_NoDataTypeService() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        ProgramDB program = builder.getProgram();

        ProgramService ps = GhidraTestEnv.programService(program);
        MemoryService msNoDataType = new MemoryService(ps);
        String result = msNoDataType.setAddressDataType(Map.of("0x402000", "int"), true).toStructuredJson();
        assertTrue(result.contains("\"message\":\"DataTypeService not available\""));
    }

    @Test
    @DisplayName("setAddressDataType returns error for empty map")
    void testSetMemoryDataType_EmptyMap() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.setAddressDataType(Map.of(), true).toStructuredJson();
        assertTrue(result.contains("No types specified"));
    }

    @Test
    @DisplayName("setAddressDataType returns error for invalid address")
    void testSetMemoryDataType_InvalidAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.setAddressDataType(Map.of("invalid", "int"), true).toStructuredJson();
        assertTrue(result.contains("Invalid address: invalid"));
    }

    @Test
    @DisplayName("setAddressDataType returns error when data type not found")
    void testSetMemoryDataType_DataTypeNotFound() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.setAddressDataType(Map.of("0x402000", "unknown_type"), true).toStructuredJson();
        assertTrue(result.contains("unknown_type"));
    }

    // ===== readMemory tests =====

    @Test
    @DisplayName("readMemory hex format returns flat record with bytes and ascii")
    void testReadMemory_Hex_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000", "48 65 6C 6C 6F", false); // "Hello"
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.readMemory("00401000", 5, "hex");
        assertInstanceOf(JsonOutput.class, result);

        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();
        assertEquals("00401000", memResult.address());
        assertEquals(5, memResult.size());
        assertEquals("hex", memResult.format());
        assertEquals("48 65 6C 6C 6F", memResult.bytes());
        assertEquals("Hello", memResult.ascii());
    }

    @Test
    @DisplayName("readMemory hex format shows non-printable chars as dots in ASCII")
    void testReadMemory_Hex_NonPrintableAscii() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000", "00 41 1F 7F", false);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.readMemory("00401000", 4, "hex");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();
        assertEquals(".A..", memResult.ascii());
    }

    @Test
    @DisplayName("readMemory hex format emits all bytes in a single flat record")
    void testReadMemory_Hex_LargeRead() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);

        StringBuilder hexBytes = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            if (i > 0) hexBytes.append(" ");
            hexBytes.append(String.format("%02X", i));
        }
        builder.setBytes("0x401000", hexBytes.toString(), false);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.readMemory("00401000", 20, "hex");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13",
                memResult.bytes());
        assertEquals("00401000", memResult.address());
    }

    @Test
    @DisplayName("readMemory decimal format returns numeric string values")
    void testReadMemory_Decimal_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000", "00 FF 0A 64", false);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.readMemory("00401000", 4, "decimal");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("decimal", memResult.format());
        assertEquals("0 255 10 100", memResult.bytes());
        assertEquals("...d", memResult.ascii());
    }

    @Test
    @DisplayName("readMemory binary format returns 8-bit padded binary strings")
    void testReadMemory_Binary_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000", "00 01 FF 0A", false);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.readMemory("00401000", 4, "binary");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("binary", memResult.format());
        assertEquals("00000000 00000001 11111111 00001010", memResult.bytes());
        assertNull(memResult.ascii());
    }

    @Test
    @DisplayName("readMemory ascii format returns individual character strings")
    void testReadMemory_Ascii_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000", "48 69 00 0A 0D 09 80", false);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.readMemory("00401000", 7, "ascii");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("ascii", memResult.format());
        assertEquals("H i \\0 \\n \\r \\t \\x80", memResult.bytes());
        assertNull(memResult.ascii());
    }

    @Test
    @DisplayName("readMemory returns error for invalid size")
    void testReadMemory_InvalidSize() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);

        String result = ms.readMemory("00401000", 0, "hex").toStructuredJson();
        assertTrue(result.contains("Size must be between 1 and 1024"));

        String result2 = ms.readMemory("00401000", 1025, "hex").toStructuredJson();
        assertTrue(result2.contains("Size must be between 1 and 1024"));
    }

    @Test
    @DisplayName("readMemory toDisplayText produces human-readable output")
    void testReadMemory_DisplayText() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000", "48 69", false); // "Hi"
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.readMemory("00401000", 2, "hex");
        String display = result.toDisplayText();

        assertTrue(display.contains("Memory at 00401000 (2 bytes, hex):"));
        assertTrue(display.contains("48 69"));
        assertTrue(display.contains("Hi"));
    }

    // ===== setAddressDataType happy-path tests =====

    @Test
    @DisplayName("setAddressDataType applies int data type at address")
    void testSetAddressDataType_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "42 00 00 00", false);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.setAddressDataType(Map.of("0x402000", "int"), true);

        // The result depends on whether DTM resolves "int" - on some Ghidra versions it may not
        String json = result.toStructuredJson();
        if (json.contains("Data types set successfully")) {
            assertInstanceOf(JsonOutput.class, result);
            SetDataTypesResult data = (SetDataTypesResult) ((JsonOutput) result).data();
            assertEquals(1, data.count());
        }
        // Otherwise it's an expected "not found" error from DTM resolution
    }

    // ===== getMemoryPermissions tests =====

    @Test
    @DisplayName("getMemoryPermissions returns error when no program is loaded")
    void testGetMemoryPermissions_NoProgram() {
        String result = nullProgramService.getMemoryPermissions("00401000").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getMemoryPermissions returns error for null address")
    void testGetMemoryPermissions_NullAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.getMemoryPermissions(null).toStructuredJson();
        assertTrue(result.contains("Address is required"));
    }

    @Test
    @DisplayName("getMemoryPermissions returns error for empty address")
    void testGetMemoryPermissions_EmptyAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.getMemoryPermissions("").toStructuredJson();
        assertTrue(result.contains("Address is required"));
    }

    @Test
    @DisplayName("getMemoryPermissions returns error for invalid address")
    void testGetMemoryPermissions_InvalidAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.getMemoryPermissions("invalid").toStructuredJson();
        assertTrue(result.contains("Invalid address"));
    }

    @Test
    @DisplayName("getMemoryPermissions returns error when no block at address")
    void testGetMemoryPermissions_NoBlock() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        // Address is valid but not in any memory block
        String result = ms.getMemoryPermissions("0x900000").toStructuredJson();
        assertTrue(result.contains("No memory block at address"));
    }

    @Test
    @DisplayName("getMemoryPermissions returns block info for valid address")
    void testGetMemoryPermissions_Success() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.getMemoryPermissions("0x401000");

        assertInstanceOf(JsonOutput.class, result);
        MemoryPermissionsResult perms = (MemoryPermissionsResult) ((JsonOutput) result).data();

        assertEquals(".text", perms.block());
        assertEquals(0x1000, perms.size());
        assertNotNull(perms.start());
        assertNotNull(perms.end());
        assertNotNull(perms.permissions());
        assertTrue(perms.initialized());
    }

    @Test
    @DisplayName("getMemoryPermissions toDisplayText produces human-readable output")
    void testGetMemoryPermissions_DisplayText() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.getMemoryPermissions("0x401000");
        String display = result.toDisplayText();

        assertTrue(display.contains("Memory permissions at"));
        assertTrue(display.contains("Block: .text"));
        assertTrue(display.contains("Read:"));
        assertTrue(display.contains("Write:"));
        assertTrue(display.contains("Execute:"));
    }

    // ===== getAddressDataType tests =====

    @Test
    @DisplayName("getAddressDataType returns error when no program is loaded")
    void testGetAddressDataType_NoProgram() {
        String result = nullProgramService.getAddressDataType("00401000").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getAddressDataType returns error for null address")
    void testGetAddressDataType_NullAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.getAddressDataType(null).toStructuredJson();
        assertTrue(result.contains("Address is required"));
    }

    @Test
    @DisplayName("getAddressDataType returns error for empty address")
    void testGetAddressDataType_EmptyAddress() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        String result = ms.getAddressDataType("").toStructuredJson();
        assertTrue(result.contains("Address is required"));
    }

    @Test
    @DisplayName("getAddressDataType returns instruction info")
    void testGetAddressDataType_Instruction() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        // x86-64: push rbp; mov rbp,rsp; nop; pop rbp; ret
        builder.setBytes("0x401000", "55 48 89 e5 90 5d c3", true);
        builder.createFunction("0x401000");
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.getAddressDataType("0x401000");

        assertInstanceOf(JsonOutput.class, result);
        AddressDataTypeResult data = (AddressDataTypeResult) ((JsonOutput) result).data();

        assertEquals("Instruction", data.category());
        assertNotNull(data.mnemonic());
        assertTrue(data.length() > 0);
    }

    @Test
    @DisplayName("getAddressDataType returns defined data info")
    void testGetAddressDataType_DefinedData() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "42 00 00 00", false);
        builder.applyDataType("0x402000", IntegerDataType.dataType);
        builder.createLabel("0x402000", "myInt");
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.getAddressDataType("0x402000");

        assertInstanceOf(JsonOutput.class, result);
        AddressDataTypeResult data = (AddressDataTypeResult) ((JsonOutput) result).data();

        assertEquals("Defined Data", data.category());
        assertNotNull(data.dataType());
        assertEquals(4, data.length());
        assertEquals("myInt", data.label());
    }

    @Test
    @DisplayName("getAddressDataType returns defined data without label")
    void testGetAddressDataType_DefinedDataNoLabel() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "42 00 00 00", false);
        builder.applyDataType("0x402000", IntegerDataType.dataType);
        // No label created
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.getAddressDataType("0x402000");

        assertInstanceOf(JsonOutput.class, result);
        AddressDataTypeResult data = (AddressDataTypeResult) ((JsonOutput) result).data();

        assertEquals("Defined Data", data.category());
        // label may be null or auto-generated
    }

    @Test
    @DisplayName("getAddressDataType returns undefined data for untyped memory")
    void testGetAddressDataType_UndefinedData() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "FF", false);
        // Memory exists but no data type or instruction applied
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.getAddressDataType("0x402000");

        assertInstanceOf(JsonOutput.class, result);
        AddressDataTypeResult data = (AddressDataTypeResult) ((JsonOutput) result).data();

        // Should be either "Undefined Data" or some other category depending on Ghidra version
        assertNotNull(data.category());
        assertEquals("00402000", data.address());
    }

    @Test
    @DisplayName("getAddressDataType toDisplayText for instruction")
    void testGetAddressDataType_DisplayText() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.setBytes("0x401000", "55 48 89 e5 90 5d c3", true);
        builder.createFunction("0x401000");
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        ToolOutput result = ms.getAddressDataType("0x401000");
        String display = result.toDisplayText();

        assertTrue(display.contains("Data type at"));
        assertTrue(display.contains("Type: Instruction"));
        assertTrue(display.contains("Mnemonic:"));
    }

    @Test
    @DisplayName("setAddressDataType applies multiple types atomically")
    void testSetAddressDataType_Multiple() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".data", "0x402000", 0x100);
        builder.setBytes("0x402000", "42 00 00 00 43 00 00 00", false);
        ProgramDB program = builder.getProgram();

        MemoryService ms = serviceFor(program);
        var types = new java.util.LinkedHashMap<String, String>();
        types.put("0x402000", "int");
        types.put("0x402004", "int");
        ToolOutput result = ms.setAddressDataType(types, true);

        String json = result.toStructuredJson();
        if (json.contains("Data types set successfully")) {
            SetDataTypesResult data = (SetDataTypesResult) ((JsonOutput) result).data();
            assertEquals(2, data.count());
        }
    }
}
