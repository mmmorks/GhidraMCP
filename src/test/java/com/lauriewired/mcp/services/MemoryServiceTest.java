package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.ReadMemoryResult;
import com.lauriewired.mcp.model.response.RenameDataResult;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Unit tests for MemoryService
 */
@ExtendWith(MockitoExtension.class)
public class MemoryServiceTest {

    private MemoryService memoryService;
    private ProgramService programService;
    private DataTypeService dataTypeService;
    private TestMemoryService testMemoryService;
    private TestProgramService testProgramService;
    private TestDataTypeService testDataTypeService;
    
    @Mock
    private MockablePluginTool mockTool;
    
    @Mock
    private ProgramManager mockProgramManager;
    
    @Mock
    private Program mockProgram;
    
    @Mock
    private Memory mockMemory;
    
    @Mock
    private MemoryBlock mockBlock1;
    
    @Mock
    private MemoryBlock mockBlock2;
    
    @Mock
    private Address mockStartAddr1;
    
    @Mock
    private Address mockEndAddr1;
    
    @Mock
    private Address mockStartAddr2;
    
    @Mock
    private Address mockEndAddr2;
    
    @Mock
    private Listing mockListing;
    
    @Mock
    private DataIterator mockDataIterator;
    
    @Mock
    private Data mockData;
    
    @Mock
    private Address mockDataAddr;
    
    @Mock
    private AddressFactory mockAddressFactory;
    
    @Mock
    private SymbolTable mockSymbolTable;
    
    @Mock
    private Symbol mockSymbol;
    
    @Mock
    private ProgramBasedDataTypeManager mockDataTypeManager;

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        dataTypeService = new DataTypeService(programService);
        memoryService = new MemoryService(programService, dataTypeService);
        
        // Setup for happy path tests
        testProgramService = new TestProgramService(mockTool);
        testDataTypeService = new TestDataTypeService(testProgramService);
        testMemoryService = new TestMemoryService(testProgramService, testDataTypeService);
    }

    @Test
    @DisplayName("getMemoryLayout returns error when no program is loaded")
    void testListSegments_NoProgram() {
        String result = memoryService.getMemoryLayout(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getMemoryLayout handles negative offset")
    void testListSegments_NegativeOffset() {
        String result = memoryService.getMemoryLayout(-1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getMemoryLayout handles zero limit")
    void testListSegments_ZeroLimit() {
        String result = memoryService.getMemoryLayout(0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listDataItems returns error when no program is loaded")
    void testListDataItems_NoProgram() {
        String result = memoryService.listDataItems(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listDataItems handles negative offset")
    void testListDataItems_NegativeOffset() {
        String result = memoryService.listDataItems(-1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listDataItems handles zero limit")
    void testListDataItems_ZeroLimit() {
        String result = memoryService.listDataItems(0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error when no program is loaded")
    void testRenameData_NoProgram() {
        String result = memoryService.renameData(Map.of("0x1000", "newName")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error for null map")
    void testRenameData_NullMap() {
        String result = memoryService.renameData((Map<String, String>) null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error for empty map")
    void testRenameData_EmptyMap() {
        String result = memoryService.renameData(Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new MemoryService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly

    // Happy path tests using mocked Ghidra objects

    @Test
    @DisplayName("getMemoryLayout returns memory blocks when program is loaded")
    void testListSegments_Success() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        
        // Mock memory blocks
        when(mockBlock1.getName()).thenReturn(".text");
        when(mockBlock1.getStart()).thenReturn(mockStartAddr1);
        when(mockBlock1.getEnd()).thenReturn(mockEndAddr1);
        when(mockStartAddr1.toString()).thenReturn("00400000");
        when(mockEndAddr1.toString()).thenReturn("00401000");
        
        when(mockBlock2.getName()).thenReturn(".data");
        when(mockBlock2.getStart()).thenReturn(mockStartAddr2);
        when(mockBlock2.getEnd()).thenReturn(mockEndAddr2);
        when(mockStartAddr2.toString()).thenReturn("00402000");
        when(mockEndAddr2.toString()).thenReturn("00403000");
        
        MemoryBlock[] blocks = {mockBlock1, mockBlock2};
        when(mockMemory.getBlocks()).thenReturn(blocks);
        
        // Execute
        String result = testMemoryService.getMemoryLayout(0, 10).toStructuredJson();

        // Verify
        assertTrue(result.contains(".text: 00400000 - 00401000"));
        assertTrue(result.contains(".data: 00402000 - 00403000"));
    }

    @Test
    @DisplayName("getMemoryLayout respects pagination limits")
    void testListSegments_Pagination() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);

        // Mock memory blocks
        when(mockBlock1.getName()).thenReturn(".text");
        when(mockBlock1.getStart()).thenReturn(mockStartAddr1);
        when(mockBlock1.getEnd()).thenReturn(mockEndAddr1);
        when(mockStartAddr1.toString()).thenReturn("00400000");
        when(mockEndAddr1.toString()).thenReturn("00401000");

        when(mockBlock2.getName()).thenReturn(".data");
        when(mockBlock2.getStart()).thenReturn(mockStartAddr2);
        when(mockBlock2.getEnd()).thenReturn(mockEndAddr2);
        when(mockStartAddr2.toString()).thenReturn("00402000");
        when(mockEndAddr2.toString()).thenReturn("00403000");

        MemoryBlock[] blocks = {mockBlock1, mockBlock2};
        when(mockMemory.getBlocks()).thenReturn(blocks);

        // Execute with limit of 1
        String result = testMemoryService.getMemoryLayout(0, 1).toStructuredJson();

        // Verify - should only contain first block
        assertTrue(result.contains(".text: 00400000 - 00401000"));
        assertFalse(result.contains(".data: 00402000 - 00403000"));
    }
    
    @Test
    @DisplayName("listDataItems returns data items when program is loaded")
    void testListDataItems_Success() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        when(mockProgram.getListing()).thenReturn(mockListing);

        // Mock memory block
        when(mockBlock1.getStart()).thenReturn(mockStartAddr1);
        when(mockBlock1.contains(mockDataAddr)).thenReturn(true);
        MemoryBlock[] blocks = {mockBlock1};
        when(mockMemory.getBlocks()).thenReturn(blocks);

        // Mock data iterator
        when(mockListing.getDefinedData(mockStartAddr1, true)).thenReturn(mockDataIterator);
        when(mockDataIterator.hasNext()).thenReturn(true, false);
        when(mockDataIterator.next()).thenReturn(mockData);

        // Mock data
        when(mockData.getAddress()).thenReturn(mockDataAddr);
        when(mockData.getLabel()).thenReturn("myVariable");
        when(mockData.getDefaultValueRepresentation()).thenReturn("0x42");
        when(mockDataAddr.toString()).thenReturn("00400100");

        // Execute
        String result = testMemoryService.listDataItems(0, 10).toStructuredJson();

        // Verify
        assertTrue(result.contains("00400100: myVariable = 0x42"));
    }

    @Test
    @DisplayName("listDataItems handles unnamed data")
    void testListDataItems_UnnamedData() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        when(mockProgram.getListing()).thenReturn(mockListing);

        // Mock memory block
        when(mockBlock1.getStart()).thenReturn(mockStartAddr1);
        when(mockBlock1.contains(mockDataAddr)).thenReturn(true);
        MemoryBlock[] blocks = {mockBlock1};
        when(mockMemory.getBlocks()).thenReturn(blocks);

        // Mock data iterator
        when(mockListing.getDefinedData(mockStartAddr1, true)).thenReturn(mockDataIterator);
        when(mockDataIterator.hasNext()).thenReturn(true, false);
        when(mockDataIterator.next()).thenReturn(mockData);

        // Mock data with no label
        when(mockData.getAddress()).thenReturn(mockDataAddr);
        when(mockData.getLabel()).thenReturn(null);
        when(mockData.getDefaultValueRepresentation()).thenReturn("0xFF");
        when(mockDataAddr.toString()).thenReturn("00400200");

        // Execute
        String result = testMemoryService.listDataItems(0, 10).toStructuredJson();

        // Verify
        assertTrue(result.contains("00400200: (unnamed) = 0xFF"));
    }
    
    @Test
    @DisplayName("renameData successfully renames multiple data labels")
    void testRenameData_MultipleAddresses_Success() throws Exception {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockProgram.getListing()).thenReturn(mockListing);
        when(mockProgram.getSymbolTable()).thenReturn(mockSymbolTable);

        // Mock two addresses
        Address mockAddr2 = mock(Address.class);
        when(mockAddressFactory.getAddress("0x1000")).thenReturn(mockDataAddr);
        when(mockAddressFactory.getAddress("0x2000")).thenReturn(mockAddr2);
        when(mockDataAddr.toString()).thenReturn("0x1000");
        when(mockAddr2.toString()).thenReturn("0x2000");

        // Mock data exists at both addresses
        when(mockListing.getDefinedDataAt(mockDataAddr)).thenReturn(mockData);
        Data mockData2 = mock(Data.class);
        when(mockListing.getDefinedDataAt(mockAddr2)).thenReturn(mockData2);

        // Mock existing symbols
        Symbol mockSymbol2 = mock(Symbol.class);
        when(mockSymbolTable.getPrimarySymbol(mockDataAddr)).thenReturn(mockSymbol);
        when(mockSymbolTable.getPrimarySymbol(mockAddr2)).thenReturn(mockSymbol2);

        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);

        // Execute with ordered map to ensure deterministic iteration
        Map<String, String> renames = new LinkedHashMap<>();
        renames.put("0x1000", "config_table");
        renames.put("0x2000", "key_buffer");
        ToolOutput result = testMemoryService.renameData(renames);

        // Verify structured result
        assertTrue(result instanceof JsonOutput);
        RenameDataResult renameResult = (RenameDataResult) ((JsonOutput) result).data();
        assertEquals("Renamed successfully", renameResult.status());
        assertEquals(2, renameResult.count());
        assertEquals("config_table", renameResult.renamed().get("0x1000"));
        assertEquals("key_buffer", renameResult.renamed().get("0x2000"));

        verify(mockSymbol).setName("config_table", SourceType.USER_DEFINED);
        verify(mockSymbol2).setName("key_buffer", SourceType.USER_DEFINED);
        verify(mockProgram).endTransaction(1, true);
    }

    @Test
    @DisplayName("renameData creates new label when no symbol exists")
    void testRenameData_NoSymbol_CreatesLabel() throws Exception {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockProgram.getListing()).thenReturn(mockListing);
        when(mockProgram.getSymbolTable()).thenReturn(mockSymbolTable);

        // Mock address
        when(mockAddressFactory.getAddress("0x2000")).thenReturn(mockDataAddr);
        when(mockDataAddr.toString()).thenReturn("0x2000");

        // Mock data exists at address
        when(mockListing.getDefinedDataAt(mockDataAddr)).thenReturn(mockData);

        // Mock no existing symbol
        when(mockSymbolTable.getPrimarySymbol(mockDataAddr)).thenReturn(null);

        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);

        // Execute
        ToolOutput result = testMemoryService.renameData(Map.of("0x2000", "brandNewLabel"));

        // Verify
        assertTrue(result instanceof JsonOutput);
        RenameDataResult renameResult = (RenameDataResult) ((JsonOutput) result).data();
        assertEquals("Renamed successfully", renameResult.status());
        assertEquals(1, renameResult.count());
        verify(mockSymbolTable).createLabel(mockDataAddr, "brandNewLabel", SourceType.USER_DEFINED);
        verify(mockProgram).endTransaction(1, true);
    }

    @Test
    @DisplayName("renameData returns error for invalid address in map")
    void testRenameData_InvalidAddress() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);

        // Mock invalid address
        when(mockAddressFactory.getAddress("invalid")).thenReturn(null);

        // Execute - pre-validation should catch this before any transaction
        String result = testMemoryService.renameData(Map.of("invalid", "newName")).toStructuredJson();

        // Verify
        assertTrue(result.contains("Invalid address: invalid"));
        verify(mockProgram, never()).startTransaction(anyString());
    }

    @Test
    @DisplayName("renameData returns error when no data at address")
    void testRenameData_NoDataAtAddress() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockProgram.getListing()).thenReturn(mockListing);

        // Mock address
        when(mockAddressFactory.getAddress("0x3000")).thenReturn(mockDataAddr);

        // Mock no data at address
        when(mockListing.getDefinedDataAt(mockDataAddr)).thenReturn(null);

        // Execute - pre-validation should catch this before any transaction
        String result = testMemoryService.renameData(Map.of("0x3000", "newName")).toStructuredJson();

        // Verify
        assertTrue(result.contains("No defined data at address: 0x3000"));
        verify(mockProgram, never()).startTransaction(anyString());
    }

    @Test
    @DisplayName("renameData returns error for empty map with program loaded")
    void testRenameData_EmptyMapWithProgram() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        // Execute
        String result = testMemoryService.renameData(Map.of()).toStructuredJson();

        // Verify
        assertTrue(result.contains("No renames specified"));
    }

    // Tests for setAddressDataType

    @Test
    @DisplayName("setAddressDataType returns error when no program is loaded")
    void testSetMemoryDataType_NoProgram() {
        String result = memoryService.setAddressDataType(Map.of("0x1000", "int"), true).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("setAddressDataType returns error when DataTypeService is null")
    void testSetMemoryDataType_NoDataTypeService() {
        // Setup mock to return a program
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        // Create MemoryService without DataTypeService using TestMemoryService
        TestMemoryService memoryServiceNoDataType = new TestMemoryService(testProgramService);
        String result = memoryServiceNoDataType.setAddressDataType(Map.of("0x1000", "int"), true).toStructuredJson();
        assertTrue(result.contains("\"message\":\"DataTypeService not available\""));
    }

    @Test
    @DisplayName("setAddressDataType returns error for empty map")
    void testSetMemoryDataType_EmptyMap() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = testMemoryService.setAddressDataType(Map.of(), true).toStructuredJson();
        assertTrue(result.contains("No types specified"));
    }

    @Test
    @DisplayName("setAddressDataType returns error for invalid address")
    void testSetMemoryDataType_InvalidAddress() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockProgram.getDataTypeManager()).thenReturn(mockDataTypeManager);

        // Mock invalid address
        when(mockAddressFactory.getAddress("invalid")).thenReturn(null);

        // Execute - pre-validation catches before transaction
        String result = testMemoryService.setAddressDataType(Map.of("invalid", "int"), true).toStructuredJson();

        // Verify
        assertTrue(result.contains("Invalid address: invalid"));
        verify(mockProgram, never()).startTransaction(anyString());
    }

    @Test
    @DisplayName("setAddressDataType returns error when data type not found")
    void testSetMemoryDataType_DataTypeNotFound() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockProgram.getDataTypeManager()).thenReturn(mockDataTypeManager);

        // Mock address
        when(mockAddressFactory.getAddress("0x1000")).thenReturn(mockDataAddr);

        // Create test service with null data type resolution
        TestDataTypeService mockTestDataTypeService = new TestDataTypeService(testProgramService) {
            @Override
            public DataType resolveDataType(DataTypeManager dtm, String typeName) {
                return null;
            }
        };
        TestMemoryService testMemoryServiceWithMock = new TestMemoryService(testProgramService, mockTestDataTypeService);

        // Execute - pre-validation catches before transaction
        String result = testMemoryServiceWithMock.setAddressDataType(Map.of("0x1000", "unknown_type"), true).toStructuredJson();

        // Verify
        assertTrue(result.contains("Data type"));
        assertTrue(result.contains("unknown_type"));
        verify(mockProgram, never()).startTransaction(anyString());
    }

    // ===== Happy path tests for readMemory =====

    private void setupReadMemoryMocks(byte[] data) throws Exception {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockAddressFactory.getAddress("00401000")).thenReturn(mockDataAddr);
        when(mockDataAddr.toString()).thenReturn("00401000");
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        when(mockMemory.getBlock(mockDataAddr)).thenReturn(mockBlock1);

        Address endAddr = mock(Address.class);
        when(mockDataAddr.add(data.length - 1)).thenReturn(endAddr);
        when(mockBlock1.contains(endAddr)).thenReturn(true);

        // Mock getBytes to populate the byte array
        doAnswer(invocation -> {
            byte[] buf = invocation.getArgument(1);
            System.arraycopy(data, 0, buf, 0, data.length);
            return null;
        }).when(mockMemory).getBytes(eq(mockDataAddr), any(byte[].class));
    }

    @Test
    @DisplayName("readMemory hex format returns flat record with bytes and ascii")
    void testReadMemory_Hex_Success() throws Exception {
        byte[] data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 5, "hex");
        assertTrue(result instanceof JsonOutput);

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
        byte[] data = {0x00, 0x41, 0x1F, 0x7F};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 4, "hex");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();
        assertEquals(".A..", memResult.ascii());
    }

    @Test
    @DisplayName("readMemory hex format emits all bytes in a single flat record")
    void testReadMemory_Hex_LargeRead() throws Exception {
        byte[] data = new byte[20];
        for (int i = 0; i < 20; i++) data[i] = (byte) i;
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 20, "hex");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13",
                memResult.bytes());
        assertEquals("00401000", memResult.address());
    }

    @Test
    @DisplayName("readMemory decimal format returns numeric string values")
    void testReadMemory_Decimal_Success() throws Exception {
        byte[] data = {0x00, (byte) 0xFF, 0x0A, 0x64};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 4, "decimal");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("decimal", memResult.format());
        assertEquals("0 255 10 100", memResult.bytes());
        assertEquals("...d", memResult.ascii());
    }

    @Test
    @DisplayName("readMemory binary format returns 8-bit padded binary strings")
    void testReadMemory_Binary_Success() throws Exception {
        byte[] data = {0x00, 0x01, (byte) 0xFF, 0x0A};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 4, "binary");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("binary", memResult.format());
        assertEquals("00000000 00000001 11111111 00001010", memResult.bytes());
        assertNull(memResult.ascii());
    }

    @Test
    @DisplayName("readMemory ascii format returns individual character strings")
    void testReadMemory_Ascii_Success() throws Exception {
        byte[] data = {0x48, 0x69, 0x00, 0x0A, 0x0D, 0x09, (byte) 0x80};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 7, "ascii");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("ascii", memResult.format());
        assertEquals("H i \\0 \\n \\r \\t \\x80", memResult.bytes());
        assertNull(memResult.ascii());
    }

    @Test
    @DisplayName("readMemory returns error for invalid size")
    void testReadMemory_InvalidSize() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = testMemoryService.readMemory("00401000", 0, "hex").toStructuredJson();
        assertTrue(result.contains("Size must be between 1 and 1024"));

        String result2 = testMemoryService.readMemory("00401000", 1025, "hex").toStructuredJson();
        assertTrue(result2.contains("Size must be between 1 and 1024"));
    }

    @Test
    @DisplayName("readMemory toDisplayText produces human-readable output")
    void testReadMemory_DisplayText() throws Exception {
        byte[] data = {0x48, 0x69};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 2, "hex");
        String display = result.toDisplayText();

        assertTrue(display.contains("Memory at 00401000 (2 bytes, hex):"));
        assertTrue(display.contains("48 69"));
        assertTrue(display.contains("Hi"));
    }
}