package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.ReadMemoryResult;

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
        String result = memoryService.renameData("0x1000", "newName").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error for null address")
    void testRenameData_NullAddress() {
        String result = memoryService.renameData(null, "newName").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error for empty address")
    void testRenameData_EmptyAddress() {
        String result = memoryService.renameData("", "newName").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error for null name")
    void testRenameData_NullName() {
        String result = memoryService.renameData("0x1000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameData returns error for empty name")
    void testRenameData_EmptyName() {
        String result = memoryService.renameData("0x1000", "").toStructuredJson();
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
    @DisplayName("renameData successfully renames existing symbol")
    void testRenameData_ExistingSymbol_Success() throws Exception {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockProgram.getListing()).thenReturn(mockListing);
        when(mockProgram.getSymbolTable()).thenReturn(mockSymbolTable);

        // Mock address
        when(mockAddressFactory.getAddress("0x1000")).thenReturn(mockDataAddr);

        // Mock data exists at address
        when(mockListing.getDefinedDataAt(mockDataAddr)).thenReturn(mockData);

        // Mock existing symbol
        when(mockSymbolTable.getPrimarySymbol(mockDataAddr)).thenReturn(mockSymbol);

        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);

        // Execute
        String result = testMemoryService.renameData("0x1000", "newName").toStructuredJson();

        // Verify
        assertTrue(result.contains("\"message\":\"Renamed successfully\""));
        verify(mockSymbol).setName("newName", SourceType.USER_DEFINED);
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

        // Mock data exists at address
        when(mockListing.getDefinedDataAt(mockDataAddr)).thenReturn(mockData);

        // Mock no existing symbol
        when(mockSymbolTable.getPrimarySymbol(mockDataAddr)).thenReturn(null);

        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);

        // Execute
        String result = testMemoryService.renameData("0x2000", "brandNewLabel").toStructuredJson();

        // Verify
        assertTrue(result.contains("\"message\":\"Renamed successfully\""));
        verify(mockSymbolTable).createLabel(mockDataAddr, "brandNewLabel", SourceType.USER_DEFINED);
        verify(mockProgram).endTransaction(1, true);
    }

    @Test
    @DisplayName("renameData returns 'Rename failed' for invalid address")
    void testRenameData_InvalidAddress() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);

        // Mock invalid address
        when(mockAddressFactory.getAddress("invalid")).thenReturn(null);

        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);

        // Execute
        String result = testMemoryService.renameData("invalid", "newName").toStructuredJson();

        // Verify
        assertTrue(result.contains("\"message\":\"Rename failed\""));
        verify(mockProgram).endTransaction(1, false);
    }

    @Test
    @DisplayName("renameData returns 'Rename failed' when no data at address")
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

        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);

        // Execute
        String result = testMemoryService.renameData("0x3000", "newName").toStructuredJson();

        // Verify
        assertTrue(result.contains("\"message\":\"Rename failed\""));
        verify(mockProgram).endTransaction(1, false);
    }

    // Tests for setAddressDataType
    
    @Test
    @DisplayName("setAddressDataType returns error when no program is loaded")
    void testSetMemoryDataType_NoProgram() {
        String result = memoryService.setAddressDataType("0x1000", "int", true).toStructuredJson();
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
        String result = memoryServiceNoDataType.setAddressDataType("0x1000", "int", true).toStructuredJson();
        assertTrue(result.contains("\"message\":\"DataTypeService not available\""));
    }


    @Test
    @DisplayName("setAddressDataType returns error for invalid address")
    void testSetMemoryDataType_InvalidAddress() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);

        // Mock invalid address
        when(mockAddressFactory.getAddress("invalid")).thenReturn(null);

        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);

        // Execute
        String result = testMemoryService.setAddressDataType("invalid", "int", true).toStructuredJson();

        // Verify
        assertTrue(result.contains("\"message\":\"Invalid address: invalid\""));
        verify(mockProgram).endTransaction(1, false);
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

        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);

        // Create test service with null data type resolution
        TestDataTypeService mockTestDataTypeService = new TestDataTypeService(testProgramService) {
            @Override
            public DataType resolveDataType(DataTypeManager dtm, String typeName) {
                return null;
            }
        };
        TestMemoryService testMemoryServiceWithMock = new TestMemoryService(testProgramService, mockTestDataTypeService);

        // Execute
        String result = testMemoryServiceWithMock.setAddressDataType("0x1000", "unknown_type", true).toStructuredJson();

        // Verify
        assertTrue(result.contains("\"message\":\"Data type"));
        assertTrue(result.contains("unknown_type"));
        verify(mockProgram).endTransaction(1, false);
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

        // Mock address addition for row addresses
        when(mockDataAddr.add(0)).thenReturn(mockDataAddr);
    }

    @Test
    @DisplayName("readMemory hex format returns structured rows with byte arrays")
    void testReadMemory_Hex_Success() throws Exception {
        byte[] data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 5, "hex");
        assertTrue(result instanceof JsonOutput);

        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();
        assertEquals("00401000", memResult.address());
        assertEquals(5, memResult.size());
        assertEquals("hex", memResult.format());
        assertEquals(1, memResult.rows().size());

        ReadMemoryResult.MemoryRow row = memResult.rows().get(0);
        assertEquals("00401000", row.address());
        assertEquals(5, row.bytes().size());
        assertEquals("48", row.bytes().get(0));
        assertEquals("65", row.bytes().get(1));
        assertEquals("6C", row.bytes().get(2));
        assertEquals("6C", row.bytes().get(3));
        assertEquals("6F", row.bytes().get(4));
        assertEquals("Hello", row.ascii());
    }

    @Test
    @DisplayName("readMemory hex format shows non-printable chars as dots in ASCII")
    void testReadMemory_Hex_NonPrintableAscii() throws Exception {
        byte[] data = {0x00, 0x41, 0x1F, 0x7F};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 4, "hex");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        ReadMemoryResult.MemoryRow row = memResult.rows().get(0);
        assertEquals(".A..", row.ascii());
    }

    @Test
    @DisplayName("readMemory hex format splits into multiple rows at 16 bytes")
    void testReadMemory_Hex_MultipleRows() throws Exception {
        byte[] data = new byte[20];
        for (int i = 0; i < 20; i++) data[i] = (byte) i;
        setupReadMemoryMocks(data);

        Address row2Addr = mock(Address.class);
        when(row2Addr.toString()).thenReturn("00401010");
        when(mockDataAddr.add(16)).thenReturn(row2Addr);

        ToolOutput result = testMemoryService.readMemory("00401000", 20, "hex");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals(2, memResult.rows().size());
        assertEquals(16, memResult.rows().get(0).bytes().size());
        assertEquals("00401000", memResult.rows().get(0).address());
        assertEquals(4, memResult.rows().get(1).bytes().size());
        assertEquals("00401010", memResult.rows().get(1).address());
    }

    @Test
    @DisplayName("readMemory decimal format returns numeric string values")
    void testReadMemory_Decimal_Success() throws Exception {
        byte[] data = {0x00, (byte) 0xFF, 0x0A, 0x64};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 4, "decimal");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("decimal", memResult.format());
        assertEquals(1, memResult.rows().size());

        ReadMemoryResult.MemoryRow row = memResult.rows().get(0);
        assertEquals("0", row.bytes().get(0));
        assertEquals("255", row.bytes().get(1));
        assertEquals("10", row.bytes().get(2));
        assertEquals("100", row.bytes().get(3));
        assertEquals("...\u0064", row.ascii()); // 0x00='.', 0xFF='.', 0x0A='.', 0x64='d'
    }

    @Test
    @DisplayName("readMemory binary format returns 8-bit padded binary strings")
    void testReadMemory_Binary_Success() throws Exception {
        byte[] data = {0x00, 0x01, (byte) 0xFF, 0x0A};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 4, "binary");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("binary", memResult.format());
        assertEquals(1, memResult.rows().size());

        ReadMemoryResult.MemoryRow row = memResult.rows().get(0);
        assertEquals("00000000", row.bytes().get(0));
        assertEquals("00000001", row.bytes().get(1));
        assertEquals("11111111", row.bytes().get(2));
        assertEquals("00001010", row.bytes().get(3));
        assertNull(row.ascii());
    }

    @Test
    @DisplayName("readMemory ascii format returns individual character strings")
    void testReadMemory_Ascii_Success() throws Exception {
        byte[] data = {0x48, 0x69, 0x00, 0x0A, 0x0D, 0x09, (byte) 0x80};
        setupReadMemoryMocks(data);

        ToolOutput result = testMemoryService.readMemory("00401000", 7, "ascii");
        ReadMemoryResult memResult = (ReadMemoryResult) ((JsonOutput) result).data();

        assertEquals("ascii", memResult.format());
        assertEquals(1, memResult.rows().size());

        ReadMemoryResult.MemoryRow row = memResult.rows().get(0);
        assertEquals("H", row.bytes().get(0));
        assertEquals("i", row.bytes().get(1));
        assertEquals("\\0", row.bytes().get(2));
        assertEquals("\\n", row.bytes().get(3));
        assertEquals("\\r", row.bytes().get(4));
        assertEquals("\\t", row.bytes().get(5));
        assertEquals("\\x80", row.bytes().get(6));
        assertNull(row.ascii());
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
        assertTrue(display.contains("00401000:"));
        assertTrue(display.contains("48"));
        assertTrue(display.contains("Hi"));
    }
}