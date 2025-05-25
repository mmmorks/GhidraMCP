package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.anyString;
import org.mockito.Mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
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
    private TestMemoryService testMemoryService;
    private TestProgramService testProgramService;
    
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

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        memoryService = new MemoryService(programService);
        
        // Setup for happy path tests
        testProgramService = new TestProgramService(mockTool);
        testMemoryService = new TestMemoryService(testProgramService);
    }

    @Test
    @DisplayName("listSegments returns error when no program is loaded")
    void testListSegments_NoProgram() {
        String result = memoryService.listSegments(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listSegments handles negative offset")
    void testListSegments_NegativeOffset() {
        String result = memoryService.listSegments(-1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listSegments handles zero limit")
    void testListSegments_ZeroLimit() {
        String result = memoryService.listSegments(0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listDefinedData returns error when no program is loaded")
    void testListDefinedData_NoProgram() {
        String result = memoryService.listDefinedData(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listDefinedData handles negative offset")
    void testListDefinedData_NegativeOffset() {
        String result = memoryService.listDefinedData(-1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listDefinedData handles zero limit")
    void testListDefinedData_ZeroLimit() {
        String result = memoryService.listDefinedData(0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameDataAtAddress returns false when no program is loaded")
    void testRenameDataAtAddress_NoProgram() {
        boolean result = memoryService.renameDataAtAddress("0x1000", "newName");
        assertFalse(result);
    }

    @Test
    @DisplayName("renameDataAtAddress returns false for null address")
    void testRenameDataAtAddress_NullAddress() {
        boolean result = memoryService.renameDataAtAddress(null, "newName");
        assertFalse(result);
    }

    @Test
    @DisplayName("renameDataAtAddress returns false for empty address")
    void testRenameDataAtAddress_EmptyAddress() {
        boolean result = memoryService.renameDataAtAddress("", "newName");
        assertFalse(result);
    }

    @Test
    @DisplayName("renameDataAtAddress returns false for null name")
    void testRenameDataAtAddress_NullName() {
        boolean result = memoryService.renameDataAtAddress("0x1000", null);
        assertFalse(result);
    }

    @Test
    @DisplayName("renameDataAtAddress returns false for empty name")
    void testRenameDataAtAddress_EmptyName() {
        boolean result = memoryService.renameDataAtAddress("0x1000", "");
        assertFalse(result);
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
    @DisplayName("listSegments returns memory blocks when program is loaded")
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
        String result = testMemoryService.listSegments(0, 10);
        
        // Verify
        assertTrue(result.contains(".text: 00400000 - 00401000"));
        assertTrue(result.contains(".data: 00402000 - 00403000"));
    }
    
    @Test
    @DisplayName("listSegments respects pagination limits")
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
        String result = testMemoryService.listSegments(0, 1);
        
        // Verify - should only contain first block
        assertTrue(result.contains(".text: 00400000 - 00401000"));
        assertFalse(result.contains(".data: 00402000 - 00403000"));
    }
    
    @Test
    @DisplayName("listDefinedData returns data items when program is loaded")
    void testListDefinedData_Success() {
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
        String result = testMemoryService.listDefinedData(0, 10);
        
        // Verify
        assertTrue(result.contains("00400100: myVariable = 0x42"));
    }
    
    @Test
    @DisplayName("listDefinedData handles unnamed data")
    void testListDefinedData_UnnamedData() {
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
        String result = testMemoryService.listDefinedData(0, 10);
        
        // Verify
        assertTrue(result.contains("00400200: (unnamed) = 0xFF"));
    }
    
    @Test
    @DisplayName("renameDataAtAddress successfully renames existing symbol")
    void testRenameDataAtAddress_ExistingSymbol_Success() throws Exception {
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
        boolean result = testMemoryService.renameDataAtAddress("0x1000", "newName");
        
        // Verify
        assertTrue(result);
        verify(mockSymbol).setName("newName", SourceType.USER_DEFINED);
        verify(mockProgram).endTransaction(1, true);
    }
    
    @Test
    @DisplayName("renameDataAtAddress creates new label when no symbol exists")
    void testRenameDataAtAddress_NoSymbol_CreatesLabel() throws Exception {
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
        boolean result = testMemoryService.renameDataAtAddress("0x2000", "brandNewLabel");
        
        // Verify
        assertTrue(result);
        verify(mockSymbolTable).createLabel(mockDataAddr, "brandNewLabel", SourceType.USER_DEFINED);
        verify(mockProgram).endTransaction(1, true);
    }
    
    @Test
    @DisplayName("renameDataAtAddress returns false for invalid address")
    void testRenameDataAtAddress_InvalidAddress() {
        // Setup mocks
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        
        // Mock invalid address
        when(mockAddressFactory.getAddress("invalid")).thenReturn(null);
        
        // Mock transaction
        when(mockProgram.startTransaction(anyString())).thenReturn(1);
        
        // Execute
        boolean result = testMemoryService.renameDataAtAddress("invalid", "newName");
        
        // Verify
        assertFalse(result);
        verify(mockProgram).endTransaction(1, false);
    }
    
    @Test
    @DisplayName("renameDataAtAddress returns false when no data at address")
    void testRenameDataAtAddress_NoDataAtAddress() {
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
        boolean result = testMemoryService.renameDataAtAddress("0x3000", "newName");
        
        // Verify
        assertFalse(result);
        verify(mockProgram).endTransaction(1, false);
    }
}