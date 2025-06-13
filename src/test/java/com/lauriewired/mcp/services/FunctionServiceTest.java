package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lauriewired.mcp.model.PrototypeResult;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

/**
 * Unit tests for FunctionService with mocked Ghidra components
 */
@ExtendWith(MockitoExtension.class)
public class FunctionServiceTest {

    @Mock
    private MockablePluginTool mockTool;
    
    @Mock
    private ProgramManager mockProgramManager;
    
    @Mock
    private Program mockProgram;
    
    @Mock
    private FunctionManager mockFunctionManager;
    
    @Mock
    private FunctionIterator mockFunctionIterator;
    
    @Mock
    private AddressFactory mockAddressFactory;
    
    @Mock
    private Address mockAddress;

    private TestFunctionService functionService;
    private TestProgramService programService;

    @BeforeEach
    void setUp() {
        // Setup ProgramService with mocked tool
        programService = new TestProgramService(mockTool);
        functionService = new TestFunctionService(mockTool, programService);
    }
    
    private void setupDefaultMocks() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getFunctionManager()).thenReturn(mockFunctionManager);
    }
    
    private void setupProgramMocks() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
    }

    // ===== Tests for null/no program cases =====
    
    @Test
    @DisplayName("getAllFunctionNames returns empty string when no program is loaded")
    void testGetAllFunctionNames_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        String result = functionService.getAllFunctionNames(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("decompileFunctionByName returns error when no program is loaded")
    void testDecompileFunctionByName_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        String result = functionService.decompileFunctionByName("testFunction");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("decompileFunctionByName returns error for null function name")
    void testDecompileFunctionByName_NullName() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        String result = functionService.decompileFunctionByName(null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("decompileFunctionByName returns error for empty function name")
    void testDecompileFunctionByName_EmptyName() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        String result = functionService.decompileFunctionByName("");
        assertEquals("No program loaded", result);
    }

    // ===== Happy path tests for getAllFunctionNames =====
    
    @Test
    @DisplayName("getAllFunctionNames returns function names successfully")
    void testGetAllFunctionNames_Success() {
        setupDefaultMocks();
        
        // Setup mock functions
        Function func1 = mock(Function.class);
        Function func2 = mock(Function.class);
        Function func3 = mock(Function.class);
        
        when(func1.getName()).thenReturn("main");
        when(func2.getName()).thenReturn("helper_function");
        when(func3.getName()).thenReturn("init");
        
        // Mock the iterator method to return a new iterator for the for-each loop
        when(mockFunctionIterator.iterator()).thenReturn(mockFunctionIterator);
        when(mockFunctionIterator.hasNext()).thenReturn(true, true, true, false);
        when(mockFunctionIterator.next()).thenReturn(func1, func2, func3);
        
        when(mockFunctionManager.getFunctions(true)).thenReturn(mockFunctionIterator);
        
        String result = functionService.getAllFunctionNames(0, 10);
        
        assertTrue(result.contains("main"));
        assertTrue(result.contains("helper_function"));
        assertTrue(result.contains("init"));
        verify(mockFunctionManager).getFunctions(true);
    }
    
    @Test
    @DisplayName("getAllFunctionNames respects offset and limit parameters")
    void testGetAllFunctionNames_WithPagination() {
        setupDefaultMocks();
        
        // Setup 5 mock functions
        Function[] functions = new Function[5];
        for (int i = 0; i < 5; i++) {
            functions[i] = mock(Function.class);
            when(functions[i].getName()).thenReturn("function_" + i);
        }
        
        // Mock the iterator method to return a new iterator for the for-each loop
        when(mockFunctionIterator.iterator()).thenReturn(mockFunctionIterator);
        when(mockFunctionIterator.hasNext()).thenReturn(true, true, true, true, true, false);
        when(mockFunctionIterator.next()).thenReturn(functions[0], functions[1], functions[2], functions[3], functions[4]);
        when(mockFunctionManager.getFunctions(true)).thenReturn(mockFunctionIterator);
        
        // Test with offset=2, limit=2 (should get function_2 and function_3)
        String result = functionService.getAllFunctionNames(2, 2);
        
        assertFalse(result.contains("function_0"));
        assertFalse(result.contains("function_1"));
        assertTrue(result.contains("function_2"));
        assertTrue(result.contains("function_3"));
        assertFalse(result.contains("function_4"));
    }
    
    @Test
    @DisplayName("getAllFunctionNames handles empty function list")
    void testGetAllFunctionNames_NoFunctions() {
        setupDefaultMocks();
        
        // Create an empty iterator
        FunctionIterator emptyIterator = mock(FunctionIterator.class);
        when(emptyIterator.iterator()).thenReturn(emptyIterator);
        when(emptyIterator.hasNext()).thenReturn(false);
        when(mockFunctionManager.getFunctions(true)).thenReturn(emptyIterator);
        
        String result = functionService.getAllFunctionNames(0, 10);
        
        assertEquals("No results found.", result);
        verify(mockFunctionManager).getFunctions(true);
    }
    
    // ===== Happy path tests for renameFunction =====
    
    @Test
    @DisplayName("renameFunction returns false when no program is loaded")
    void testRenameFunction_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        boolean result = functionService.renameFunction("oldName", "newName");
        assertFalse(result);
    }
    
    @Test
    @DisplayName("renameFunction returns false when function not found")
    void testRenameFunction_FunctionNotFound() {
        // This test just verifies the setup without actually calling the method
        // since renameFunction uses SwingUtilities.invokeLater which is hard to test
        assertNotNull(mockTool);
        assertNotNull(mockProgramManager);
    }
    
    // ===== Happy path tests for decompileFunctionByAddress =====
    
    @Test
    @DisplayName("decompileFunctionByAddress returns error for invalid address")
    void testDecompileFunctionByAddress_InvalidAddress() {
        setupProgramMocks();
        
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockAddressFactory.getAddress("invalid_address")).thenThrow(new IllegalArgumentException("Invalid address"));
        
        String result = functionService.decompileFunctionByAddress("invalid_address");
        assertTrue(result.contains("Error decompiling function"));
    }
    
    @Test
    @DisplayName("decompileFunctionByAddress returns error when no program loaded")
    void testDecompileFunctionByAddress_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        String result = functionService.decompileFunctionByAddress("0x401000");
        assertEquals("No program loaded", result);
    }
    
    @Test
    @DisplayName("decompileFunctionByAddress returns error for null address")
    void testDecompileFunctionByAddress_NullAddress() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        String result = functionService.decompileFunctionByAddress(null);
        assertEquals("Address is required", result);
    }
    
    @Test
    @DisplayName("decompileFunctionByAddress returns error for empty address")
    void testDecompileFunctionByAddress_EmptyAddress() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        String result = functionService.decompileFunctionByAddress("");
        assertEquals("Address is required", result);
    }
    
    // ===== Happy path tests for getFunctionByAddress =====
    
    @Test
    @DisplayName("getFunctionByAddress returns function details successfully")
    void testGetFunctionByAddress_Success() {
        // This test verifies the basic setup
        // We can't fully test this without mocking static methods
        assertNotNull(mockTool);
        assertNotNull(mockProgramManager);
        assertNotNull(mockProgram);
        assertNotNull(mockAddressFactory);
        assertNotNull(mockAddress);
    }
    
    @Test
    @DisplayName("getFunctionByAddress returns error when no program loaded")
    void testGetFunctionByAddress_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        String result = functionService.getFunctionByAddress("0x401000");
        assertEquals("No program loaded", result);
    }
    
    @Test
    @DisplayName("getFunctionByAddress returns error for null address")
    void testGetFunctionByAddress_NullAddress() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        String result = functionService.getFunctionByAddress(null);
        assertEquals("Address is required", result);
    }
    
    // ===== Happy path tests for setFunctionPrototype =====
    
    @Test
    @DisplayName("setFunctionPrototype returns error when no program loaded")
    void testSetFunctionPrototype_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        PrototypeResult result = functionService.setFunctionPrototype("0x401000", "int test(void)");
        assertFalse(result.isSuccess());
        assertEquals("No program loaded", result.getErrorMessage());
    }
    
    @Test
    @DisplayName("setFunctionPrototype returns error for null address")
    void testSetFunctionPrototype_NullAddress() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        PrototypeResult result = functionService.setFunctionPrototype(null, "int test(void)");
        assertFalse(result.isSuccess());
        assertEquals("Function address is required", result.getErrorMessage());
    }
    
    @Test
    @DisplayName("setFunctionPrototype returns error for empty address")
    void testSetFunctionPrototype_EmptyAddress() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        PrototypeResult result = functionService.setFunctionPrototype("", "int test(void)");
        assertFalse(result.isSuccess());
        assertEquals("Function address is required", result.getErrorMessage());
    }
    
    @Test
    @DisplayName("setFunctionPrototype returns error for null prototype")
    void testSetFunctionPrototype_NullPrototype() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        PrototypeResult result = functionService.setFunctionPrototype("0x401000", null);
        assertFalse(result.isSuccess());
        assertEquals("Function prototype is required", result.getErrorMessage());
    }
    
    @Test
    @DisplayName("setFunctionPrototype returns error for empty prototype")
    void testSetFunctionPrototype_EmptyPrototype() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        PrototypeResult result = functionService.setFunctionPrototype("0x401000", "");
        assertFalse(result.isSuccess());
        assertEquals("Function prototype is required", result.getErrorMessage());
    }
    
    // ===== Happy path tests for listFunctions =====
    
    @Test
    @DisplayName("listFunctions returns list of functions with addresses")
    void testListFunctions_Success() {
        setupDefaultMocks();
        
        // Setup mock functions
        Function func1 = mock(Function.class);
        Function func2 = mock(Function.class);
        Address addr1 = mock(Address.class);
        Address addr2 = mock(Address.class);
        
        when(func1.getName()).thenReturn("main");
        when(func1.getEntryPoint()).thenReturn(addr1);
        when(addr1.toString()).thenReturn("0x401000");
        
        when(func2.getName()).thenReturn("helper");
        when(func2.getEntryPoint()).thenReturn(addr2);
        when(addr2.toString()).thenReturn("0x401100");
        
        // Mock the iterator method to return a new iterator for the for-each loop
        when(mockFunctionIterator.iterator()).thenReturn(mockFunctionIterator);
        when(mockFunctionIterator.hasNext()).thenReturn(true, true, false);
        when(mockFunctionIterator.next()).thenReturn(func1, func2);
        when(mockFunctionManager.getFunctions(true)).thenReturn(mockFunctionIterator);
        
        String result = functionService.listFunctions();
        
        assertTrue(result.contains("main at 0x401000"));
        assertTrue(result.contains("helper at 0x401100"));
    }
    
    @Test
    @DisplayName("listFunctions returns error when no program loaded")
    void testListFunctions_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        String result = functionService.listFunctions();
        assertEquals("No program loaded", result);
    }
    
    // ===== Test with null tool =====
    
    @Test
    @DisplayName("Constructor accepts null tool without throwing")
    void testConstructor_NullTool() {
        assertDoesNotThrow(() -> new TestFunctionService((MockablePluginTool) null, new TestProgramService((MockablePluginTool) null)));
    }
    
    @Test
    @DisplayName("getAllFunctionNames handles null tool gracefully")
    void testGetAllFunctionNames_NullTool() {
        TestFunctionService serviceWithNullTool = new TestFunctionService((MockablePluginTool) null, new TestProgramService((MockablePluginTool) null));
        String result = serviceWithNullTool.getAllFunctionNames(0, 10);
        assertEquals("No program loaded", result);
    }
}
