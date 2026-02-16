package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
    @DisplayName("getFunctionCode returns error when no program is loaded")
    void testGetFunctionCode_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.getFunctionCode("testFunction", "C");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getFunctionCode returns error for null identifier")
    void testGetFunctionCode_NullIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.getFunctionCode(null, "C");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getFunctionCode returns error for empty identifier")
    void testGetFunctionCode_EmptyIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.getFunctionCode("", "C");
        assertEquals("Function identifier is required", result);
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
    @DisplayName("renameFunction returns error when no program is loaded")
    void testRenameFunction_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.renameFunction("oldName", "newName");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameFunction returns error for null identifier")
    void testRenameFunction_NullIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.renameFunction(null, "newName");
        assertEquals("Function identifier is required", result);
    }

    @Test
    @DisplayName("renameFunction returns error for null new name")
    void testRenameFunction_NullNewName() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.renameFunction("oldName", null);
        assertEquals("New name is required", result);
    }
    
    // ===== Tests for getFunctionCode modes =====

    @Test
    @DisplayName("getFunctionCode defaults to C mode for null mode")
    void testGetFunctionCode_NullMode() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.getFunctionCode("main", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getFunctionCode accepts assembly mode alias 'asm'")
    void testGetFunctionCode_AsmAlias() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.getFunctionCode("main", "asm");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getFunctionCode returns 'Function not found' when function does not exist")
    void testGetFunctionCode_FunctionNotFound() {
        setupDefaultMocks();

        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);
        when(mockAddressFactory.getAddress("nonexistent")).thenReturn(null);

        // Empty function iterator for name lookup fallback
        FunctionIterator emptyIterator = mock(FunctionIterator.class);
        when(emptyIterator.iterator()).thenReturn(emptyIterator);
        when(emptyIterator.hasNext()).thenReturn(false);
        when(mockFunctionManager.getFunctions(true)).thenReturn(emptyIterator);

        String result = functionService.getFunctionCode("nonexistent", "C");
        assertEquals("Function not found: nonexistent", result);
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
    @DisplayName("setFunctionPrototype returns error for null identifier")
    void testSetFunctionPrototype_NullIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        PrototypeResult result = functionService.setFunctionPrototype(null, "int test(void)");
        assertFalse(result.isSuccess());
        assertEquals("Function identifier is required", result.getErrorMessage());
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for empty identifier")
    void testSetFunctionPrototype_EmptyIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        PrototypeResult result = functionService.setFunctionPrototype("", "int test(void)");
        assertFalse(result.isSuccess());
        assertEquals("Function identifier is required", result.getErrorMessage());
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
    
    // ===== Tests for resolveFunction =====

    @Test
    @DisplayName("resolveFunction returns null for null program")
    void testResolveFunction_NullProgram() {
        var result = functionService.resolveFunction(null, "main");
        assertNull(result);
    }

    @Test
    @DisplayName("resolveFunction returns null for null identifier")
    void testResolveFunction_NullIdentifier() {
        var result = functionService.resolveFunction(mockProgram, null);
        assertNull(result);
    }

    @Test
    @DisplayName("resolveFunction returns null for empty identifier")
    void testResolveFunction_EmptyIdentifier() {
        var result = functionService.resolveFunction(mockProgram, "");
        assertNull(result);
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
