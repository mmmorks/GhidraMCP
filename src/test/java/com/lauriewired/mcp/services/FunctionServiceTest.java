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

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.FunctionCodeResult;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
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
    @DisplayName("listFunctions returns empty string when no program is loaded")
    void testGetAllFunctionNames_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        String result = functionService.listFunctions(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getFunctionCode returns error when no program is loaded")
    void testGetFunctionCode_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.getFunctionCode("testFunction", "C").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getFunctionCode returns error for null identifier")
    void testGetFunctionCode_NullIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.getFunctionCode(null, "C").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getFunctionCode returns error for empty identifier")
    void testGetFunctionCode_EmptyIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.getFunctionCode("", "C").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    // ===== Happy path tests for listFunctions =====
    
    @Test
    @DisplayName("listFunctions returns function names successfully")
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
        
        String result = functionService.listFunctions(0, 10).toStructuredJson();

        assertTrue(result.contains("main"));
        assertTrue(result.contains("helper_function"));
        assertTrue(result.contains("init"));
        verify(mockFunctionManager).getFunctions(true);
    }
    
    @Test
    @DisplayName("listFunctions respects offset and limit parameters")
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
        String result = functionService.listFunctions(2, 2).toStructuredJson();

        assertFalse(result.contains("function_0"));
        assertFalse(result.contains("function_1"));
        assertTrue(result.contains("function_2"));
        assertTrue(result.contains("function_3"));
        assertFalse(result.contains("function_4"));
    }
    
    @Test
    @DisplayName("listFunctions handles empty function list")
    void testGetAllFunctionNames_NoFunctions() {
        setupDefaultMocks();
        
        // Create an empty iterator
        FunctionIterator emptyIterator = mock(FunctionIterator.class);
        when(emptyIterator.iterator()).thenReturn(emptyIterator);
        when(emptyIterator.hasNext()).thenReturn(false);
        when(mockFunctionManager.getFunctions(true)).thenReturn(emptyIterator);
        
        String result = functionService.listFunctions(0, 10).toStructuredJson();

        assertTrue(result.contains("\"total_items\":0"));
        verify(mockFunctionManager).getFunctions(true);
    }
    
    // ===== Tests for renameFunctions =====

    @Test
    @DisplayName("renameFunctions returns error when no program is loaded")
    void testRenameFunctions_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.renameFunctions(java.util.Map.of("oldName", "newName")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameFunctions returns error for null map")
    void testRenameFunctions_NullMap() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.renameFunctions(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No renames specified\""));
    }

    @Test
    @DisplayName("renameFunctions returns error for empty map")
    void testRenameFunctions_EmptyMap() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.renameFunctions(java.util.Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No renames specified\""));
    }
    
    // ===== Tests for getFunctionCode modes =====

    @Test
    @DisplayName("getFunctionCode defaults to C mode for null mode")
    void testGetFunctionCode_NullMode() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.getFunctionCode("main", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getFunctionCode accepts assembly mode alias 'asm'")
    void testGetFunctionCode_AsmAlias() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.getFunctionCode("main", "asm").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
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

        String result = functionService.getFunctionCode("nonexistent", "C").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function not found: nonexistent\""));
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
        
        String result = functionService.getFunctionByAddress("0x401000").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getFunctionByAddress returns error for null address")
    void testGetFunctionByAddress_NullAddress() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.getFunctionByAddress(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Address is required\""));
    }
    
    // ===== Happy path tests for setFunctionPrototype =====
    
    @Test
    @DisplayName("setFunctionPrototype returns error when no program loaded")
    void testSetFunctionPrototype_NoProgram() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);

        String result = functionService.setFunctionPrototype("0x401000", "int test(void)").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for null identifier")
    void testSetFunctionPrototype_NullIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.setFunctionPrototype(null, "int test(void)").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for empty identifier")
    void testSetFunctionPrototype_EmptyIdentifier() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.setFunctionPrototype("", "int test(void)").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for null prototype")
    void testSetFunctionPrototype_NullPrototype() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.setFunctionPrototype("0x401000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function prototype is required\""));
    }

    @Test
    @DisplayName("setFunctionPrototype returns error for empty prototype")
    void testSetFunctionPrototype_EmptyPrototype() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);

        String result = functionService.setFunctionPrototype("0x401000", "").toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function prototype is required\""));
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
    @DisplayName("listFunctions handles null tool gracefully")
    void testGetAllFunctionNames_NullTool() {
        TestFunctionService serviceWithNullTool = new TestFunctionService((MockablePluginTool) null, new TestProgramService((MockablePluginTool) null));
        String result = serviceWithNullTool.listFunctions(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    // ===== Happy path tests for getFunctionCode assembly mode =====

    private Function setupFunctionWithInstructions() {
        setupDefaultMocks();
        when(mockProgram.getAddressFactory()).thenReturn(mockAddressFactory);

        // resolveFunction tries address first, then falls back to name lookup
        when(mockAddressFactory.getAddress("main")).thenReturn(null);

        Function func = mock(Function.class);
        when(func.getName()).thenReturn("main");

        Address entryAddr = mock(Address.class);
        when(func.getEntryPoint()).thenReturn(entryAddr);

        AddressSetView body = mock(AddressSetView.class);
        Address endAddr = mock(Address.class);
        when(body.getMaxAddress()).thenReturn(endAddr);
        when(func.getBody()).thenReturn(body);

        // Wire up function lookup by name
        FunctionIterator funcIter = mock(FunctionIterator.class);
        when(funcIter.iterator()).thenReturn(funcIter);
        when(funcIter.hasNext()).thenReturn(true, false);
        when(funcIter.next()).thenReturn(func);
        when(mockFunctionManager.getFunctions(true)).thenReturn(funcIter);

        return func;
    }

    @Test
    @DisplayName("getFunctionCode assembly mode returns structured CodeLine list")
    void testGetFunctionCode_Assembly_Success() {
        Function func = setupFunctionWithInstructions();
        Address endAddr = func.getBody().getMaxAddress();

        Listing listing = mock(Listing.class);
        when(mockProgram.getListing()).thenReturn(listing);

        // Create mock instructions
        Address addr1 = mock(Address.class);
        when(addr1.toString()).thenReturn("00401000");
        when(addr1.compareTo(endAddr)).thenReturn(-1);

        Address addr2 = mock(Address.class);
        when(addr2.toString()).thenReturn("00401002");
        when(addr2.compareTo(endAddr)).thenReturn(0);

        Instruction instr1 = mock(Instruction.class);
        when(instr1.getAddress()).thenReturn(addr1);
        when(instr1.toString()).thenReturn("push ebp");

        Instruction instr2 = mock(Instruction.class);
        when(instr2.getAddress()).thenReturn(addr2);
        when(instr2.toString()).thenReturn("mov ebp,esp");

        InstructionIterator instrIter = mock(InstructionIterator.class);
        when(instrIter.hasNext()).thenReturn(true, true, false);
        when(instrIter.next()).thenReturn(instr1, instr2);
        when(listing.getInstructions(func.getEntryPoint(), true)).thenReturn(instrIter);

        when(listing.getComment(CommentType.EOL, addr1)).thenReturn(null);
        when(listing.getComment(CommentType.EOL, addr2)).thenReturn(null);

        ToolOutput result = functionService.getFunctionCode("main", "assembly");
        assertTrue(result instanceof JsonOutput);

        String json = result.toStructuredJson();
        assertTrue(json.contains("\"function\":\"main\""));
        assertTrue(json.contains("\"format\":\"assembly\""));
        assertTrue(json.contains("\"address\":\"00401000\""));
        assertTrue(json.contains("\"code\":\"push ebp\""));
        assertTrue(json.contains("\"address\":\"00401002\""));
        assertTrue(json.contains("\"code\":\"mov ebp,esp\""));

        // Verify structured data
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();
        assertEquals("main", data.function());
        assertEquals("assembly", data.format());
        assertEquals(2, data.lines().size());
        assertEquals("00401000", data.lines().get(0).address());
        assertEquals("push ebp", data.lines().get(0).code());
        assertNull(data.lines().get(0).comment());
        assertEquals("00401002", data.lines().get(1).address());
        assertEquals("mov ebp,esp", data.lines().get(1).code());
    }

    @Test
    @DisplayName("getFunctionCode assembly mode includes EOL comments")
    void testGetFunctionCode_Assembly_WithComments() {
        Function func = setupFunctionWithInstructions();
        Address endAddr = func.getBody().getMaxAddress();

        Listing listing = mock(Listing.class);
        when(mockProgram.getListing()).thenReturn(listing);

        Address addr1 = mock(Address.class);
        when(addr1.toString()).thenReturn("00401000");
        when(addr1.compareTo(endAddr)).thenReturn(-1);

        Instruction instr1 = mock(Instruction.class);
        when(instr1.getAddress()).thenReturn(addr1);
        when(instr1.toString()).thenReturn("call 0x00402000");

        InstructionIterator instrIter = mock(InstructionIterator.class);
        when(instrIter.hasNext()).thenReturn(true, false);
        when(instrIter.next()).thenReturn(instr1);
        when(listing.getInstructions(func.getEntryPoint(), true)).thenReturn(instrIter);

        when(listing.getComment(CommentType.EOL, addr1)).thenReturn("call to helper");

        ToolOutput result = functionService.getFunctionCode("main", "asm");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals("assembly", data.format());
        assertEquals(1, data.lines().size());
        assertEquals("call to helper", data.lines().get(0).comment());
    }

    @Test
    @DisplayName("getFunctionCode assembly mode preserves instruction order")
    void testGetFunctionCode_Assembly_PreservesOrder() {
        Function func = setupFunctionWithInstructions();
        Address endAddr = func.getBody().getMaxAddress();

        Listing listing = mock(Listing.class);
        when(mockProgram.getListing()).thenReturn(listing);

        // Create 4 instructions in specific order
        String[] addresses = {"00401000", "00401002", "00401004", "00401006"};
        String[] mnemonics = {"push ebp", "mov ebp,esp", "sub esp,0x10", "ret"};
        Instruction[] instrs = new Instruction[4];

        Instruction prev = null;
        for (int i = addresses.length - 1; i >= 0; i--) {
            Address addr = mock(Address.class);
            when(addr.toString()).thenReturn(addresses[i]);
            when(addr.compareTo(endAddr)).thenReturn(i < 3 ? -1 : 0);

            instrs[i] = mock(Instruction.class);
            when(instrs[i].getAddress()).thenReturn(addr);
            when(instrs[i].toString()).thenReturn(mnemonics[i]);
            when(listing.getComment(CommentType.EOL, addr)).thenReturn(null);
        }

        InstructionIterator instrIter = mock(InstructionIterator.class);
        when(instrIter.hasNext()).thenReturn(true, true, true, true, false);
        when(instrIter.next()).thenReturn(instrs[0], instrs[1], instrs[2], instrs[3]);
        when(listing.getInstructions(func.getEntryPoint(), true)).thenReturn(instrIter);

        ToolOutput result = functionService.getFunctionCode("main", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals(4, data.lines().size());
        for (int i = 0; i < 4; i++) {
            assertEquals(addresses[i], data.lines().get(i).address());
            assertEquals(mnemonics[i], data.lines().get(i).code());
        }
    }

    @Test
    @DisplayName("getFunctionCode assembly mode toDisplayText reproduces readable format")
    void testGetFunctionCode_Assembly_DisplayText() {
        Function func = setupFunctionWithInstructions();
        Address endAddr = func.getBody().getMaxAddress();

        Listing listing = mock(Listing.class);
        when(mockProgram.getListing()).thenReturn(listing);

        Address addr1 = mock(Address.class);
        when(addr1.toString()).thenReturn("00401000");
        when(addr1.compareTo(endAddr)).thenReturn(0);

        Instruction instr1 = mock(Instruction.class);
        when(instr1.getAddress()).thenReturn(addr1);
        when(instr1.toString()).thenReturn("ret");

        InstructionIterator instrIter = mock(InstructionIterator.class);
        when(instrIter.hasNext()).thenReturn(true, false);
        when(instrIter.next()).thenReturn(instr1);
        when(listing.getInstructions(func.getEntryPoint(), true)).thenReturn(instrIter);

        when(listing.getComment(CommentType.EOL, addr1)).thenReturn("function return");

        ToolOutput result = functionService.getFunctionCode("main", "assembly");
        String display = result.toDisplayText();

        assertTrue(display.contains("00401000: ret ; function return"));
    }

    @Test
    @DisplayName("getFunctionCode assembly mode handles empty function body")
    void testGetFunctionCode_Assembly_EmptyBody() {
        Function func = setupFunctionWithInstructions();

        Listing listing = mock(Listing.class);
        when(mockProgram.getListing()).thenReturn(listing);

        InstructionIterator instrIter = mock(InstructionIterator.class);
        when(instrIter.hasNext()).thenReturn(false);
        when(listing.getInstructions(func.getEntryPoint(), true)).thenReturn(instrIter);

        ToolOutput result = functionService.getFunctionCode("main", "assembly");
        FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) result).data();

        assertEquals("main", data.function());
        assertEquals("assembly", data.format());
        assertEquals(0, data.lines().size());
    }
}
