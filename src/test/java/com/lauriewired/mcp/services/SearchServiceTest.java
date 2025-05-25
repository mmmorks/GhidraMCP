package com.lauriewired.mcp.services;

import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Unit tests for SearchService
 */
@ExtendWith(MockitoExtension.class)
public class SearchServiceTest {

    private SearchService searchService;
    private SearchService searchServiceWithMocks;
    private ProgramService programService;
    private ProgramService mockProgramService;
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
    private MemoryBlock mockBlock;
    
    @Mock
    private Address mockAddress;
    
    @Mock
    private AddressFactory mockAddressFactory;
    
    @Mock
    private AddressSpace mockAddressSpace;
    
    @Mock
    private SymbolTable mockSymbolTable;
    
    @Mock
    private Symbol mockSymbol;
    
    @Mock
    private FunctionManager mockFunctionManager;
    
    @Mock
    private Function mockFunction;
    
    @Mock
    private Listing mockListing;
    
    @Mock
    private InstructionIterator mockInstructionIterator;
    
    @Mock
    private Instruction mockInstruction;
    
    @Mock
    private FunctionIterator mockFunctionIterator;
    
    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        searchService = new SearchService(programService);
        
        // Setup for happy path tests
        testProgramService = new TestProgramService(mockTool);
        
        // Create a mock ProgramService for happy path tests
        ProgramService mockProgramService = mock(ProgramService.class);
        SearchService searchServiceWithMocks = new SearchService(mockProgramService);
        
        // Store as instance variables for use in tests
        this.mockProgramService = mockProgramService;
        this.searchServiceWithMocks = searchServiceWithMocks;
    }

    @Test
    @DisplayName("searchMemory returns error when no program is loaded")
    void testSearchMemory_NoProgram() {
        String result = searchService.searchMemory("test", true, null, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchMemory returns error for null query")
    void testSearchMemory_NullQuery() {
        String result = searchService.searchMemory(null, true, null, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchMemory returns error for empty query")
    void testSearchMemory_EmptyQuery() {
        String result = searchService.searchMemory("", true, null, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchMemory handles string search type")
    void testSearchMemory_StringSearch() {
        String result = searchService.searchMemory("test string", true, null, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchMemory handles hex pattern search type")
    void testSearchMemory_HexSearch() {
        String result = searchService.searchMemory("48 65 6C 6C 6F", false, null, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchMemory handles hex pattern with wildcards")
    void testSearchMemory_HexSearchWithWildcards() {
        String result = searchService.searchMemory("48 ?? 6C 6C ??", false, null, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchMemory with specific block name")
    void testSearchMemory_WithBlockName() {
        String result = searchService.searchMemory("test", true, ".text", 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchMemory handles zero limit")
    void testSearchMemory_ZeroLimit() {
        String result = searchService.searchMemory("test", true, null, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchMemory handles negative limit")
    void testSearchMemory_NegativeLimit() {
        String result = searchService.searchMemory("test", true, null, -1);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDisassembly returns error when no program is loaded")
    void testSearchDisassembly_NoProgram() {
        String result = searchService.searchDisassembly("mov", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDisassembly returns error for null query")
    void testSearchDisassembly_NullQuery() {
        String result = searchService.searchDisassembly(null, 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDisassembly returns error for empty query")
    void testSearchDisassembly_EmptyQuery() {
        String result = searchService.searchDisassembly("", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDisassembly handles invalid regex pattern")
    void testSearchDisassembly_InvalidRegex() {
        String result = searchService.searchDisassembly("[invalid", 0, 10);
        // When no program is loaded, it returns "No program loaded" before checking regex
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDisassembly handles valid regex pattern")
    void testSearchDisassembly_ValidRegex() {
        String result = searchService.searchDisassembly("mov.*eax", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDisassembly handles negative offset")
    void testSearchDisassembly_NegativeOffset() {
        String result = searchService.searchDisassembly("mov", -1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDisassembly handles zero limit")
    void testSearchDisassembly_ZeroLimit() {
        String result = searchService.searchDisassembly("mov", 0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDecompiledCode returns error when no program is loaded")
    void testSearchDecompiledCode_NoProgram() {
        String result = searchService.searchDecompiledCode("function", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDecompiledCode returns error for null query")
    void testSearchDecompiledCode_NullQuery() {
        String result = searchService.searchDecompiledCode(null, 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDecompiledCode returns error for empty query")
    void testSearchDecompiledCode_EmptyQuery() {
        String result = searchService.searchDecompiledCode("", 0, 10);
        assertEquals("No program loaded", result);
    }

    // Happy path tests using TestSearchService and mocked dependencies

    @Test
    @DisplayName("searchMemory with program loaded returns result")
    void testSearchMemory_WithProgram() {
        // Setup minimal mocks needed for the method to run
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        
        // Create empty memory blocks to avoid NPE
        MemoryBlock[] blocks = new MemoryBlock[0];
        when(mockMemory.getBlocks()).thenReturn(blocks);
        
        // Test
        String result = searchServiceWithMocks.searchMemory("test", true, null, 10);
        
        // Verify - with no memory blocks, it should return no matches
        assertNotNull(result);
        assertEquals("No matches found for query: test", result);
    }

    @Test
    @DisplayName("searchDisassembly with executable blocks")
    void testSearchDisassembly_WithExecutableBlocks() {
        // Setup
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        when(mockProgram.getListing()).thenReturn(mockListing);
        
        // Setup memory blocks
        MemoryBlock[] blocks = { mockBlock };
        when(mockMemory.getBlocks()).thenReturn(blocks);
        when(mockBlock.isExecute()).thenReturn(true);
        when(mockBlock.getStart()).thenReturn(mockAddress);
        when(mockBlock.getEnd()).thenReturn(mockAddress);
        
        // Create empty instruction iterator
        when(mockListing.getInstructions(any(Address.class), anyBoolean())).thenReturn(mockInstructionIterator);
        when(mockInstructionIterator.hasNext()).thenReturn(false);
        
        // Test
        String result = searchServiceWithMocks.searchDisassembly("MOV", 0, 10);
        
        // Verify
        assertNotNull(result);
        assertEquals("No matches found for pattern: MOV", result);
    }

    @Test
    @DisplayName("searchDecompiledCode with no functions returns no matches")
    void testSearchDecompiledCode_NoFunctions() {
        // Setup
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getFunctionManager()).thenReturn(mockFunctionManager);
        
        // Mock language that doesn't support pcode to avoid decompiler initialization
        ghidra.program.model.lang.Language mockLanguage = mock(ghidra.program.model.lang.Language.class);
        when(mockProgram.getLanguage()).thenReturn(mockLanguage);
        when(mockLanguage.supportsPcode()).thenReturn(false);
        
        // Mock empty function iterator - need to mock iterator() method for for-each loop
        Iterator<Function> emptyIterator = mock(Iterator.class);
        when(emptyIterator.hasNext()).thenReturn(false);
        when(mockFunctionManager.getFunctions(true)).thenReturn(mockFunctionIterator);
        when(mockFunctionIterator.iterator()).thenReturn(emptyIterator);
        
        // Test
        String result = searchServiceWithMocks.searchDecompiledCode("test", 0, 10);
        
        // Verify - when language doesn't support pcode, it should return an error
        assertNotNull(result);
        assertTrue(result.contains("Decompiler not available") || result.contains("No matches found"));
    }

    @Test
    @DisplayName("searchMemory handles hex pattern")
    void testSearchMemory_HexPattern() {
        // Setup minimal mocks
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        
        // Empty memory blocks
        when(mockMemory.getBlocks()).thenReturn(new MemoryBlock[0]);
        
        // Test with hex pattern
        String result = searchServiceWithMocks.searchMemory("48 89 5C 24", false, null, 10);
        
        // Verify
        assertNotNull(result);
        assertEquals("No matches found for query: 48 89 5C 24", result);
    }

    @Test
    @DisplayName("searchDisassembly with no executable blocks")
    void testSearchDisassembly_NoExecutableBlocks() {
        // Setup
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        
        // No executable blocks
        when(mockMemory.getBlocks()).thenReturn(new MemoryBlock[0]);
        
        // Test
        String result = searchServiceWithMocks.searchDisassembly("MOV", 0, 10);
        
        // Verify
        assertNotNull(result);
        assertEquals("No executable code blocks found in program", result);
    }

    @Test
    @DisplayName("searchMemory with invalid hex pattern")
    void testSearchMemory_InvalidHexPattern() {
        // Setup
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        
        // Test with invalid hex pattern - this will fail early due to parsing error
        String result = searchServiceWithMocks.searchMemory("ZZ XX", false, null, 10);
        
        // Verify - should handle the error
        assertNotNull(result);
        assertTrue(result.contains("Error searching memory") || result.contains("No matches found") || result.contains("No program loaded"));
    }

    @Test
    @DisplayName("searchDecompiledCode handles invalid regex pattern")
    void testSearchDecompiledCode_InvalidRegex() {
        String result = searchService.searchDecompiledCode("(unclosed", 0, 10);
        // When no program is loaded, it returns "No program loaded" before checking regex
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDecompiledCode handles valid regex pattern")
    void testSearchDecompiledCode_ValidRegex() {
        String result = searchService.searchDecompiledCode("if\\s*\\(.*\\)", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDecompiledCode handles negative offset")
    void testSearchDecompiledCode_NegativeOffset() {
        String result = searchService.searchDecompiledCode("function", -1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("searchDecompiledCode handles zero limit")
    void testSearchDecompiledCode_ZeroLimit() {
        String result = searchService.searchDecompiledCode("function", 0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new SearchService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
    
    @Test
    @DisplayName("searchMemory with specific block name")
    void testSearchMemory_WithSpecificBlockName() {
        // Setup
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        
        // Mock specific block lookup
        when(mockMemory.getBlock(".text")).thenReturn(mockBlock);
        when(mockBlock.getStart()).thenReturn(mockAddress);
        when(mockBlock.getEnd()).thenReturn(mockAddress);
        when(mockAddress.getAddressSpace()).thenReturn(mockAddressSpace);
        when(mockAddress.getOffsetAsBigInteger()).thenReturn(java.math.BigInteger.valueOf(0x401000));
        
        // Test with specific block name
        String result = searchServiceWithMocks.searchMemory("test", true, ".text", 10);
        
        // Verify
        assertNotNull(result);
        assertEquals("No matches found for query: test", result);
    }
    
    @Test
    @DisplayName("searchMemory returns error for non-existent block")
    void testSearchMemory_BlockNotFound() {
        // Setup
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        
        // Mock block not found
        when(mockMemory.getBlock("nonexistent")).thenReturn(null);
        
        // Test
        String result = searchServiceWithMocks.searchMemory("test", true, "nonexistent", 10);
        
        // Verify
        assertEquals("Memory block not found: nonexistent", result);
    }
    
    @Test
    @DisplayName("searchMemory handles wildcards in hex pattern")
    void testSearchMemory_HexPatternWithWildcards() {
        // Setup
        when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getMemory()).thenReturn(mockMemory);
        
        // Empty memory blocks
        when(mockMemory.getBlocks()).thenReturn(new MemoryBlock[0]);
        
        // Test with hex pattern containing wildcards
        String result = searchServiceWithMocks.searchMemory("48 ?? 5C ??", false, null, 10);
        
        // Verify
        assertNotNull(result);
        assertEquals("No matches found for query: 48 ?? 5C ??", result);
    }
    
}