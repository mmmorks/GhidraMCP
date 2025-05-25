package com.lauriewired.mcp.utils;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Unit tests for GhidraUtils
 */
public class GhidraUtilsTest {
    
    /**
     * Tests for getFunctionForAddress method that don't require mocking
     */
    @Nested
    class GetFunctionForAddressNullTests {
        
        @Test
        @DisplayName("getFunctionForAddress returns null for null program")
        void testGetFunctionForAddress_NullProgram() {
            Address mockAddress = mock(Address.class);
            Function result = GhidraUtils.getFunctionForAddress(null, mockAddress);
            assertNull(result);
        }
        
        @Test
        @DisplayName("getFunctionForAddress returns null for null address")
        void testGetFunctionForAddress_NullAddress() {
            // Don't create a Program mock for this test
            Function result = GhidraUtils.getFunctionForAddress(mock(Program.class), null);
            assertNull(result);
        }
    }
    
    /**
     * Tests for getFunctionForAddress method that require mocking
     */
    @Nested
    @ExtendWith(MockitoExtension.class)
    class GetFunctionForAddressMockTests {
        
        @Mock
        private Program mockProgram;
        
        @Mock
        private FunctionManager mockFunctionManager;
        
        @Mock
        private Function mockFunction;
        
        @Mock
        private Address mockAddress;
        
        @Test
        @DisplayName("getFunctionForAddress returns function at exact address")
        void testGetFunctionForAddress_ExactMatch() {
            when(mockProgram.getFunctionManager()).thenReturn(mockFunctionManager);
            when(mockFunctionManager.getFunctionAt(mockAddress)).thenReturn(mockFunction);
            
            Function result = GhidraUtils.getFunctionForAddress(mockProgram, mockAddress);
            
            assertEquals(mockFunction, result);
            verify(mockFunctionManager).getFunctionAt(mockAddress);
            verify(mockFunctionManager, never()).getFunctionContaining(any());
        }
        
        @Test
        @DisplayName("getFunctionForAddress returns function containing address when no exact match")
        void testGetFunctionForAddress_ContainingMatch() {
            when(mockProgram.getFunctionManager()).thenReturn(mockFunctionManager);
            when(mockFunctionManager.getFunctionAt(mockAddress)).thenReturn(null);
            when(mockFunctionManager.getFunctionContaining(mockAddress)).thenReturn(mockFunction);
            
            Function result = GhidraUtils.getFunctionForAddress(mockProgram, mockAddress);
            
            assertEquals(mockFunction, result);
            verify(mockFunctionManager).getFunctionAt(mockAddress);
            verify(mockFunctionManager).getFunctionContaining(mockAddress);
        }
        
        @Test
        @DisplayName("getFunctionForAddress returns null when no function found")
        void testGetFunctionForAddress_NoMatch() {
            when(mockProgram.getFunctionManager()).thenReturn(mockFunctionManager);
            when(mockFunctionManager.getFunctionAt(mockAddress)).thenReturn(null);
            when(mockFunctionManager.getFunctionContaining(mockAddress)).thenReturn(null);
            
            Function result = GhidraUtils.getFunctionForAddress(mockProgram, mockAddress);
            
            assertNull(result);
        }
    }
    
    /**
     * Tests for variable-related methods
     */
    @Nested
    @ExtendWith(MockitoExtension.class)
    class VariableTests {
        
        @Mock
        private HighFunction mockHighFunction;
        
        @Mock
        private LocalSymbolMap mockLocalSymbolMap;
        
        @Mock
        private HighSymbol mockHighSymbol;
        
        @Test
        @DisplayName("findVariableByName finds variable with matching name")
        void testFindVariableByName_Found() {
            String variableName = "testVar";
            List<HighSymbol> symbols = new ArrayList<>();
            symbols.add(mockHighSymbol);
            
            when(mockHighFunction.getLocalSymbolMap()).thenReturn(mockLocalSymbolMap);
            when(mockLocalSymbolMap.getSymbols()).thenReturn(symbols.iterator());
            when(mockHighSymbol.getName()).thenReturn(variableName);
            
            HighSymbol result = GhidraUtils.findVariableByName(mockHighFunction, variableName);
            
            assertEquals(mockHighSymbol, result);
        }
        
        @Test
        @DisplayName("findVariableByName returns null when variable not found")
        void testFindVariableByName_NotFound() {
            String variableName = "testVar";
            List<HighSymbol> symbols = new ArrayList<>();
            HighSymbol otherSymbol = mock(HighSymbol.class);
            when(otherSymbol.getName()).thenReturn("otherVar");
            symbols.add(otherSymbol);
            
            when(mockHighFunction.getLocalSymbolMap()).thenReturn(mockLocalSymbolMap);
            when(mockLocalSymbolMap.getSymbols()).thenReturn(symbols.iterator());
            
            HighSymbol result = GhidraUtils.findVariableByName(mockHighFunction, variableName);
            
            assertNull(result);
        }
        
        @Test
        @DisplayName("findVariableByName returns null for null high function")
        void testFindVariableByName_NullHighFunction() {
            HighSymbol result = GhidraUtils.findVariableByName(null, "test");
            assertNull(result);
        }
        
        @Test
        @DisplayName("findVariableByName returns null for null variable name")
        void testFindVariableByName_NullVariableName() {
            HighSymbol result = GhidraUtils.findVariableByName(mockHighFunction, null);
            assertNull(result);
        }
    }
    
    /**
     * Tests for symbol-related methods that don't require Program mock
     */
    @Nested
    class SymbolNullTests {
        
        @Test
        @DisplayName("getSymbolAddress returns null for null program")
        void testGetSymbolAddress_NullProgram() {
            Address result = GhidraUtils.getSymbolAddress(null, "test");
            assertNull(result);
        }
        
        @Test
        @DisplayName("getSymbolAddress returns null for null symbol name")
        void testGetSymbolAddress_NullSymbolName() {
            Address result = GhidraUtils.getSymbolAddress(mock(Program.class), null);
            assertNull(result);
        }
        
        @Test
        @DisplayName("getSymbolAddress returns null for empty symbol name")
        void testGetSymbolAddress_EmptySymbolName() {
            Address result = GhidraUtils.getSymbolAddress(mock(Program.class), "");
            assertNull(result);
        }
    }
    
    /**
     * Tests for symbol-related methods that require Program mock
     */
    @Nested
    @ExtendWith(MockitoExtension.class)
    class SymbolMockTests {
        
        @Mock
        private Program mockProgram;
        
        @Mock
        private SymbolTable mockSymbolTable;
        
        @Mock
        private Symbol mockSymbol;
        
        @Mock
        private SymbolIterator mockSymbolIterator;
        
        @Mock
        private Address mockAddress;
        
        @Test
        @DisplayName("getSymbolAddress returns address for existing symbol")
        void testGetSymbolAddress_Found() {
            String symbolName = "main";
            
            when(mockProgram.getSymbolTable()).thenReturn(mockSymbolTable);
            when(mockSymbolTable.getSymbols(symbolName)).thenReturn(mockSymbolIterator);
            when(mockSymbolIterator.hasNext()).thenReturn(true);
            when(mockSymbolIterator.next()).thenReturn(mockSymbol);
            when(mockSymbol.getAddress()).thenReturn(mockAddress);
            
            Address result = GhidraUtils.getSymbolAddress(mockProgram, symbolName);
            
            assertEquals(mockAddress, result);
        }
        
        @Test
        @DisplayName("getSymbolAddress returns null when symbol not found")
        void testGetSymbolAddress_NotFound() {
            String symbolName = "nonExistent";
            
            when(mockProgram.getSymbolTable()).thenReturn(mockSymbolTable);
            when(mockSymbolTable.getSymbols(symbolName)).thenReturn(mockSymbolIterator);
            when(mockSymbolIterator.hasNext()).thenReturn(false);
            
            Address result = GhidraUtils.getSymbolAddress(mockProgram, symbolName);
            
            assertNull(result);
        }
    }
    
    /**
     * Tests for checkFullCommit method
     */
    @Nested
    @ExtendWith(MockitoExtension.class)
    class CheckFullCommitTests {
        
        @Mock
        private HighSymbol mockHighSymbol;
        
        @Mock
        private HighFunction mockHighFunction;
        
        @Mock
        private Function mockFunction;
        
        @Mock
        private LocalSymbolMap mockLocalSymbolMap;
        
        @Test
        @DisplayName("checkFullCommit returns false for non-parameter symbol")
        void testCheckFullCommit_NonParameter() {
            when(mockHighSymbol.isParameter()).thenReturn(false);
            
            boolean result = GhidraUtils.checkFullCommit(mockHighSymbol, mockHighFunction);
            
            assertFalse(result);
        }
        
        @Test
        @DisplayName("checkFullCommit returns true when parameter counts differ")
        void testCheckFullCommit_DifferentParamCounts() {
            when(mockHighSymbol.isParameter()).thenReturn(true);
            when(mockHighFunction.getFunction()).thenReturn(mockFunction);
            when(mockHighFunction.getLocalSymbolMap()).thenReturn(mockLocalSymbolMap);
            
            Parameter[] params = new Parameter[2];
            when(mockFunction.getParameters()).thenReturn(params);
            when(mockLocalSymbolMap.getNumParams()).thenReturn(3);
            
            boolean result = GhidraUtils.checkFullCommit(mockHighSymbol, mockHighFunction);
            
            assertTrue(result);
        }
    }
}
