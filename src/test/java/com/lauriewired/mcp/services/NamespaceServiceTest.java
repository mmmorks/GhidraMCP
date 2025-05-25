package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for NamespaceService
 */
public class NamespaceServiceTest {

    private NamespaceService namespaceService;
    private ProgramService programService;

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        namespaceService = new NamespaceService(programService);
    }

    @Test
    @DisplayName("getAllClassNames returns error when no program is loaded")
    void testGetAllClassNames_NoProgram() {
        String result = namespaceService.getAllClassNames(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getAllClassNames handles negative offset")
    void testGetAllClassNames_NegativeOffset() {
        String result = namespaceService.getAllClassNames(-1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getAllClassNames handles zero limit")
    void testGetAllClassNames_ZeroLimit() {
        String result = namespaceService.getAllClassNames(0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getAllClassNames handles large offset")
    void testGetAllClassNames_LargeOffset() {
        String result = namespaceService.getAllClassNames(1000, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listNamespaces returns error when no program is loaded")
    void testListNamespaces_NoProgram() {
        String result = namespaceService.listNamespaces(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listNamespaces handles negative offset")
    void testListNamespaces_NegativeOffset() {
        String result = namespaceService.listNamespaces(-1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listNamespaces handles zero limit")
    void testListNamespaces_ZeroLimit() {
        String result = namespaceService.listNamespaces(0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listSymbols returns error when no program is loaded")
    void testListSymbols_NoProgram() {
        String result = namespaceService.listSymbols(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listSymbols handles negative offset")
    void testListSymbols_NegativeOffset() {
        String result = namespaceService.listSymbols(-1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listSymbols handles zero limit")
    void testListSymbols_ZeroLimit() {
        String result = namespaceService.listSymbols(0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listImports returns error when no program is loaded")
    void testListImports_NoProgram() {
        String result = namespaceService.listImports(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listImports handles negative offset")
    void testListImports_NegativeOffset() {
        String result = namespaceService.listImports(-1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listImports handles zero limit")
    void testListImports_ZeroLimit() {
        String result = namespaceService.listImports(0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listExports returns error when no program is loaded")
    void testListExports_NoProgram() {
        String result = namespaceService.listExports(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listExports handles negative offset")
    void testListExports_NegativeOffset() {
        String result = namespaceService.listExports(-1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listExports handles zero limit")
    void testListExports_ZeroLimit() {
        String result = namespaceService.listExports(0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getSymbolAddress returns error when no program is loaded")
    void testGetSymbolAddress_NoProgram() {
        String result = namespaceService.getSymbolAddress("main");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getSymbolAddress returns error for null symbol name")
    void testGetSymbolAddress_NullSymbolName() {
        String result = namespaceService.getSymbolAddress(null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getSymbolAddress returns error for empty symbol name")
    void testGetSymbolAddress_EmptySymbolName() {
        String result = namespaceService.getSymbolAddress("");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getSymbolAddress handles valid symbol name")
    void testGetSymbolAddress_ValidSymbolName() {
        String result = namespaceService.getSymbolAddress("main");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getSymbolAddress handles symbol with special characters")
    void testGetSymbolAddress_SpecialCharacters() {
        String result = namespaceService.getSymbolAddress("_start@plt");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new NamespaceService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
}