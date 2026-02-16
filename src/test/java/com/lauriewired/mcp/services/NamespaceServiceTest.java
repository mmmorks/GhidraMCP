package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
    @DisplayName("listSymbols returns error when no program is loaded")
    void testListSymbols_NoProgram() {
        String result = namespaceService.listSymbols(0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listSymbols handles negative offset")
    void testListSymbols_NegativeOffset() {
        String result = namespaceService.listSymbols(-1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listSymbols handles zero limit")
    void testListSymbols_ZeroLimit() {
        String result = namespaceService.listSymbols(0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress returns error when no program is loaded")
    void testGetSymbolAddress_NoProgram() {
        String result = namespaceService.getSymbolAddress("main").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress returns error for null symbol name")
    void testGetSymbolAddress_NullSymbolName() {
        String result = namespaceService.getSymbolAddress(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress returns error for empty symbol name")
    void testGetSymbolAddress_EmptySymbolName() {
        String result = namespaceService.getSymbolAddress("").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress handles valid symbol name")
    void testGetSymbolAddress_ValidSymbolName() {
        String result = namespaceService.getSymbolAddress("main").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getSymbolAddress handles symbol with special characters")
    void testGetSymbolAddress_SpecialCharacters() {
        String result = namespaceService.getSymbolAddress("_start@plt").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new NamespaceService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
}
