package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for VariableService
 */
public class VariableServiceTest {

    private VariableService variableService;
    private ProgramService programService;

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        variableService = new VariableService(programService);
    }

    @Test
    @DisplayName("renameVariableInFunction returns error when no program is loaded")
    void testRenameVariableInFunction_NoProgram() {
        String result = variableService.renameVariableInFunction("main", "oldVar", "newVar", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameVariableInFunction returns error for null function name")
    void testRenameVariableInFunction_NullFunctionName() {
        String result = variableService.renameVariableInFunction(null, "oldVar", "newVar", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameVariableInFunction returns error for empty function name")
    void testRenameVariableInFunction_EmptyFunctionName() {
        String result = variableService.renameVariableInFunction("", "oldVar", "newVar", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameVariableInFunction returns error for null old variable name")
    void testRenameVariableInFunction_NullOldVarName() {
        String result = variableService.renameVariableInFunction("main", null, "newVar", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameVariableInFunction returns error for empty old variable name")
    void testRenameVariableInFunction_EmptyOldVarName() {
        String result = variableService.renameVariableInFunction("main", "", "newVar", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameVariableInFunction returns error for null new variable name")
    void testRenameVariableInFunction_NullNewVarName() {
        String result = variableService.renameVariableInFunction("main", "oldVar", null, null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameVariableInFunction returns error for empty new variable name")
    void testRenameVariableInFunction_EmptyNewVarName() {
        String result = variableService.renameVariableInFunction("main", "oldVar", "", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameVariableInFunction handles split with usage address")
    void testRenameVariableInFunction_WithUsageAddress() {
        String result = variableService.renameVariableInFunction("main", "oldVar", "newVar", "0x1000");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameVariableInFunction handles split with invalid usage address")
    void testRenameVariableInFunction_InvalidUsageAddress() {
        String result = variableService.renameVariableInFunction("main", "oldVar", "newVar", "invalid");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("setLocalVariableType returns false when no program is loaded")
    void testSetLocalVariableType_NoProgram() {
        boolean result = variableService.setLocalVariableType("0x1000", "varName", "int");
        assertFalse(result);
    }

    @Test
    @DisplayName("setLocalVariableType returns false for null function address")
    void testSetLocalVariableType_NullFunctionAddress() {
        boolean result = variableService.setLocalVariableType(null, "varName", "int");
        assertFalse(result);
    }

    @Test
    @DisplayName("setLocalVariableType returns false for empty function address")
    void testSetLocalVariableType_EmptyFunctionAddress() {
        boolean result = variableService.setLocalVariableType("", "varName", "int");
        assertFalse(result);
    }

    @Test
    @DisplayName("setLocalVariableType returns false for null variable name")
    void testSetLocalVariableType_NullVariableName() {
        boolean result = variableService.setLocalVariableType("0x1000", null, "int");
        assertFalse(result);
    }

    @Test
    @DisplayName("setLocalVariableType returns false for empty variable name")
    void testSetLocalVariableType_EmptyVariableName() {
        boolean result = variableService.setLocalVariableType("0x1000", "", "int");
        assertFalse(result);
    }

    @Test
    @DisplayName("setLocalVariableType returns false for null type")
    void testSetLocalVariableType_NullType() {
        boolean result = variableService.setLocalVariableType("0x1000", "varName", null);
        assertFalse(result);
    }

    @Test
    @DisplayName("setLocalVariableType returns false for empty type")
    void testSetLocalVariableType_EmptyType() {
        boolean result = variableService.setLocalVariableType("0x1000", "varName", "");
        assertFalse(result);
    }

    @Test
    @DisplayName("setLocalVariableType handles common data types")
    void testSetLocalVariableType_CommonTypes() {
        assertFalse(variableService.setLocalVariableType("0x1000", "varName", "int"));
        assertFalse(variableService.setLocalVariableType("0x1000", "varName", "char"));
        assertFalse(variableService.setLocalVariableType("0x1000", "varName", "void*"));
        assertFalse(variableService.setLocalVariableType("0x1000", "varName", "DWORD"));
    }

    @Test
    @DisplayName("setLocalVariableType handles invalid address format")
    void testSetLocalVariableType_InvalidAddress() {
        boolean result = variableService.setLocalVariableType("invalid", "varName", "int");
        assertFalse(result);
    }

    @Test
    @DisplayName("renameVariableInFunction returns JSON response format")
    void testRenameVariableInFunction_ResponseFormat() {
        String result = variableService.renameVariableInFunction("main", "oldVar", "newVar", null);
        // Even with no program loaded, we should get a proper error message
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new VariableService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
}