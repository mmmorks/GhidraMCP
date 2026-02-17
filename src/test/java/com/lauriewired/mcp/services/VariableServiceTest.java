package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.Mockito.when;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ghidra.program.model.listing.Program;

/**
 * Unit tests for VariableService
 */
public class VariableServiceTest {

    private VariableService variableService;
    private ProgramService programService;
    private FunctionService functionService;

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        functionService = new FunctionService(null, programService);
        variableService = new VariableService(programService, functionService);
    }

    @Test
    @DisplayName("splitVariable returns error when no program is loaded")
    void testSplitVariable_NoProgram() {
        String result = variableService.splitVariable("main", "oldVar", "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for null function name")
    void testSplitVariable_NullFunctionName() {
        String result = variableService.splitVariable(null, "oldVar", "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for empty function name")
    void testSplitVariable_EmptyFunctionName() {
        String result = variableService.splitVariable("", "oldVar", "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for null variable name")
    void testSplitVariable_NullVariableName() {
        String result = variableService.splitVariable("main", null, "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for empty variable name")
    void testSplitVariable_EmptyVariableName() {
        String result = variableService.splitVariable("main", "", "00401000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for null new name (uses default)")
    void testSplitVariable_NullNewName() {
        String result = variableService.splitVariable("main", "oldVar", "00401000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns error for empty new name (uses default)")
    void testSplitVariable_EmptyNewName() {
        String result = variableService.splitVariable("main", "oldVar", "00401000", "").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable handles usage address")
    void testSplitVariable_WithUsageAddress() {
        String result = variableService.splitVariable("main", "oldVar", "0x1000", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable handles invalid usage address")
    void testSplitVariable_InvalidUsageAddress() {
        String result = variableService.splitVariable("main", "oldVar", "invalid", "newVar").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("splitVariable returns JSON response format")
    void testSplitVariable_ResponseFormat() {
        String result = variableService.splitVariable("main", "oldVar", "00401000", "newVar").toStructuredJson();
        // Even with no program loaded, we should get a proper error message
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    // ===== Tests for renameVariables =====

    @Test
    @DisplayName("renameVariables returns error when no program is loaded")
    void testRenameVariables_NoProgram() {
        String result = variableService.renameVariables("main",
            java.util.Map.of("local_10", "buffer_size")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameVariables returns error for null renames")
    void testRenameVariables_NullRenames() {
        String result = variableService.renameVariables("main", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("renameVariables returns error for empty renames")
    void testRenameVariables_EmptyRenames() {
        String result = variableService.renameVariables("main", java.util.Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null services without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new VariableService(null, null));
    }

    // ===== Tests for setVariableTypes =====

    @Test
    @DisplayName("setVariableTypes returns error when no program is loaded")
    void testSetVariableTypes_NoProgram() {
        String result = variableService.setVariableTypes("0x1000",
            java.util.Map.of("local_10", "int")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("setVariableTypes returns error for null function identifier")
    void testSetVariableTypes_NullIdentifier() {
        String result = variableService.setVariableTypes(null,
            java.util.Map.of("local_10", "int")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setVariableTypes returns error for empty function identifier")
    void testSetVariableTypes_EmptyIdentifier() {
        String result = variableService.setVariableTypes("",
            java.util.Map.of("local_10", "int")).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Function identifier is required\""));
    }

    @Test
    @DisplayName("setVariableTypes returns error for null types map")
    void testSetVariableTypes_NullTypes() {
        String result = variableService.setVariableTypes("0x1000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No variable types specified\""));
    }

    @Test
    @DisplayName("setVariableTypes returns error for empty types map")
    void testSetVariableTypes_EmptyTypes() {
        String result = variableService.setVariableTypes("0x1000", java.util.Map.of()).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No variable types specified\""));
    }

    // ===== Tests with mocked services (real logic) =====

    @Nested
    @ExtendWith(MockitoExtension.class)
    class WithMockedProgram {

        @Mock
        private ProgramService mockProgramService;

        @Mock
        private FunctionService mockFunctionService;

        @Mock
        private Program mockProgram;

        private VariableService svc;

        @BeforeEach
        void init() {
            svc = new VariableService(mockProgramService, mockFunctionService);
        }

        // --- renameVariables ---

        @Test
        @DisplayName("renameVariables returns error for null renames with loaded program")
        void testRenameVariables_NullRenames_ProgramLoaded() {
            when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
            String result = svc.renameVariables("main", null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No renames specified\""));
        }

        @Test
        @DisplayName("renameVariables returns error for empty renames with loaded program")
        void testRenameVariables_EmptyRenames_ProgramLoaded() {
            when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
            String result = svc.renameVariables("main", java.util.Map.of()).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No renames specified\""));
        }

        @Test
        @DisplayName("renameVariables returns 'Function not found' for unknown function")
        void testRenameVariables_FunctionNotFound() {
            when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
            when(mockFunctionService.resolveFunction(mockProgram, "nonexistent")).thenReturn(null);

            String result = svc.renameVariables("nonexistent",
                java.util.Map.of("local_10", "buffer")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function not found: nonexistent\""));
        }

        // --- setVariableTypes ---

        @Test
        @DisplayName("setVariableTypes returns error for null identifier with loaded program")
        void testSetVariableTypes_NullIdentifier_ProgramLoaded() {
            // Validation happens before getCurrentProgram() is called
            String result = svc.setVariableTypes(null, java.util.Map.of("x", "int")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function identifier is required\""));
        }

        @Test
        @DisplayName("setVariableTypes returns error for empty identifier with loaded program")
        void testSetVariableTypes_EmptyIdentifier_ProgramLoaded() {
            String result = svc.setVariableTypes("", java.util.Map.of("x", "int")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function identifier is required\""));
        }

        @Test
        @DisplayName("setVariableTypes returns error for null types with loaded program")
        void testSetVariableTypes_NullTypes_ProgramLoaded() {
            String result = svc.setVariableTypes("main", null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No variable types specified\""));
        }

        @Test
        @DisplayName("setVariableTypes returns error for empty types with loaded program")
        void testSetVariableTypes_EmptyTypes_ProgramLoaded() {
            String result = svc.setVariableTypes("main", java.util.Map.of()).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No variable types specified\""));
        }

        @Test
        @DisplayName("setVariableTypes returns 'Function not found' for unknown function")
        void testSetVariableTypes_FunctionNotFound() {
            when(mockProgramService.getCurrentProgram()).thenReturn(mockProgram);
            when(mockFunctionService.resolveFunction(mockProgram, "nonexistent")).thenReturn(null);

            String result = svc.setVariableTypes("nonexistent",
                java.util.Map.of("local_10", "int")).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Function not found: nonexistent\""));
        }
    }
}
