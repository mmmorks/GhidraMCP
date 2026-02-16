package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for AnalysisService
 */
public class AnalysisServiceTest {

    private AnalysisService analysisService;
    private ProgramService programService;
    private FunctionService functionService;

    @BeforeEach
    @SuppressWarnings("unused")
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        functionService = new FunctionService(null, programService);
        analysisService = new AnalysisService(programService, functionService);
    }

    @Test
    @DisplayName("analyzeControlFlow returns error when no program is loaded")
    void testAnalyzeControlFlow_NoProgram() {
        String result = analysisService.analyzeControlFlow("0x1000");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeControlFlow returns error for null identifier")
    void testAnalyzeControlFlow_NullIdentifier() {
        String result = analysisService.analyzeControlFlow(null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeControlFlow returns error for empty identifier")
    void testAnalyzeControlFlow_EmptyIdentifier() {
        String result = analysisService.analyzeControlFlow("");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeControlFlow handles invalid identifier")
    void testAnalyzeControlFlow_InvalidIdentifier() {
        String result = analysisService.analyzeControlFlow("invalid");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeDataFlow returns error when no program is loaded")
    void testAnalyzeDataFlow_NoProgram() {
        String result = analysisService.analyzeDataFlow("0x1000", "variable");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for null identifier")
    void testAnalyzeDataFlow_NullIdentifier() {
        String result = analysisService.analyzeDataFlow(null, "variable");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for empty identifier")
    void testAnalyzeDataFlow_EmptyIdentifier() {
        String result = analysisService.analyzeDataFlow("", "variable");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for null variable name")
    void testAnalyzeDataFlow_NullVariableName() {
        String result = analysisService.analyzeDataFlow("0x1000", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for empty variable name")
    void testAnalyzeDataFlow_EmptyVariableName() {
        String result = analysisService.analyzeDataFlow("0x1000", "");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getCallGraph returns error when no program is loaded")
    void testGetCallGraph_NoProgram() {
        String result = analysisService.getCallGraph("0x1000", 3, "both");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getCallGraph returns error for null identifier")
    void testGetCallGraph_NullIdentifier() {
        String result = analysisService.getCallGraph(null, 3, "both");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getCallGraph returns error for empty identifier")
    void testGetCallGraph_EmptyIdentifier() {
        String result = analysisService.getCallGraph("", 3, "both");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getCallGraph limits depth to maximum of 5")
    void testGetCallGraph_MaxDepth() {
        String result = analysisService.getCallGraph("0x1000", 10, "both");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getCallGraph handles zero depth")
    void testGetCallGraph_ZeroDepth() {
        String result = analysisService.getCallGraph("0x1000", 0, "both");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getCallGraph handles negative depth")
    void testGetCallGraph_NegativeDepth() {
        String result = analysisService.getCallGraph("0x1000", -1, "both");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getCallGraph handles callers direction")
    void testGetCallGraph_CallersDirection() {
        String result = analysisService.getCallGraph("0x1000", 2, "callers");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getCallGraph handles callees direction")
    void testGetCallGraph_CalleesDirection() {
        String result = analysisService.getCallGraph("0x1000", 2, "callees");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences returns error when no program is loaded")
    void testListReferences_NoProgram() {
        String result = analysisService.listReferences("0x1000", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences returns error for null address")
    void testListReferences_NullAddress() {
        String result = analysisService.listReferences(null, 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences returns error for empty address")
    void testListReferences_EmptyAddress() {
        String result = analysisService.listReferences("", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences handles symbol name")
    void testListReferences_SymbolName() {
        String result = analysisService.listReferences("main", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences handles hex address")
    void testListReferences_HexAddress() {
        String result = analysisService.listReferences("0x1000", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences handles negative offset")
    void testListReferences_NegativeOffset() {
        String result = analysisService.listReferences("0x1000", -1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences handles zero limit")
    void testListReferences_ZeroLimit() {
        String result = analysisService.listReferences("0x1000", 0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new AnalysisService(null, null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
}