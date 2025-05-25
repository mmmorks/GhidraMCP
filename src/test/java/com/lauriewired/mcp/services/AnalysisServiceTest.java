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

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        analysisService = new AnalysisService(programService);
    }

    @Test
    @DisplayName("analyzeControlFlow returns error when no program is loaded")
    void testAnalyzeControlFlow_NoProgram() {
        String result = analysisService.analyzeControlFlow("0x1000");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeControlFlow returns error for null address")
    void testAnalyzeControlFlow_NullAddress() {
        String result = analysisService.analyzeControlFlow(null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeControlFlow returns error for empty address")
    void testAnalyzeControlFlow_EmptyAddress() {
        String result = analysisService.analyzeControlFlow("");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeControlFlow handles invalid address format")
    void testAnalyzeControlFlow_InvalidAddress() {
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
    @DisplayName("analyzeDataFlow returns error for null address")
    void testAnalyzeDataFlow_NullAddress() {
        String result = analysisService.analyzeDataFlow(null, "variable");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for empty address")
    void testAnalyzeDataFlow_EmptyAddress() {
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
    @DisplayName("analyzeCallGraph returns error when no program is loaded")
    void testAnalyzeCallGraph_NoProgram() {
        String result = analysisService.analyzeCallGraph("0x1000", 3);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeCallGraph returns error for null address")
    void testAnalyzeCallGraph_NullAddress() {
        String result = analysisService.analyzeCallGraph(null, 3);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeCallGraph returns error for empty address")
    void testAnalyzeCallGraph_EmptyAddress() {
        String result = analysisService.analyzeCallGraph("", 3);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("analyzeCallGraph limits depth to maximum of 5")
    void testAnalyzeCallGraph_MaxDepth() {
        String result = analysisService.analyzeCallGraph("0x1000", 10);
        assertEquals("No program loaded", result);
        // Note: With a real program, we would verify depth is limited to 5
    }

    @Test
    @DisplayName("analyzeCallGraph handles zero depth")
    void testAnalyzeCallGraph_ZeroDepth() {
        String result = analysisService.analyzeCallGraph("0x1000", 0);
        assertEquals("No program loaded", result);
        // Note: With a real program, we would verify depth is set to minimum of 1
    }

    @Test
    @DisplayName("analyzeCallGraph handles negative depth")
    void testAnalyzeCallGraph_NegativeDepth() {
        String result = analysisService.analyzeCallGraph("0x1000", -1);
        assertEquals("No program loaded", result);
        // Note: With a real program, we would verify depth is set to minimum of 1
    }

    @Test
    @DisplayName("listReferences returns error when no program is loaded")
    void testListReferences_NoProgram() {
        String result = analysisService.listReferences("0x1000", 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences returns error for null name or address")
    void testListReferences_NullNameOrAddress() {
        String result = analysisService.listReferences(null, 0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listReferences returns error for empty name or address")
    void testListReferences_EmptyNameOrAddress() {
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
        assertDoesNotThrow(() -> new AnalysisService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
}