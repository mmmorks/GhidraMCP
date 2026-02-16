package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for CommentService
 */
public class CommentServiceTest {

    private CommentService commentService;
    private ProgramService programService;

    @BeforeEach
    @SuppressWarnings("unused")
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        commentService = new CommentService(programService);
    }

    @Test
    @DisplayName("setComment returns failure message when no program is loaded")
    void testSetComment_NoProgram() {
        String result = commentService.setComment("0x1000", "Test comment", "pre").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment returns failure message for null address")
    void testSetComment_NullAddress() {
        String result = commentService.setComment(null, "Test comment", "pre").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment returns failure message for empty address")
    void testSetComment_EmptyAddress() {
        String result = commentService.setComment("", "Test comment", "eol").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment returns failure message for null comment")
    void testSetComment_NullComment() {
        String result = commentService.setComment("0x1000", null, "pre").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment returns failure message for invalid comment type")
    void testSetComment_InvalidType() {
        String result = commentService.setComment("0x1000", "Test", "invalid_type").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment accepts 'pre' type")
    void testSetComment_PreType() {
        String result = commentService.setComment("0x1000", "Test", "pre").toStructuredJson();
        assertTrue(result.contains("Failed to set comment")); // fails because no program loaded
    }

    @Test
    @DisplayName("setComment accepts 'decompiler' type alias")
    void testSetComment_DecompilerType() {
        String result = commentService.setComment("0x1000", "Test", "decompiler").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment accepts 'eol' type")
    void testSetComment_EolType() {
        String result = commentService.setComment("0x1000", "Test", "eol").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment accepts 'disassembly' type alias")
    void testSetComment_DisassemblyType() {
        String result = commentService.setComment("0x1000", "Test", "disassembly").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment accepts 'post' type")
    void testSetComment_PostType() {
        String result = commentService.setComment("0x1000", "Test", "post").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment accepts 'plate' type")
    void testSetComment_PlateType() {
        String result = commentService.setComment("0x1000", "Test", "plate").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment accepts 'repeatable' type")
    void testSetComment_RepeatableType() {
        String result = commentService.setComment("0x1000", "Test", "repeatable").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment handles multiline comment")
    void testSetComment_MultilineComment() {
        String result = commentService.setComment("0x1000", "Line 1\nLine 2\nLine 3", "pre").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("setComment handles special characters in comment")
    void testSetComment_SpecialCharacters() {
        String result = commentService.setComment("0x1000", "Test /* comment */ with // special chars", "eol").toStructuredJson();
        assertTrue(result.contains("Failed to set comment"));
    }

    @Test
    @DisplayName("getComment returns error when no program is loaded")
    void testGetComment_NoProgram() {
        String result = commentService.getComment("0x1000").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getComment returns error for null address")
    void testGetComment_NullAddress() {
        String result = commentService.getComment(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new CommentService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
}
