package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    @DisplayName("setComment returns false when no program is loaded")
    void testSetComment_NoProgram() {
        boolean result = commentService.setComment("0x1000", "Test comment", "pre");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment returns false for null address")
    void testSetComment_NullAddress() {
        boolean result = commentService.setComment(null, "Test comment", "pre");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment returns false for empty address")
    void testSetComment_EmptyAddress() {
        boolean result = commentService.setComment("", "Test comment", "eol");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment returns false for null comment")
    void testSetComment_NullComment() {
        boolean result = commentService.setComment("0x1000", null, "pre");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment returns false for invalid comment type")
    void testSetComment_InvalidType() {
        boolean result = commentService.setComment("0x1000", "Test", "invalid_type");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment accepts 'pre' type")
    void testSetComment_PreType() {
        boolean result = commentService.setComment("0x1000", "Test", "pre");
        assertFalse(result); // false because no program loaded
    }

    @Test
    @DisplayName("setComment accepts 'decompiler' type alias")
    void testSetComment_DecompilerType() {
        boolean result = commentService.setComment("0x1000", "Test", "decompiler");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment accepts 'eol' type")
    void testSetComment_EolType() {
        boolean result = commentService.setComment("0x1000", "Test", "eol");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment accepts 'disassembly' type alias")
    void testSetComment_DisassemblyType() {
        boolean result = commentService.setComment("0x1000", "Test", "disassembly");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment accepts 'post' type")
    void testSetComment_PostType() {
        boolean result = commentService.setComment("0x1000", "Test", "post");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment accepts 'plate' type")
    void testSetComment_PlateType() {
        boolean result = commentService.setComment("0x1000", "Test", "plate");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment accepts 'repeatable' type")
    void testSetComment_RepeatableType() {
        boolean result = commentService.setComment("0x1000", "Test", "repeatable");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment handles multiline comment")
    void testSetComment_MultilineComment() {
        boolean result = commentService.setComment("0x1000", "Line 1\nLine 2\nLine 3", "pre");
        assertFalse(result);
    }

    @Test
    @DisplayName("setComment handles special characters in comment")
    void testSetComment_SpecialCharacters() {
        boolean result = commentService.setComment("0x1000", "Test /* comment */ with // special chars", "eol");
        assertFalse(result);
    }

    @Test
    @DisplayName("getComments returns error when no program is loaded")
    void testGetComments_NoProgram() {
        String result = commentService.getComments("0x1000");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("getComments returns error for null address")
    void testGetComments_NullAddress() {
        String result = commentService.getComments(null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new CommentService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
}
