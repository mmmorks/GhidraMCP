package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
    @DisplayName("setDecompilerComment returns false when no program is loaded")
    void testSetDecompilerComment_NoProgram() {
        boolean result = commentService.setDecompilerComment("0x1000", "Test comment");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDecompilerComment returns false for null address")
    void testSetDecompilerComment_NullAddress() {
        boolean result = commentService.setDecompilerComment(null, "Test comment");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDecompilerComment returns false for empty address")
    void testSetDecompilerComment_EmptyAddress() {
        boolean result = commentService.setDecompilerComment("", "Test comment");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDecompilerComment returns false for null comment")
    void testSetDecompilerComment_NullComment() {
        boolean result = commentService.setDecompilerComment("0x1000", null);
        assertFalse(result);
    }

    @Test
    @DisplayName("setDecompilerComment handles empty comment")
    void testSetDecompilerComment_EmptyComment() {
        boolean result = commentService.setDecompilerComment("0x1000", "");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDisassemblyComment returns false when no program is loaded")
    void testSetDisassemblyComment_NoProgram() {
        boolean result = commentService.setDisassemblyComment("0x1000", "Test comment");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDisassemblyComment returns false for null address")
    void testSetDisassemblyComment_NullAddress() {
        boolean result = commentService.setDisassemblyComment(null, "Test comment");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDisassemblyComment returns false for empty address")
    void testSetDisassemblyComment_EmptyAddress() {
        boolean result = commentService.setDisassemblyComment("", "Test comment");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDisassemblyComment returns false for null comment")
    void testSetDisassemblyComment_NullComment() {
        boolean result = commentService.setDisassemblyComment("0x1000", null);
        assertFalse(result);
    }

    @Test
    @DisplayName("setDisassemblyComment handles empty comment")
    void testSetDisassemblyComment_EmptyComment() {
        boolean result = commentService.setDisassemblyComment("0x1000", "");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDecompilerComment handles multiline comment")
    void testSetDecompilerComment_MultilineComment() {
        boolean result = commentService.setDecompilerComment("0x1000", "Line 1\nLine 2\nLine 3");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDisassemblyComment handles multiline comment")
    void testSetDisassemblyComment_MultilineComment() {
        boolean result = commentService.setDisassemblyComment("0x1000", "Line 1\nLine 2\nLine 3");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDecompilerComment handles special characters in comment")
    void testSetDecompilerComment_SpecialCharacters() {
        boolean result = commentService.setDecompilerComment("0x1000", "Test /* comment */ with // special chars");
        assertFalse(result);
    }

    @Test
    @DisplayName("setDisassemblyComment handles special characters in comment")
    void testSetDisassemblyComment_SpecialCharacters() {
        boolean result = commentService.setDisassemblyComment("0x1000", "Test /* comment */ with // special chars");
        assertFalse(result);
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new CommentService(null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
}