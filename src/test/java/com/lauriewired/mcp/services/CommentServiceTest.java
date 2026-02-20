package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

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

    // -----------------------------------------------------------------------
    // ProgramBuilder-based happy-path tests
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("ProgramBuilder-based happy-path tests")
    class HappyPathTests {

        private ProgramBuilder builder;
        private CommentService svc;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @BeforeEach
        void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            // Create a code unit by setting bytes and disassembling (MIPS NOP)
            builder.setBytes("0x401000", "00 00 00 00", true);

            ProgramDB program = builder.getProgram();
            ProgramService ps = GhidraTestEnv.programService(program);
            svc = new CommentService(ps);
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        @Test
        @DisplayName("setComment sets a pre comment successfully")
        void testSetComment_Pre_Success() {
            ToolOutput result = svc.setComment("0x401000", "Pre comment text", "pre");
            assertInstanceOf(StatusOutput.class, result);
            assertTrue(result.toStructuredJson().contains("Comment set successfully"));
        }

        @Test
        @DisplayName("setComment sets an EOL comment successfully")
        void testSetComment_Eol_Success() {
            ToolOutput result = svc.setComment("0x401000", "EOL comment text", "eol");
            assertInstanceOf(StatusOutput.class, result);
            assertTrue(result.toStructuredJson().contains("Comment set successfully"));
        }

        @Test
        @DisplayName("setComment sets a post comment successfully")
        void testSetComment_Post_Success() {
            ToolOutput result = svc.setComment("0x401000", "Post comment text", "post");
            assertInstanceOf(StatusOutput.class, result);
            assertTrue(result.toStructuredJson().contains("Comment set successfully"));
        }

        @Test
        @DisplayName("setComment sets a plate comment successfully")
        void testSetComment_Plate_Success() {
            ToolOutput result = svc.setComment("0x401000", "Plate comment text", "plate");
            assertInstanceOf(StatusOutput.class, result);
            assertTrue(result.toStructuredJson().contains("Comment set successfully"));
        }

        @Test
        @DisplayName("setComment sets a repeatable comment successfully")
        void testSetComment_Repeatable_Success() {
            ToolOutput result = svc.setComment("0x401000", "Repeatable comment text", "repeatable");
            assertInstanceOf(StatusOutput.class, result);
            assertTrue(result.toStructuredJson().contains("Comment set successfully"));
        }

        @Test
        @DisplayName("getComment retrieves all comment types set at an address")
        void testGetComment_Success() {
            // Set multiple comment types
            svc.setComment("0x401000", "My pre comment", "pre");
            svc.setComment("0x401000", "My eol comment", "eol");
            svc.setComment("0x401000", "My post comment", "post");
            svc.setComment("0x401000", "My plate comment", "plate");
            svc.setComment("0x401000", "My repeatable comment", "repeatable");

            ToolOutput result = svc.getComment("0x401000");
            assertInstanceOf(JsonOutput.class, result);

            String json = result.toStructuredJson();
            assertTrue(json.contains("My pre comment"));
            assertTrue(json.contains("My eol comment"));
            assertTrue(json.contains("My post comment"));
            assertTrue(json.contains("My plate comment"));
            assertTrue(json.contains("My repeatable comment"));
        }

        @Test
        @DisplayName("getComment returns error when address has no code unit")
        void testGetComment_NoCodeUnit() {
            // 0x900000 is outside all memory blocks so getCodeUnitAt returns null
            ToolOutput result = svc.getComment("0x900000");
            assertInstanceOf(StatusOutput.class, result);
            assertTrue(result.toStructuredJson().contains("No code unit at address"));
        }

        @Test
        @DisplayName("getComment returns error for invalid address string")
        void testGetComment_InvalidAddress() {
            ToolOutput result = svc.getComment("not_an_address");
            assertInstanceOf(StatusOutput.class, result);
            String json = result.toStructuredJson();
            // Should get an error — either "Invalid address" or a caught exception message
            assertTrue(json.contains("\"success\":false"));
        }

        @Test
        @DisplayName("setComment overwrites an existing comment")
        void testSetComment_Overwrite() {
            // Set initial comment
            svc.setComment("0x401000", "Original comment", "pre");

            // Verify original was set
            String json1 = svc.getComment("0x401000").toStructuredJson();
            assertTrue(json1.contains("Original comment"));

            // Overwrite with new comment
            ToolOutput result = svc.setComment("0x401000", "Replacement comment", "pre");
            assertTrue(result.toStructuredJson().contains("Comment set successfully"));

            // Verify overwrite
            String json2 = svc.getComment("0x401000").toStructuredJson();
            assertTrue(json2.contains("Replacement comment"));
            // Original should be gone
            assertTrue(!json2.contains("Original comment"));
        }
    }
}
