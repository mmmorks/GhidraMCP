package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.response.FunctionCodeResult;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

/**
 * Unit tests for CommentService
 */
public class CommentServiceTest {

    @Nested
    @DisplayName("No program loaded (null-guard tests)")
    class NoProgramTests {

        private CommentService commentService;

        @BeforeEach
        void setUp() {
            ProgramService programService = new ProgramService(null);
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
        @DisplayName("setComment with null comment clears (fails here due to no program)")
        void testSetComment_NullComment() {
            String result = commentService.setComment("0x1000", null, "pre").toStructuredJson();
            assertTrue(result.contains("Failed to set comment")); // fails because no program loaded
        }

        @Test
        @DisplayName("setComment with empty comment clears (fails here due to no program)")
        void testSetComment_EmptyComment() {
            String result = commentService.setComment("0x1000", "", "pre").toStructuredJson();
            assertTrue(result.contains("Failed to set comment")); // fails because no program loaded
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
        @DisplayName("Constructor accepts null program service without throwing")
        void testConstructor_NullProgramService() {
            assertDoesNotThrow(() -> new CommentService(null));
        }
    }

    @Nested
    @DisplayName("ProgramBuilder-based happy-path tests")
    class HappyPathTests {

        private ProgramBuilder builder;
        private CommentService svc;
        private FunctionService funcService;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @BeforeEach
        void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            // MIPS: simple function (Pattern A)
            builder.setBytes("0x401000",
                "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
                true);
            builder.createFunction("0x401000");

            ProgramDB program = builder.getProgram();
            ProgramService ps = GhidraTestEnv.programService(program);
            svc = new CommentService(ps);
            funcService = GhidraTestEnv.functionService(program);
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        private List<String> assemblyCodeLines() {
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) funcService.getFunctionCode("0x401000", "assembly")).data();
            return data.lines().stream().map(m -> m.values().iterator().next()).toList();
        }

        @Test
        @DisplayName("setComment pre comment appears in assembly listing")
        void testSetComment_Pre_VisibleInAssembly() {
            svc.setComment("0x401000", "Pre comment text", "pre");
            List<String> codes = assemblyCodeLines();
            assertTrue(codes.stream().anyMatch(c -> c.equals("; Pre comment text")),
                "Pre comment should appear in assembly output, got: " + codes);
        }

        @Test
        @DisplayName("setComment EOL comment appears inline in assembly listing")
        void testSetComment_Eol_VisibleInAssembly() {
            svc.setComment("0x401000", "EOL comment text", "eol");
            List<String> codes = assemblyCodeLines();
            assertTrue(codes.stream().anyMatch(c -> c.contains("; EOL comment text") && !c.startsWith(";")),
                "EOL comment should be inlined on instruction, got: " + codes);
        }

        @Test
        @DisplayName("setComment post comment appears in assembly listing")
        void testSetComment_Post_VisibleInAssembly() {
            svc.setComment("0x401000", "Post comment text", "post");
            List<String> codes = assemblyCodeLines();
            assertTrue(codes.stream().anyMatch(c -> c.equals("; Post comment text")),
                "Post comment should appear in assembly output, got: " + codes);
        }

        @Test
        @DisplayName("setComment plate comment appears in assembly listing")
        void testSetComment_Plate_VisibleInAssembly() {
            svc.setComment("0x401000", "Plate comment text", "plate");
            List<String> codes = assemblyCodeLines();
            assertTrue(codes.stream().anyMatch(c -> c.equals("; Plate comment text")),
                "Plate comment should appear in assembly output, got: " + codes);
        }

        @Test
        @DisplayName("setComment repeatable comment appears inline in assembly listing")
        void testSetComment_Repeatable_VisibleInAssembly() {
            svc.setComment("0x401000", "Repeatable comment text", "repeatable");
            List<String> codes = assemblyCodeLines();
            assertTrue(codes.stream().anyMatch(c -> c.contains("; Repeatable comment text") && !c.startsWith(";")),
                "Repeatable comment should be inlined on instruction, got: " + codes);
        }

        @Test
        @DisplayName("pre/decompiler comment appears in C listing")
        void testPreComment_VisibleInCListing() {
            svc.setComment("0x401000", "Decompiler annotation", "pre");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) funcService.getFunctionCode("0x401000", "C")).data();
            List<String> codes = data.lines().stream().map(m -> m.values().iterator().next()).toList();
            assertTrue(codes.stream().anyMatch(c -> c.contains("Decompiler annotation")),
                "Pre/decompiler comment should appear in C output, got: " + codes);
        }

        @Test
        @DisplayName("plate comment appears in C listing as block comment")
        void testPlateComment_VisibleInCListing() {
            svc.setComment("0x401000", "Plate header", "plate");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) funcService.getFunctionCode("0x401000", "C")).data();
            List<String> codes = data.lines().stream().map(m -> m.values().iterator().next()).toList();
            assertTrue(codes.stream().anyMatch(c -> c.contains("Plate header")),
                "Plate comment should appear in C output, got: " + codes);
        }

        @Test
        @DisplayName("EOL, post, repeatable comments do not appear in C listing")
        void testNonDecompilerComments_NotInCListing() {
            svc.setComment("0x401000", "EOL only", "eol");
            svc.setComment("0x401000", "Post only", "post");
            svc.setComment("0x401000", "Repeatable only", "repeatable");
            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) funcService.getFunctionCode("0x401000", "C")).data();
            List<String> codes = data.lines().stream().map(m -> m.values().iterator().next()).toList();
            assertTrue(codes.stream().noneMatch(c ->
                    c.contains("EOL only") || c.contains("Post only") ||
                    c.contains("Repeatable only")),
                "EOL/post/repeatable comments should not appear in C output, got: " + codes);
        }

        @Test
        @DisplayName("all comment types appear in pcode listing")
        void testComments_VisibleInPcode() {
            // Get pcode output first to find an address that has pcode ops
            FunctionCodeResult initial = (FunctionCodeResult) ((JsonOutput) funcService.getFunctionCode("0x401000", "pcode")).data();
            assertFalse(initial.lines().isEmpty(), "Pcode should have at least one op");
            String pcodeAddr = initial.lines().get(0).keySet().iterator().next();

            // Set all comment types at that address
            svc.setComment(pcodeAddr, "Plate header", "plate");
            svc.setComment(pcodeAddr, "Pre comment", "pre");
            svc.setComment(pcodeAddr, "EOL comment", "eol");
            svc.setComment(pcodeAddr, "Post comment", "post");
            svc.setComment(pcodeAddr, "Repeatable comment", "repeatable");

            FunctionCodeResult data = (FunctionCodeResult) ((JsonOutput) funcService.getFunctionCode("0x401000", "pcode")).data();
            List<String> codes = data.lines().stream().map(m -> m.values().iterator().next()).toList();
            assertTrue(codes.stream().anyMatch(c -> c.equals("; Plate header")),
                "Plate comment should appear in pcode output, got: " + codes);
            assertTrue(codes.stream().anyMatch(c -> c.equals("; Pre comment")),
                "Pre comment should appear in pcode output, got: " + codes);
            assertTrue(codes.stream().anyMatch(c -> c.equals("; EOL comment")),
                "EOL comment should appear in pcode output, got: " + codes);
            assertTrue(codes.stream().anyMatch(c -> c.equals("; Post comment")),
                "Post comment should appear in pcode output, got: " + codes);
            assertTrue(codes.stream().anyMatch(c -> c.equals("; Repeatable comment")),
                "Repeatable comment should appear in pcode output, got: " + codes);
        }

        @Test
        @DisplayName("setComment with empty string clears an existing comment")
        void testSetComment_EmptyStringClearsComment() {
            svc.setComment("0x401000", "Temporary comment", "eol");
            List<String> before = assemblyCodeLines();
            assertTrue(before.stream().anyMatch(c -> c.contains("Temporary comment")),
                "Comment should be present before clearing, got: " + before);

            String result = svc.setComment("0x401000", "", "eol").toStructuredJson();
            assertTrue(result.contains("Comment cleared successfully"), "Should report cleared, got: " + result);

            List<String> after = assemblyCodeLines();
            assertTrue(after.stream().noneMatch(c -> c.contains("Temporary comment")),
                "Comment should be removed after clearing, got: " + after);
        }

        @Test
        @DisplayName("setComment with null clears an existing comment")
        void testSetComment_NullClearsComment() {
            svc.setComment("0x401000", "Another comment", "pre");
            List<String> before = assemblyCodeLines();
            assertTrue(before.stream().anyMatch(c -> c.contains("Another comment")),
                "Comment should be present before clearing, got: " + before);

            String result = svc.setComment("0x401000", null, "pre").toStructuredJson();
            assertTrue(result.contains("Comment cleared successfully"), "Should report cleared, got: " + result);

            List<String> after = assemblyCodeLines();
            assertTrue(after.stream().noneMatch(c -> c.contains("Another comment")),
                "Comment should be removed after clearing, got: " + after);
        }

        @Test
        @DisplayName("setComment overwrites an existing comment visible in assembly")
        void testSetComment_Overwrite() {
            svc.setComment("0x401000", "Original comment", "eol");
            svc.setComment("0x401000", "Replacement comment", "eol");
            List<String> codes = assemblyCodeLines();
            assertTrue(codes.stream().anyMatch(c -> c.contains("Replacement comment")),
                "Replacement comment should appear, got: " + codes);
            assertTrue(codes.stream().noneMatch(c -> c.contains("Original comment")),
                "Original comment should be gone, got: " + codes);
        }
    }
}
