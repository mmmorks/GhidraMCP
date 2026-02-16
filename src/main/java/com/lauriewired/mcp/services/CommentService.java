package com.lauriewired.mcp.services;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.utils.ProgramTransaction;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Service class for comment-related operations in Ghidra
 */
public class CommentService {
    private final ProgramService programService;
    
    /**
     * Creates a new CommentService
     *
     * @param programService the program service for accessing the current program
     */
    public CommentService(ProgramService programService) {
        this.programService = programService;
    }
    
    @McpTool(post = true, description = """
        Set a comment at an address.

        Creates or replaces a comment of the specified type.

        Returns: Success or failure message

        Examples:
            set_comment("00401010", "Initialize config", "decompiler")
            set_comment("00401010", "Save return address", "eol")
            set_comment("00401000", "--- Main Entry ---", "plate") """)
    public String setComment(
            @Param("Target address (e.g., \"00401000\" or \"ram:00401000\")") String address,
            @Param("Comment text to set") String comment,
            @Param("Comment type: \"pre\"/\"decompiler\", \"eol\"/\"disassembly\", \"post\", \"plate\", \"repeatable\"") String type) {
        if (type == null || type.isEmpty()) {
            return "Error: 'type' parameter is required (pre, post, eol, plate, repeatable)";
        }
        int commentType = switch (type.toLowerCase()) {
            case "pre", "decompiler" -> CodeUnit.PRE_COMMENT;
            case "post" -> CodeUnit.POST_COMMENT;
            case "eol", "disassembly" -> CodeUnit.EOL_COMMENT;
            case "plate" -> CodeUnit.PLATE_COMMENT;
            case "repeatable" -> CodeUnit.REPEATABLE_COMMENT;
            default -> -1;
        };
        if (commentType == -1) {
            return "Failed to set comment. Valid types: pre, post, eol, plate, repeatable";
        }
        boolean success = setCommentAtAddress(address, comment, commentType, "Set " + type + " comment");
        return success ? "Comment set successfully" : "Failed to set comment. Valid types: pre, post, eol, plate, repeatable";
    }

    /**
     * Set a comment using the specified comment type constant
     *
     * @param addressStr address where the comment should be placed
     * @param comment comment text
     * @param commentType type of comment (CodeUnit.PRE_COMMENT, CodeUnit.EOL_COMMENT, etc.)
     * @param transactionName name of the transaction for the program history
     * @return true if successful
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        try (var tx = ProgramTransaction.start(program, transactionName)) {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            program.getListing().setComment(addr, commentType, comment);
            tx.commit();
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
            return false;
        }
    }
    
    @McpTool(description = """
        Get all comments at a specific address.

        Retrieves all comment types (pre/decompiler, post, eol/disassembly, plate, repeatable).

        Returns: All comments found at the address, organized by type

        Example: get_comment("00401000") -> "Pre Comment (Decompiler): Initialize system..." """)
    public String getComment(
            @Param("Address to get comments from (e.g., \"00401000\")") String address) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (address == null || address.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) return "Invalid address: " + address;

            CodeUnit codeUnit = program.getListing().getCodeUnitAt(addr);
            if (codeUnit == null) return "No code unit at address: " + address;
            
            StringBuilder result = new StringBuilder();
            result.append("Comments at ").append(address).append(":\n");
            
            // Get all comment types
            String preComment = codeUnit.getComment(CodeUnit.PRE_COMMENT);
            String postComment = codeUnit.getComment(CodeUnit.POST_COMMENT);
            String eolComment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
            String plateComment = codeUnit.getComment(CodeUnit.PLATE_COMMENT);
            String repeatableComment = codeUnit.getComment(CodeUnit.REPEATABLE_COMMENT);
            
            boolean hasComments = false;
            
            if (preComment != null) {
                result.append("\nPre Comment (Decompiler):\n").append(preComment).append("\n");
                hasComments = true;
            }
            
            if (postComment != null) {
                result.append("\nPost Comment:\n").append(postComment).append("\n");
                hasComments = true;
            }
            
            if (eolComment != null) {
                result.append("\nEnd-of-Line Comment (Disassembly):\n").append(eolComment).append("\n");
                hasComments = true;
            }
            
            if (plateComment != null) {
                result.append("\nPlate Comment:\n").append(plateComment).append("\n");
                hasComments = true;
            }
            
            if (repeatableComment != null) {
                result.append("\nRepeatable Comment:\n").append(repeatableComment).append("\n");
                hasComments = true;
            }
            
            if (!hasComments) {
                result.append("\n(No comments found at this address)\n");
            }
            
            return result.toString();
        } catch (Exception e) {
            return "Error getting comments: " + e.getMessage();
        }
    }
    
}
