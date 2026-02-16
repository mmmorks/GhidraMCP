package com.lauriewired.mcp.services;

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
    
    /**
     * Set a comment at an address with the specified comment type string.
     *
     * @param addressStr address where the comment should be placed
     * @param comment comment text
     * @param commentType comment type: "pre"/"decompiler", "post", "eol"/"disassembly", "plate", "repeatable"
     * @return true if successful, false if invalid type or error
     */
    public boolean setComment(String addressStr, String comment, String commentType) {
        int type = switch (commentType.toLowerCase()) {
            case "pre", "decompiler" -> CodeUnit.PRE_COMMENT;
            case "post" -> CodeUnit.POST_COMMENT;
            case "eol", "disassembly" -> CodeUnit.EOL_COMMENT;
            case "plate" -> CodeUnit.PLATE_COMMENT;
            case "repeatable" -> CodeUnit.REPEATABLE_COMMENT;
            default -> -1;
        };
        if (type == -1) return false;
        return setCommentAtAddress(addressStr, comment, type, "Set " + commentType + " comment");
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
    
    /**
     * Get all comments at a specific address
     *
     * @param addressStr address to get comments from
     * @return all comments at the address
     */
    public String getComments(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(addr);
            if (codeUnit == null) return "No code unit at address: " + addressStr;
            
            StringBuilder result = new StringBuilder();
            result.append("Comments at ").append(addressStr).append(":\n");
            
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
