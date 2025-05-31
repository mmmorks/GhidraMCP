package com.lauriewired.mcp.services;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

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
     * Set a comment for a given address in the function pseudocode
     * 
     * @param addressStr address where the comment should be placed
     * @param comment comment text
     * @return true if successful
     */
    public boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }
    
    /**
     * Set a comment for a given address in the function disassembly
     * 
     * @param addressStr address where the comment should be placed
     * @param comment comment text
     * @return true if successful
     */
    public boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }
    
    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
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
        
        AtomicBoolean success = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }
        
        return success.get();
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
    
    /**
     * Get decompiler comment at a specific address
     *
     * @param addressStr address to get comment from
     * @return decompiler comment or message if none found
     */
    public String getDecompilerComment(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(addr);
            if (codeUnit == null) return "No code unit at address: " + addressStr;
            
            String comment = codeUnit.getComment(CodeUnit.PRE_COMMENT);
            if (comment != null) {
                return "Decompiler comment at " + addressStr + ":\n" + comment;
            } else {
                return "No decompiler comment found at " + addressStr;
            }
        } catch (Exception e) {
            return "Error getting decompiler comment: " + e.getMessage();
        }
    }
    
    /**
     * Get disassembly comment at a specific address
     *
     * @param addressStr address to get comment from
     * @return disassembly comment or message if none found
     */
    public String getDisassemblyComment(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(addr);
            if (codeUnit == null) return "No code unit at address: " + addressStr;
            
            String comment = codeUnit.getComment(CodeUnit.EOL_COMMENT);
            if (comment != null) {
                return "Disassembly comment at " + addressStr + ":\n" + comment;
            } else {
                return "No disassembly comment found at " + addressStr;
            }
        } catch (Exception e) {
            return "Error getting disassembly comment: " + e.getMessage();
        }
    }
}
