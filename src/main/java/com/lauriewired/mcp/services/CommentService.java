package com.lauriewired.mcp.services;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicBoolean;

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
}
