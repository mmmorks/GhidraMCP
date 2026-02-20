package com.lauriewired.mcp.services;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.ProgramTransaction;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
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
    public CommentService(final ProgramService programService) {
        this.programService = programService;
    }

    @McpTool(post = true, description = """
        Set a comment at an address.

        Creates or replaces a comment of the specified type.

        Returns: Success or failure message

        Examples:
            set_comment("00401010", "Initialize config", "decompiler")
            set_comment("00401010", "Save return address", "eol")
            set_comment("00401000", "--- Main Entry ---", "plate") """,
        outputType = StatusOutput.class, responseType = StatusOutput.class)
    public ToolOutput setComment(
            @Param("final Target address (e.g., \"00401000\" or \"ram:00401000\")") final String address,
            @Param("Comment text to set") final String comment,
            @Param("final Comment type: \"pre\"/\"decompiler\", \"eol\"/\"disassembly\", \"post\", \"plate\", \"repeatable\"") final String type) {
        if (type == null || type.isEmpty()) {
            return StatusOutput.error("Error: 'type' parameter is required (pre, post, eol, plate, repeatable)");
        }
        final CommentType commentType = switch (type.toLowerCase()) {
            case "pre", "decompiler" -> CommentType.PRE;
            case "post" -> CommentType.POST;
            case "eol", "disassembly" -> CommentType.EOL;
            case "plate" -> CommentType.PLATE;
            case "repeatable" -> CommentType.REPEATABLE;
            default -> null;
        };
        if (commentType == null) {
            return StatusOutput.error("Failed to set comment. Valid types: pre, post, eol, plate, repeatable");
        }
        final boolean success = setCommentAtAddress(address, comment, commentType, "Set " + type + " comment");
        return success ? StatusOutput.ok("Comment set successfully") : StatusOutput.error("Failed to set comment. Valid types: pre, post, eol, plate, repeatable");
    }

    /**
     * Set a comment using the specified comment type constant
     */
    private boolean setCommentAtAddress(final String addressStr, final String comment, final CommentType commentType, final String transactionName) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        try (var tx = ProgramTransaction.start(program, transactionName)) {
            final Address addr = program.getAddressFactory().getAddress(addressStr);
            program.getListing().setComment(addr, commentType, comment);
            tx.commit();
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
            return false;
        }
    }

}
