package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

public record CommentResult(String address, Comments comments) implements Displayable {
    public record Comments(String pre, String post, String eol, String plate, String repeatable) {}

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Comments at ").append(address).append(":\n");

        boolean hasComments = false;

        if (comments.pre() != null) {
            sb.append("\nPre Comment (Decompiler):\n").append(comments.pre()).append("\n");
            hasComments = true;
        }
        if (comments.post() != null) {
            sb.append("\nPost Comment:\n").append(comments.post()).append("\n");
            hasComments = true;
        }
        if (comments.eol() != null) {
            sb.append("\nEnd-of-Line Comment (Disassembly):\n").append(comments.eol()).append("\n");
            hasComments = true;
        }
        if (comments.plate() != null) {
            sb.append("\nPlate Comment:\n").append(comments.plate()).append("\n");
            hasComments = true;
        }
        if (comments.repeatable() != null) {
            sb.append("\nRepeatable Comment:\n").append(comments.repeatable()).append("\n");
            hasComments = true;
        }

        if (!hasComments) {
            sb.append("\n(No comments found at this address)\n");
        }

        return sb.toString();
    }
}
