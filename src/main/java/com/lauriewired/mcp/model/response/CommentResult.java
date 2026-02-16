package com.lauriewired.mcp.model.response;

public record CommentResult(String address, Comments comments) {
    public record Comments(String pre, String post, String eol, String plate, String repeatable) {}
}
