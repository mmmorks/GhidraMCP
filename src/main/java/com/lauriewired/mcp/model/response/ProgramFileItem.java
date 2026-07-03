package com.lauriewired.mcp.model.response;

/** One program file in the project tree, for list_program_files. */
public record ProgramFileItem(String path, String name, String contentType, boolean open) {
    @Override
    public String toString() {
        return path + "  (" + contentType + ")" + (open ? "  [open]" : "");
    }
}
