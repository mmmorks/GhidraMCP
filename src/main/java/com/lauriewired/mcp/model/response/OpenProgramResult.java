package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

/** Result of open_program: program info for the newly-current program plus an optional warning. */
public record OpenProgramResult(ProgramInfoResult info, String warning) implements Displayable {
    @Override
    public String toDisplayText() {
        final String base = info.toDisplayText();
        return warning == null ? base : base + "\nWarning: " + warning;
    }
}
