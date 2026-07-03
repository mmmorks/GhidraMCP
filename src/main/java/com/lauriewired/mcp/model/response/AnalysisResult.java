package com.lauriewired.mcp.model.response;

import com.lauriewired.mcp.model.Displayable;

/** Result of reanalyze_program (and the analysis portion of import_program). */
public record AnalysisResult(boolean analyzed, int functionCount, int symbolCount, long elapsedMs)
        implements Displayable {
    @Override
    public String toDisplayText() {
        return "Analyzed: " + analyzed
            + "\nFunctions: " + functionCount
            + "\nSymbols: " + symbolCount
            + "\nElapsed: " + elapsedMs + " ms";
    }
}
