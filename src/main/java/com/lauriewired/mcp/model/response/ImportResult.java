package com.lauriewired.mcp.model.response;

import java.util.List;
import com.lauriewired.mcp.model.Displayable;

/** Result of import_program. */
public record ImportResult(
    String name,
    String projectPath,
    String format,
    String languageId,
    int functionCount,
    boolean analyzed,
    List<String> additionalPrograms,
    String warning
) implements Displayable {
    public ImportResult {
        additionalPrograms = additionalPrograms == null ? List.of() : List.copyOf(additionalPrograms);
    }

    @Override
    public String toDisplayText() {
        final StringBuilder sb = new StringBuilder();
        sb.append("Imported: ").append(name).append("\n");
        sb.append("Project path: ").append(projectPath).append("\n");
        sb.append("Format: ").append(format).append("\n");
        sb.append("Language: ").append(languageId).append("\n");
        sb.append("Analyzed: ").append(analyzed).append("\n");
        sb.append("Functions: ").append(functionCount);
        if (!additionalPrograms.isEmpty()) {
            sb.append("\nAdditional programs: ").append(String.join(", ", additionalPrograms));
        }
        if (warning != null) {
            sb.append("\nWarning: ").append(warning);
        }
        return sb.toString();
    }
}
