package com.lauriewired.mcp.api;

/**
 * Runtime definition of a single tool parameter, built from @Param annotation + reflection.
 */
public record ToolParamDef(
    String name,           // snake_case parameter name
    ParamType type,        // inferred from Java type
    boolean required,      // true if no defaultValue specified
    Object defaultValue,   // parsed default, or null
    String description     // from @Param.value()
) {}
