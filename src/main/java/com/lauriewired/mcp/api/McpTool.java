package com.lauriewired.mcp.api;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.lauriewired.mcp.model.ToolOutput;

/**
 * Marks a method as an MCP tool endpoint.
 * Reflection discovers annotated methods at startup, auto-converts camelCase names
 * to snake_case for the MCP/HTTP interface, and registers HTTP handlers.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface McpTool {
    /** Override tool name (empty = derive from method name via Json.toSnakeCase). */
    String name() default "";

    /** Tool description text. A Parameters: section is auto-appended from @Param annotations. */
    String description();

    /** If true, the endpoint accepts POST; otherwise GET. */
    boolean post() default false;

    /** Output type for this tool — determines fallback outputSchema in /mcp/tools. */
    Class<? extends ToolOutput> outputType() default ToolOutput.class;

    /** Response record type — used to derive outputSchema via reflection. Void.class means no typed schema. */
    Class<?> responseType() default Void.class;
}
