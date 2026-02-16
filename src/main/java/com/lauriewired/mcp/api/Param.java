package com.lauriewired.mcp.api;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotates a parameter of an @McpTool method with its description and optional default.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface Param {
    /** Sentinel value indicating the parameter is required (no default). */
    String REQUIRED = "\0__REQUIRED__";

    /** Parameter description shown to MCP clients. */
    String value();

    /** Default value as a string, or {@link #REQUIRED} if the parameter is required. */
    String defaultValue() default "\0__REQUIRED__";
}
