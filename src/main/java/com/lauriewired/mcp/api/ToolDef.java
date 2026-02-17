package com.lauriewired.mcp.api;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.HttpUtils;
import com.lauriewired.mcp.utils.Json;
import com.sun.net.httpserver.HttpExchange;

/**
 * Runtime tool definition built from an @McpTool-annotated method via reflection.
 * Holds all metadata needed to register HTTP handlers and serve MCP tool schemas.
 */
public class ToolDef {
    private final String name;              // snake_case tool name
    private final String description;       // full description including auto-generated Parameters section
    private final boolean post;             // true = POST, false = GET
    private final List<ToolParamDef> params;
    private final boolean hasComplexTypes;  // true if any param is a Map or List type
    private final Class<? extends ToolOutput> outputType;
    private final Class<?> responseType;    // response record type for schema generation

    private ToolDef(final String name, final String rawDescription, final boolean post, final List<ToolParamDef> params,
                    final Class<? extends ToolOutput> outputType, final Class<?> responseType) {
        this.name = name;
        this.post = post;
        this.params = params;
        this.outputType = outputType;
        this.responseType = responseType;
        this.hasComplexTypes = params.stream().anyMatch(p ->
            p.type() == ParamType.STRING_MAP || p.type() == ParamType.LONG_MAP || p.type() == ParamType.STRING_PAIR_LIST);
        this.description = buildFullDescription(rawDescription, params);
    }

    /**
     * Build a ToolDef from an annotated method using reflection.
     */
    public static ToolDef fromMethod(final Method method, final McpTool annotation) {
        final String toolName = annotation.name().isEmpty()
            ? Json.toSnakeCase(method.getName())
            : annotation.name();

        final Parameter[] javaParams = method.getParameters();
        final java.lang.annotation.Annotation[][] paramAnnotations = method.getParameterAnnotations();
        final java.lang.reflect.Type[] genericTypes = method.getGenericParameterTypes();

        final List<ToolParamDef> paramDefs = new ArrayList<>();
        for (int i = 0; i < javaParams.length; i++) {
            final Param paramAnn = findParamAnnotation(paramAnnotations[i]);
            if (paramAnn == null) continue;

            final String paramName = Json.toSnakeCase(javaParams[i].getName());
            final ParamType paramType = ParamType.inferFrom(genericTypes[i]);
            final boolean required = paramAnn.defaultValue().equals(Param.REQUIRED);
            final Object defaultValue = required ? null : parseDefault(paramAnn.defaultValue(), paramType);

            paramDefs.add(new ToolParamDef(paramName, paramType, required, defaultValue, paramAnn.value()));
        }

        return new ToolDef(toolName, annotation.description(), annotation.post(), paramDefs,
            annotation.outputType(), annotation.responseType());
    }

    /**
     * Parse parameters from an HttpExchange (GET query params or POST body).
     * Returns a Map keyed by snake_case parameter names with typed values.
     */
    public Map<String, Object> parseParams(final HttpExchange exchange) throws Exception {
        final Map<String, Object> result = new LinkedHashMap<>();

        if (params.isEmpty()) return result;

        if (post && hasComplexTypes) {
            // POST with complex types: read raw body and use extractJson* methods
            final String body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            for (final ToolParamDef p : params) {
                final Object value = switch (p.type()) {
                    case STRING_MAP -> {
                        final Map<String, String> map = ApiHandlerRegistry.extractJsonObject(body, p.name());
                        yield map.isEmpty() && !p.required() ? p.defaultValue() : map;
                    }
                    case LONG_MAP -> {
                        final Map<String, Long> map = ApiHandlerRegistry.extractJsonLongObject(body, p.name());
                        yield (map == null || map.isEmpty()) && !p.required() ? p.defaultValue() : map;
                    }
                    case STRING_PAIR_LIST -> {
                        final List<String[]> list = ApiHandlerRegistry.extractJsonArrayOfPairs(body, p.name());
                        yield list == null && !p.required() ? p.defaultValue() : list;
                    }
                    case STRING -> {
                        final String s = ApiHandlerRegistry.extractJsonString(body, p.name());
                        yield s != null ? s : (p.required() ? null : p.defaultValue());
                    }
                    case INTEGER -> {
                        final Integer intVal = ApiHandlerRegistry.extractJsonInt(body, p.name());
                        yield intVal != null ? intVal : (p.required() ? null : p.defaultValue());
                    }
                    case LONG -> {
                        // Reuse extractJsonInt's number-finding logic, but parse as Long
                        final String s = ApiHandlerRegistry.extractJsonString(body, p.name());
                        if (s != null) {
                            try {
                                yield s.startsWith("0x") || s.startsWith("0X")
                                    ? Long.parseLong(s.substring(2), 16)
                                    : Long.parseLong(s);
                            } catch (NumberFormatException e) {
                                yield p.required() ? null : p.defaultValue();
                            }
                        }
                        final Integer intVal = ApiHandlerRegistry.extractJsonInt(body, p.name());
                        yield intVal != null ? (long) intVal : (p.required() ? null : p.defaultValue());
                    }
                    case BOOLEAN -> {
                        final String s = ApiHandlerRegistry.extractJsonString(body, p.name());
                        yield s != null ? Boolean.parseBoolean(s) : (p.required() ? null : p.defaultValue());
                    }
                };
                result.put(p.name(), value);
            }
        } else if (post) {
            // POST without complex types: use parsePostParams
            final Map<String, String> raw = HttpUtils.parsePostParams(exchange);
            for (final ToolParamDef p : params) {
                final String rawVal = raw.get(p.name());
                result.put(p.name(), p.type().parseFromString(rawVal, p.defaultValue()));
            }
        } else {
            // GET: parse query params
            final Map<String, String> raw = HttpUtils.parseQueryParams(exchange);
            for (final ToolParamDef p : params) {
                final String rawVal = raw.get(p.name());
                result.put(p.name(), p.type().parseFromString(rawVal, p.defaultValue()));
            }
        }

        return result;
    }

    /**
     * Generate JSON for the /mcp/tools listing (one tool entry).
     */
    public String toToolJson() {
        final Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("name", name);
        tool.put("description", description);
        tool.put("method", post ? "POST" : "GET");
        tool.put("inputSchema", buildInputSchemaMap());

        final String schema = SchemaGenerator.generateSchema(responseType, outputType);
        if (schema != null) {
            try {
                tool.put("outputSchema", Json.readValue(schema, Object.class));
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse generated schema for tool: " + name, e);
            }
        }

        return Json.serialize(tool);
    }

    /**
     * Build the input schema as a Map for Jackson serialization.
     */
    private Map<String, Object> buildInputSchemaMap() {
        final Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        if (!params.isEmpty()) {
            final Map<String, Object> properties = new LinkedHashMap<>();
            for (final ToolParamDef p : params) {
                properties.put(p.name(), p.type().toJsonSchemaMap(p.description(), p.required(),
                    p.defaultValue() != null ? String.valueOf(p.defaultValue()) : null));
            }
            schema.put("properties", properties);

            final List<String> required = params.stream()
                .filter(ToolParamDef::required)
                .map(ToolParamDef::name)
                .toList();
            if (!required.isEmpty()) {
                schema.put("required", required);
            }
        }

        return schema;
    }

    /**
     * Generate JSON Schema for this tool's input parameters.
     */
    public String toInputSchemaJson() {
        return Json.serialize(buildInputSchemaMap());
    }

    public String getName() { return name; }
    public String getDescription() { return description; }
    public boolean isPost() { return post; }
    public List<ToolParamDef> getParams() { return List.copyOf(params); }
    public Class<? extends ToolOutput> getOutputType() { return outputType; }

    private static String buildFullDescription(final String rawDescription, final List<ToolParamDef> params) {
        if (params.isEmpty()) return rawDescription;

        final StringBuilder sb = new StringBuilder(rawDescription);
        sb.append("\n\n    Parameters:\n");
        for (final ToolParamDef p : params) {
            sb.append("        ").append(p.name()).append(": ").append(p.description());
            if (!p.required() && p.defaultValue() != null) {
                sb.append(" (default: ").append(p.defaultValue()).append(")");
            }
            sb.append("\n");
        }
        return sb.toString().stripTrailing();
    }

    private static Param findParamAnnotation(final java.lang.annotation.Annotation[] annotations) {
        for (final var ann : annotations) {
            if (ann instanceof Param p) return p;
        }
        return null;
    }

    private static Object parseDefault(final String defaultStr, final ParamType type) {
        if (defaultStr == null || defaultStr.equals(Param.REQUIRED)) return null;
        if (defaultStr.isEmpty()) return null;
        return switch (type) {
            case INTEGER -> {
                try { yield Integer.parseInt(defaultStr); }
                catch (NumberFormatException e) { yield null; }
            }
            case LONG -> {
                try { yield Long.parseLong(defaultStr); }
                catch (NumberFormatException e) { yield null; }
            }
            case BOOLEAN -> Boolean.parseBoolean(defaultStr);
            default -> defaultStr;
        };
    }
}
