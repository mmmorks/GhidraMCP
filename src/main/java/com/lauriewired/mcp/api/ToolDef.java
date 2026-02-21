package com.lauriewired.mcp.api;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
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
            // POST with complex types: parse JSON body once with Jackson
            final String body = new String(HttpUtils.readRequestBody(exchange.getRequestBody()), java.nio.charset.StandardCharsets.UTF_8);
            final JsonNode root = Json.readTree(body);
            for (final ToolParamDef p : params) {
                final JsonNode fieldNode = (root != null) ? root.get(p.name()) : null;
                final Object value = switch (p.type()) {
                    case STRING_MAP -> {
                        if (fieldNode == null || !fieldNode.isObject()) {
                            yield !p.required() ? p.defaultValue() : Map.of();
                        }
                        final Map<String, String> map = new LinkedHashMap<>();
                        fieldNode.fields().forEachRemaining(e -> map.put(e.getKey(), e.getValue().asText()));
                        yield map.isEmpty() && !p.required() ? p.defaultValue() : map;
                    }
                    case LONG_MAP -> {
                        if (fieldNode == null || !fieldNode.isObject()) {
                            yield !p.required() ? p.defaultValue() : Map.of();
                        }
                        final Map<String, Long> map = new LinkedHashMap<>();
                        fieldNode.fields().forEachRemaining(e -> {
                            final var v = e.getValue();
                            if (v.isNumber()) {
                                map.put(e.getKey(), v.asLong());
                            } else {
                                try {
                                    map.put(e.getKey(), Json.parseHexLong(v.asText()));
                                } catch (NumberFormatException ignored) { /* skip */ }
                            }
                        });
                        yield (map.isEmpty()) && !p.required() ? p.defaultValue() : map;
                    }
                    case STRING_PAIR_LIST -> {
                        if (fieldNode == null || !fieldNode.isArray()) {
                            yield !p.required() ? p.defaultValue() : null;
                        }
                        if (fieldNode.isEmpty()) yield List.of();
                        final List<String[]> list = new ArrayList<>();
                        for (final var pair : fieldNode) {
                            if (pair.isArray() && pair.size() >= 2) {
                                list.add(new String[]{pair.get(0).asText(), pair.get(1).asText()});
                            }
                        }
                        yield list;
                    }
                    case STRING -> {
                        if (fieldNode == null || fieldNode.isNull()) {
                            yield p.required() ? null : p.defaultValue();
                        }
                        yield fieldNode.asText();
                    }
                    case INTEGER -> {
                        if (fieldNode == null || fieldNode.isNull()) {
                            yield p.required() ? null : p.defaultValue();
                        }
                        if (fieldNode.isNumber()) yield fieldNode.asInt();
                        try {
                            yield Integer.parseInt(fieldNode.asText());
                        } catch (NumberFormatException e) {
                            yield p.required() ? null : p.defaultValue();
                        }
                    }
                    case LONG -> {
                        if (fieldNode == null || fieldNode.isNull()) {
                            yield p.required() ? null : p.defaultValue();
                        }
                        if (fieldNode.isNumber()) yield fieldNode.asLong();
                        try {
                            yield Json.parseHexLong(fieldNode.asText());
                        } catch (NumberFormatException e) {
                            yield p.required() ? null : p.defaultValue();
                        }
                    }
                    case BOOLEAN -> {
                        if (fieldNode == null || fieldNode.isNull()) {
                            yield p.required() ? null : p.defaultValue();
                        }
                        if (fieldNode.isBoolean()) yield fieldNode.asBoolean();
                        yield Boolean.parseBoolean(fieldNode.asText());
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
        final String normalized = normalizeDescription(rawDescription);
        if (params.isEmpty()) return normalized;

        final StringBuilder sb = new StringBuilder(normalized);
        sb.append("\n\nParameters:\n");
        for (final ToolParamDef p : params) {
            sb.append("    ").append(p.name()).append(": ").append(p.description());
            if (!p.required() && p.defaultValue() != null) {
                sb.append(" (default: ").append(p.defaultValue()).append(")");
            }
            sb.append("\n");
        }
        return sb.toString().stripTrailing();
    }

    /**
     * Normalize a description by unwrapping continuation lines within paragraphs.
     *
     * Java text blocks preserve line breaks that exist only for source readability.
     * This method joins those continuation lines while preserving intentional structure:
     * blank-line paragraph breaks and indented blocks under bare labels (e.g. "Examples:").
     */
    static String normalizeDescription(final String raw) {
        final String[] lines = raw.split("\n", -1);

        // Group consecutive non-blank lines into paragraphs
        final List<List<String>> paragraphs = new ArrayList<>();
        List<String> current = new ArrayList<>();
        for (final String line : lines) {
            if (line.trim().isEmpty()) {
                if (!current.isEmpty()) {
                    paragraphs.add(current);
                    current = new ArrayList<>();
                }
            } else {
                current.add(line);
            }
        }
        if (!current.isEmpty()) paragraphs.add(current);

        final StringBuilder result = new StringBuilder();
        for (int i = 0; i < paragraphs.size(); i++) {
            if (i > 0) result.append("\n\n");
            final List<String> para = paragraphs.get(i);
            final String firstTrimmed = para.get(0).trim();

            // A bare label like "Examples:" — preserve indented lines beneath it
            if (para.size() > 1 && firstTrimmed.endsWith(":") && !firstTrimmed.contains(": ")) {
                for (int j = 0; j < para.size(); j++) {
                    if (j > 0) result.append("\n");
                    result.append(para.get(j));
                }
            } else {
                // Join continuation lines into a single paragraph
                final StringBuilder joined = new StringBuilder(firstTrimmed);
                for (int j = 1; j < para.size(); j++) {
                    final String trimmed = para.get(j).trim();
                    if (!trimmed.isEmpty()) {
                        joined.append(" ").append(trimmed);
                    }
                }
                result.append(joined);
            }
        }
        return result.toString();
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
