package com.lauriewired.mcp.api;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.HttpUtils;
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

    private ToolDef(String name, String rawDescription, boolean post, List<ToolParamDef> params,
                    Class<? extends ToolOutput> outputType) {
        this.name = name;
        this.post = post;
        this.params = params;
        this.outputType = outputType;
        this.hasComplexTypes = params.stream().anyMatch(p ->
            p.type() == ParamType.STRING_MAP || p.type() == ParamType.LONG_MAP || p.type() == ParamType.STRING_PAIR_LIST);
        this.description = buildFullDescription(rawDescription, params);
    }

    /**
     * Build a ToolDef from an annotated method using reflection.
     */
    public static ToolDef fromMethod(Method method, McpTool annotation) {
        String toolName = annotation.name().isEmpty()
            ? camelToSnake(method.getName())
            : annotation.name();

        Parameter[] javaParams = method.getParameters();
        java.lang.annotation.Annotation[][] paramAnnotations = method.getParameterAnnotations();
        java.lang.reflect.Type[] genericTypes = method.getGenericParameterTypes();

        List<ToolParamDef> paramDefs = new ArrayList<>();
        for (int i = 0; i < javaParams.length; i++) {
            Param paramAnn = findParamAnnotation(paramAnnotations[i]);
            if (paramAnn == null) continue;

            String paramName = camelToSnake(javaParams[i].getName());
            ParamType paramType = ParamType.inferFrom(genericTypes[i]);
            boolean required = paramAnn.defaultValue().equals(Param.REQUIRED);
            Object defaultValue = required ? null : parseDefault(paramAnn.defaultValue(), paramType);

            paramDefs.add(new ToolParamDef(paramName, paramType, required, defaultValue, paramAnn.value()));
        }

        return new ToolDef(toolName, annotation.description(), annotation.post(), paramDefs, annotation.outputType());
    }

    /**
     * Convert a camelCase string to snake_case.
     */
    public static String camelToSnake(String camel) {
        return camel.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase();
    }

    /**
     * Parse parameters from an HttpExchange (GET query params or POST body).
     * Returns a Map keyed by snake_case parameter names with typed values.
     */
    public Map<String, Object> parseParams(HttpExchange exchange) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();

        if (params.isEmpty()) return result;

        if (post && hasComplexTypes) {
            // POST with complex types: read raw body and use extractJson* methods
            String body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            for (ToolParamDef p : params) {
                Object value = switch (p.type()) {
                    case STRING_MAP -> {
                        Map<String, String> map = ApiHandlerRegistry.extractJsonObject(body, p.name());
                        yield map.isEmpty() && !p.required() ? p.defaultValue() : map;
                    }
                    case LONG_MAP -> {
                        Map<String, Long> map = ApiHandlerRegistry.extractJsonLongObject(body, p.name());
                        yield (map == null || map.isEmpty()) && !p.required() ? p.defaultValue() : map;
                    }
                    case STRING_PAIR_LIST -> {
                        List<String[]> list = ApiHandlerRegistry.extractJsonArrayOfPairs(body, p.name());
                        yield list == null && !p.required() ? p.defaultValue() : list;
                    }
                    case STRING -> {
                        String s = ApiHandlerRegistry.extractJsonString(body, p.name());
                        yield s != null ? s : (p.required() ? null : p.defaultValue());
                    }
                    case INTEGER -> {
                        Integer intVal = ApiHandlerRegistry.extractJsonInt(body, p.name());
                        yield intVal != null ? intVal : (p.required() ? null : p.defaultValue());
                    }
                    case LONG -> {
                        // Reuse extractJsonInt's number-finding logic, but parse as Long
                        String s = ApiHandlerRegistry.extractJsonString(body, p.name());
                        if (s != null) {
                            try {
                                yield s.startsWith("0x") || s.startsWith("0X")
                                    ? Long.parseLong(s.substring(2), 16)
                                    : Long.parseLong(s);
                            } catch (NumberFormatException e) {
                                yield p.required() ? null : p.defaultValue();
                            }
                        }
                        Integer intVal = ApiHandlerRegistry.extractJsonInt(body, p.name());
                        yield intVal != null ? (long) intVal : (p.required() ? null : p.defaultValue());
                    }
                    case BOOLEAN -> {
                        String s = ApiHandlerRegistry.extractJsonString(body, p.name());
                        yield s != null ? Boolean.parseBoolean(s) : (p.required() ? null : p.defaultValue());
                    }
                };
                result.put(p.name(), value);
            }
        } else if (post) {
            // POST without complex types: use parsePostParams
            Map<String, String> raw = HttpUtils.parsePostParams(exchange);
            for (ToolParamDef p : params) {
                String rawVal = raw.get(p.name());
                result.put(p.name(), p.type().parseFromString(rawVal, p.defaultValue()));
            }
        } else {
            // GET: parse query params
            Map<String, String> raw = HttpUtils.parseQueryParams(exchange);
            for (ToolParamDef p : params) {
                String rawVal = raw.get(p.name());
                result.put(p.name(), p.type().parseFromString(rawVal, p.defaultValue()));
            }
        }

        return result;
    }

    /**
     * Generate JSON for the /mcp/tools listing (one tool entry).
     */
    public String toToolJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"name\": \"").append(escapeJson(name)).append("\"");
        sb.append(", \"description\": \"").append(escapeJson(description)).append("\"");
        sb.append(", \"method\": \"").append(post ? "POST" : "GET").append("\"");
        sb.append(", \"inputSchema\": ").append(toInputSchemaJson());
        sb.append(", \"outputSchema\": ").append(ToolOutput.schemaFor(outputType));
        sb.append("}");
        return sb.toString();
    }

    /**
     * Generate JSON Schema for this tool's input parameters.
     */
    public String toInputSchemaJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"type\": \"object\"");

        if (!params.isEmpty()) {
            sb.append(", \"properties\": {");
            boolean first = true;
            for (ToolParamDef p : params) {
                if (!first) sb.append(", ");
                sb.append(p.type().toJsonSchemaFragment(p.name(), p.description(), p.required(),
                    p.defaultValue() != null ? String.valueOf(p.defaultValue()) : null));
                first = false;
            }
            sb.append("}");

            // Required array
            List<String> required = params.stream()
                .filter(ToolParamDef::required)
                .map(ToolParamDef::name)
                .toList();
            if (!required.isEmpty()) {
                sb.append(", \"required\": [");
                for (int i = 0; i < required.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("\"").append(required.get(i)).append("\"");
                }
                sb.append("]");
            }
        }

        sb.append("}");
        return sb.toString();
    }

    public String getName() { return name; }
    public String getDescription() { return description; }
    public boolean isPost() { return post; }
    public List<ToolParamDef> getParams() { return List.copyOf(params); }
    public Class<? extends ToolOutput> getOutputType() { return outputType; }

    private static String buildFullDescription(String rawDescription, List<ToolParamDef> params) {
        if (params.isEmpty()) return rawDescription;

        StringBuilder sb = new StringBuilder(rawDescription);
        sb.append("\n\n    Parameters:\n");
        for (ToolParamDef p : params) {
            sb.append("        ").append(p.name()).append(": ").append(p.description());
            if (!p.required() && p.defaultValue() != null) {
                sb.append(" (default: ").append(p.defaultValue()).append(")");
            }
            sb.append("\n");
        }
        return sb.toString().stripTrailing();
    }

    private static Param findParamAnnotation(java.lang.annotation.Annotation[] annotations) {
        for (var ann : annotations) {
            if (ann instanceof Param p) return p;
        }
        return null;
    }

    private static Object parseDefault(String defaultStr, ParamType type) {
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

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
