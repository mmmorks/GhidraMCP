package com.lauriewired.mcp.api;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.lauriewired.mcp.McpServerManager;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.Json;
import com.lauriewired.mcp.services.AnalysisService;
import com.lauriewired.mcp.services.CommentService;
import com.lauriewired.mcp.services.DataTypeService;
import com.lauriewired.mcp.services.FunctionService;
import com.lauriewired.mcp.services.MemoryService;
import com.lauriewired.mcp.services.NamespaceService;
import com.lauriewired.mcp.services.ProgramService;
import com.lauriewired.mcp.services.SearchService;
import com.lauriewired.mcp.services.VariableService;
import com.lauriewired.mcp.telemetry.TelemetryInterceptor;
import com.lauriewired.mcp.telemetry.TelemetryLogger;
import com.lauriewired.mcp.utils.HttpUtils;
import com.lauriewired.mcp.utils.TimeoutHandler;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * Registers and manages API endpoints for the HTTP server.
 * Uses @McpTool annotations + reflection to discover tool methods and auto-register handlers.
 */
public class ApiHandlerRegistry {
    private final McpServerManager serverManager;
    private final FunctionService functionService;
    private final NamespaceService namespaceService;
    private final DataTypeService dataTypeService;
    private final AnalysisService analysisService;
    private final CommentService commentService;
    private final MemoryService memoryService;
    private final ProgramService programService;
    private final SearchService searchService;
    private final VariableService variableService;
    private final TelemetryLogger telemetryLogger;
    private final TimeoutHandler timeoutHandler;
    private final List<ToolDef> toolDefs = new ArrayList<>();

    public ApiHandlerRegistry(
            final McpServerManager serverManager,
            final FunctionService functionService,
            final NamespaceService namespaceService,
            final DataTypeService dataTypeService,
            final AnalysisService analysisService,
            final CommentService commentService,
            final MemoryService memoryService,
            final ProgramService programService,
            final SearchService searchService,
            final VariableService variableService) {
        this.serverManager = serverManager;
        this.functionService = functionService;
        this.namespaceService = namespaceService;
        this.dataTypeService = dataTypeService;
        this.analysisService = analysisService;
        this.commentService = commentService;
        this.memoryService = memoryService;
        this.programService = programService;
        this.searchService = searchService;
        this.variableService = variableService;
        this.telemetryLogger = new TelemetryLogger();

        final int timeoutSeconds = serverManager.getRequestTimeoutSeconds();
        this.timeoutHandler = new TimeoutHandler(timeoutSeconds);
        this.timeoutHandler.start();
    }

    /**
     * Register all API endpoints with the server via reflection over @McpTool methods on services.
     */
    public void registerAllEndpoints() {
        if (!serverManager.isServerRunning()) {
            Msg.warn(this, "Cannot register endpoints: Server is not running");
            return;
        }

        final HttpServer server = serverManager.getServer();
        toolDefs.clear();

        final Object[] services = {
            programService, functionService, namespaceService,
            dataTypeService, analysisService, commentService,
            memoryService, searchService, variableService
        };

        for (final Object service : services) {
            // Walk up the class hierarchy to find @McpTool methods declared in the
            // actual service class.  This is necessary because proxy/mock frameworks
            // (e.g. Mockito ByteBuddy subclasses) override methods without carrying
            // over annotations, so we must scan the declaring superclass directly.
            for (Class<?> clz = service.getClass(); clz != null && clz != Object.class; clz = clz.getSuperclass()) {
                for (final Method method : clz.getDeclaredMethods()) {
                    final McpTool ann = method.getAnnotation(McpTool.class);
                    if (ann == null) continue;
                    if (!ToolOutput.class.isAssignableFrom(method.getReturnType())) {
                        Msg.error(this, "@McpTool method " + method.getName()
                            + " must return ToolOutput, but returns " + method.getReturnType().getSimpleName());
                        continue;
                    }
                    method.setAccessible(true);
                    final ToolDef def = ToolDef.fromMethod(method, ann);
                    toolDefs.add(def);
                    registerEndpoint(server, def.getName(), createHandler(def, method, service));
                }
            }
        }

        // Register the /mcp/tools metadata endpoint
        registerMcpToolsEndpoint(server);

        Msg.info(this, "Registered " + toolDefs.size() + " tool endpoints + /mcp/tools");
    }

    /**
     * Get the list of registered tool definitions (for testing).
     */
    public List<ToolDef> getToolDefs() {
        return List.copyOf(toolDefs);
    }

    public void shutdown() {
        if (telemetryLogger != null) {
            telemetryLogger.shutdown();
            Msg.info(this, "Telemetry logger shut down successfully");
        }
        if (timeoutHandler != null) {
            timeoutHandler.shutdown();
            Msg.info(this, "Timeout handler shut down successfully");
        }
    }

    private HttpHandler wrapWithTelemetryAndTimeout(final HttpHandler handler, final String toolName, final String endpoint) {
        final HttpHandler telemetryHandler = new TelemetryInterceptor(handler, telemetryLogger, toolName, endpoint);
        return timeoutHandler.wrap(telemetryHandler);
    }

    private void registerEndpoint(final HttpServer server, final String toolName, final HttpHandler handler) {
        final String endpoint = "/" + toolName;
        server.createContext(endpoint, wrapWithTelemetryAndTimeout(handler, toolName, endpoint));
    }

    /**
     * Create an HttpHandler from a ToolDef + Method, dispatching params via reflection.
     */
    private HttpHandler createHandler(final ToolDef def, final Method method, final Object target) {
        return exchange -> {
            try {
                final Map<String, Object> params = def.parseParams(exchange);
                // Build args array in method parameter order
                final java.lang.reflect.Parameter[] methodParams = method.getParameters();
                final Object[] args = new Object[methodParams.length];
                for (int i = 0; i < methodParams.length; i++) {
                    final Param paramAnn = methodParams[i].getAnnotation(Param.class);
                    if (paramAnn != null) {
                        final String snakeName = Json.toSnakeCase(methodParams[i].getName());
                        args[i] = params.get(snakeName);
                    }
                }
                final Object rawResult = method.invoke(target, args);
                if (rawResult instanceof ToolOutput output) {
                    HttpUtils.sendStructuredResponse(exchange, output);
                } else {
                    HttpUtils.sendResponse(exchange, String.valueOf(rawResult));
                }
            } catch (java.lang.reflect.InvocationTargetException e) {
                final Throwable cause = e.getCause() != null ? e.getCause() : e;
                Msg.error(this, "Tool invocation failed: " + def.getName(), cause);
                HttpUtils.sendJsonErrorResponse(exchange, 500, "Error: " + cause.getMessage());
            } catch (Exception e) {
                Msg.error(this, "Unexpected error handling tool: " + def.getName(), e);
                HttpUtils.sendJsonErrorResponse(exchange, 500, "Error: " + e.getMessage());
            }
        };
    }

    /**
     * Register the /mcp/tools endpoint that serves tool definitions as JSON.
     */
    private void registerMcpToolsEndpoint(final HttpServer server) {
        registerEndpoint(server, "mcp/tools", exchange -> {
            final StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < toolDefs.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(toolDefs.get(i).toToolJson());
            }
            sb.append("]");
            final byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
    }

    // =========================================================================
    // JSON extraction utilities (used by ToolDef.parseParams for complex types)
    // Backed by Jackson's ObjectMapper via Json.readTree().
    // =========================================================================

    static String extractJsonString(final String json, final String key) {
        final var node = Json.readTree(json);
        if (node == null || !node.has(key)) return null;
        final var value = node.get(key);
        if (value.isNull()) return null;
        return value.asText();
    }

    static Integer extractJsonInt(final String json, final String key) {
        final var node = Json.readTree(json);
        if (node == null || !node.has(key)) return null;
        final var value = node.get(key);
        if (value.isNull()) return null;
        if (value.isNumber()) return value.asInt();
        // Handle string-encoded integers
        try {
            return Integer.parseInt(value.asText());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static Map<String, String> extractJsonObject(final String json, final String key) {
        final var node = Json.readTree(json);
        if (node == null || !node.has(key)) return Map.of();
        final var obj = node.get(key);
        if (!obj.isObject()) return Map.of();

        final Map<String, String> result = new LinkedHashMap<>();
        final var fields = obj.fields();
        while (fields.hasNext()) {
            final var entry = fields.next();
            result.put(entry.getKey(), entry.getValue().asText());
        }
        return result;
    }

    @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
    static List<String[]> extractJsonArrayOfPairs(final String json, final String key) {
        final var node = Json.readTree(json);
        if (node == null || !node.has(key)) return null;
        final var arr = node.get(key);
        if (!arr.isArray()) return null;
        if (arr.isEmpty()) return List.of();

        final List<String[]> result = new ArrayList<>();
        for (final var pair : arr) {
            if (!pair.isArray() || pair.size() < 2) continue;
            result.add(new String[]{pair.get(0).asText(), pair.get(1).asText()});
        }
        return result;
    }

    static Map<String, Long> extractJsonLongObject(final String json, final String key) {
        final var node = Json.readTree(json);
        if (node == null || !node.has(key)) return Map.of();
        final var obj = node.get(key);
        if (!obj.isObject()) return Map.of();

        final Map<String, Long> result = new LinkedHashMap<>();
        final var fields = obj.fields();
        while (fields.hasNext()) {
            final var entry = fields.next();
            final var value = entry.getValue();
            if (value.isNumber()) {
                result.put(entry.getKey(), value.asLong());
            } else {
                // Handle string-encoded longs (including hex)
                final String numStr = value.asText().trim();
                try {
                    if (numStr.startsWith("0x") || numStr.startsWith("0X")) {
                        result.put(entry.getKey(), Long.parseLong(numStr.substring(2), 16));
                    } else {
                        result.put(entry.getKey(), Long.parseLong(numStr));
                    }
                } catch (NumberFormatException ignored) {
                    // skip entries with non-numeric values
                }
            }
        }
        return result;
    }
}
