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
                    HttpUtils.sendResponse(exchange, (String) rawResult);
                }
            } catch (java.lang.reflect.InvocationTargetException e) {
                final Throwable cause = e.getCause();
                HttpUtils.sendJsonErrorResponse(exchange, 500, "Error: " + (cause != null ? cause.getMessage() : e.getMessage()));
            } catch (Exception e) {
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
    // =========================================================================

    static int findUnescapedQuote(final String s, final int fromIndex) {
        int i = fromIndex;
        while (i < s.length()) {
            final int q = s.indexOf('"', i);
            if (q < 0) return -1;
            int backslashes = 0;
            int j = q - 1;
            while (j >= 0 && s.charAt(j) == '\\') {
                backslashes++;
                j--;
            }
            if (backslashes % 2 == 0) {
                return q;
            }
            i = q + 1;
        }
        return -1;
    }

    static String unescapeJsonString(final String s) {
        if (s == null || s.indexOf('\\') < 0) return s;
        final StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                final char next = s.charAt(i + 1);
                switch (next) {
                    case '"':  sb.append('"');  i++; break;
                    case '\\': sb.append('\\'); i++; break;
                    case 'n':  sb.append('\n'); i++; break;
                    case 'r':  sb.append('\r'); i++; break;
                    case 't':  sb.append('\t'); i++; break;
                    case 'b':  sb.append('\b'); i++; break;
                    case 'f':  sb.append('\f'); i++; break;
                    case '/':  sb.append('/');  i++; break;
                    case 'u':
                        if (i + 5 < s.length()) {
                            try {
                                final int cp = Integer.parseInt(s.substring(i + 2, i + 6), 16);
                                sb.append((char) cp);
                                i += 5;
                            } catch (NumberFormatException e) {
                                sb.append(c);
                            }
                        } else {
                            sb.append(c);
                        }
                        break;
                    default:
                        sb.append(c);
                        break;
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    static String extractJsonString(final String json, final String key) {
        final String searchKey = "\"" + key + "\"";
        final int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        final int colonIndex = json.indexOf(':', keyIndex + searchKey.length());
        if (colonIndex < 0) return null;

        final int quoteStart = json.indexOf('"', colonIndex + 1);
        if (quoteStart < 0) return null;

        final int quoteEnd = findUnescapedQuote(json, quoteStart + 1);
        if (quoteEnd < 0) return null;

        return unescapeJsonString(json.substring(quoteStart + 1, quoteEnd));
    }

    static Integer extractJsonInt(final String json, final String key) {
        final String searchKey = "\"" + key + "\"";
        final int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        final int colonIndex = json.indexOf(':', keyIndex + searchKey.length());
        if (colonIndex < 0) return null;

        int numStart = colonIndex + 1;
        while (numStart < json.length() && Character.isWhitespace(json.charAt(numStart))) numStart++;

        if (numStart < json.length() && json.charAt(numStart) == '"') {
            final int quoteEnd = json.indexOf('"', numStart + 1);
            if (quoteEnd < 0) return null;
            try {
                return Integer.parseInt(json.substring(numStart + 1, quoteEnd));
            } catch (NumberFormatException e) {
                return null;
            }
        }

        int numEnd = numStart;
        while (numEnd < json.length() && (Character.isDigit(json.charAt(numEnd)) ||
               json.charAt(numEnd) == '-')) {
            numEnd++;
        }
        if (numEnd == numStart) return null;

        try {
            return Integer.parseInt(json.substring(numStart, numEnd));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static Map<String, String> extractJsonObject(final String json, final String key) {
        final String searchKey = "\"" + key + "\"";
        final int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return Map.of();

        final int braceStart = json.indexOf('{', keyIndex + searchKey.length());
        if (braceStart < 0) return Map.of();

        int depth = 1;
        int braceEnd = braceStart + 1;
        while (braceEnd < json.length() && depth > 0) {
            final char c = json.charAt(braceEnd);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            braceEnd++;
        }

        final String inner = json.substring(braceStart + 1, braceEnd - 1).trim();
        if (inner.isEmpty()) return Map.of();

        final Map<String, String> result = new LinkedHashMap<>();
        int i = 0;
        while (i < inner.length()) {
            final int qs1 = inner.indexOf('"', i);
            if (qs1 < 0) break;
            final int qe1 = findUnescapedQuote(inner, qs1 + 1);
            if (qe1 < 0) break;
            final String k = unescapeJsonString(inner.substring(qs1 + 1, qe1));

            final int qs2 = inner.indexOf('"', qe1 + 1);
            if (qs2 < 0) break;
            final int qe2 = findUnescapedQuote(inner, qs2 + 1);
            if (qe2 < 0) break;
            final String v = unescapeJsonString(inner.substring(qs2 + 1, qe2));

            result.put(k, v);
            i = qe2 + 1;
        }
        return result;
    }

    @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
    static List<String[]> extractJsonArrayOfPairs(final String json, final String key) {
        final String searchKey = "\"" + key + "\"";
        final int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        final int bracketStart = json.indexOf('[', keyIndex + searchKey.length());
        if (bracketStart < 0) return null;

        int depth = 1;
        int bracketEnd = bracketStart + 1;
        boolean inQuote = false;
        while (bracketEnd < json.length() && depth > 0) {
            final char c = json.charAt(bracketEnd);
            if (c == '"' && (bracketEnd == 0 || json.charAt(bracketEnd - 1) != '\\')) {
                inQuote = !inQuote;
            } else if (!inQuote) {
                if (c == '[') depth++;
                else if (c == ']') depth--;
            }
            bracketEnd++;
        }

        final String inner = json.substring(bracketStart + 1, bracketEnd - 1).trim();
        if (inner.isEmpty()) return List.of();

        final List<String[]> result = new ArrayList<>();
        int i = 0;
        while (i < inner.length()) {
            int arrStart = -1;
            for (int j = i; j < inner.length(); j++) {
                if (inner.charAt(j) == '[') { arrStart = j; break; }
            }
            if (arrStart < 0) break;

            int arrDepth = 1;
            int arrEnd = arrStart + 1;
            boolean arrInQuote = false;
            while (arrEnd < inner.length() && arrDepth > 0) {
                final char c = inner.charAt(arrEnd);
                if (c == '"' && (arrEnd == 0 || inner.charAt(arrEnd - 1) != '\\')) {
                    arrInQuote = !arrInQuote;
                } else if (!arrInQuote) {
                    if (c == '[') arrDepth++;
                    else if (c == ']') arrDepth--;
                }
                arrEnd++;
            }

            final String pair = inner.substring(arrStart + 1, arrEnd - 1);
            final int qs1 = pair.indexOf('"');
            if (qs1 < 0) { i = arrEnd; continue; }
            final int qe1 = findUnescapedQuote(pair, qs1 + 1);
            if (qe1 < 0) { i = arrEnd; continue; }
            final int qs2 = pair.indexOf('"', qe1 + 1);
            if (qs2 < 0) { i = arrEnd; continue; }
            final int qe2 = findUnescapedQuote(pair, qs2 + 1);
            if (qe2 < 0) { i = arrEnd; continue; }

            result.add(new String[]{unescapeJsonString(pair.substring(qs1 + 1, qe1)), unescapeJsonString(pair.substring(qs2 + 1, qe2))});
            i = arrEnd;
        }
        return result;
    }

    static Map<String, Long> extractJsonLongObject(final String json, final String key) {
        final String searchKey = "\"" + key + "\"";
        final int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return Map.of();

        final int braceStart = json.indexOf('{', keyIndex + searchKey.length());
        if (braceStart < 0) return Map.of();

        int depth = 1;
        int braceEnd = braceStart + 1;
        while (braceEnd < json.length() && depth > 0) {
            final char c = json.charAt(braceEnd);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            braceEnd++;
        }

        final String inner = json.substring(braceStart + 1, braceEnd - 1).trim();
        if (inner.isEmpty()) return Map.of();

        final Map<String, Long> result = new LinkedHashMap<>();
        int i = 0;
        while (i < inner.length()) {
            final int qs1 = inner.indexOf('"', i);
            if (qs1 < 0) break;
            final int qe1 = findUnescapedQuote(inner, qs1 + 1);
            if (qe1 < 0) break;
            final String k = unescapeJsonString(inner.substring(qs1 + 1, qe1));

            final int colonIdx = inner.indexOf(':', qe1 + 1);
            if (colonIdx < 0) break;

            int numStart = colonIdx + 1;
            while (numStart < inner.length() && Character.isWhitespace(inner.charAt(numStart))) numStart++;

            int numEnd = numStart;
            while (numEnd < inner.length() && (Character.isDigit(inner.charAt(numEnd)) ||
                   inner.charAt(numEnd) == '-' || inner.charAt(numEnd) == 'x' ||
                   inner.charAt(numEnd) == 'X' ||
                   (inner.charAt(numEnd) >= 'a' && inner.charAt(numEnd) <= 'f') ||
                   (inner.charAt(numEnd) >= 'A' && inner.charAt(numEnd) <= 'F'))) {
                numEnd++;
            }

            final String numStr = inner.substring(numStart, numEnd).trim();
            try {
                long value;
                if (numStr.startsWith("0x") || numStr.startsWith("0X")) {
                    value = Long.parseLong(numStr.substring(2), 16);
                } else {
                    value = Long.parseLong(numStr);
                }
                result.put(k, value);
            } catch (NumberFormatException ignored) {
                // skip entries with non-numeric values
            }
            i = numEnd;
        }
        return result;
    }
}
