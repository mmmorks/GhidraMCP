package com.lauriewired.mcp.utils;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.sun.net.httpserver.HttpExchange;

import ghidra.util.Msg;

/**
 * Utility methods for HTTP operations in GhidraMCP
 */
public class HttpUtils {
    
    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    public static Map<String, String> parseQueryParams(HttpExchange exchange) {
        var query = exchange.getRequestURI().getRawQuery(); // e.g. offset=10&limit=100
        if (query == null) return Map.of();
        
        return Arrays.stream(query.split("&"))
            .filter(p -> p.contains("="))
            .map(p -> p.split("=", 2))
            .filter(kv -> kv.length == 2)
            .collect(Collectors.toMap(
                kv -> decodeUrlParameter(kv[0]),
                kv -> decodeUrlParameter(kv[1]),
                (v1, v2) -> v1 // In case of duplicate keys, keep the first value
            ));
    }
    
    /**
     * Helper method to decode URL parameters safely
     */
    private static String decodeUrlParameter(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            Msg.warn(HttpUtils.class, "Error decoding URL parameter: " + value + " - " + e.getMessage());
            return value; // Return the original value if decoding fails
        }
    }

    /**
     * Parse post body params, auto-detecting JSON or form-encoded format.
     * If body starts with '{', parses as JSON; otherwise parses as form-encoded.
     */
    public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        var body = exchange.getRequestBody().readAllBytes();
        var bodyStr = new String(body, StandardCharsets.UTF_8).trim();

        // Auto-detect JSON bodies
        if (bodyStr.startsWith("{")) {
            return parseJsonBody(bodyStr);
        }

        return parseFormBody(bodyStr);
    }

    /**
     * Parse form-encoded body params, e.g. oldName=foo&newName=bar
     */
    static Map<String, String> parseFormBody(String bodyStr) {
        return Arrays.stream(bodyStr.split("&"))
            .filter(pair -> !pair.isEmpty())
            .map(pair -> {
                var equalsIndex = pair.indexOf('=');
                if (equalsIndex == -1) return null;

                try {
                    var key = decodeUrlParameter(pair.substring(0, equalsIndex));
                    var value = equalsIndex < pair.length() - 1 ?
                        decodeUrlParameter(pair.substring(equalsIndex + 1)) : "";
                    return Map.entry(key, value);
                } catch (IllegalArgumentException e) {
                    Msg.warn(HttpUtils.class, "Error decoding URL parameter: " + pair + " - " + e.getMessage());
                    return null;
                }
            })
            .filter(Objects::nonNull)
    .collect(Collectors.toMap(
        Map.Entry::getKey,
        Map.Entry::getValue,
        (v1, v2) -> v2 // In case of duplicate keys, keep the last
    ));
    }

    /**
     * Parse a flat JSON object body into a Map of string key-value pairs.
     * Handles string values (with escaped quotes), numeric/boolean values
     * (converted to strings), and null values (skipped).
     */
    public static Map<String, String> parseJsonBody(String body) {
        Map<String, String> result = new java.util.LinkedHashMap<>();
        if (body == null || body.isEmpty()) return result;

        String trimmed = body.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return result;

        // Strip outer braces
        String inner = trimmed.substring(1, trimmed.length() - 1).trim();
        if (inner.isEmpty()) return result;

        int i = 0;
        while (i < inner.length()) {
            // Find key
            int qs = inner.indexOf('"', i);
            if (qs < 0) break;
            int qe = findNextUnescapedQuote(inner, qs + 1);
            if (qe < 0) break;
            String key = unescapeJsonValue(inner.substring(qs + 1, qe));

            // Find colon
            int colon = inner.indexOf(':', qe + 1);
            if (colon < 0) break;

            // Skip whitespace after colon
            int valStart = colon + 1;
            while (valStart < inner.length() && Character.isWhitespace(inner.charAt(valStart))) valStart++;
            if (valStart >= inner.length()) break;

            char firstChar = inner.charAt(valStart);

            if (firstChar == '"') {
                // String value
                int valEnd = findNextUnescapedQuote(inner, valStart + 1);
                if (valEnd < 0) break;
                result.put(key, unescapeJsonValue(inner.substring(valStart + 1, valEnd)));
                i = valEnd + 1;
            } else if (firstChar == '{' || firstChar == '[') {
                // Nested object or array — skip entirely (not a flat value)
                int depth = 1;
                char open = firstChar;
                char close = (open == '{') ? '}' : ']';
                int pos = valStart + 1;
                boolean inStr = false;
                while (pos < inner.length() && depth > 0) {
                    char c = inner.charAt(pos);
                    if (c == '"' && (pos == 0 || inner.charAt(pos - 1) != '\\')) {
                        inStr = !inStr;
                    } else if (!inStr) {
                        if (c == open) depth++;
                        else if (c == close) depth--;
                    }
                    pos++;
                }
                // Don't put nested structures in the flat map
                i = pos;
            } else if (inner.startsWith("null", valStart)) {
                // Null value — skip
                i = valStart + 4;
            } else {
                // Numeric, boolean, or other literal value
                int valEnd = valStart;
                while (valEnd < inner.length() && inner.charAt(valEnd) != ',' && inner.charAt(valEnd) != '}') {
                    valEnd++;
                }
                result.put(key, inner.substring(valStart, valEnd).trim());
                i = valEnd;
            }

            // Skip comma
            while (i < inner.length() && (inner.charAt(i) == ',' || Character.isWhitespace(inner.charAt(i)))) i++;
        }

        return result;
    }

    /**
     * Find the next unescaped double-quote in a string.
     */
    static int findNextUnescapedQuote(String s, int fromIndex) {
        int i = fromIndex;
        while (i < s.length()) {
            int q = s.indexOf('"', i);
            if (q < 0) return -1;
            int backslashes = 0;
            int j = q - 1;
            while (j >= 0 && s.charAt(j) == '\\') { backslashes++; j--; }
            if (backslashes % 2 == 0) return q;
            i = q + 1;
        }
        return -1;
    }

    /**
     * Unescape a JSON string value.
     */
    static String unescapeJsonValue(String s) {
        if (s == null || s.indexOf('\\') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case '"':  sb.append('"');  i++; break;
                    case '\\': sb.append('\\'); i++; break;
                    case 'n':  sb.append('\n'); i++; break;
                    case 'r':  sb.append('\r'); i++; break;
                    case 't':  sb.append('\t'); i++; break;
                    case '/':  sb.append('/');  i++; break;
                    default:   sb.append(c);         break;
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    public static String paginateList(List<String> items, int offset, int limit) {
        if (limit <= 0 || items.isEmpty()) return "";
        
        var start = Math.max(0, offset);
        if (start >= items.size()) return "";
        
        return items.stream()
            .skip(start)
            .limit(limit)
            .collect(Collectors.joining("\n"));
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    public static int parseIntOrDefault(String val, int defaultValue) {
        return Optional.ofNullable(val)
            .map(str -> {
                try {
                    return Integer.parseInt(str);
                } catch (NumberFormatException e) {
                    return defaultValue;
                }
            })
            .orElse(defaultValue);
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    public static String escapeNonAscii(String input) {
        if (input == null) return "";
        
        return input.chars()
            .mapToObj(c -> (c >= 32 && c < 127) ? 
                String.valueOf((char)c) : 
                String.format("\\x%02x", c & 0xFF))
            .collect(Collectors.joining());
    }

    /** Error prefixes that indicate a service-level error response */
    private static final String[] ERROR_PREFIXES = {
        "Error", "Failed", "Invalid", "No program loaded", "No function",
        "Function not found", "Function identifier is required",
        "New name is required", "Address is required",
        "No current location", "No tool available",
        "Code viewer service not available", "Decompilation failed",
        "No high function", "Could not", "No code unit",
        "No references found", "No matches found", "No executable code",
        "Rename failed", "Symbol not found", "DataTypeService not available"
    };

    /**
     * Check if a response string represents an error.
     */
    public static boolean isErrorResponse(String response) {
        if (response == null || response.isEmpty()) return false;
        for (String prefix : ERROR_PREFIXES) {
            if (response.startsWith(prefix)) return true;
        }
        return false;
    }

    /**
     * Send a structured HTTP response from a ToolOutput.
     * Routes StatusOutput with success==false to error response; otherwise sends success envelope.
     */
    public static void sendStructuredResponse(HttpExchange exchange, ToolOutput output) throws IOException {
        if (output instanceof StatusOutput status && !status.success()) {
            sendJsonErrorResponse(exchange, 400, status.message());
        } else {
            String jsonBody = "{\"status\":\"success\",\"data\":" + output.toStructuredJson() + "}";
            sendRawJson(exchange, 200, jsonBody);
        }
    }

    /**
     * Send an HTTP response, automatically wrapping in a JSON envelope.
     * Detects error responses and routes to the appropriate JSON method.
     */
    public static void sendResponse(HttpExchange exchange, String response) throws IOException {
        if (isErrorResponse(response)) {
            sendJsonErrorResponse(exchange, 400, response);
        } else {
            sendJsonResponse(exchange, response);
        }
    }

    /**
     * Send a JSON success response: {"status":"success","data":...}
     * If data looks like JSON (starts with { or [), embeds it raw; otherwise quotes as string.
     */
    public static void sendJsonResponse(HttpExchange exchange, String data) throws IOException {
        String jsonBody;
        if (data != null && !data.isEmpty()) {
            String trimmed = data.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                jsonBody = "{\"status\":\"success\",\"data\":" + trimmed + "}";
            } else {
                jsonBody = "{\"status\":\"success\",\"data\":\"" + escapeJson(data) + "\"}";
            }
        } else {
            jsonBody = "{\"status\":\"success\",\"data\":\"\"}";
        }
        sendRawJson(exchange, 200, jsonBody);
    }

    /**
     * Send a JSON error response: {"status":"error","error":"..."}
     */
    public static void sendJsonErrorResponse(HttpExchange exchange, int statusCode, String errorMessage) throws IOException {
        String jsonBody = "{\"status\":\"error\",\"error\":\"" + escapeJson(errorMessage) + "\"}";
        sendRawJson(exchange, statusCode, jsonBody);
    }

    /**
     * Send a raw JSON string as HTTP response with the given status code.
     */
    private static void sendRawJson(HttpExchange exchange, int statusCode, String jsonBody) throws IOException {
        var bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
    
    /**
     * Escape a string for JSON output.
     * Single-pass implementation handling all JSON-required escapes including
     * control characters U+0000–U+001F.
     */
    public static String escapeJson(String text) {
        if (text == null) {
            return null;
        }

        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        return sb.toString();
    }
}
