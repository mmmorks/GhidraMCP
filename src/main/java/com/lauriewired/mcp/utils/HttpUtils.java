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
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        var body = exchange.getRequestBody().readAllBytes();
        var bodyStr = new String(body, StandardCharsets.UTF_8);
        
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

    /**
     * Send a plain text HTTP response
     */
    public static void sendResponse(HttpExchange exchange, String response) throws IOException {
        var bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
    
    /**
     * Escape a string for JSON output
     */
    public static String escapeJson(String text) {
        if (text == null) {
            return null;
        }
        
        // Order matters: escape backslashes first, then other characters
        return text
            .replace("\\", "\\\\")  // Must be first
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }
}
