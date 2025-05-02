package com.lauriewired.mcp.utils;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import ghidra.util.Msg;

/**
 * Utility methods for HTTP operations in GhidraMCP
 */
public class HttpUtils {
    
    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    public static Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getRawQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (IllegalArgumentException e) {
                        // Log the error but continue processing other parameters
                        Msg.warn(HttpUtils.class, "Error decoding URL parameter: " + p + " - " + e.getMessage());
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            // Skip empty pairs
            if (pair.isEmpty()) {
                continue;
            }
            
            // Find the first equals sign
            int equalsIndex = pair.indexOf('=');
            
            // If there's no equals sign, skip this parameter
            if (equalsIndex == -1) {
                continue;
            }
            
            try {
                // Extract key (everything before the first equals sign)
                String key = URLDecoder.decode(pair.substring(0, equalsIndex), StandardCharsets.UTF_8);
                
                // Extract value (everything after the first equals sign, or empty string if at the end)
                String value = "";
                if (equalsIndex < pair.length() - 1) {
                    value = URLDecoder.decode(pair.substring(equalsIndex + 1), StandardCharsets.UTF_8);
                }
                
                params.put(key, value);
            } catch (IllegalArgumentException e) {
                // Log the error but continue processing other parameters
                Msg.warn(HttpUtils.class, "Error decoding URL parameter: " + pair + " - " + e.getMessage());
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    public static String paginateList(List<String> items, int offset, int limit) {
        // Handle zero or negative limit
        if (limit <= 0) {
            return "";
        }
        
        // Handle negative offset by treating it as 0
        int start = Math.max(0, offset);
        // Calculate end position
        int end = Math.min(items.size(), start + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    public static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    public static String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Send a plain text HTTP response
     */
    public static void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
    
    /**
     * Escape a string for JSON output
     */
    public static String escapeJson(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }
}
