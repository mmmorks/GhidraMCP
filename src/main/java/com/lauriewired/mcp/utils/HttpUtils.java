package com.lauriewired.mcp.utils;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.sun.net.httpserver.HttpExchange;

import ghidra.util.Msg;

/**
 * Utility methods for HTTP operations in GhidraMCP
 */
public class HttpUtils {

    /** Maximum allowed request body size (1 MB) */
    public static final int MAX_BODY_SIZE = 1024 * 1024;

    /**
     * Read the request body with a size limit. Throws IOException if the body exceeds MAX_BODY_SIZE.
     */
    public static byte[] readRequestBody(final InputStream inputStream) throws IOException {
        final byte[] body = inputStream.readNBytes(MAX_BODY_SIZE + 1);
        if (body.length > MAX_BODY_SIZE) {
            throw new IOException("Request body exceeds maximum allowed size of " + MAX_BODY_SIZE + " bytes");
        }
        return body;
    }

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    public static Map<String, String> parseQueryParams(final HttpExchange exchange) {
        final var query = exchange.getRequestURI().getRawQuery(); // e.g. offset=10&limit=100
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
    private static String decodeUrlParameter(final String value) {
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
    public static Map<String, String> parsePostParams(final HttpExchange exchange) throws IOException {
        final var body = readRequestBody(exchange.getRequestBody());
        final var bodyStr = new String(body, StandardCharsets.UTF_8).trim();

        // Auto-detect JSON bodies
        if (bodyStr.startsWith("{")) {
            return parseJsonBody(bodyStr);
        }

        return parseFormBody(bodyStr);
    }

    /**
     * Parse form-encoded body params, e.g. oldName=foo&newName=bar
     */
    static Map<String, String> parseFormBody(final String bodyStr) {
        return Arrays.stream(bodyStr.split("&"))
            .filter(pair -> !pair.isEmpty())
            .map(pair -> {
                final var equalsIndex = pair.indexOf('=');
                if (equalsIndex == -1) return null;

                try {
                    final var key = decodeUrlParameter(pair.substring(0, equalsIndex));
                    final var value = equalsIndex < pair.length() - 1 ?
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
     * Handles string values, numeric/boolean values (converted to strings),
     * and skips null values and nested objects/arrays.
     */
    public static Map<String, String> parseJsonBody(final String body) {
        final Map<String, String> result = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) return result;

        final JsonNode root = Json.readTree(body.trim());
        if (root == null || !root.isObject()) return result;

        final var fields = root.fields();
        while (fields.hasNext()) {
            final var entry = fields.next();
            final JsonNode value = entry.getValue();
            if (value.isNull() || value.isObject() || value.isArray()) continue;
            result.put(entry.getKey(), value.asText());
        }
        return result;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    public static String paginateList(final List<String> items, final int offset, final int limit) {
        final int clampedLimit = Math.min(Math.max(1, limit), com.lauriewired.mcp.model.ListOutput.MAX_LIMIT);
        if (items.isEmpty()) return "";

        final var start = Math.max(0, offset);
        if (start >= items.size()) return "";

        return items.stream()
            .skip(start)
            .limit(clampedLimit)
            .collect(Collectors.joining("\n"));
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    public static int parseIntOrDefault(final String val, final int defaultValue) {
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
    public static String escapeNonAscii(final String input) {
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
    public static boolean isErrorResponse(final String response) {
        if (response == null || response.isEmpty()) return false;
        for (final String prefix : ERROR_PREFIXES) {
            if (response.startsWith(prefix)) return true;
        }
        return false;
    }

    /**
     * Send a structured HTTP response from a ToolOutput.
     * Routes StatusOutput with success==false to error response; otherwise sends success envelope.
     */
    public static void sendStructuredResponse(final HttpExchange exchange, final ToolOutput output) throws IOException {
        if (output instanceof StatusOutput status && !status.success()) {
            sendJsonErrorResponse(exchange, 400, status.message());
        } else {
            final Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("status", "success");
            // Parse the structured JSON back to an object so it's embedded inline
            envelope.put("data", Json.readValue(output.toStructuredJson(), Object.class));
            envelope.put("text", output.toDisplayText());
            sendRawJson(exchange, 200, Json.serialize(envelope));
        }
    }

    /**
     * Send an HTTP response, automatically wrapping in a JSON envelope.
     * Detects error responses and routes to the appropriate JSON method.
     */
    public static void sendResponse(final HttpExchange exchange, final String response) throws IOException {
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
    public static void sendJsonResponse(final HttpExchange exchange, final String data) throws IOException {
        final Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("status", "success");
        if (data != null && !data.isEmpty()) {
            final String trimmed = data.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                envelope.put("data", Json.readValue(trimmed, Object.class));
            } else {
                envelope.put("data", data);
            }
        } else {
            envelope.put("data", "");
        }
        sendRawJson(exchange, 200, Json.serialize(envelope));
    }

    /**
     * Send a JSON error response: {"status":"error","error":"..."}
     */
    public static void sendJsonErrorResponse(final HttpExchange exchange, final int statusCode, final String errorMessage) throws IOException {
        final Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("status", "error");
        envelope.put("error", errorMessage);
        sendRawJson(exchange, statusCode, Json.serialize(envelope));
    }

    /**
     * Send a raw JSON string as HTTP response with the given status code.
     */
    private static void sendRawJson(final HttpExchange exchange, final int statusCode, final String jsonBody) throws IOException {
        final var bytes = jsonBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
    
    /**
     * Escape a string for JSON output.
     * Delegates to Jackson for correct escaping of all special and control characters.
     */
    public static String escapeJson(final String text) {
        if (text == null) {
            return null;
        }
        // Jackson's serialize wraps in quotes: "escaped content"
        // Strip the surrounding quotes to get just the escaped content.
        final String quoted = Json.serialize(text);
        return quoted.substring(1, quoted.length() - 1);
    }
}
