package com.lauriewired.mcp.telemetry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * HTTP handler wrapper that intercepts requests and responses for telemetry logging
 */
public class TelemetryInterceptor implements HttpHandler {
    private final HttpHandler wrappedHandler;
    private final TelemetryLogger telemetryLogger;
    private final String toolName;
    private final String endpoint;
    
    public TelemetryInterceptor(final HttpHandler handler, final TelemetryLogger logger, final String toolName, final String endpoint) {
        this.wrappedHandler = handler;
        this.telemetryLogger = logger;
        this.toolName = toolName;
        this.endpoint = endpoint;
    }
    
    @Override
    public void handle(final HttpExchange exchange) throws IOException {
        final long startTime = System.currentTimeMillis();
        final Map<String, Object> parameters = new HashMap<>();
        String errorType = null;
        String errorMessage = null;
        boolean success = false;
        String responseBody = "";
        
        try {
            // Capture request parameters
            parameters.putAll(parseQueryParams(exchange));
            
            // Buffer the request body if it's a POST request
            byte[] requestBodyBytes = null;
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                requestBodyBytes = com.lauriewired.mcp.utils.HttpUtils.readRequestBody(exchange.getRequestBody());
                parameters.putAll(parsePostParams(exchange.getRequestHeaders().getFirst("Content-Type"), requestBodyBytes));
            }
            
            // Log tool start
            telemetryLogger.logToolStart(toolName, endpoint, parameters);
            
            // Create a wrapper for the response to capture output
            final HttpExchangeWrapper wrapper = new HttpExchangeWrapper(exchange, requestBodyBytes);
            
            // Execute the actual handler
            wrappedHandler.handle(wrapper);
            
            // Capture response
            responseBody = wrapper.getCapturedResponseBody();
            final int responseCode = wrapper.getCapturedResponseCode();
            
            // Determine success based on HTTP status code
            success = responseCode >= 200 && responseCode < 300;
            
            if (!success) {
                errorType = "HTTP_" + responseCode;
                errorMessage = responseBody;
            }
            
        } catch (IOException | RuntimeException e) {
            errorType = e.getClass().getSimpleName();
            errorMessage = e.getMessage();
            success = false;
            
            throw e;
        } finally {
            // Log the result
            if (success) {
                final Map<String, Object> metadata = new HashMap<>();
                metadata.put("responseLength", responseBody.length());
                telemetryLogger.logToolSuccess(toolName, endpoint, startTime, responseBody, metadata);
            } else {
                final Map<String, Object> context = new HashMap<>();
                context.put("parameters", parameters);
                telemetryLogger.logToolFailure(toolName, endpoint, startTime, errorType, errorMessage, context);
            }
        }
    }
    
    private Map<String, Object> parseQueryParams(final HttpExchange exchange) {
        final Map<String, Object> params = new HashMap<>();
        final String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            for (final String param : query.split("&")) {
                final String[] pair = param.split("=", 2);
                if (pair.length == 2) {
                    params.put(pair[0], pair[1]);
                }
            }
        }
        return params;
    }
    
    private Map<String, Object> parsePostParams(final String contentType, final byte[] bodyBytes) throws IOException {
        final Map<String, Object> params = new HashMap<>();
        if (bodyBytes == null) return params;

        final String body = new String(bodyBytes, StandardCharsets.UTF_8).trim();

        // Handle JSON content type or auto-detect JSON body
        if ((contentType != null && contentType.contains("application/json")) || body.startsWith("{")) {
            final Map<String, String> jsonParams = com.lauriewired.mcp.utils.HttpUtils.parseJsonBody(body);
            params.putAll(jsonParams);
            return params;
        }

        if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
            for (final String param : body.split("&")) {
                final String[] pair = param.split("=", 2);
                if (pair.length == 2) {
                    params.put(pair[0], java.net.URLDecoder.decode(pair[1], "UTF-8"));
                }
            }
        }

        return params;
    }
    
    /**
     * Wrapper class to capture HTTP response data
     */
    private static class HttpExchangeWrapper extends HttpExchange {
        private final HttpExchange wrapped;
        private final ByteArrayOutputStream responseCapture;
        private final byte[] bufferedRequestBody;
        private OutputStream originalOutput;
        private int responseCode = 200;
        
        public HttpExchangeWrapper(final HttpExchange exchange, final byte[] requestBodyBytes) {
            this.wrapped = exchange;
            this.responseCapture = new ByteArrayOutputStream();
            this.bufferedRequestBody = requestBodyBytes;
        }
        
        @Override
        public void sendResponseHeaders(final int rCode, final long responseLength) throws IOException {
            this.responseCode = rCode;
            wrapped.sendResponseHeaders(rCode, responseLength);
        }
        
        @Override
        public OutputStream getResponseBody() {
            if (originalOutput == null) {
                originalOutput = wrapped.getResponseBody();
                return new TeeOutputStream(originalOutput, responseCapture);
            }
            return originalOutput;
        }
        
        public String getCapturedResponseBody() {
            return responseCapture.toString(StandardCharsets.UTF_8);
        }
        
        public int getCapturedResponseCode() {
            return responseCode;
        }
        
        // Delegate all other methods
        @Override
        public com.sun.net.httpserver.Headers getRequestHeaders() {
            return wrapped.getRequestHeaders();
        }
        
        @Override
        public com.sun.net.httpserver.Headers getResponseHeaders() {
            return wrapped.getResponseHeaders();
        }
        
        @Override
        public java.net.URI getRequestURI() {
            return wrapped.getRequestURI();
        }
        
        @Override
        public String getRequestMethod() {
            return wrapped.getRequestMethod();
        }
        
        @Override
        public com.sun.net.httpserver.HttpContext getHttpContext() {
            return wrapped.getHttpContext();
        }
        
        @Override
        public void close() {
            wrapped.close();
        }
        
        @Override
        public InputStream getRequestBody() {
            // Return a new ByteArrayInputStream with the buffered body
            if (bufferedRequestBody != null) {
                return new ByteArrayInputStream(bufferedRequestBody);
            }
            return wrapped.getRequestBody();
        }
        
        @Override
        public java.net.InetSocketAddress getRemoteAddress() {
            return wrapped.getRemoteAddress();
        }
        
        @Override
        public int getResponseCode() {
            return -1; // Default implementation as required by HttpExchange
        }
        
        @Override
        public java.net.InetSocketAddress getLocalAddress() {
            return wrapped.getLocalAddress();
        }
        
        @Override
        public String getProtocol() {
            return wrapped.getProtocol();
        }
        
        @Override
        public Object getAttribute(final String name) {
            return wrapped.getAttribute(name);
        }
        
        @Override
        public void setAttribute(final String name, final Object value) {
            wrapped.setAttribute(name, value);
        }
        
        @Override
        public void setStreams(final InputStream i, final OutputStream o) {
            wrapped.setStreams(i, o);
        }
        
        @Override
        public com.sun.net.httpserver.HttpPrincipal getPrincipal() {
            return wrapped.getPrincipal();
        }
    }
    
    /**
     * Output stream that writes to two streams simultaneously
     */
    private static class TeeOutputStream extends OutputStream {
        private final OutputStream out1;
        private final OutputStream out2;
        
        public TeeOutputStream(final OutputStream out1, final OutputStream out2) {
            this.out1 = out1;
            this.out2 = out2;
        }
        
        @Override
        public void write(final int b) throws IOException {
            out1.write(b);
            out2.write(b);
        }
        
        @Override
        public void write(final byte[] b, final int off, final int len) throws IOException {
            out1.write(b, off, len);
            out2.write(b, off, len);
        }
        
        @Override
        public void flush() throws IOException {
            out1.flush();
            out2.flush();
        }
        
        @Override
        public void close() throws IOException {
            try (out1) {
                out2.close();
            }
        }
    }
}