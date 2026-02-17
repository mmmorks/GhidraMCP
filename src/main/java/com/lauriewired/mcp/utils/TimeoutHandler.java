package com.lauriewired.mcp.utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import ghidra.util.Msg;

/**
 * Timeout manager that enforces request timeouts for GET requests.
 * Uses a single monitor thread with a priority queue to efficiently track all timeouts.
 * A single instance should be created and reused for all handlers.
 */
public class TimeoutHandler {
    private final long timeoutNanos;
    private final PriorityQueue<RequestContext> timeoutQueue;
    private final Object queueLock = new Object();
    private final Thread monitorThread;
    private final AtomicBoolean shutdown;
    private final AtomicBoolean started;
    
    /**
     * Context for tracking in-flight requests
     */
    private static class RequestContext implements Comparable<RequestContext> {
        final HttpExchange exchange;
        final Thread handlerThread;
        final String path;
        final long timeoutAt; // Absolute time in nanos when this request times out
        final AtomicBoolean completed = new AtomicBoolean(false);
        final AtomicBoolean timedOut = new AtomicBoolean(false);
        
        RequestContext(final HttpExchange exchange, final Thread handlerThread, final String path, final long timeoutAt) {
            this.exchange = exchange;
            this.handlerThread = handlerThread;
            this.path = path;
            this.timeoutAt = timeoutAt;
        }
        
        @Override
        public int compareTo(final RequestContext other) {
            // Earlier timeouts come first
            return Long.compare(this.timeoutAt, other.timeoutAt);
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) return true;
            if (!(o instanceof RequestContext other)) return false;
            return this.timeoutAt == other.timeoutAt && Objects.equals(this.path, other.path);
        }

        @Override
        public int hashCode() {
            return Objects.hash(timeoutAt, path);
        }
    }
    
    /**
     * Create a new timeout handler
     *
     * @param timeoutSeconds the timeout in seconds (0 or negative means no timeout)
     */
    public TimeoutHandler(final int timeoutSeconds) {
        this.timeoutNanos = timeoutSeconds * 1_000_000_000L; // Convert to nanoseconds
        this.timeoutQueue = new PriorityQueue<>();
        this.shutdown = new AtomicBoolean(false);
        this.started = new AtomicBoolean(false);
        
        // Only create monitor thread if timeout is enabled
        if (timeoutSeconds > 0) {
            this.monitorThread = new Thread(this::monitorTimeouts, "GhidraMCP-Timeout-Monitor");
            this.monitorThread.setDaemon(true);
            // Do NOT start the thread here - wait for explicit start() call
        } else {
            this.monitorThread = null;
        }
    }
    
    /**
     * Start the timeout handler. Must be called after construction.
     * This method is idempotent - multiple calls have no effect.
     */
    public void start() {
        if (monitorThread != null && started.compareAndSet(false, true)) {
            monitorThread.start();
        }
    }
    
    /**
     * Create a wrapped handler that enforces timeouts
     *
     * @param delegate the actual handler to wrap
     * @return the wrapped handler
     */
    public HttpHandler wrap(final HttpHandler delegate) {
        return new TimeoutWrappedHandler(delegate);
    }
    
    /**
     * Inner class that wraps individual handlers
     */
    private class TimeoutWrappedHandler implements HttpHandler {
        private final HttpHandler delegate;
        
        TimeoutWrappedHandler(final HttpHandler delegate) {
            this.delegate = delegate;
        }
        
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            TimeoutHandler.this.handleWithTimeout(exchange, delegate);
        }
    }
    
    /**
     * Monitor thread that checks for timed out requests
     */
    private void monitorTimeouts() {
        while (!shutdown.get()) {
            try {
                RequestContext nextTimeout = null;
                long waitTime = Long.MAX_VALUE;
                
                synchronized (queueLock) {
                    // Clean up completed requests and find next timeout
                    while (!timeoutQueue.isEmpty()) {
                        final RequestContext context = timeoutQueue.peek();
                        if (context.completed.get()) {
                            // Remove completed requests
                            timeoutQueue.poll();
                        } else {
                            // Found next active request
                            nextTimeout = context;
                            final long now = System.nanoTime();
                            waitTime = Math.max(0, context.timeoutAt - now);
                            break;
                        }
                    }
                    
                    if (nextTimeout == null) {
                        // No requests to monitor, wait indefinitely
                        queueLock.wait();
                        continue;
                    } else if (waitTime > 0) {
                        // Wait until the next timeout
                        final long waitMillis = waitTime / 1_000_000;
                        final int waitNanos = (int) (waitTime % 1_000_000);
                        queueLock.wait(waitMillis, waitNanos);
                        continue;
                    }
                }
                
                // We have a request that should timeout now
                if (!nextTimeout.completed.get()) {
                    final long now = System.nanoTime();
                    if (now >= nextTimeout.timeoutAt) {
                        // Request has timed out
                        nextTimeout.timedOut.set(true);
                        
                        // Try to close the exchange to interrupt I/O
                        try {
                            nextTimeout.exchange.close();
                        } catch (Exception ignored) {
                            // Closing a timed-out exchange may fail; safe to ignore
                        }
                        
                        // Interrupt the handler thread
                        nextTimeout.handlerThread.interrupt();
                        
                        Msg.warn(this, String.format("Request timeout after %.1f seconds for: %s",
                            timeoutNanos / 1_000_000_000.0, nextTimeout.path));
                        
                        // Remove from queue
                        synchronized (queueLock) {
                            timeoutQueue.remove(nextTimeout);
                        }
                    }
                }
            } catch (InterruptedException e) {
                // Check if shutdown requested
                if (shutdown.get()) {
                    Thread.currentThread().interrupt();
                    break;
                }
                // Otherwise, continue monitoring
            }
        }
    }
    
    /**
     * Handle a request with timeout enforcement
     */
    private void handleWithTimeout(final HttpExchange exchange, final HttpHandler delegate) throws IOException {
        // Only apply timeout to GET requests
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            delegate.handle(exchange);
            return;
        }
        
        // If timeout is disabled (0 or negative), just execute normally
        if (timeoutNanos <= 0) {
            delegate.handle(exchange);
            return;
        }
        
        final String requestPath = exchange.getRequestURI().getPath();
        final long timeoutAt = System.nanoTime() + timeoutNanos;
        final RequestContext context = new RequestContext(exchange, Thread.currentThread(), requestPath, timeoutAt);
        
        // Add to timeout queue and notify monitor
        synchronized (queueLock) {
            timeoutQueue.offer(context);
            queueLock.notify(); // Wake up monitor thread to recalculate next timeout
        }
        
        try {
            // Execute the handler in the current thread
            delegate.handle(exchange);
            
            // Mark as completed
            context.completed.set(true);
            
            // Check if we timed out during execution
            if (context.timedOut.get()) {
                Msg.warn(this, String.format("Request completed but had already timed out after %.1f seconds for: %s",
                    timeoutNanos / 1_000_000_000.0, requestPath));
            }
        } catch (IOException e) {
            context.completed.set(true);
            
            // If we timed out, log it but still throw the IOException
            if (context.timedOut.get()) {
                Msg.warn(this, String.format("Request timed out after %.1f seconds and threw IOException for: %s",
                    timeoutNanos / 1_000_000_000.0, requestPath));
            }
            throw e;
        } catch (RuntimeException e) {
            context.completed.set(true);
            
            // If we timed out, send timeout response instead of propagating the exception
            if (context.timedOut.get()) {
                sendTimeoutResponse(exchange);
            } else {
                // Normal runtime exception, send error response
                Msg.error(this, "Request execution failed: " + requestPath, e);
                sendErrorResponse(exchange, "Internal server error");
            }
        }
    }
    
    /**
     * Send a timeout response to the client as JSON
     */
    private void sendTimeoutResponse(final HttpExchange exchange) throws IOException {
        final String errorMsg = String.format("Request timeout - operation took longer than %.1f seconds",
            timeoutNanos / 1_000_000_000.0);
        sendJsonError(exchange, 408, errorMsg);
    }

    /**
     * Send an error response to the client as JSON
     */
    private void sendErrorResponse(final HttpExchange exchange, final String message) throws IOException {
        sendJsonError(exchange, 500, message);
    }

    /**
     * Send a JSON error envelope with the given status code and message.
     */
    private static void sendJsonError(final HttpExchange exchange, final int statusCode, final String message) throws IOException {
        final java.util.Map<String, Object> envelope = new java.util.LinkedHashMap<>();
        envelope.put("status", "error");
        envelope.put("error", message);
        final byte[] bytes = Json.serialize(envelope).getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);

        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
    
    /**
     * Shutdown the timeout handler and stop the monitor thread
     */
    public void shutdown() {
        shutdown.set(true);
        if (monitorThread != null && started.get()) {
            // Wake up the monitor thread
            synchronized (queueLock) {
                queueLock.notify();
            }
            
            // Wait for it to finish
            try {
                monitorThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}