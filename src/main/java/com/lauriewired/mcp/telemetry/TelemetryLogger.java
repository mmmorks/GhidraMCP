package com.lauriewired.mcp.telemetry;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.util.Msg;

/**
 * Telemetry logger for tracking MCP tool usage, success rates, and failure patterns.
 * Outputs structured JSON logs for easy parsing and analysis.
 *
 * <p>Uses hand-rolled JSON serialization to avoid runtime dependency on Gson,
 * which is not guaranteed to be on Ghidra's extension classloader path.
 */
public class TelemetryLogger {
    private static final String DEFAULT_TELEMETRY_DIR = System.getProperty("user.home") + "/.ghidra_mcp/telemetry";
    private static final String LOG_FILE_PREFIX = "mcp_telemetry_";
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

    private final Path telemetryDir;
    private final Map<String, ToolMetrics> toolMetrics;
    private final AtomicLong sessionRequestCount;
    private final String sessionId;
    private final long sessionStartTime;

    /**
     * Metrics tracked for each tool
     */
    private static class ToolMetrics {
        final AtomicLong invocationCount = new AtomicLong(0);
        final AtomicLong successCount = new AtomicLong(0);
        final AtomicLong failureCount = new AtomicLong(0);
        final AtomicLong totalDurationMs = new AtomicLong(0);
        final AtomicLong minDurationMs = new AtomicLong(Long.MAX_VALUE);
        final AtomicLong maxDurationMs = new AtomicLong(0);
        final Map<String, AtomicLong> errorCounts = new ConcurrentHashMap<>();
    }

    /**
     * Telemetry event structure
     */
    public static class TelemetryEvent {
        public final String timestamp;
        public final String sessionId;
        public final String eventType;
        public final String toolName;
        public final String endpoint;
        public final Map<String, Object> parameters;
        public final boolean success;
        public final String errorType;
        public final String errorMessage;
        public final long durationMs;
        public final long requestSize;
        public final long responseSize;
        public final Map<String, Object> metadata;

        public TelemetryEvent(final String sessionId, final String eventType, final String toolName, final String endpoint,
                            final Map<String, Object> parameters, final boolean success, final String errorType,
                            final String errorMessage, final long durationMs, final long requestSize, final long responseSize,
                            final Map<String, Object> metadata) {
            this.timestamp = TIMESTAMP_FORMAT.format(LocalDateTime.now(ZoneId.of("UTC")));
            this.sessionId = sessionId;
            this.eventType = eventType;
            this.toolName = toolName;
            this.endpoint = endpoint;
            this.parameters = parameters;
            this.success = success;
            this.errorType = errorType;
            this.errorMessage = errorMessage;
            this.durationMs = durationMs;
            this.requestSize = requestSize;
            this.responseSize = responseSize;
            this.metadata = metadata;
        }
    }

    public TelemetryLogger() {
        this(DEFAULT_TELEMETRY_DIR);
    }

    public TelemetryLogger(final String telemetryDirPath) {
        this.telemetryDir = Paths.get(telemetryDirPath);
        this.toolMetrics = new ConcurrentHashMap<>();
        this.sessionRequestCount = new AtomicLong(0);
        this.sessionStartTime = System.currentTimeMillis();
        this.sessionId = generateSessionId();

        // Create telemetry directory if it doesn't exist
        try {
            Files.createDirectories(telemetryDir);
            Msg.info(TelemetryLogger.class, "Telemetry directory created/verified at: " + telemetryDir);
        } catch (IOException e) {
            Msg.error(TelemetryLogger.class, "Failed to create telemetry directory: " + e.getMessage());
        }

        // Note: Session start logging moved to a separate init() method to avoid using 'this' in constructor
    }

    /**
     * Initialize the telemetry logger after construction.
     * This should be called immediately after creating the TelemetryLogger instance.
     */
    public void init() {
        // Log session start
        logSessionEvent("SESSION_START", null);
    }

    /**
     * Log the start of a tool invocation
     */
    public long logToolStart(final String toolName, final String endpoint, final Map<String, Object> parameters) {
        final long startTime = System.currentTimeMillis();
        sessionRequestCount.incrementAndGet();

        final ToolMetrics metrics = toolMetrics.computeIfAbsent(toolName, k -> new ToolMetrics());
        metrics.invocationCount.incrementAndGet();

        // Log the start event
        final Map<String, Object> metadata = new ConcurrentHashMap<>();
        metadata.put("sessionRequestNumber", sessionRequestCount.get());
        metadata.put("totalInvocations", metrics.invocationCount.get());

        final TelemetryEvent event = new TelemetryEvent(
            sessionId,
            "TOOL_START",
            toolName,
            endpoint,
            parameters,
            true,
            null,
            null,
            0,
            estimateSize(parameters),
            0,
            metadata
        );

        writeEvent(event);
        return startTime;
    }

    /**
     * Log successful tool completion
     */
    public void logToolSuccess(final String toolName, final String endpoint, final long startTime,
                              final String response, final Map<String, Object> additionalMetadata) {
        final long duration = System.currentTimeMillis() - startTime;

        final ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics != null) {
            metrics.successCount.incrementAndGet();
            metrics.totalDurationMs.addAndGet(duration);
            updateMinMax(metrics, duration);
        }

        final Map<String, Object> metadata = new ConcurrentHashMap<>();
        metadata.put("successRate", calculateSuccessRate(toolName));
        metadata.put("avgDuration", calculateAvgDuration(toolName));
        if (additionalMetadata != null) {
            metadata.putAll(additionalMetadata);
        }

        final TelemetryEvent event = new TelemetryEvent(
            sessionId,
            "TOOL_SUCCESS",
            toolName,
            endpoint,
            null,
            true,
            null,
            null,
            duration,
            0,
            estimateSize(response),
            metadata
        );

        writeEvent(event);
    }

    /**
     * Log tool failure
     */
    public void logToolFailure(final String toolName, final String endpoint, final long startTime,
                              final String errorType, final String errorMessage, final Map<String, Object> context) {
        final long duration = System.currentTimeMillis() - startTime;

        final ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics != null) {
            metrics.failureCount.incrementAndGet();
            metrics.totalDurationMs.addAndGet(duration);
            updateMinMax(metrics, duration);

            // Track error types
            final String errorKey = errorType != null ? errorType : "UNKNOWN_ERROR";
            metrics.errorCounts.computeIfAbsent(errorKey, k -> new AtomicLong(0)).incrementAndGet();
        }

        final Map<String, Object> metadata = new ConcurrentHashMap<>();
        metadata.put("successRate", calculateSuccessRate(toolName));
        metadata.put("failureRate", calculateFailureRate(toolName));
        metadata.put("errorTypeCount", metrics != null ? metrics.errorCounts.get(errorType) : 0);
        if (context != null) {
            metadata.putAll(context);
        }

        final TelemetryEvent event = new TelemetryEvent(
            sessionId,
            "TOOL_FAILURE",
            toolName,
            endpoint,
            null,
            false,
            errorType,
            errorMessage,
            duration,
            0,
            0,
            metadata
        );

        writeEvent(event);
    }

    /**
     * Log session-level events
     */
    public void logSessionEvent(final String eventType, final Map<String, Object> metadata) {
        final Map<String, Object> sessionMetadata = new ConcurrentHashMap<>();
        sessionMetadata.put("sessionDuration", System.currentTimeMillis() - sessionStartTime);
        sessionMetadata.put("totalRequests", sessionRequestCount.get());
        sessionMetadata.put("uniqueToolsUsed", toolMetrics.size());

        if (metadata != null) {
            sessionMetadata.putAll(metadata);
        }

        final TelemetryEvent event = new TelemetryEvent(
            sessionId,
            eventType,
            null,
            null,
            null,
            true,
            null,
            null,
            0,
            0,
            0,
            sessionMetadata
        );

        writeEvent(event);
    }

    /**
     * Generate daily summary report
     */
    public void generateDailySummary() {
        final Map<String, Object> summary = new ConcurrentHashMap<>();
        summary.put("date", DATE_FORMAT.format(LocalDateTime.now()));
        summary.put("sessionId", sessionId);
        summary.put("totalRequests", sessionRequestCount.get());
        summary.put("sessionDurationMs", System.currentTimeMillis() - sessionStartTime);

        final Map<String, Object> toolSummaries = new ConcurrentHashMap<>();
        for (final Map.Entry<String, ToolMetrics> entry : toolMetrics.entrySet()) {
            final String toolName = entry.getKey();
            final ToolMetrics metrics = entry.getValue();

            final Map<String, Object> toolSummary = new ConcurrentHashMap<>();
            toolSummary.put("invocations", metrics.invocationCount.get());
            toolSummary.put("successes", metrics.successCount.get());
            toolSummary.put("failures", metrics.failureCount.get());
            toolSummary.put("successRate", calculateSuccessRate(toolName));
            toolSummary.put("avgDurationMs", calculateAvgDuration(toolName));
            toolSummary.put("minDurationMs", metrics.minDurationMs.get() == Long.MAX_VALUE ? 0 : metrics.minDurationMs.get());
            toolSummary.put("maxDurationMs", metrics.maxDurationMs.get());
            toolSummary.put("errorTypes", metrics.errorCounts);

            toolSummaries.put(toolName, toolSummary);
        }

        summary.put("tools", toolSummaries);

        // Write summary to separate file with pretty printing
        final Path summaryFile = telemetryDir.resolve("summary_" + DATE_FORMAT.format(LocalDateTime.now()) + ".json");
        try {
            final String json = toJsonPretty(summary);
            Files.write(summaryFile.toFile().toPath(), (json + "\n").getBytes(StandardCharsets.UTF_8),
                       StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            Msg.info(TelemetryLogger.class, "Daily summary written to: " + summaryFile);
        } catch (IOException e) {
            Msg.error(TelemetryLogger.class, "Failed to write daily summary: " + e.getMessage());
        }
    }

    /**
     * Shutdown telemetry and generate final reports
     */
    public void shutdown() {
        logSessionEvent("SESSION_END", null);
        generateDailySummary();
    }

    // --- JSON serialization (no external dependencies) ---

    private void writeEvent(final TelemetryEvent event) {
        final String date = DATE_FORMAT.format(LocalDateTime.now());
        final Path logFile = telemetryDir.resolve(LOG_FILE_PREFIX + date + ".jsonl");

        try {
            final String jsonLine = eventToJson(event) + "\n";
            Files.write(logFile, jsonLine.getBytes(StandardCharsets.UTF_8),
                       StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            Msg.error(TelemetryLogger.class, "Failed to write telemetry event: " + e.getMessage());
        }
    }

    private String eventToJson(final TelemetryEvent event) {
        final StringBuilder sb = new StringBuilder();
        sb.append('{');
        appendJsonString(sb, "timestamp", event.timestamp); sb.append(',');
        appendJsonString(sb, "sessionId", event.sessionId); sb.append(',');
        appendJsonString(sb, "eventType", event.eventType); sb.append(',');
        appendJsonString(sb, "toolName", event.toolName); sb.append(',');
        appendJsonString(sb, "endpoint", event.endpoint); sb.append(',');
        appendJsonMap(sb, "parameters", event.parameters); sb.append(',');
        sb.append("\"success\":").append(event.success).append(',');
        appendJsonString(sb, "errorType", event.errorType); sb.append(',');
        appendJsonString(sb, "errorMessage", event.errorMessage); sb.append(',');
        sb.append("\"durationMs\":").append(event.durationMs).append(',');
        sb.append("\"requestSize\":").append(event.requestSize).append(',');
        sb.append("\"responseSize\":").append(event.responseSize).append(',');
        appendJsonMap(sb, "metadata", event.metadata);
        sb.append('}');
        return sb.toString();
    }

    private static void appendJsonString(final StringBuilder sb, final String key, final String value) {
        sb.append('"').append(escapeJson(key)).append("\":");
        if (value == null) {
            sb.append("null");
        } else {
            sb.append('"').append(escapeJson(value)).append('"');
        }
    }

    private static void appendJsonMap(final StringBuilder sb, final String key, final Map<String, Object> map) {
        sb.append('"').append(escapeJson(key)).append("\":");
        if (map == null) {
            sb.append("null");
        } else {
            sb.append(mapToJson(map));
        }
    }

    private static String mapToJson(final Map<?, ?> map) {
        final StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (final Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(escapeJson(String.valueOf(entry.getKey()))).append("\":");
            sb.append(valueToJson(entry.getValue()));
        }
        sb.append('}');
        return sb.toString();
    }

    private static String valueToJson(final Object value) {
        if (value == null) return "null";
        if (value instanceof String s) return "\"" + escapeJson(s) + "\"";
        if (value instanceof Number) return value.toString();
        if (value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?> m) return mapToJson(m);
        if (value instanceof AtomicLong al) return String.valueOf(al.get());
        return "\"" + escapeJson(value.toString()) + "\"";
    }

    static String toJsonPretty(final Map<?, ?> map) {
        return toJsonPretty(map, 0);
    }

    private static String toJsonPretty(final Map<?, ?> map, final int indent) {
        final StringBuilder sb = new StringBuilder();
        final String pad = "  ".repeat(indent + 1);
        final String closePad = "  ".repeat(indent);
        sb.append("{\n");
        boolean first = true;
        for (final Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) sb.append(",\n");
            first = false;
            sb.append(pad).append('"').append(escapeJson(String.valueOf(entry.getKey()))).append("\": ");
            final Object val = entry.getValue();
            if (val instanceof Map<?, ?> m) {
                sb.append(toJsonPretty(m, indent + 1));
            } else {
                sb.append(valueToJson(val));
            }
        }
        sb.append('\n').append(closePad).append('}');
        return sb.toString();
    }

    private static String escapeJson(final String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // --- Helper methods ---

    private String generateSessionId() {
        // Use a combination of timestamp and random value instead of object identity
        return "session_" + Instant.now().toEpochMilli() + "_" +
               Integer.toHexString(ThreadLocalRandom.current().nextInt());
    }

    private void updateMinMax(final ToolMetrics metrics, final long duration) {
        metrics.minDurationMs.updateAndGet(min -> Math.min(min, duration));
        metrics.maxDurationMs.updateAndGet(max -> Math.max(max, duration));
    }

    private double calculateSuccessRate(final String toolName) {
        final ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics == null || metrics.invocationCount.get() == 0) {
            return 0.0;
        }
        return (double) metrics.successCount.get() / metrics.invocationCount.get();
    }

    private double calculateFailureRate(final String toolName) {
        final ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics == null || metrics.invocationCount.get() == 0) {
            return 0.0;
        }
        return (double) metrics.failureCount.get() / metrics.invocationCount.get();
    }

    private double calculateAvgDuration(final String toolName) {
        final ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics == null || metrics.invocationCount.get() == 0) {
            return 0.0;
        }
        return (double) metrics.totalDurationMs.get() / metrics.invocationCount.get();
    }

    private long estimateSize(final Object obj) {
        if (obj == null) return 0;
        if (obj instanceof String string) {
            return string.length();
        }
        if (obj instanceof Map<?, ?> map) {
            return mapToJson(map).length();
        }
        return obj.toString().length();
    }
}
