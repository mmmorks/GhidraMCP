package com.lauriewired.mcp.telemetry;

import java.io.FileWriter;
import java.io.IOException;
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
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.util.Msg;

/**
 * Telemetry logger for tracking MCP tool usage, success rates, and failure patterns.
 * Outputs structured JSON logs for easy parsing and analysis.
 */
public class TelemetryLogger {
    private static final String DEFAULT_TELEMETRY_DIR = System.getProperty("user.home") + "/.ghidra_mcp/telemetry";
    private static final String LOG_FILE_PREFIX = "mcp_telemetry_";
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    
    private final Gson gson;
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
        
        public TelemetryEvent(String sessionId, String eventType, String toolName, String endpoint,
                            Map<String, Object> parameters, boolean success, String errorType,
                            String errorMessage, long durationMs, long requestSize, long responseSize,
                            Map<String, Object> metadata) {
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
    
    public TelemetryLogger(String telemetryDirPath) {
        this.gson = new GsonBuilder()
            .create(); // No pretty printing for JSONL format
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
    public long logToolStart(String toolName, String endpoint, Map<String, Object> parameters) {
        long startTime = System.currentTimeMillis();
        sessionRequestCount.incrementAndGet();
        
        ToolMetrics metrics = toolMetrics.computeIfAbsent(toolName, k -> new ToolMetrics());
        metrics.invocationCount.incrementAndGet();
        
        // Log the start event
        Map<String, Object> metadata = new ConcurrentHashMap<>();
        metadata.put("sessionRequestNumber", sessionRequestCount.get());
        metadata.put("totalInvocations", metrics.invocationCount.get());
        
        TelemetryEvent event = new TelemetryEvent(
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
    public void logToolSuccess(String toolName, String endpoint, long startTime, 
                              String response, Map<String, Object> additionalMetadata) {
        long duration = System.currentTimeMillis() - startTime;
        
        ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics != null) {
            metrics.successCount.incrementAndGet();
            metrics.totalDurationMs.addAndGet(duration);
            updateMinMax(metrics, duration);
        }
        
        Map<String, Object> metadata = new ConcurrentHashMap<>();
        metadata.put("successRate", calculateSuccessRate(toolName));
        metadata.put("avgDuration", calculateAvgDuration(toolName));
        if (additionalMetadata != null) {
            metadata.putAll(additionalMetadata);
        }
        
        TelemetryEvent event = new TelemetryEvent(
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
    public void logToolFailure(String toolName, String endpoint, long startTime,
                              String errorType, String errorMessage, Map<String, Object> context) {
        long duration = System.currentTimeMillis() - startTime;
        
        ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics != null) {
            metrics.failureCount.incrementAndGet();
            metrics.totalDurationMs.addAndGet(duration);
            updateMinMax(metrics, duration);
            
            // Track error types
            String errorKey = errorType != null ? errorType : "UNKNOWN_ERROR";
            metrics.errorCounts.computeIfAbsent(errorKey, k -> new AtomicLong(0)).incrementAndGet();
        }
        
        Map<String, Object> metadata = new ConcurrentHashMap<>();
        metadata.put("successRate", calculateSuccessRate(toolName));
        metadata.put("failureRate", calculateFailureRate(toolName));
        metadata.put("errorTypeCount", metrics != null ? metrics.errorCounts.get(errorType) : 0);
        if (context != null) {
            metadata.putAll(context);
        }
        
        TelemetryEvent event = new TelemetryEvent(
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
    public void logSessionEvent(String eventType, Map<String, Object> metadata) {
        Map<String, Object> sessionMetadata = new ConcurrentHashMap<>();
        sessionMetadata.put("sessionDuration", System.currentTimeMillis() - sessionStartTime);
        sessionMetadata.put("totalRequests", sessionRequestCount.get());
        sessionMetadata.put("uniqueToolsUsed", toolMetrics.size());
        
        if (metadata != null) {
            sessionMetadata.putAll(metadata);
        }
        
        TelemetryEvent event = new TelemetryEvent(
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
        Map<String, Object> summary = new ConcurrentHashMap<>();
        summary.put("date", DATE_FORMAT.format(LocalDateTime.now()));
        summary.put("sessionId", sessionId);
        summary.put("totalRequests", sessionRequestCount.get());
        summary.put("sessionDurationMs", System.currentTimeMillis() - sessionStartTime);
        
        Map<String, Object> toolSummaries = new ConcurrentHashMap<>();
        for (Map.Entry<String, ToolMetrics> entry : toolMetrics.entrySet()) {
            String toolName = entry.getKey();
            ToolMetrics metrics = entry.getValue();
            
            Map<String, Object> toolSummary = new ConcurrentHashMap<>();
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
        Path summaryFile = telemetryDir.resolve("summary_" + DATE_FORMAT.format(LocalDateTime.now()) + ".json");
        try (FileWriter writer = new FileWriter(summaryFile.toFile(), true)) {
            Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();
            prettyGson.toJson(summary, writer);
            writer.write("\n");
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
    
    // Helper methods
    
    private void writeEvent(TelemetryEvent event) {
        String date = DATE_FORMAT.format(LocalDateTime.now());
        Path logFile = telemetryDir.resolve(LOG_FILE_PREFIX + date + ".jsonl");
        
        try {
            String jsonLine = gson.toJson(event) + "\n";
            Files.write(logFile, jsonLine.getBytes(), 
                       StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            Msg.error(TelemetryLogger.class, "Failed to write telemetry event: " + e.getMessage());
        }
    }
    
    private String generateSessionId() {
        // Use a combination of timestamp and random value instead of object identity
        return "session_" + Instant.now().toEpochMilli() + "_" +
               Integer.toHexString((int)(Math.random() * Integer.MAX_VALUE));
    }
    
    private void updateMinMax(ToolMetrics metrics, long duration) {
        metrics.minDurationMs.updateAndGet(min -> Math.min(min, duration));
        metrics.maxDurationMs.updateAndGet(max -> Math.max(max, duration));
    }
    
    private double calculateSuccessRate(String toolName) {
        ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics == null || metrics.invocationCount.get() == 0) {
            return 0.0;
        }
        return (double) metrics.successCount.get() / metrics.invocationCount.get();
    }
    
    private double calculateFailureRate(String toolName) {
        ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics == null || metrics.invocationCount.get() == 0) {
            return 0.0;
        }
        return (double) metrics.failureCount.get() / metrics.invocationCount.get();
    }
    
    private double calculateAvgDuration(String toolName) {
        ToolMetrics metrics = toolMetrics.get(toolName);
        if (metrics == null || metrics.invocationCount.get() == 0) {
            return 0.0;
        }
        return (double) metrics.totalDurationMs.get() / metrics.invocationCount.get();
    }
    
    private long estimateSize(Object obj) {
        if (obj == null) return 0;
        if (obj instanceof String string) {
            return string.length();
        }
        if (obj instanceof Map) {
            return gson.toJson(obj).length();
        }
        return obj.toString().length();
    }
}