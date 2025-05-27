package com.lauriewired.mcp.telemetry;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for TelemetryLogger
 */
public class TelemetryLoggerTest {
    
    private TelemetryLogger telemetryLogger;
    
    @TempDir
    Path tempDir;
    
    @BeforeEach
    @SuppressWarnings("unused")
    void setUp() {
        // Use temp directory for telemetry during tests
        String testTelemetryDir = tempDir.resolve(".ghidra_mcp/telemetry").toString();
        telemetryLogger = new TelemetryLogger(testTelemetryDir);
        telemetryLogger.init();
    }
    
    @AfterEach
    @SuppressWarnings("unused")
    void tearDown() {
        if (telemetryLogger != null) {
            telemetryLogger.shutdown();
        }
    }
    
    @Test
    void testLogToolStart() {
        // Given
        String toolName = "test_tool";
        String endpoint = "/test";
        Map<String, Object> params = new HashMap<>();
        params.put("param1", "value1");
        params.put("param2", 123);
        
        // When
        long startTime = telemetryLogger.logToolStart(toolName, endpoint, params);
        
        // Then
        assertTrue(startTime > 0);
        
        // Verify log file was created
        Path telemetryDir = tempDir.resolve(".ghidra_mcp/telemetry");
        assertTrue(Files.exists(telemetryDir));
    }
    
    @Test
    void testLogToolSuccess() throws InterruptedException {
        // Given
        String toolName = "test_tool";
        String endpoint = "/test";
        long startTime = System.currentTimeMillis();
        
        // Simulate some processing time
        Thread.sleep(100);
        
        // When
        telemetryLogger.logToolSuccess(toolName, endpoint, startTime, "Success response", null);
        
        // Then - verify telemetry directory exists
        Path telemetryDir = tempDir.resolve(".ghidra_mcp/telemetry");
        assertTrue(Files.exists(telemetryDir));
    }
    
    @Test
    void testLogToolFailure() {
        // Given
        String toolName = "test_tool";
        String endpoint = "/test";
        long startTime = System.currentTimeMillis();
        String errorType = "TestError";
        String errorMessage = "Test error message";
        
        // When
        telemetryLogger.logToolFailure(toolName, endpoint, startTime, errorType, errorMessage, null);
        
        // Then - verify telemetry directory exists
        Path telemetryDir = tempDir.resolve(".ghidra_mcp/telemetry");
        assertTrue(Files.exists(telemetryDir));
    }
    
    @Test
    void testMultipleToolInvocations() throws InterruptedException {
        // Given
        String toolName1 = "tool1";
        String toolName2 = "tool2";
        
        // When - simulate multiple tool invocations
        for (int i = 0; i < 5; i++) {
            long start1 = telemetryLogger.logToolStart(toolName1, "/endpoint1", null);
            Thread.sleep(10);
            telemetryLogger.logToolSuccess(toolName1, "/endpoint1", start1, "OK", null);
            
            long start2 = telemetryLogger.logToolStart(toolName2, "/endpoint2", null);
            Thread.sleep(5);
            if (i % 2 == 0) {
                telemetryLogger.logToolSuccess(toolName2, "/endpoint2", start2, "OK", null);
            } else {
                telemetryLogger.logToolFailure(toolName2, "/endpoint2", start2, "Error", "Failed", null);
            }
        }
        
        // Then - verify files exist
        Path telemetryDir = tempDir.resolve(".ghidra_mcp/telemetry");
        assertTrue(Files.exists(telemetryDir));
        
        // Generate summary
        telemetryLogger.generateDailySummary();
        
        // Verify summary file exists
        try {
            List<Path> summaryFiles = Files.list(telemetryDir)
                .filter(p -> p.getFileName().toString().startsWith("summary_"))
                .toList();
            assertFalse(summaryFiles.isEmpty(), "Summary file should be created");
        } catch (Exception e) {
            fail("Failed to check for summary files: " + e.getMessage());
        }
    }
    
    @Test
    void testSessionEvents() {
        // Given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("testKey", "testValue");
        
        // When
        telemetryLogger.logSessionEvent("TEST_EVENT", metadata);
        
        // Then - verify telemetry directory exists
        Path telemetryDir = tempDir.resolve(".ghidra_mcp/telemetry");
        assertTrue(Files.exists(telemetryDir));
    }
    
    @Test
    void testShutdown() {
        // Given
        String toolName = "test_tool";
        long startTime = telemetryLogger.logToolStart(toolName, "/test", null);
        telemetryLogger.logToolSuccess(toolName, "/test", startTime, "OK", null);
        
        // When
        telemetryLogger.shutdown();
        
        // Then - verify summary file is created
        Path telemetryDir = tempDir.resolve(".ghidra_mcp/telemetry");
        assertTrue(Files.exists(telemetryDir));
        
        try {
            boolean hasSummary = Files.list(telemetryDir)
                .anyMatch(p -> p.getFileName().toString().startsWith("summary_"));
            assertTrue(hasSummary, "Summary file should be created on shutdown");
        } catch (Exception e) {
            fail("Failed to check for summary files: " + e.getMessage());
        }
    }
}