package com.lauriewired.mcp;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;

class McpServerManagerTest {

    @Test
    void testMcpServerManagerClass() {
        // Basic test to verify the class exists and has expected methods
        Class<?> clazz = McpServerManager.class;
        
        // Verify class exists
        assertNotNull(clazz);
        
        // Verify it has the expected methods
        try {
            assertNotNull(clazz.getMethod("startServer"));
            assertNotNull(clazz.getMethod("stopServer"));
            assertNotNull(clazz.getMethod("getServer"));
            assertNotNull(clazz.getMethod("isServerRunning"));
        } catch (NoSuchMethodException e) {
            fail("Expected method not found: " + e.getMessage());
        }
    }

    // Note: Testing the actual functionality would require either:
    // 1. Refactoring McpServerManager to be more testable (dependency injection)
    // 2. Using a full Ghidra test environment
    // 3. Integration tests rather than unit tests
}