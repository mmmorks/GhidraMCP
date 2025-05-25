package com.lauriewired;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import ghidra.framework.plugintool.util.PluginStatus;

class GhidraMCPPluginTest {

    @Test
    void testPluginInfo() {
        // Test that the plugin has correct metadata
        Class<?> pluginClass = GhidraMCPPlugin.class;
        
        // Check if @PluginInfo annotation is present
        assertTrue(pluginClass.isAnnotationPresent(ghidra.framework.plugintool.PluginInfo.class));
        
        ghidra.framework.plugintool.PluginInfo info = pluginClass.getAnnotation(ghidra.framework.plugintool.PluginInfo.class);
        assertNotNull(info);
        
        // Verify plugin metadata
        assertEquals(PluginStatus.RELEASED, info.status());
        assertEquals("HTTP server plugin", info.shortDescription());
        assertTrue(info.description().contains("HTTP server"));
    }

    // Note: Testing the constructor and other methods would require a full Ghidra test environment
    // which is beyond the scope of unit testing. These would be better as integration tests.
}