package com.lauriewired.mcp;

import com.sun.net.httpserver.HttpServer;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * Manages the HTTP server for GhidraMCP
 */
public class McpServerManager {
    private HttpServer server;
    private final PluginTool tool;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;
    
    /**
     * Creates a new McpServerManager
     *
     * @param tool the plugin tool
     */
    public McpServerManager(PluginTool tool) {
        this.tool = tool;
        registerOptions();
    }
    
    /**
     * Register configuration options for the HTTP server
     */
    private void registerOptions() {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
    }
    
    /**
     * Start the HTTP server with the configured port
     *
     * @return true if the server was started successfully
     * @throws IOException if there was an error starting the server
     */
    public boolean startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        
        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            stopServer();
        }
        
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(null);
        
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
        
        return server != null;
    }
    
    /**
     * Stop the HTTP server if it is running
     */
    public void stopServer() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
    }
    
    /**
     * Get the current HTTP server instance
     *
     * @return the HTTP server or null if not running
     */
    public HttpServer getServer() {
        return server;
    }
    
    /**
     * Check if the server is running
     *
     * @return true if the server is running
     */
    public boolean isServerRunning() {
        return server != null;
    }
}
