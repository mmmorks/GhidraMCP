package com.lauriewired.mcp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;

import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

/**
 * Manages the HTTP server for GhidraMCP
 */
public class McpServerManager {
    private HttpServer server;
    private ExecutorService executorService;
    private final PluginTool tool;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String THREAD_POOL_SIZE_OPTION_NAME = "Thread Pool Size";
    private static final String REQUEST_TIMEOUT_OPTION_NAME = "Request Timeout (seconds)";
    private static final int DEFAULT_PORT = 8080;
    private static final int DEFAULT_THREAD_POOL_SIZE = 10;
    private static final int DEFAULT_REQUEST_TIMEOUT_SECONDS = 30;
    
    /**
     * Creates a new McpServerManager
     *
     * @param tool the plugin tool
     */
    public McpServerManager(final PluginTool tool) {
        this.tool = tool;
        registerOptions();
    }
    
    /**
     * Register configuration options for the HTTP server
     */
    private void registerOptions() {
        final Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
        
        options.registerOption(THREAD_POOL_SIZE_OPTION_NAME, DEFAULT_THREAD_POOL_SIZE,
            null, // No help location for now
            "The number of threads in the thread pool for handling concurrent HTTP requests. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
        
        options.registerOption(REQUEST_TIMEOUT_OPTION_NAME, DEFAULT_REQUEST_TIMEOUT_SECONDS,
            null, // No help location for now
            "The timeout in seconds for HTTP GET requests. Requests exceeding this time will be cancelled. " +
            "Default is 30 seconds. Requires Ghidra restart or plugin reload to take effect after changing.");
    }
    
    /**
     * Start the HTTP server with the configured port
     *
     * @return true if the server was started successfully
     * @throws IOException if there was an error starting the server
     */
    public boolean startServer() throws IOException {
        // Read the configured options
        final Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        final int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        final int threadPoolSize = options.getInt(THREAD_POOL_SIZE_OPTION_NAME, DEFAULT_THREAD_POOL_SIZE);
        
        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            stopServer();
        }
        
        // Create the HTTP server
        server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // Create a thread pool executor for handling concurrent requests
        final ThreadFactory threadFactory = new ThreadFactory() {
            private final AtomicInteger threadNumber = new AtomicInteger(1);
            
            @Override
            public Thread newThread(final Runnable r) {
                final Thread thread = new Thread(r, "GhidraMCP-HTTP-Worker-" + threadNumber.getAndIncrement());
                thread.setDaemon(true); // Daemon threads will not prevent JVM shutdown
                return thread;
            }
        };
        
        executorService = Executors.newFixedThreadPool(threadPoolSize, threadFactory);
        server.setExecutor(executorService);
        
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port +
                    " with " + threadPoolSize + " worker threads");
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
                if (executorService != null) {
                    executorService.shutdown();
                    executorService = null;
                }
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
            
            // Shutdown the executor service
            if (executorService != null) {
                executorService.shutdown();
                try {
                    // Wait for existing tasks to complete
                    if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                        Msg.warn(this, "Executor service did not terminate in time, forcing shutdown...");
                        executorService.shutdownNow();
                        // Wait a bit for tasks to respond to being cancelled
                        if (!executorService.awaitTermination(2, TimeUnit.SECONDS)) {
                            Msg.error(this, "Executor service did not terminate");
                        }
                    }
                } catch (InterruptedException e) {
                    // Re-interrupt the current thread
                    Thread.currentThread().interrupt();
                    // Force shutdown
                    executorService.shutdownNow();
                }
                executorService = null;
            }
            
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
    
    /**
     * Get the configured request timeout in seconds
     *
     * @return the request timeout in seconds
     */
    public int getRequestTimeoutSeconds() {
        final Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        return options.getInt(REQUEST_TIMEOUT_OPTION_NAME, DEFAULT_REQUEST_TIMEOUT_SECONDS);
    }
}
