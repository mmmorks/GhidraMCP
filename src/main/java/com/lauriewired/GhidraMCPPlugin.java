package com.lauriewired;

import java.io.IOException;

import com.lauriewired.mcp.McpServerManager;
import com.lauriewired.mcp.api.ApiHandlerRegistry;
import com.lauriewired.mcp.services.AnalysisService;
import com.lauriewired.mcp.services.CommentService;
import com.lauriewired.mcp.services.DataTypeService;
import com.lauriewired.mcp.services.FunctionService;
import com.lauriewired.mcp.services.MemoryService;
import com.lauriewired.mcp.services.NamespaceService;
import com.lauriewired.mcp.services.ProgramService;
import com.lauriewired.mcp.services.SearchService;
import com.lauriewired.mcp.services.VariableService;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

/**
 * A Ghidra plugin that starts an HTTP server to expose program data through REST APIs.
 * This plugin provides access to Ghidra's functionality like decompilation, analysis,
 * and program structure through HTTP endpoints for use by external tools.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    // Core components
    private McpServerManager serverManager;
    private ApiHandlerRegistry apiHandlerRegistry;
    
    // Service instances
    private ProgramService programService;
    private FunctionService functionService;
    private NamespaceService namespaceService;
    private DataTypeService dataTypeService;
    private AnalysisService analysisService;
    private CommentService commentService;
    private MemoryService memoryService;
    private VariableService variableService;
    private SearchService searchService;

    /**
     * Plugin constructor
     * 
     * @param tool the plugin tool
     */
    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(GhidraMCPPlugin.class, "GhidraMCPPlugin loading...");
        
        try {
            initializeServices();
            startServer();
        } catch (Exception e) {
            Msg.error(GhidraMCPPlugin.class, "Failed to initialize GhidraMCP plugin", e);
        }
        
        Msg.info(GhidraMCPPlugin.class, "GhidraMCPPlugin loaded!");
    }

    /**
     * Initialize all service instances
     */
    private void initializeServices() {
        this.programService = new ProgramService(tool);
        this.functionService = new FunctionService(tool, programService);
        this.namespaceService = new NamespaceService(programService);
        this.dataTypeService = new DataTypeService(programService);
        this.analysisService = new AnalysisService(programService);
        this.commentService = new CommentService(programService);
        this.memoryService = new MemoryService(programService, dataTypeService);
        this.variableService = new VariableService(programService);
        this.searchService = new SearchService(programService);
        
        Msg.info(GhidraMCPPlugin.class, "All services initialized");
    }
    
    /**
     * Start the HTTP server and register endpoints
     */
    private void startServer() {
        // Create server manager
        serverManager = new McpServerManager(tool);
        
        try {
            // Start the HTTP server
            if (!serverManager.startServer()) {
                Msg.error(GhidraMCPPlugin.class, "Failed to start HTTP server");
                return;
            }
            
            // Create API handler registry with all services
            apiHandlerRegistry = new ApiHandlerRegistry(
                serverManager,
                functionService,
                namespaceService,
                dataTypeService,
                analysisService,
                commentService,
                memoryService,
                programService,
                searchService,
                variableService
            );
            
            // Register all API endpoints
            apiHandlerRegistry.registerAllEndpoints();
            
        } catch (IOException e) {
            Msg.error(GhidraMCPPlugin.class, "Failed to start HTTP server", e);
        }
    }

    @Override
    public void dispose() {
        if (serverManager != null) {
            serverManager.stopServer();
        }
        super.dispose();
    }
}
