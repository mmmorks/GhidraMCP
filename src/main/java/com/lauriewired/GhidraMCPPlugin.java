package com.lauriewired;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

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
import com.lauriewired.mcp.utils.HttpUtils;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.data.DataTypeManager;
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
        Msg.info(this, "GhidraMCPPlugin loading...");
        
        try {
            initializeServices();
            startServer();
        } catch (Exception e) {
            Msg.error(this, "Failed to initialize GhidraMCP plugin", e);
        }
        
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    /**
     * Initialize all service instances
     */
    private void initializeServices() {
        // Create all services with programService as the core dependency
        var programService = new ProgramService(tool);
        this.programService = programService;
        
        // Initialize all dependent services
        this.functionService = new FunctionService(tool, programService);
        this.namespaceService = new NamespaceService(programService);
        this.dataTypeService = new DataTypeService(programService);
        this.analysisService = new AnalysisService(programService);
        this.commentService = new CommentService(programService);
        this.memoryService = new MemoryService(programService);
        this.variableService = new VariableService(programService);
        this.searchService = new SearchService(programService);
        
        Msg.info(this, "All services initialized");
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
                Msg.error(this, "Failed to start HTTP server");
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
                memoryService
            );
            
            // Register all API endpoints
            apiHandlerRegistry.registerAllEndpoints();
            registerSearchEndpoints();
            registerVariableEndpoints();
            
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
    }
    
    /**
     * Register search-related endpoints
     */
    private void registerSearchEndpoints() {
        if (!serverManager.isServerRunning()) return;
        
        // Memory search endpoint
        serverManager.getServer().createContext("/searchMemory", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parseQueryParams(exchange);
                String query = params.get("query");
                boolean asString = "true".equalsIgnoreCase(params.get("asString"));
                String blockName = params.get("blockName");
                int limit = Integer.parseInt(params.getOrDefault("limit", "10"));
                
                String result = searchService.searchMemory(query, asString, blockName, limit);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Error processing search request: " + e.getMessage());
            }
        });
        
        // Disassembly search endpoint
        serverManager.getServer().createContext("/searchDisassembly", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parseQueryParams(exchange);
                String query = params.get("query");
                int offset = Integer.parseInt(params.getOrDefault("offset", "0"));
                int limit = Integer.parseInt(params.getOrDefault("limit", "10"));
                
                String result = searchService.searchDisassembly(query, offset, limit);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Error processing disassembly search: " + e.getMessage());
            }
        });
        
        // Decompiled code search endpoint
        serverManager.getServer().createContext("/searchDecompiled", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parseQueryParams(exchange);
                String query = params.get("query");
                int offset = Integer.parseInt(params.getOrDefault("offset", "0"));
                int limit = Integer.parseInt(params.getOrDefault("limit", "5"));
                
                String result = searchService.searchDecompiledCode(query, offset, limit);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Error processing decompiled code search: " + e.getMessage());
            }
        });
    }

    /**
     * Register variable-related endpoints
     */
    private void registerVariableEndpoints() {
        if (!serverManager.isServerRunning()) return;
        
        // Rename variable endpoint
        serverManager.getServer().createContext("/renameVariable", exchange -> {
            try {
                var params = HttpUtils.parsePostParams(exchange);
                var functionName = params.get("functionName");
                var oldName = params.get("oldName");
                var newName = params.get("newName");
                var usageAddress = params.get("usageAddress");
                
                var result = variableService.renameVariableInFunction(functionName, oldName, newName, usageAddress);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, String.format("Error: %s", e.getMessage()));
            }
        });
        
        // Split variable endpoint
        serverManager.getServer().createContext("/splitVariable", exchange -> {
            try {
                var params = HttpUtils.parsePostParams(exchange);
                var functionName = params.get("functionName");
                var variableName = params.get("variableName");
                var usageAddress = params.get("usageAddress");
                
                // Use Optional to handle the optional newName parameter
                var newName = Optional.ofNullable(params.get("newName"))
                    .filter(name -> !name.isEmpty())
                    .orElse(variableName + "_split");
                
                var result = variableService.renameVariableInFunction(functionName, variableName, newName, usageAddress);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, String.format("Error: %s", e.getMessage()));
            }
        });
        
        // Set local variable type endpoint
        serverManager.getServer().createContext("/set_local_variable_type", exchange -> {
            try {
                var params = HttpUtils.parsePostParams(exchange);
                var functionAddress = params.get("function_address");
                var variableName = params.get("variable_name");
                var newType = params.get("new_type");
                
                // Build the response message with a formatted text block
                var responseMsg = new StringBuilder(String.format("""
                    Setting variable type: %s
                    to %s
                    in function at %s
                    
                    """, variableName, newType, functionAddress));
                
                // Get data type info using Optional for cleaner null handling
                Optional.ofNullable(programService.getCurrentProgram())
                    .ifPresent(program -> {
                        var dtm = program.getDataTypeManager();
                        var directType = dataTypeService.findDataTypeByNameInAllCategories(dtm, newType);
                        
                        if (directType != null) {
                            responseMsg.append(String.format("Found type: %s\n", directType.getPathName()));
                        } else if (newType.startsWith("P") && newType.length() > 1) {
                            findPointerBaseType(dtm, newType, responseMsg);
                        } else {
                            responseMsg.append(String.format("Type not found directly: %s\n", newType));
                        }
                    });
                
                // Try to set the type
                var success = variableService.setLocalVariableType(functionAddress, variableName, newType);
                var successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
                responseMsg.append(String.format("\nResult: %s", successMsg));
                
                HttpUtils.sendResponse(exchange, responseMsg.toString());
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, String.format("Error: %s", e.getMessage()));
            }
        });
    }
    
    /**
     * Helper method to find pointer base type
     */
    private void findPointerBaseType(DataTypeManager dtm, String pointerType, StringBuilder responseMsg) {
        var baseTypeName = pointerType.substring(1);
        var baseType = dataTypeService.findDataTypeByNameInAllCategories(dtm, baseTypeName);
        
        if (baseType != null) {
            responseMsg.append(String.format("Found base type for pointer: %s\n", baseType.getPathName()));
        } else {
            responseMsg.append(String.format("Base type not found for pointer: %s\n", baseTypeName));
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
