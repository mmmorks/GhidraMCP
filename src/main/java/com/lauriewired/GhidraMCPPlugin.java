package com.lauriewired;

import com.lauriewired.mcp.McpServerManager;
import com.lauriewired.mcp.api.ApiHandlerRegistry;
import com.lauriewired.mcp.services.AnalysisService;
import com.lauriewired.mcp.services.CommentService;
import com.lauriewired.mcp.services.DataTypeService;
import com.lauriewired.mcp.services.FunctionService;
import com.lauriewired.mcp.services.MemoryService;
import com.lauriewired.mcp.services.NamespaceService;
import com.lauriewired.mcp.services.ProgramService;
import com.lauriewired.mcp.services.VariableService;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.Map;
import ghidra.program.model.listing.Program;

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
        // Create service instances in dependency order
        programService = new ProgramService(tool);
        functionService = new FunctionService(tool, programService);
        namespaceService = new NamespaceService(programService);
        dataTypeService = new DataTypeService(programService);
        analysisService = new AnalysisService(programService);
        commentService = new CommentService(programService);
        memoryService = new MemoryService(programService);
        variableService = new VariableService(programService);
        
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
            boolean started = serverManager.startServer();
            if (!started) {
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
            
            // Register variable endpoints
            registerVariableEndpoints();
            
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
    }
    
    /**
     * Register variable-related endpoints
     */
    private void registerVariableEndpoints() {
        if (!serverManager.isServerRunning()) {
            return;
        }
        
        // Rename variable endpoint
        serverManager.getServer().createContext("/renameVariable", exchange -> {
            try {
                Map<String, String> params = com.lauriewired.mcp.utils.HttpUtils.parsePostParams(exchange);
                String functionName = params.get("functionName");
                String oldName = params.get("oldName");
                String newName = params.get("newName");
                String usageAddress = params.get("usageAddress");
                
                String result = variableService.renameVariableInFunction(functionName, oldName, newName, usageAddress);
                com.lauriewired.mcp.utils.HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                com.lauriewired.mcp.utils.HttpUtils.sendResponse(exchange, "Error: " + e.getMessage());
            }
        });
        
        // Split variable endpoint
        serverManager.getServer().createContext("/splitVariable", exchange -> {
            try {
                Map<String, String> params = com.lauriewired.mcp.utils.HttpUtils.parsePostParams(exchange);
                String functionName = params.get("functionName");
                String variableName = params.get("variableName");
                String usageAddress = params.get("usageAddress");
                String newName = params.get("newName"); // Optional
                
                // If newName is not provided, generate a unique name
                if (newName == null || newName.isEmpty()) {
                    newName = variableName + "_split";
                }
                
                String result = variableService.renameVariableInFunction(functionName, variableName, newName, usageAddress);
                com.lauriewired.mcp.utils.HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                com.lauriewired.mcp.utils.HttpUtils.sendResponse(exchange, "Error: " + e.getMessage());
            }
        });
        
        // Set local variable type endpoint
        serverManager.getServer().createContext("/set_local_variable_type", exchange -> {
            try {
                Map<String, String> params = com.lauriewired.mcp.utils.HttpUtils.parsePostParams(exchange);
                String functionAddress = params.get("function_address");
                String variableName = params.get("variable_name");
                String newType = params.get("new_type");
                
                // Capture detailed information about setting the type
                StringBuilder responseMsg = new StringBuilder();
                responseMsg.append("Setting variable type: ").append(variableName)
                          .append(" to ").append(newType)
                          .append(" in function at ").append(functionAddress).append("\n\n");
                
                // Attempt to find the data type in various categories
                Program program = programService.getCurrentProgram();
                if (program != null) {
                    ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();
                    ghidra.program.model.data.DataType directType = dataTypeService.findDataTypeByNameInAllCategories(dtm, newType);
                    if (directType != null) {
                        responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                    } else if (newType.startsWith("P") && newType.length() > 1) {
                        String baseTypeName = newType.substring(1);
                        ghidra.program.model.data.DataType baseType = dataTypeService.findDataTypeByNameInAllCategories(dtm, baseTypeName);
                        if (baseType != null) {
                            responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                        } else {
                            responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                        }
                    } else {
                        responseMsg.append("Type not found directly: ").append(newType).append("\n");
                    }
                }
                
                // Try to set the type
                boolean success = variableService.setLocalVariableType(functionAddress, variableName, newType);
                
                String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
                responseMsg.append("\nResult: ").append(successMsg);
                
                com.lauriewired.mcp.utils.HttpUtils.sendResponse(exchange, responseMsg.toString());
            } catch (IOException e) {
                com.lauriewired.mcp.utils.HttpUtils.sendResponse(exchange, "Error: " + e.getMessage());
            }
        });
    }

    @Override
    public void dispose() {
        if (serverManager != null) {
            serverManager.stopServer();
        }
        super.dispose();
    }
}
