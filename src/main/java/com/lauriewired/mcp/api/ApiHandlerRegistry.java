package com.lauriewired.mcp.api;

import com.lauriewired.mcp.McpServerManager;
import com.lauriewired.mcp.model.PrototypeResult;
import com.lauriewired.mcp.services.AnalysisService;
import com.lauriewired.mcp.services.CommentService;
import com.lauriewired.mcp.services.DataTypeService;
import com.lauriewired.mcp.services.FunctionService;
import com.lauriewired.mcp.services.MemoryService;
import com.lauriewired.mcp.services.NamespaceService;
import com.lauriewired.mcp.utils.HttpUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Functional interfaces for handler methods
 */
interface PaginatedHandler {
    String execute(int offset, int limit);
}

interface CommentHandler {
    boolean execute(String address, String comment);
}

/**
 * Registers and manages API endpoints for the HTTP server
 */
public class ApiHandlerRegistry {
    private final McpServerManager serverManager;
    private final FunctionService functionService;
    private final NamespaceService namespaceService;
    private final DataTypeService dataTypeService;
    private final AnalysisService analysisService;
    private final CommentService commentService;
    private final MemoryService memoryService;
    
    /**
     * Creates a new ApiHandlerRegistry
     *
     * @param serverManager the server manager
     * @param functionService the function service
     * @param namespaceService the namespace service
     * @param dataTypeService the data type service
     * @param analysisService the analysis service
     * @param commentService the comment service
     * @param memoryService the memory service
     */
    public ApiHandlerRegistry(
            McpServerManager serverManager,
            FunctionService functionService,
            NamespaceService namespaceService,
            DataTypeService dataTypeService,
            AnalysisService analysisService,
            CommentService commentService,
            MemoryService memoryService) {
        this.serverManager = serverManager;
        this.functionService = functionService;
        this.namespaceService = namespaceService;
        this.dataTypeService = dataTypeService;
        this.analysisService = analysisService;
        this.commentService = commentService;
        this.memoryService = memoryService;
    }
    
    /**
     * Register all API endpoints with the server
     */
    public void registerAllEndpoints() {
        if (!serverManager.isServerRunning()) {
            Msg.warn(this, "Cannot register endpoints: Server is not running");
            return;
        }
        
        HttpServer server = serverManager.getServer();
        
        // Register endpoints for all services
        registerFunctionEndpoints(server);
        registerNamespaceEndpoints(server);
        registerDataTypeEndpoints(server);
        registerAnalysisEndpoints(server);
        registerMemoryEndpoints(server);
        registerCommentEndpoints(server);
        
        Msg.info(this, "All API endpoints registered successfully");
    }
    
    /**
     * Register function-related endpoints
     */
    private void registerFunctionEndpoints(HttpServer server) {
        // List functions with pagination
        server.createContext("/methods", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
                int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
                int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
                
                HttpUtils.sendResponse(exchange, functionService.getAllFunctionNames(offset, limit));
            }
        });
        
        // Decompile function by name
        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes());
            HttpUtils.sendResponse(exchange, functionService.decompileFunctionByName(name));
        });
        
        // Rename function
        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String response = functionService.renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            HttpUtils.sendResponse(exchange, response);
        });
        
        // Get function by address
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionService.getFunctionByAddress(address));
        });
        
        // Get current address
        server.createContext("/get_current_address", exchange -> {
            HttpUtils.sendResponse(exchange, functionService.getCurrentAddress());
        });
        
        // Get current function
        server.createContext("/get_current_function", exchange -> {
            HttpUtils.sendResponse(exchange, functionService.getCurrentFunction());
        });
        
        // List all functions
        server.createContext("/list_functions", exchange -> {
            HttpUtils.sendResponse(exchange, functionService.listFunctions());
        });
        
        // Decompile function by address
        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionService.decompileFunctionByAddress(address));
        });
        
        // Disassemble function
        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionService.disassembleFunction(address));
        });
        
        // Rename function by address
        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = functionService.renameFunctionByAddress(functionAddress, newName);
            HttpUtils.sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });
        
        // Search functions by name
        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, functionService.searchFunctionsByName(searchTerm, offset, limit));
        });
        
        // Set function prototype
        server.createContext("/set_function_prototype", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                try {
                    Map<String, String> params = HttpUtils.parsePostParams(exchange);
                    String functionAddress = params.get("function_address");
                    String prototype = params.get("prototype");
                    
                    // Call the set prototype function and get detailed result
                    PrototypeResult result = functionService.setFunctionPrototype(functionAddress, prototype);
                    
                    // Format response based on success/failure and any messages
                    String response;
                    if (result.isSuccess()) {
                        response = "Function prototype set successfully";
                        if (!result.getErrorMessage().isEmpty()) {
                            response += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                        }
                    } else {
                        response = "Failed to set function prototype: " + result.getErrorMessage();
                    }
                    
                    HttpUtils.sendResponse(exchange, response);
                } catch (IOException e) {
                    HttpUtils.sendResponse(exchange, "Error processing request: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Register namespace and class endpoints
     */
    private void registerNamespaceEndpoints(HttpServer server) {
        // Register classes endpoint
        server.createContext("/classes", createPaginatedHandler(namespaceService::getAllClassNames));
        
        // Register namespaces endpoint
        server.createContext("/namespaces", createPaginatedHandler(namespaceService::listNamespaces));
        
        // Register symbols endpoint
        server.createContext("/symbols", createPaginatedHandler(namespaceService::listSymbols));
        
        // Register imports endpoint
        server.createContext("/imports", createPaginatedHandler(namespaceService::listImports));
        
        // Register exports endpoint
        server.createContext("/exports", createPaginatedHandler(namespaceService::listExports));
        
        // Get symbol address
        server.createContext("/get_symbol_address", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String symbolName = qparams.get("symbol_name");
            HttpUtils.sendResponse(exchange, namespaceService.getSymbolAddress(symbolName));
        });
    }
    
    /**
     * Register structure and data type endpoints
     */
    private void registerDataTypeEndpoints(HttpServer server) {
        // List structures
        server.createContext("/structures", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, dataTypeService.listStructures(offset, limit));
        });
        
        // Rename struct field
        server.createContext("/renameStructField", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                try {
                    Map<String, String> params = HttpUtils.parsePostParams(exchange);
                    String result = dataTypeService.renameStructField(
                        params.get("structName"),
                        params.get("oldFieldName"),
                        params.get("newFieldName")
                    );
                    HttpUtils.sendResponse(exchange, result);
                } catch (IOException e) {
                    HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * Register analysis endpoints
     */
    private void registerAnalysisEndpoints(HttpServer server) {
        // List references
        server.createContext("/references", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, analysisService.listReferences(address, offset, limit));
        });
        
        // Analyze control flow
        server.createContext("/analyze_control_flow", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, analysisService.analyzeControlFlow(address));
        });
        
        // Analyze data flow
        server.createContext("/analyze_data_flow", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            String variableName = qparams.get("variable");
            HttpUtils.sendResponse(exchange, analysisService.analyzeDataFlow(address, variableName));
        });
        
        // Analyze call graph
        server.createContext("/analyze_call_graph", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int depth = HttpUtils.parseIntOrDefault(qparams.get("depth"), 2);
            HttpUtils.sendResponse(exchange, analysisService.analyzeCallGraph(address, depth));
        });
    }
    
    /**
     * Register memory and data endpoints
     */
    private void registerMemoryEndpoints(HttpServer server) {
        // List segments
        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, memoryService.listSegments(offset, limit));
        });
        
        // List data items
        server.createContext("/data", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, memoryService.listDefinedData(offset, limit));
        });
        
        // Rename data
        server.createContext("/renameData", exchange -> {
            Map<String, String> params;
            try {
                params = HttpUtils.parsePostParams(exchange);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
                return;
            }
            
            boolean success = memoryService.renameDataAtAddress(params.get("address"), params.get("newName"));
            HttpUtils.sendResponse(exchange, success ? "Renamed successfully" : "Rename failed");
        });
    }
    
    /**
     * Register comments endpoints
     */
    private void registerCommentEndpoints(HttpServer server) {
        // Set decompiler comment
        server.createContext("/set_decompiler_comment", createCommentHandler(commentService::setDecompilerComment));
        
        // Set disassembly comment
        server.createContext("/set_disassembly_comment", createCommentHandler(commentService::setDisassemblyComment));
    }
    
    /**
     * Helper method to create a pagination handler
     */
    private HttpHandler createPaginatedHandler(final PaginatedHandler handler) {
        return new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
                int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
                int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
                HttpUtils.sendResponse(exchange, handler.execute(offset, limit));
            }
        };
    }
    
    /**
     * Helper method to create a comment handler
     */
    private HttpHandler createCommentHandler(final CommentHandler handler) {
        return new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                try {
                    Map<String, String> params = HttpUtils.parsePostParams(exchange);
                    String address = params.get("address");
                    String comment = params.get("comment");
                    boolean success = handler.execute(address, comment);
                    
                    HttpUtils.sendResponse(exchange, 
                        success ? "Comment set successfully" : "Failed to set comment");
                } catch (IOException e) {
                    HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
                }
            }
        };
    }
}
