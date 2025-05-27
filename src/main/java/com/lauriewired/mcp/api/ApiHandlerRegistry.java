package com.lauriewired.mcp.api;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

import com.lauriewired.mcp.McpServerManager;
import com.lauriewired.mcp.model.PrototypeResult;
import com.lauriewired.mcp.services.AnalysisService;
import com.lauriewired.mcp.services.CommentService;
import com.lauriewired.mcp.services.DataTypeService;
import com.lauriewired.mcp.services.FunctionService;
import com.lauriewired.mcp.services.MemoryService;
import com.lauriewired.mcp.services.NamespaceService;
import com.lauriewired.mcp.services.ProgramService;
import com.lauriewired.mcp.services.SearchService;
import com.lauriewired.mcp.services.VariableService;
import com.lauriewired.mcp.telemetry.TelemetryInterceptor;
import com.lauriewired.mcp.telemetry.TelemetryLogger;
import com.lauriewired.mcp.utils.HttpUtils;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

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
    private final ProgramService programService;
    private final SearchService searchService;
    private final VariableService variableService;
    private final TelemetryLogger telemetryLogger;
    
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
     * @param programService the program service
     * @param searchService the search service
     * @param variableService the variable service
     */
    public ApiHandlerRegistry(
            McpServerManager serverManager,
            FunctionService functionService,
            NamespaceService namespaceService,
            DataTypeService dataTypeService,
            AnalysisService analysisService,
            CommentService commentService,
            MemoryService memoryService,
            ProgramService programService,
            SearchService searchService,
            VariableService variableService) {
        this.serverManager = serverManager;
        this.functionService = functionService;
        this.namespaceService = namespaceService;
        this.dataTypeService = dataTypeService;
        this.analysisService = analysisService;
        this.commentService = commentService;
        this.memoryService = memoryService;
        this.programService = programService;
        this.searchService = searchService;
        this.variableService = variableService;
        this.telemetryLogger = new TelemetryLogger();
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
        registerSearchEndpoints(server);
        registerVariableEndpoints(server);
        
        Msg.info(this, "All API endpoints registered successfully");
    }
    
    /**
     * Shutdown the telemetry logger and save final reports
     */
    public void shutdown() {
        if (telemetryLogger != null) {
            telemetryLogger.shutdown();
            Msg.info(this, "Telemetry logger shut down successfully");
        }
    }
    
    /**
     * Wrap a handler with telemetry logging
     */
    private HttpHandler wrapWithTelemetry(HttpHandler handler, String toolName, String endpoint) {
        return new TelemetryInterceptor(handler, telemetryLogger, toolName, endpoint);
    }
    
    /**
     * Register an endpoint with automatic telemetry wrapping using standardized naming
     * This method uses the tool name as the endpoint path (with leading slash)
     */
    private void registerEndpoint(HttpServer server, String toolName, HttpHandler handler) {
        String endpoint = "/" + toolName;
        server.createContext(endpoint, wrapWithTelemetry(handler, toolName, endpoint));
    }
    
    /**
     * Register function-related endpoints
     */
    private void registerFunctionEndpoints(HttpServer server) {
        // List functions with pagination
        registerEndpoint(server, "list_methods", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            
            HttpUtils.sendResponse(exchange, functionService.getAllFunctionNames(offset, limit));
        });
        
        // Decompile function by name
        registerEndpoint(server, "decompile_function", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes());
            HttpUtils.sendResponse(exchange, functionService.decompileFunctionByName(name));
        });
        
        // Rename function
        registerEndpoint(server, "rename_function", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String response = functionService.renameFunction(params.get("old_name"), params.get("new_name"))
                    ? "Renamed successfully" : "Rename failed";
            HttpUtils.sendResponse(exchange, response);
        });
        
        // Get function by address
        registerEndpoint(server, "get_function_by_address", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionService.getFunctionByAddress(address));
        });
        
        // Get current address
        registerEndpoint(server, "get_current_address", exchange -> {
            HttpUtils.sendResponse(exchange, functionService.getCurrentAddress());
        });
        
        // Get current function
        registerEndpoint(server, "get_current_function", exchange -> {
            HttpUtils.sendResponse(exchange, functionService.getCurrentFunction());
        });
        
        // List all functions
        registerEndpoint(server, "list_functions", exchange -> {
            HttpUtils.sendResponse(exchange, functionService.listFunctions());
        });
        
        // Decompile function by address
        registerEndpoint(server, "decompile_function_by_address", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionService.decompileFunctionByAddress(address));
        });
        
        // Disassemble function
        registerEndpoint(server, "disassemble_function", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, functionService.disassembleFunction(address));
        });
        
        // Rename function by address
        registerEndpoint(server, "rename_function_by_address", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = functionService.renameFunctionByAddress(functionAddress, newName);
            HttpUtils.sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });
        
        // Search functions by name
        registerEndpoint(server, "search_functions_by_name", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, functionService.searchFunctionsByName(searchTerm, offset, limit));
        });
        
        // Set function prototype
        registerEndpoint(server, "set_function_prototype", exchange -> {
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
        });
    }
    
    /**
     * Register namespace and class endpoints
     */
    private void registerNamespaceEndpoints(HttpServer server) {
        // Register classes endpoint
        registerEndpoint(server, "list_classes",
            createPaginatedHandler(namespaceService::getAllClassNames));
        
        // Register namespaces endpoint
        registerEndpoint(server, "list_namespaces",
            createPaginatedHandler(namespaceService::listNamespaces));
        
        // Register symbols endpoint
        registerEndpoint(server, "list_symbols",
            createPaginatedHandler(namespaceService::listSymbols));
        
        // Register imports endpoint
        registerEndpoint(server, "list_imports",
            createPaginatedHandler(namespaceService::listImports));
        
        // Register exports endpoint
        registerEndpoint(server, "list_exports",
            createPaginatedHandler(namespaceService::listExports));
        
        // Get symbol address
        registerEndpoint(server, "get_symbol_address", exchange -> {
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
        registerEndpoint(server, "list_structures", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, dataTypeService.listStructures(offset, limit));
        });
        
        // Rename struct field
        registerEndpoint(server, "rename_struct_field", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parsePostParams(exchange);
                String result = dataTypeService.renameStructField(
                        params.get("struct_name"),
                        params.get("old_field_name"),
                        params.get("new_field_name")
                );
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
            }
        });
        
        // Create structure
        registerEndpoint(server, "create_structure", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parsePostParams(exchange);
                String structName = params.get("name");
                int size = HttpUtils.parseIntOrDefault(params.get("size"), 0);
                String categoryPath = params.get("category_path");
                
                String result = dataTypeService.createStructure(structName, size, categoryPath);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
            }
        });
        
        // Add structure field
        registerEndpoint(server, "add_structure_field", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parsePostParams(exchange);
                String structName = params.get("struct_name");
                String fieldName = params.get("field_name");
                String fieldType = params.get("field_type");
                int fieldSize = HttpUtils.parseIntOrDefault(params.get("field_size"), -1);
                int offset = HttpUtils.parseIntOrDefault(params.get("offset"), -1);
                String comment = params.get("comment");
                
                String result = dataTypeService.addStructureField(structName, fieldName, fieldType,
                                                                 fieldSize, offset, comment);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
            }
        });
        
        // Create enum
        registerEndpoint(server, "create_enum", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parsePostParams(exchange);
                String enumName = params.get("name");
                int size = HttpUtils.parseIntOrDefault(params.get("size"), 4);
                String categoryPath = params.get("category_path");
                
                String result = dataTypeService.createEnum(enumName, size, categoryPath);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
            }
        });
        
        // Add enum value
        registerEndpoint(server, "add_enum_value", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parsePostParams(exchange);
                String enumName = params.get("enum_name");
                String valueName = params.get("value_name");
                long value = Long.parseLong(params.getOrDefault("value", "0"));
                
                String result = dataTypeService.addEnumValue(enumName, valueName, value);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
            } catch (NumberFormatException e) {
                HttpUtils.sendResponse(exchange, "Invalid numeric value: " + e.getMessage());
            }
        });
        
        // List enums
        registerEndpoint(server, "list_enums", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, dataTypeService.listEnums(offset, limit));
        });
    }
    
    /**
     * Register analysis endpoints
     */
    private void registerAnalysisEndpoints(HttpServer server) {
        // List references
        registerEndpoint(server, "list_references", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, analysisService.listReferences(address, offset, limit));
        });
        
        // Analyze control flow
        registerEndpoint(server, "analyze_control_flow", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, analysisService.analyzeControlFlow(address));
        });
        
        // Analyze data flow
        registerEndpoint(server, "analyze_data_flow", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            String variableName = qparams.get("variable");
            HttpUtils.sendResponse(exchange, analysisService.analyzeDataFlow(address, variableName));
        });
        
        // Analyze call graph
        registerEndpoint(server, "analyze_call_graph", exchange -> {
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
        registerEndpoint(server, "list_segments", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, memoryService.listSegments(offset, limit));
        });
        
        // List data items
        registerEndpoint(server, "list_data_items", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, memoryService.listDefinedData(offset, limit));
        });
        
        // Rename data
        registerEndpoint(server, "rename_data", exchange -> {
            Map<String, String> params;
            try {
                params = HttpUtils.parsePostParams(exchange);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
                return;
            }
            
            boolean success = memoryService.renameDataAtAddress(params.get("address"), params.get("new_name"));
            HttpUtils.sendResponse(exchange, success ? "Renamed successfully" : "Rename failed");
        });
        
        // Set memory data type
        registerEndpoint(server, "set_memory_data_type", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parsePostParams(exchange);
                String address = params.get("address");
                String dataType = params.get("data_type");
                boolean clearExisting = "true".equalsIgnoreCase(params.get("clear_existing"));
                
                String result = memoryService.setMemoryDataType(address, dataType, clearExisting);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
            }
        });
    }
    
    /**
     * Register comments endpoints
     */
    private void registerCommentEndpoints(HttpServer server) {
        // Set decompiler comment
        registerEndpoint(server, "set_decompiler_comment",
            createCommentHandler(commentService::setDecompilerComment));
        
        // Set disassembly comment
        registerEndpoint(server, "set_disassembly_comment",
            createCommentHandler(commentService::setDisassemblyComment));
    }
    
    /**
     * Register search-related endpoints
     */
    private void registerSearchEndpoints(HttpServer server) {
        // Memory search endpoint
        registerEndpoint(server, "search_memory", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parseQueryParams(exchange);
                String query = params.get("query");
                boolean asString = "true".equalsIgnoreCase(params.get("as_string"));
                String blockName = params.get("block_name");
                int limit = Integer.parseInt(params.getOrDefault("limit", "10"));
                
                String result = searchService.searchMemory(query, asString, blockName, limit);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException | RuntimeException e) {
                HttpUtils.sendResponse(exchange, "Error processing search request: " + e.getMessage());
            }
        });
        
        // Disassembly search endpoint
        registerEndpoint(server, "search_disassembly", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parseQueryParams(exchange);
                String query = params.get("query");
                int offset = Integer.parseInt(params.getOrDefault("offset", "0"));
                int limit = Integer.parseInt(params.getOrDefault("limit", "10"));
                
                String result = searchService.searchDisassembly(query, offset, limit);
                HttpUtils.sendResponse(exchange, result);
            } catch (RuntimeException | IOException e) {
                HttpUtils.sendResponse(exchange, "Error processing disassembly search: " + e.getMessage());
            }
        });
        
        // Decompiled code search endpoint
        registerEndpoint(server, "search_decompiled", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parseQueryParams(exchange);
                String query = params.get("query");
                int offset = Integer.parseInt(params.getOrDefault("offset", "0"));
                int limit = Integer.parseInt(params.getOrDefault("limit", "5"));
                
                String result = searchService.searchDecompiledCode(query, offset, limit);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException | RuntimeException e) {
                HttpUtils.sendResponse(exchange, "Error processing decompiled code search: " + e.getMessage());
            }
        });
    }

    /**
     * Register variable-related endpoints
     */
    private void registerVariableEndpoints(HttpServer server) {
        // Rename variable endpoint
        registerEndpoint(server, "rename_variable", exchange -> {
            try {
                var params = HttpUtils.parsePostParams(exchange);
                var functionName = params.get("function_name");
                var oldName = params.get("old_name");
                var newName = params.get("new_name");
                var usageAddress = params.get("usage_address");
                
                var result = variableService.renameVariableInFunction(functionName, oldName, newName, usageAddress);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, String.format("Error: %s", e.getMessage()));
            }
        });
        
        // Split variable endpoint
        registerEndpoint(server, "split_variable", exchange -> {
            try {
                var params = HttpUtils.parsePostParams(exchange);
                var functionName = params.get("function_name");
                var variableName = params.get("variable_name");
                var usageAddress = params.get("usage_address");
                
                // Use Optional to handle the optional new_name parameter
                var newName = Optional.ofNullable(params.get("new_name"))
                    .filter(name -> !name.isEmpty())
                    .orElse(variableName + "_split");
                
                var result = variableService.renameVariableInFunction(functionName, variableName, newName, usageAddress);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, String.format("Error: %s", e.getMessage()));
            }
        });
        
        // Set local variable type endpoint
        registerEndpoint(server, "set_local_variable_type", exchange -> {
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
    private void findPointerBaseType(ghidra.program.model.data.DataTypeManager dtm, String pointerType, StringBuilder responseMsg) {
        var baseTypeName = pointerType.substring(1);
        var baseType = dataTypeService.findDataTypeByNameInAllCategories(dtm, baseTypeName);
        
        if (baseType != null) {
            responseMsg.append(String.format("Found base type for pointer: %s\n", baseType.getPathName()));
        } else {
            responseMsg.append(String.format("Base type not found for pointer: %s\n", baseTypeName));
        }
    }
    
    /**
     * Helper method to create a pagination handler
     */
    private HttpHandler createPaginatedHandler(final PaginatedHandler handler) {
        return exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, handler.execute(offset, limit));
        };
    }
    
    /**
     * Helper method to create a comment handler
     */
    private HttpHandler createCommentHandler(final CommentHandler handler) {
        return exchange -> {
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
        };
    }
}
