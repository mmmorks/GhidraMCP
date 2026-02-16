package com.lauriewired.mcp.api;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;

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
import com.lauriewired.mcp.utils.TimeoutHandler;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.util.Msg;

/**
 * Functional interfaces for handler methods
 */
interface PaginatedHandler {
    String execute(int offset, int limit);
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
    private final TimeoutHandler timeoutHandler;
    
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
        
        // Create a single timeout handler instance for all endpoints
        int timeoutSeconds = serverManager.getRequestTimeoutSeconds();
        this.timeoutHandler = new TimeoutHandler(timeoutSeconds);
        this.timeoutHandler.start(); // Start the monitor thread after construction
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
        
        // Shutdown the timeout handler
        if (timeoutHandler != null) {
            timeoutHandler.shutdown();
            Msg.info(this, "Timeout handler shut down successfully");
        }
    }
    
    /**
     * Wrap a handler with telemetry logging and timeout
     */
    private HttpHandler wrapWithTelemetryAndTimeout(HttpHandler handler, String toolName, String endpoint) {
        // First wrap with telemetry (reusing the same logger instance)
        HttpHandler telemetryHandler = new TelemetryInterceptor(handler, telemetryLogger, toolName, endpoint);
        
        // Then wrap with timeout (using the singleton instance)
        return timeoutHandler.wrap(telemetryHandler);
    }
    
    /**
     * Register an endpoint with automatic telemetry and timeout wrapping using standardized naming
     * This method uses the tool name as the endpoint path (with leading slash)
     */
    private void registerEndpoint(HttpServer server, String toolName, HttpHandler handler) {
        String endpoint = "/" + toolName;
        server.createContext(endpoint, wrapWithTelemetryAndTimeout(handler, toolName, endpoint));
    }
    
    /**
     * Register function-related endpoints
     */
    private void registerFunctionEndpoints(HttpServer server) {
        // List functions with pagination
        registerEndpoint(server, "list_functions", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);

            HttpUtils.sendResponse(exchange, functionService.getAllFunctionNames(offset, limit));
        });
        
        // Get function code (C pseudocode, assembly, or pcode)
        registerEndpoint(server, "get_function_code", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String identifier = qparams.get("function_identifier");
            String mode = qparams.getOrDefault("mode", "C");
            HttpUtils.sendResponse(exchange, functionService.getFunctionCode(identifier, mode));
        });
        
        // Rename function (accepts name or address as identifier)
        registerEndpoint(server, "rename_function", exchange -> {
            Map<String, String> params = HttpUtils.parsePostParams(exchange);
            String identifier = params.get("function_identifier");
            String newName = params.get("new_name");
            HttpUtils.sendResponse(exchange, functionService.renameFunction(identifier, newName));
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
        // Register symbols endpoint
        registerEndpoint(server, "list_symbols",
            createPaginatedHandler(namespaceService::listSymbols));
        
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
        // List data types (structs and/or enums)
        registerEndpoint(server, "list_data_types", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String kind = qparams.getOrDefault("kind", "all");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, dataTypeService.listDataTypes(kind, offset, limit));
        });
        
        // Bulk update structure (JSON body)
        registerEndpoint(server, "update_structure", exchange -> {
            try {
                var body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                var structName = extractJsonString(body, "name");
                var newName = extractJsonString(body, "new_name");
                var sizeVal = extractJsonInt(body, "size");
                var fieldRenames = extractJsonObject(body, "field_renames");
                var typeChanges = extractJsonObject(body, "type_changes");

                String result = dataTypeService.updateStructure(structName, newName, sizeVal,
                        fieldRenames.isEmpty() ? null : fieldRenames,
                        typeChanges.isEmpty() ? null : typeChanges);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Error: " + e.getMessage());
            }
        });

        // Bulk update enum (JSON body)
        registerEndpoint(server, "update_enum", exchange -> {
            try {
                var body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                var enumName = extractJsonString(body, "name");
                var newName = extractJsonString(body, "new_name");
                var sizeVal = extractJsonInt(body, "size");
                var valueRenames = extractJsonObject(body, "value_renames");
                var valueChanges = extractJsonLongObject(body, "value_changes");

                String result = dataTypeService.updateEnum(enumName, newName, sizeVal,
                        valueRenames.isEmpty() ? null : valueRenames,
                        valueChanges == null || valueChanges.isEmpty() ? null : valueChanges);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Error: " + e.getMessage());
            }
        });
        
        // Create structure (JSON body with optional inline fields)
        registerEndpoint(server, "create_structure", exchange -> {
            try {
                var body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                var structName = extractJsonString(body, "name");
                var sizeStr = extractJsonString(body, "size");
                int size = 0;
                if (sizeStr != null) {
                    try { size = Integer.parseInt(sizeStr); } catch (NumberFormatException ignored) {}
                }
                var categoryPath = extractJsonString(body, "category_path");
                var fields = extractJsonArrayOfPairs(body, "fields");

                String result = dataTypeService.createStructure(structName, size, categoryPath, fields);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Error: " + e.getMessage());
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
        
        // Get data type details (auto-detects struct vs enum)
        registerEndpoint(server, "get_data_type", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String name = qparams.get("name");
            HttpUtils.sendResponse(exchange, dataTypeService.getDataType(name));
        });

        // Create enum (JSON body with optional inline values)
        registerEndpoint(server, "create_enum", exchange -> {
            try {
                var body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                var enumName = extractJsonString(body, "name");
                var sizeStr = extractJsonString(body, "size");
                int size = 4;
                if (sizeStr != null) {
                    try { size = Integer.parseInt(sizeStr); } catch (NumberFormatException ignored) {}
                }
                var categoryPath = extractJsonString(body, "category_path");
                var values = extractJsonLongObject(body, "values");

                String result = dataTypeService.createEnum(enumName, size, categoryPath, values);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, "Error: " + e.getMessage());
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
        
        // Find data type usage
        registerEndpoint(server, "find_data_type_usage", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String typeName = qparams.get("type_name");
            String fieldName = qparams.get("field_name");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, dataTypeService.findDataTypeUsage(typeName, fieldName, offset, limit));
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
        
        // List references from
        registerEndpoint(server, "list_references_from", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, analysisService.listReferencesFrom(address, offset, limit));
        });
        
        // Get function callers
        registerEndpoint(server, "get_function_callers", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String functionName = qparams.get("function_name");
            HttpUtils.sendResponse(exchange, analysisService.getFunctionCallers(functionName));
        });
        
        // Get call hierarchy
        registerEndpoint(server, "get_call_hierarchy", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String functionName = qparams.get("function_name");
            int depth = HttpUtils.parseIntOrDefault(qparams.get("depth"), 2);
            HttpUtils.sendResponse(exchange, analysisService.getCallHierarchy(functionName, depth));
        });
    }
    
    /**
     * Register memory and data endpoints
     */
    private void registerMemoryEndpoints(HttpServer server) {
        // Get memory layout (segments)
        registerEndpoint(server, "get_memory_layout", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            int offset = HttpUtils.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = HttpUtils.parseIntOrDefault(qparams.get("limit"), 100);
            HttpUtils.sendResponse(exchange, memoryService.getMemoryLayout(offset, limit));
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
        
        // Set data type at address
        registerEndpoint(server, "set_address_data_type", exchange -> {
            try {
                Map<String, String> params = HttpUtils.parsePostParams(exchange);
                String address = params.get("address");
                String dataType = params.get("data_type");
                boolean clearExisting = "true".equalsIgnoreCase(params.get("clear_existing"));

                String result = memoryService.setAddressDataType(address, dataType, clearExisting);
                HttpUtils.sendResponse(exchange, result);
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
            }
        });
        
        // Read memory
        registerEndpoint(server, "read_memory", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            int size = HttpUtils.parseIntOrDefault(qparams.get("size"), 16);
            String format = qparams.getOrDefault("format", "hex");
            HttpUtils.sendResponse(exchange, memoryService.readMemory(address, size, format));
        });
        
        // Get memory permissions
        registerEndpoint(server, "get_memory_permissions", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, memoryService.getMemoryPermissions(address));
        });
        
        // Get data type at address
        registerEndpoint(server, "get_address_data_type", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, memoryService.getAddressDataType(address));
        });
    }

    private static HttpHandler createCommentHandler(BiFunction<String, String, Boolean> setter) {
        return exchange -> {
            try {
                Map<String, String> params = HttpUtils.parsePostParams(exchange);
                String address = params.get("address");
                String comment = params.get("comment");
                boolean success = setter.apply(address, comment);
                
                HttpUtils.sendResponse(exchange,
                        success ? "Comment set successfully" : "Failed to set comment");
            } catch (IOException e) {
                HttpUtils.sendResponse(exchange, "Error parsing parameters: " + e.getMessage());
            }
        };
    } 
    /**
     * Register comments endpoints
     */
    private void registerCommentEndpoints(HttpServer server) {

        registerEndpoint(server, "set_decompiler_comment", createCommentHandler(commentService::setDecompilerComment));
        registerEndpoint(server, "set_disassembly_comment", createCommentHandler(commentService::setDisassemblyComment));
        
        // Get comments
        registerEndpoint(server, "get_comments", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, commentService.getComments(address));
        });
        
        // Get decompiler comment
        registerEndpoint(server, "get_decompiler_comment", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, commentService.getDecompilerComment(address));
        });
        
        // Get disassembly comment
        registerEndpoint(server, "get_disassembly_comment", exchange -> {
            Map<String, String> qparams = HttpUtils.parseQueryParams(exchange);
            String address = qparams.get("address");
            HttpUtils.sendResponse(exchange, commentService.getDisassemblyComment(address));
        });
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
        // Batch rename variables endpoint (JSON body: {"function_name": "...", "renames": {"old": "new", ...}})
        registerEndpoint(server, "rename_variables", exchange -> {
            try {
                var body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                // Simple JSON parsing without external library
                var functionName = extractJsonString(body, "function_name");
                var renames = extractJsonObject(body, "renames");

                var result = variableService.batchRenameVariables(functionName, renames);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
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
        
        // Batch set variable types endpoint (JSON body: {"function_address": "...", "types": {"var": "type", ...}})
        registerEndpoint(server, "set_variable_types", exchange -> {
            try {
                var body = new String(exchange.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                var functionAddress = extractJsonString(body, "function_address");
                var types = extractJsonObject(body, "types");

                var result = variableService.batchSetVariableTypes(functionAddress, types);
                HttpUtils.sendResponse(exchange, result);
            } catch (Exception e) {
                HttpUtils.sendResponse(exchange, String.format("Error: %s", e.getMessage()));
            }
        });
    }
    
    /**
     * Extract a JSON string value by key from a JSON object string.
     * Simple parser for {"key": "value"} patterns without external libraries.
     */
    static String extractJsonString(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        int colonIndex = json.indexOf(':', keyIndex + searchKey.length());
        if (colonIndex < 0) return null;

        int quoteStart = json.indexOf('"', colonIndex + 1);
        if (quoteStart < 0) return null;

        int quoteEnd = json.indexOf('"', quoteStart + 1);
        if (quoteEnd < 0) return null;

        return json.substring(quoteStart + 1, quoteEnd);
    }

    /**
     * Extract a JSON integer value by key from a JSON object string.
     * Returns null if the key is not found or the value is not a valid integer.
     */
    static Integer extractJsonInt(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        int colonIndex = json.indexOf(':', keyIndex + searchKey.length());
        if (colonIndex < 0) return null;

        // Skip whitespace after colon
        int numStart = colonIndex + 1;
        while (numStart < json.length() && Character.isWhitespace(json.charAt(numStart))) numStart++;

        // Check if value is a quoted string (number in quotes)
        if (numStart < json.length() && json.charAt(numStart) == '"') {
            int quoteEnd = json.indexOf('"', numStart + 1);
            if (quoteEnd < 0) return null;
            try {
                return Integer.parseInt(json.substring(numStart + 1, quoteEnd));
            } catch (NumberFormatException e) {
                return null;
            }
        }

        // Read unquoted number
        int numEnd = numStart;
        while (numEnd < json.length() && (Character.isDigit(json.charAt(numEnd)) ||
               json.charAt(numEnd) == '-')) {
            numEnd++;
        }
        if (numEnd == numStart) return null;

        try {
            return Integer.parseInt(json.substring(numStart, numEnd));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Extract a JSON object as a Map of string key-value pairs.
     * Handles {"key": {"k1": "v1", "k2": "v2"}} patterns.
     */
    static Map<String, String> extractJsonObject(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return Map.of();

        int braceStart = json.indexOf('{', keyIndex + searchKey.length());
        if (braceStart < 0) return Map.of();

        // Find matching close brace
        int depth = 1;
        int braceEnd = braceStart + 1;
        while (braceEnd < json.length() && depth > 0) {
            char c = json.charAt(braceEnd);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            braceEnd++;
        }

        String inner = json.substring(braceStart + 1, braceEnd - 1).trim();
        if (inner.isEmpty()) return Map.of();

        // Parse "key": "value" pairs
        Map<String, String> result = new java.util.LinkedHashMap<>();
        int i = 0;
        while (i < inner.length()) {
            int qs1 = inner.indexOf('"', i);
            if (qs1 < 0) break;
            int qe1 = inner.indexOf('"', qs1 + 1);
            if (qe1 < 0) break;
            String k = inner.substring(qs1 + 1, qe1);

            int qs2 = inner.indexOf('"', qe1 + 1);
            if (qs2 < 0) break;
            int qe2 = inner.indexOf('"', qs2 + 1);
            if (qe2 < 0) break;
            String v = inner.substring(qs2 + 1, qe2);

            result.put(k, v);
            i = qe2 + 1;
        }
        return result;
    }

    /**
     * Extract a JSON array of two-element string arrays: [["a","b"],["c","d"]]
     * Returns a List of String[2] pairs.
     * Handles values containing brackets (e.g., "char[32]") by parsing quoted strings properly.
     */
    static java.util.List<String[]> extractJsonArrayOfPairs(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        int bracketStart = json.indexOf('[', keyIndex + searchKey.length());
        if (bracketStart < 0) return null;

        // Find matching close bracket (skip content inside quotes)
        int depth = 1;
        int bracketEnd = bracketStart + 1;
        boolean inQuote = false;
        while (bracketEnd < json.length() && depth > 0) {
            char c = json.charAt(bracketEnd);
            if (c == '"' && (bracketEnd == 0 || json.charAt(bracketEnd - 1) != '\\')) {
                inQuote = !inQuote;
            } else if (!inQuote) {
                if (c == '[') depth++;
                else if (c == ']') depth--;
            }
            bracketEnd++;
        }

        String inner = json.substring(bracketStart + 1, bracketEnd - 1).trim();
        if (inner.isEmpty()) return java.util.List.of();

        // Parse by extracting pairs of quoted strings between each inner [ ... ]
        // We track bracket depth while respecting quotes
        java.util.List<String[]> result = new java.util.ArrayList<>();
        int i = 0;
        while (i < inner.length()) {
            // Find start of inner array
            int arrStart = -1;
            for (int j = i; j < inner.length(); j++) {
                if (inner.charAt(j) == '[') { arrStart = j; break; }
            }
            if (arrStart < 0) break;

            // Find matching end bracket, respecting quotes
            int arrDepth = 1;
            int arrEnd = arrStart + 1;
            boolean arrInQuote = false;
            while (arrEnd < inner.length() && arrDepth > 0) {
                char c = inner.charAt(arrEnd);
                if (c == '"' && (arrEnd == 0 || inner.charAt(arrEnd - 1) != '\\')) {
                    arrInQuote = !arrInQuote;
                } else if (!arrInQuote) {
                    if (c == '[') arrDepth++;
                    else if (c == ']') arrDepth--;
                }
                arrEnd++;
            }

            String pair = inner.substring(arrStart + 1, arrEnd - 1);
            // Extract two quoted strings from the pair
            int qs1 = pair.indexOf('"');
            if (qs1 < 0) { i = arrEnd; continue; }
            int qe1 = pair.indexOf('"', qs1 + 1);
            if (qe1 < 0) { i = arrEnd; continue; }
            int qs2 = pair.indexOf('"', qe1 + 1);
            if (qs2 < 0) { i = arrEnd; continue; }
            int qe2 = pair.indexOf('"', qs2 + 1);
            if (qe2 < 0) { i = arrEnd; continue; }

            result.add(new String[]{pair.substring(qs1 + 1, qe1), pair.substring(qs2 + 1, qe2)});
            i = arrEnd;
        }
        return result;
    }

    /**
     * Extract a JSON object as a Map of string keys to long values.
     * Handles {"key": {"NAME1": 0, "NAME2": 1}} patterns.
     */
    static java.util.Map<String, Long> extractJsonLongObject(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex < 0) return null;

        int braceStart = json.indexOf('{', keyIndex + searchKey.length());
        if (braceStart < 0) return null;

        // Find matching close brace
        int depth = 1;
        int braceEnd = braceStart + 1;
        while (braceEnd < json.length() && depth > 0) {
            char c = json.charAt(braceEnd);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            braceEnd++;
        }

        String inner = json.substring(braceStart + 1, braceEnd - 1).trim();
        if (inner.isEmpty()) return java.util.Map.of();

        // Parse "key": number pairs
        java.util.Map<String, Long> result = new java.util.LinkedHashMap<>();
        int i = 0;
        while (i < inner.length()) {
            int qs1 = inner.indexOf('"', i);
            if (qs1 < 0) break;
            int qe1 = inner.indexOf('"', qs1 + 1);
            if (qe1 < 0) break;
            String k = inner.substring(qs1 + 1, qe1);

            int colonIdx = inner.indexOf(':', qe1 + 1);
            if (colonIdx < 0) break;

            // Find the number value (skip whitespace, read until comma/end)
            int numStart = colonIdx + 1;
            while (numStart < inner.length() && Character.isWhitespace(inner.charAt(numStart))) numStart++;

            int numEnd = numStart;
            while (numEnd < inner.length() && (Character.isDigit(inner.charAt(numEnd)) ||
                   inner.charAt(numEnd) == '-' || inner.charAt(numEnd) == 'x' ||
                   inner.charAt(numEnd) == 'X' ||
                   (inner.charAt(numEnd) >= 'a' && inner.charAt(numEnd) <= 'f') ||
                   (inner.charAt(numEnd) >= 'A' && inner.charAt(numEnd) <= 'F'))) {
                numEnd++;
            }

            String numStr = inner.substring(numStart, numEnd).trim();
            try {
                long value;
                if (numStr.startsWith("0x") || numStr.startsWith("0X")) {
                    value = Long.parseLong(numStr.substring(2), 16);
                } else {
                    value = Long.parseLong(numStr);
                }
                result.put(k, value);
            } catch (NumberFormatException e) {
                // skip invalid values
            }
            i = numEnd;
        }
        return result;
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
    
}
