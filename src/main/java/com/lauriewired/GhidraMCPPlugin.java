package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/references", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listReferences(address, offset, limit));
        });

        server.createContext("/renameStructField", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("structName");
            String oldFieldName = params.get("oldFieldName");
            String newFieldName = params.get("newFieldName");
            String result = renameStructField(structName, oldFieldName, newFieldName);
            sendResponse(exchange, result);
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean success = renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, success ? "Renamed successfully" : "Rename failed");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            
            // Unified variable renaming that supports both identification methods
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/structures", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listStructures(offset, limit));
        });

        server.createContext("/symbols", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSymbols(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");
            
            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);
            
            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");
            
            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");
            
            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
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
            boolean success = setLocalVariableType(functionAddress, variableName, newType);
            
            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);
            
            sendResponse(exchange, responseMsg.toString());
        });

        // Program Analysis API endpoints
        
        server.createContext("/analyze_control_flow", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, analyzeControlFlow(address));
        });
        
        server.createContext("/analyze_data_flow", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String variableName = qparams.get("variable");
            sendResponse(exchange, analyzeDataFlow(address, variableName));
        });
        
        server.createContext("/analyze_call_graph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int depth = parseIntOrDefault(qparams.get("depth"), 2);
            sendResponse(exchange, analyzeCallGraph(address, depth));
        });
        
        server.createContext("/get_symbol_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String symbolName = qparams.get("symbol_name");
            sendResponse(exchange, getSymbolAddress(symbolName));
        });

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
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------



    private String listStructures(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        List<Structure> structs = new ArrayList<>();
        // Get all structures from the data type manager
        dtm.getAllStructures().forEachRemaining((struct) -> {
            structs.add(struct);
        });
        Collections.sort(structs, Comparator.comparing(Structure::getName));  
        List<String> lines = new ArrayList<>();
        for (Structure struct : structs) {
            StringBuilder sb = new StringBuilder();
            sb.append(struct.getName()).append(": {");
            for (int i = 0; i < struct.getNumComponents(); i++) {
                DataTypeComponent comp = struct.getComponent(i);
                if (i > 0) sb.append(", ");
                sb.append(comp.getDataType().getName())
                .append(" ")
                .append(comp.getFieldName());
            }
            sb.append("}");
            lines.add(sb.toString());
        }
        return paginateList(lines, offset, limit);
    }
    
    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listSymbols(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(false)) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private boolean renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        Msg.error(this, "Invalid address: " + addressStr);
                        return;
                    }
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                        } else {
                            try {
                                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                                successFlag.set(true);
                            } catch (Exception e) {
                                Msg.error(this, "Failed to create label: " + e.getMessage());
                            }
                        }
                    } else {
                        Msg.error(this, "No defined data at address: " + addressStr);
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
        return successFlag.get();
    }

    private String renameStructField(String structName, String oldFieldName, String newFieldName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || oldFieldName == null || newFieldName == null) {
            return "Structure name, old field name, and new field name are required";
        }

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename struct field");
                try {
                    ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
                    Structure struct = (Structure) dtm.getDataType("/" + structName);
                    if (struct != null) {
                        // Check if oldFieldName matches pattern "field<N>_0x<offset>"
                        if (oldFieldName.matches("field\\d+_0x[0-9a-fA-F]+")) {
                            // Extract index number from field name
                            int index = Integer.parseInt(oldFieldName.substring(5, oldFieldName.indexOf('_')));
                            if (index >= 0 && index < struct.getNumComponents()) {
                                DataTypeComponent component = struct.getComponent(index);
                                struct.replace(index, component.getDataType(), component.getLength(), 
                                            newFieldName, component.getComment());
                                successFlag.set(true);
                            }
                        } else {
                            // Original logic for named fields
                            for (int i = 0; i < struct.getNumComponents(); i++) {
                                DataTypeComponent component = struct.getComponent(i);
                                if ((component.getFieldName() != null) && 
                                    component.getFieldName().equals(oldFieldName)) {
                                    struct.replace(i, component.getDataType(), component.getLength(),
                                                newFieldName, component.getComment());
                                    successFlag.set(true);
                                    break;
                                }
                            }
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming struct field", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }

        return successFlag.get() ? "Field renamed successfully" : "Failed to rename field";
    }

    private String listReferences(String nameOrAddress, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (nameOrAddress == null) return "NameOrAddress is required";

        List<String> refs = new ArrayList<>();
        try {
            // Try to get the address directly first (if addressStr is a hex address)
            Address addr = program.getAddressFactory().getAddress(nameOrAddress);

            // If addr is null or we couldn't get it directly, try to find it as a symbol name
            if (addr == null) {
                addr = getSymbolAddressInternal(program, nameOrAddress);
            }
            
            ReferenceManager refMgr = program.getReferenceManager();
            
            // Get references to this address
            for (Reference ref : refMgr.getReferencesTo(addr)) {
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                // Get function containing the reference if it exists
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcName = func != null ? func.getName() : "not in function";
                
                refs.add(String.format("%s -> %s (from %s in %s)", 
                    fromAddr, addr, refType.getName(), funcName));
            }

            if (refs.isEmpty()) {
                return "No references found to " + nameOrAddress + " (address: " + addr + ")";
            }

            Collections.sort(refs);
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references: " + e.getMessage();
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();

            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final Function finalFunction = func;
        final HighVariable highVariable = highSymbol.getHighVariable();

        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false, 
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }

                    final HighVariable newHighVariable = highFunction.splitOutMergeGroup(highVariable, highVariable.getRepresentative());
                    final HighSymbol finalHighSymbol = newHighVariable.getSymbol();

                    DataType dataType = finalHighSymbol.getDataType();
                    if (Undefined.isUndefined(dataType)) {
                        dataType = AbstractIntegerDataType.getUnsignedDataType(dataType.getLength(), program.getDataTypeManager());
                    }

                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        dataType,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        
        if (!successFlag.get()) {
            return "Failed to rename variable";
        }
        
        // Get updated variable list after renaming
        try {
            // Re-decompile to get the updated state
            DecompileResults updatedResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (updatedResult == null || !updatedResult.decompileCompleted()) {
                return "Variable renamed, but failed to get updated variable list";
            }
            
            HighFunction updatedHighFunction = updatedResult.getHighFunction();
            if (updatedHighFunction == null) {
                return "Variable renamed, but failed to get updated high function";
            }
            
            LocalSymbolMap updatedSymbolMap = updatedHighFunction.getLocalSymbolMap();
            if (updatedSymbolMap == null) {
                return "Variable renamed, but failed to get updated symbol map";
            }
            
            List<Map<String, String>> variableList = new ArrayList<>();
            Iterator<HighSymbol> updatedSymbols = updatedSymbolMap.getSymbols();
            while (updatedSymbols.hasNext()) {
                HighSymbol symbol = updatedSymbols.next();
                Map<String, String> varInfo = new HashMap<>();
                varInfo.put("name", symbol.getName());
                varInfo.put("dataType", symbol.getDataType().getName());
                
                HighVariable var = symbol.getHighVariable();
                if (var != null && var.getSymbol() != null) {
                    varInfo.put("storage", var.getSymbol().getStorage().toString());
                }
                
                variableList.add(varInfo);
            }
            
            // Create JSON response
            StringBuilder jsonResponse = new StringBuilder();
            jsonResponse.append("{\n");
            jsonResponse.append("  \"status\": \"Variable renamed\",\n");
            jsonResponse.append("  \"variables\": [\n");
            
            for (int i = 0; i < variableList.size(); i++) {
                Map<String, String> varInfo = variableList.get(i);
                jsonResponse.append("    {\n");
                jsonResponse.append("      \"name\": \"").append(escapeJson(varInfo.get("name"))).append("\",\n");
                jsonResponse.append("      \"dataType\": \"").append(escapeJson(varInfo.get("dataType"))).append("\"");
                jsonResponse.append("\n    }");
                if (i < variableList.size() - 1) {
                    jsonResponse.append(",");
                }
                jsonResponse.append("\n");
            }
            
            jsonResponse.append("  ]\n");
            jsonResponse.append("}");
            
            return jsonResponse.toString();
            
        } catch (Exception e) {
            String errorMsg = "Variable renamed, but failed to collect variable info: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return "Variable renamed";
        }
    }
    
    private String escapeJson(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);
            
            if (func == null) return "No function found at address " + addressStr;
            
            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }
    
    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";
        
        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }
    
    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";
        
        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";
        
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        
        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();
        
        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }
    
    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        
        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }
        
        return result.toString();
    }
    
    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }
    
    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;
            
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            
            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;
            
            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();
            
            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";
                
                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }
            
            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    
   
    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;
        
        AtomicBoolean success = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }
        
        return success.get();
    }
    
    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }
    
    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }
   
    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }
        
        AtomicBoolean success = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }
        
        return success.get();
    }
    
    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);
            
            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }
            
            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }
    
    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;
        
        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }
        
        public boolean isSuccess() {
            return success;
        }
        
        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }
        
        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
        
        return new PrototypeResult(success.get(), errorMessage.toString());
    }
    
    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);
            
            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }
            
            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);
            
            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);
            
            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);
            
        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }
    
    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }
    
    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();
            
            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);
            
            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);
            
            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);
            
            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }
            
            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);
            
            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());
            
            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }
    
    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }
        
        AtomicBoolean success = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }
        
        return success.get();
    }
    
    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);
            
            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }
            
            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }
            
            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }
            
            // Find the symbol by name
            HighSymbol symbol = findVariableByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }
            
            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }
            
            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());
            
            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);
            
            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }
            
            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);
            
            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);
            
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }
    
    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findVariableByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }
    
    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation
        
        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());
        
        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }
        
        return results;
    }
    
    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );
            
            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }
    
    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }
        
        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);
            
            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }
            
            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }
            
            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }
        
        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }
                
                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    
    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     * 
     * package-private for testing
     */
    static Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getRawQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (IllegalArgumentException e) {
                        // Log the error but continue processing other parameters
                        Msg.warn(GhidraMCPPlugin.class, "Error decoding URL parameter: " + p + " - " + e.getMessage());
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     * 
     * package-private for testing
     */
    static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            // Skip empty pairs
            if (pair.isEmpty()) {
                continue;
            }
            
            // Find the first equals sign
            int equalsIndex = pair.indexOf('=');
            
            // If there's no equals sign, skip this parameter
            if (equalsIndex == -1) {
                continue;
            }
            
            try {
                // Extract key (everything before the first equals sign)
                String key = URLDecoder.decode(pair.substring(0, equalsIndex), StandardCharsets.UTF_8);
                
                // Extract value (everything after the first equals sign, or empty string if at the end)
                String value = "";
                if (equalsIndex < pair.length() - 1) {
                    value = URLDecoder.decode(pair.substring(equalsIndex + 1), StandardCharsets.UTF_8);
                }
                
                params.put(key, value);
            } catch (IllegalArgumentException e) {
                // Log the error but continue processing other parameters
                Msg.warn(GhidraMCPPlugin.class, "Error decoding URL parameter: " + pair + " - " + e.getMessage());
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     * 
     * package-private for testing
     */
    static String paginateList(List<String> items, int offset, int limit) {
        // Handle zero or negative limit
        if (limit <= 0) {
            return "";
        }
        
        // Handle negative offset by treating it as 0
        int start = Math.max(0, offset);
        // Calculate end position
        int end = Math.min(items.size(), start + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private static String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }
        
        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }
    
    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    // ----------------------------------------------------------------------------------
    // Program Analysis API methods
    // ----------------------------------------------------------------------------------
    
    /**
     * Analyze the control flow of a function
     * @param addressStr The address of the function to analyze
     * @return A textual representation of the control flow graph
     */
    private String analyzeControlFlow(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;
            
            StringBuilder result = new StringBuilder();
            result.append("Control Flow Analysis for function: ").append(func.getName())
                  .append(" at ").append(func.getEntryPoint()).append("\n\n");
            
            // Use BasicBlockModel to get the control flow graph
            BasicBlockModel bbModel = new BasicBlockModel(program);
            
            // Get the function's body
            AddressSetView functionBodyView = func.getBody();
            AddressSet functionBody = new AddressSet(functionBodyView);
            
            // Get the code blocks (basic blocks) for the function
            CodeBlockIterator blockIterator = bbModel.getCodeBlocksContaining(functionBody, new ConsoleTaskMonitor());
            
            // Map to store blocks by address for easier reference
            Map<Address, CodeBlock> blockMap = new HashMap<>();
            List<CodeBlock> blocks = new ArrayList<>();
            
            // First pass: collect all blocks
            while (blockIterator.hasNext()) {
                CodeBlock block = blockIterator.next();
                blocks.add(block);
                blockMap.put(block.getFirstStartAddress(), block);
            }
            
            // Sort blocks by address for consistent output
            blocks.sort(Comparator.comparing(CodeBlock::getFirstStartAddress));
            
            // Second pass: print blocks and their destinations
            for (CodeBlock block : blocks) {
                result.append("Block at ").append(block.getFirstStartAddress())
                      .append(" (").append(block.getMinAddress()).append(" - ")
                      .append(block.getMaxAddress()).append(")\n");
                
                // Get the destinations (successors) of this block
                CodeBlockReferenceIterator destIter = block.getDestinations(new ConsoleTaskMonitor());
                if (!destIter.hasNext()) {
                    result.append("  - Terminal block (no successors)\n");
                }
                
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    CodeBlock destBlock = ref.getDestinationBlock();
                    
                    // Determine the type of flow
                    String flowType = "Unknown";
                    if (ref.getFlowType().isJump()) {
                        if (ref.getFlowType().isConditional()) {
                            flowType = "Conditional Jump";
                        } else {
                            flowType = "Unconditional Jump";
                        }
                    } else if (ref.getFlowType().isFallthrough()) {
                        flowType = "Fallthrough";
                    } else if (ref.getFlowType().isCall()) {
                        flowType = "Call";
                    } else if (ref.getFlowType().isTerminal()) {
                        flowType = "Return";
                    }
                    
                    result.append("  - ").append(flowType).append(" to ")
                          .append(destBlock.getFirstStartAddress()).append("\n");
                }
                
                // Add the instructions in this block
                result.append("  Instructions:\n");
                Listing listing = program.getListing();
                InstructionIterator instructions = listing.getInstructions(block, true);
                while (instructions.hasNext()) {
                    Instruction instr = instructions.next();
                    result.append("    ").append(instr.getAddress()).append(": ")
                          .append(instr.toString()).append("\n");
                }
                
                result.append("\n");
            }
            
            return result.toString();
        } catch (Exception e) {
            return "Error analyzing control flow: " + e.getMessage();
        }
    }
    
    /**
     * Analyze the data flow for a variable in a function
     * @param addressStr The address of the function to analyze
     * @param variableName The name of the variable to track
     * @return A textual representation of the data flow
     */
    private String analyzeDataFlow(String addressStr, String variableName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (variableName == null || variableName.isEmpty()) return "Variable name is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;
            
            StringBuilder result = new StringBuilder();
            result.append("Data Flow Analysis for variable '").append(variableName)
                  .append("' in function ").append(func.getName())
                  .append(" at ").append(func.getEntryPoint()).append("\n\n");
            
            // Decompile the function to get high-level variable information
            DecompileResults decompResults = decompileFunction(func, program);
            if (decompResults == null || !decompResults.decompileCompleted()) {
                return "Could not decompile function for data flow analysis";
            }
            
            HighFunction highFunc = decompResults.getHighFunction();
            if (highFunc == null) {
                return "No high function available for data flow analysis";
            }
            
            // Find the variable by name
            HighSymbol targetSymbol = findVariableByName(highFunc, variableName);
            if (targetSymbol == null) {
                return "Variable '" + variableName + "' not found in function";
            }
            
            HighVariable highVar = targetSymbol.getHighVariable();
            if (highVar == null) {
                return "No high variable found for '" + variableName + "'";
            }
            
            // Get information about the variable
            result.append("Variable information:\n");
            result.append("  Name: ").append(highVar.getName()).append("\n");
            result.append("  Type: ").append(highVar.getDataType().getName()).append("\n");
            result.append("  Storage: ");
            
            Varnode[] instances = highVar.getInstances();
            if (instances.length > 0) {
                for (int i = 0; i < instances.length; i++) {
                    if (i > 0) result.append(", ");
                    result.append(instances[i].getAddress());
                }
            } else {
                result.append("No storage information available");
            }
            result.append("\n\n");
            
            // Track definitions and uses of the variable
            result.append("Variable definitions and uses:\n");
            
            // Get all PcodeOps that define or use this variable
            Map<Address, String> defUseMap = new HashMap<>();
            
            for (Varnode instance : instances) {
                // Get the PcodeOp that defines this instance
                PcodeOp defOp = instance.getDef();
                if (defOp != null) {
                    Address defAddr = defOp.getSeqnum().getTarget();
                    String opType = defOp.getMnemonic();
                    defUseMap.put(defAddr, "DEFINE: " + opType);
                }
                
                // Get all PcodeOps that use this instance
                Iterator<PcodeOp> descendants = instance.getDescendants();
                while (descendants.hasNext()) {
                    PcodeOp useOp = descendants.next();
                    Address useAddr = useOp.getSeqnum().getTarget();
                    String opType = useOp.getMnemonic();
                    defUseMap.put(useAddr, "USE: " + opType);
                }
            }
            
            // Sort the addresses for consistent output
            List<Address> sortedAddrs = new ArrayList<>(defUseMap.keySet());
            sortedAddrs.sort(Comparator.naturalOrder());
            
            // Get the listing for instruction information
            Listing listing = program.getListing();
            
            // Print the definitions and uses
            for (Address opAddr : sortedAddrs) {
                Instruction instr = listing.getInstructionAt(opAddr);
                if (instr != null) {
                    result.append("  ").append(opAddr).append(": ")
                          .append(defUseMap.get(opAddr)).append(" - ")
                          .append(instr.toString()).append("\n");
                }
            }
            
            return result.toString();
        } catch (Exception e) {
            return "Error analyzing data flow: " + e.getMessage();
        }
    }
    
    /**
     * Analyze the call graph starting from a function
     * @param addressStr The address of the function to start from
     * @param depth The maximum depth to traverse (default: 2)
     * @return A textual representation of the call graph
     */
    private String analyzeCallGraph(String addressStr, int depth) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        // Limit depth to prevent excessive output
        depth = Math.min(Math.max(depth, 1), 5);
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function rootFunc = getFunctionForAddress(program, addr);
            if (rootFunc == null) return "No function found at or containing address " + addressStr;
            
            StringBuilder result = new StringBuilder();
            result.append("Call Graph Analysis for function: ").append(rootFunc.getName())
                  .append(" at ").append(rootFunc.getEntryPoint())
                  .append(" (depth: ").append(depth).append(")\n\n");
            
            // Set to track visited functions to avoid cycles
            Set<Function> visited = new HashSet<>();
            
            // Start the recursive call graph traversal
            buildCallGraph(rootFunc, result, visited, 0, depth);
            
            return result.toString();
        } catch (Exception e) {
            return "Error analyzing call graph: " + e.getMessage();
        }
    }
    
    /**
     * Recursive helper method to build the call graph
     */
    private void buildCallGraph(Function func, StringBuilder result, Set<Function> visited, 
                               int currentDepth, int maxDepth) {
        // Add indentation based on depth
        String indent = "  ".repeat(currentDepth);
        
        // Print the current function
        result.append(indent).append("- ").append(func.getName())
              .append(" at ").append(func.getEntryPoint());
        
        // Check if we've already visited this function or reached max depth
        if (visited.contains(func)) {
            result.append(" (already visited)\n");
            return;
        }
        
        result.append("\n");
        
        // Mark as visited
        visited.add(func);
        
        // Stop if we've reached the maximum depth
        if (currentDepth >= maxDepth) {
            return;
        }
        
        // Get all functions called by this function
        Set<Function> calledFunctions = new HashSet<>();
        
        // Get references from this function
        ReferenceManager refMgr = func.getProgram().getReferenceManager();
        AddressSetView body = func.getBody();
        
        // Iterate through all addresses in the function body
        AddressIterator addrIter = body.getAddresses(true);
        while (addrIter.hasNext()) {
            Address fromAddr = addrIter.next();
            
            // Get all references from this address
            for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                // Check if it's a call reference
                if (ref.getReferenceType().isCall()) {
                    Address toAddr = ref.getToAddress();
                    
                    // Get the function at the destination address
                    Function calledFunc = func.getProgram().getFunctionManager().getFunctionAt(toAddr);
                    if (calledFunc != null) {
                        calledFunctions.add(calledFunc);
                    }
                }
            }
        }
        
        // Sort called functions by name for consistent output
        List<Function> sortedCalled = new ArrayList<>(calledFunctions);
        sortedCalled.sort(Comparator.comparing(Function::getName));
        
        // Recursively process called functions
        for (Function calledFunc : sortedCalled) {
            buildCallGraph(calledFunc, result, visited, currentDepth + 1, maxDepth);
        }
    }
    private String getSymbolAddress(String symbolName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        final Address symbolAddress = getSymbolAddressInternal(program, symbolName);
        if (symbolAddress != null) {
            return "Symbol '" + symbolName + "' found at address: " + symbolAddress.toString();
        } else {
            return "Symbol not found";
        }
    }
    private Address getSymbolAddressInternal(Program program, String symbolName) {
        final SymbolTable symbolTable = program.getSymbolTable();
        final SymbolIterator symbolIterator = symbolTable.getSymbols(symbolName);
        
        if (symbolIterator.hasNext()) {
            // Use the first matching symbol's address
            Symbol symbol = symbolIterator.next();
            return symbol.getAddress();
        } else {
            return null;
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
