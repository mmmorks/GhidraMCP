package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.TextOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.GhidraUtils;
import com.lauriewired.mcp.utils.JsonBuilder;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * Service for advanced program analysis operations
 */
public class AnalysisService {
    private final ProgramService programService;
    private final FunctionService functionService;

    /**
     * Creates a new AnalysisService
     *
     * @param programService the program service for accessing the current program
     * @param functionService the function service for resolving function identifiers
     */
    public AnalysisService(ProgramService programService, FunctionService functionService) {
        this.programService = programService;
        this.functionService = functionService;
    }

    @McpTool(outputType = JsonOutput.class, description = """
        Analyze the control flow of a function.

        Creates a textual control flow graph (CFG) showing how basic blocks connect.

        Returns: Detailed CFG with blocks, jumps, and instructions

        Note: Basic blocks are instruction sequences with single entry/exit points.
        Essential for understanding branching and loops.

        Example: analyze_control_flow("main") -> "Control Flow Analysis for function:..." """)
    public ToolOutput analyzeControlFlow(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") String functionIdentifier) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return StatusOutput.error("Function identifier is required");

        try {
            Function func = functionService.resolveFunction(program, functionIdentifier);
            if (func == null) return StatusOutput.error("Function not found: " + functionIdentifier);

            BasicBlockModel bbModel = new BasicBlockModel(program);
            AddressSet functionBody = new AddressSet(func.getBody());
            CodeBlockIterator blockIterator = bbModel.getCodeBlocksContaining(functionBody, new ConsoleTaskMonitor());

            List<CodeBlock> blocks = new ArrayList<>();
            while (blockIterator.hasNext()) {
                blocks.add(blockIterator.next());
            }
            blocks.sort(Comparator.comparing(CodeBlock::getFirstStartAddress));

            JsonBuilder.JsonArrayBuilder blocksArray = JsonBuilder.array();

            for (CodeBlock block : blocks) {
                // Build successors array
                JsonBuilder.JsonArrayBuilder successors = JsonBuilder.array();
                CodeBlockReferenceIterator destIter = block.getDestinations(new ConsoleTaskMonitor());
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    String flowType = "Unknown";
                    if (ref.getFlowType().isJump()) {
                        flowType = ref.getFlowType().isConditional() ? "Conditional Jump" : "Unconditional Jump";
                    } else if (ref.getFlowType().isFallthrough()) {
                        flowType = "Fallthrough";
                    } else if (ref.getFlowType().isCall()) {
                        flowType = "Call";
                    } else if (ref.getFlowType().isTerminal()) {
                        flowType = "Return";
                    }
                    successors.addRaw(JsonBuilder.object()
                            .put("type", flowType)
                            .put("target", ref.getDestinationBlock().getFirstStartAddress().toString())
                            .build());
                }

                // Build instructions array
                JsonBuilder.JsonArrayBuilder instrArray = JsonBuilder.array();
                Listing listing = program.getListing();
                InstructionIterator instructions = listing.getInstructions(block, true);
                while (instructions.hasNext()) {
                    Instruction instr = instructions.next();
                    instrArray.addRaw(JsonBuilder.object()
                            .put("address", instr.getAddress().toString())
                            .put("text", instr.toString())
                            .build());
                }

                blocksArray.addRaw(JsonBuilder.object()
                        .put("address", block.getFirstStartAddress().toString())
                        .putObject("range", JsonBuilder.object()
                                .put("start", block.getMinAddress().toString())
                                .put("end", block.getMaxAddress().toString()))
                        .putArray("successors", successors)
                        .putArray("instructions", instrArray)
                        .build());
            }

            String json = JsonBuilder.object()
                    .put("function", func.getName())
                    .put("entryPoint", func.getEntryPoint().toString())
                    .putArray("blocks", blocksArray)
                    .build();
            return new JsonOutput(json);
        } catch (Exception e) {
            return StatusOutput.error("Error analyzing control flow: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, description = """
        Analyze the data flow for a variable in a function.

        Tracks where a variable is defined (written) and used (read) throughout execution paths.

        Returns: Detailed analysis with variable info, definitions and uses

        Note: Helps understand value propagation and useful for analyzing algorithms.

        Example: analyze_data_flow("main", "local_10") -> "Data Flow Analysis..." """)
    public ToolOutput analyzeDataFlow(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") String functionIdentifier,
            @Param("Variable name to track") String variable) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return StatusOutput.error("Function identifier is required");
        if (variable == null || variable.isEmpty()) return StatusOutput.error("Variable name is required");

        try {
            Function func = functionService.resolveFunction(program, functionIdentifier);
            if (func == null) return StatusOutput.error("Function not found: " + functionIdentifier);

            DecompileResults decompResults = GhidraUtils.decompileFunction(func, program);
            if (decompResults == null) {
                return StatusOutput.error("Could not decompile function for data flow analysis");
            }

            HighFunction highFunc = decompResults.getHighFunction();
            if (highFunc == null) {
                return StatusOutput.error("No high function available for data flow analysis");
            }

            ghidra.program.model.pcode.HighSymbol targetSymbol =
                GhidraUtils.findVariableByName(highFunc, variable);

            if (targetSymbol == null) {
                return StatusOutput.error("Variable '" + variable + "' not found in function");
            }

            HighVariable highVar = targetSymbol.getHighVariable();
            if (highVar == null) {
                return StatusOutput.error("No high variable found for '" + variable + "'");
            }

            // Build storage info
            Varnode[] instances = highVar.getInstances();
            StringBuilder storage = new StringBuilder();
            for (int i = 0; i < instances.length; i++) {
                if (i > 0) storage.append(", ");
                storage.append(instances[i].getAddress());
            }

            // Track definitions and uses
            Map<Address, String[]> defUseMap = new HashMap<>();
            for (Varnode instance : instances) {
                PcodeOp defOp = instance.getDef();
                if (defOp != null) {
                    Address defAddr = defOp.getSeqnum().getTarget();
                    defUseMap.put(defAddr, new String[]{"DEFINE", defOp.getMnemonic()});
                }
                Iterator<PcodeOp> descendants = instance.getDescendants();
                while (descendants.hasNext()) {
                    PcodeOp useOp = descendants.next();
                    Address useAddr = useOp.getSeqnum().getTarget();
                    defUseMap.put(useAddr, new String[]{"USE", useOp.getMnemonic()});
                }
            }

            List<Address> sortedAddrs = new ArrayList<>(defUseMap.keySet());
            sortedAddrs.sort(Comparator.naturalOrder());

            Listing listing = program.getListing();
            JsonBuilder.JsonArrayBuilder refsArray = JsonBuilder.array();
            for (Address opAddr : sortedAddrs) {
                Instruction instr = listing.getInstructionAt(opAddr);
                if (instr != null) {
                    String[] entry = defUseMap.get(opAddr);
                    refsArray.addRaw(JsonBuilder.object()
                            .put("address", opAddr.toString())
                            .put("kind", entry[0])
                            .put("operation", entry[1])
                            .put("instruction", instr.toString())
                            .build());
                }
            }

            String json = JsonBuilder.object()
                    .put("function", func.getName())
                    .putObject("variable", JsonBuilder.object()
                            .put("name", highVar.getName())
                            .put("type", highVar.getDataType().getName())
                            .put("storage", storage.toString()))
                    .putArray("references", refsArray)
                    .build();
            return new JsonOutput(json);
        } catch (Exception e) {
            return StatusOutput.error("Error analyzing data flow: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, description = """
        Get the call graph for a function.

        Shows callers (functions that call this one), callees (functions this one calls), or both.

        Returns: Hierarchical call graph with function names and addresses

        Examples:
            get_call_graph("main") -> full call hierarchy for main
            get_call_graph("process_data", direction="callers") -> who calls process_data
            get_call_graph("00401000", depth=3, direction="callees") -> what does this function call """)
    public ToolOutput getCallGraph(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") String functionIdentifier,
            @Param(value = "Maximum depth to traverse (1-5, default: 2)", defaultValue = "2") int depth,
            @Param(value = "\"callers\" for upstream only, \"callees\" for downstream only, \"both\" for full hierarchy (default: \"both\")", defaultValue = "both") String direction) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty())
            return StatusOutput.error("Function identifier is required");

        depth = Math.min(Math.max(depth, 1), 5);

        Function targetFunc = functionService.resolveFunction(program, functionIdentifier);
        if (targetFunc == null) return StatusOutput.error("Function not found: " + functionIdentifier);

        String dir = (direction == null || direction.isEmpty()) ? "both" : direction.toLowerCase();

        JsonBuilder builder = JsonBuilder.object()
                .put("function", targetFunc.getName())
                .put("entryPoint", targetFunc.getEntryPoint().toString())
                .put("depth", depth)
                .put("direction", dir);

        if ("callers".equals(dir) || "both".equals(dir)) {
            Set<Function> visited = new HashSet<>();
            JsonBuilder.JsonArrayBuilder callersArray = JsonBuilder.array();
            buildCallerHierarchyJson(targetFunc, callersArray, visited, 0, depth);
            builder.putArray("callers", callersArray);
        }

        if ("callees".equals(dir) || "both".equals(dir)) {
            Set<Function> visited = new HashSet<>();
            JsonBuilder.JsonArrayBuilder calleesArray = JsonBuilder.array();
            buildCallGraphJson(targetFunc, calleesArray, visited, 0, depth);
            builder.putArray("callees", calleesArray);
        }

        return new JsonOutput(builder.build());
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
        AddressIterator addrIter = func.getBody().getAddresses(true);
        
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
    
    /** JSON version: build callees hierarchy into a JsonArrayBuilder. */
    private void buildCallGraphJson(Function func, JsonBuilder.JsonArrayBuilder array,
                                     Set<Function> visited, int currentDepth, int maxDepth) {
        if (visited.contains(func) || currentDepth >= maxDepth) return;
        visited.add(func);

        Set<Function> calledFunctions = new HashSet<>();
        ReferenceManager refMgr = func.getProgram().getReferenceManager();
        AddressIterator addrIter = func.getBody().getAddresses(true);
        while (addrIter.hasNext()) {
            Address fromAddr = addrIter.next();
            for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                if (ref.getReferenceType().isCall()) {
                    Function calledFunc = func.getProgram().getFunctionManager().getFunctionAt(ref.getToAddress());
                    if (calledFunc != null) calledFunctions.add(calledFunc);
                }
            }
        }

        List<Function> sorted = new ArrayList<>(calledFunctions);
        sorted.sort(Comparator.comparing(Function::getName));

        for (Function calledFunc : sorted) {
            JsonBuilder.JsonArrayBuilder childCallees = JsonBuilder.array();
            buildCallGraphJson(calledFunc, childCallees, visited, currentDepth + 1, maxDepth);
            array.addRaw(JsonBuilder.object()
                    .put("name", calledFunc.getName())
                    .put("address", calledFunc.getEntryPoint().toString())
                    .putArray("callees", childCallees)
                    .build());
        }
    }

    /** JSON version: build callers hierarchy into a JsonArrayBuilder. */
    private void buildCallerHierarchyJson(Function func, JsonBuilder.JsonArrayBuilder array,
                                           Set<Function> visited, int currentDepth, int maxDepth) {
        if (visited.contains(func) || currentDepth >= maxDepth) return;
        visited.add(func);

        Set<Function> callers = new HashSet<>();
        ReferenceManager refMgr = func.getProgram().getReferenceManager();
        for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
            if (ref.getReferenceType().isCall()) {
                Function callerFunc = func.getProgram().getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (callerFunc != null && !callerFunc.equals(func)) callers.add(callerFunc);
            }
        }

        List<Function> sorted = new ArrayList<>(callers);
        sorted.sort(Comparator.comparing(Function::getName));

        for (Function caller : sorted) {
            JsonBuilder.JsonArrayBuilder childCallers = JsonBuilder.array();
            buildCallerHierarchyJson(caller, childCallers, visited, currentDepth + 1, maxDepth);
            array.addRaw(JsonBuilder.object()
                    .put("name", caller.getName())
                    .put("address", caller.getEntryPoint().toString())
                    .putArray("callers", childCallers)
                    .build());
        }
    }

    @McpTool(description = """
        List cross-references (xrefs) to the specified address.

        Shows locations where an address is referenced from, helping track usage.

        Returns: References with source address, type, and containing function

        Example: list_references("00401000") -> ['00400f50 -> 00401000 (from CALL in main)', ...] """,
        outputType = ListOutput.class)
    public ToolOutput listReferences(
            @Param("Target address (e.g., \"00401000\" or \"ram:00401000\")") String address,
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") int offset,
            @Param(value = "Maximum references to return", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null) return StatusOutput.error("Address or name is required");

        List<String> refs = new ArrayList<>();
        try {
            // Try to get the address directly first (if addressStr is a hex address)
            Address addr = program.getAddressFactory().getAddress(address);

            // If addr is null or we couldn't get it directly, try to find it as a symbol name
            if (addr == null) {
                addr = GhidraUtils.getSymbolAddress(program, address);
            }

            if (addr == null) {
                return StatusOutput.error("Could not resolve address for " + address);
            }

            ReferenceManager refMgr = program.getReferenceManager();

            // Get references to this address
            for (Reference ref : refMgr.getReferencesTo(addr)) {
                Address fromAddr = ref.getFromAddress();
                ghidra.program.model.symbol.RefType refType = ref.getReferenceType();

                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcName = func != null ? func.getName() : "not in function";

                refs.add(JsonBuilder.object()
                        .put("from", fromAddr.toString())
                        .put("to", addr.toString())
                        .put("type", refType.getName())
                        .put("function", funcName)
                        .build());
            }

            if (refs.isEmpty()) {
                return StatusOutput.error("No references found to " + address);
            }

            Collections.sort(refs);
            return ListOutput.paginate(refs, offset, limit);
        } catch (Exception e) {
            return StatusOutput.error("Error getting references: " + e.getMessage());
        }
    }
    
    @McpTool(description = """
        List all references FROM a specific address.

        Shows what addresses/symbols this address references (calls, jumps, data access).

        Returns: List of references with destination addresses and types

        Note: Complements list_references which shows references TO an address.

        Example: list_references_from("main") -> "00401000 -> 00401234 (strlen) [CALL]" """,
        outputType = ListOutput.class)
    public ToolOutput listReferencesFrom(
            @Param("Source address or symbol name (e.g., \"00401000\" or \"main\")") String address,
            @Param(value = "Starting index for pagination (default: 0)", defaultValue = "0") int offset,
            @Param(value = "Maximum number of references to return (default: 100)", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null) return StatusOutput.error("Address or name is required");

        List<String> refs = new ArrayList<>();
        try {
            // Try to get the address directly first (if addressStr is a hex address)
            Address addr = program.getAddressFactory().getAddress(address);

            // If addr is null or we couldn't get it directly, try to find it as a symbol name
            if (addr == null) {
                addr = GhidraUtils.getSymbolAddress(program, address);
            }

            if (addr == null) {
                return StatusOutput.error("Could not resolve address for " + address);
            }

            ReferenceManager refMgr = program.getReferenceManager();

            // Get references from this address
            for (Reference ref : refMgr.getReferencesFrom(addr)) {
                Address toAddr = ref.getToAddress();
                ghidra.program.model.symbol.RefType refType = ref.getReferenceType();

                Symbol destSymbol = program.getSymbolTable().getPrimarySymbol(toAddr);
                String destName = destSymbol != null ? destSymbol.getName() : "unnamed";

                Function func = program.getFunctionManager().getFunctionContaining(toAddr);
                String funcName = func != null ? func.getName() : "not in function";

                refs.add(JsonBuilder.object()
                        .put("from", addr.toString())
                        .put("to", toAddr.toString())
                        .put("destination", destName)
                        .put("type", refType.getName())
                        .put("function", funcName)
                        .build());
            }

            if (refs.isEmpty()) {
                return StatusOutput.error("No references found from " + address);
            }

            Collections.sort(refs);
            return ListOutput.paginate(refs, offset, limit);
        } catch (Exception e) {
            return StatusOutput.error("Error getting references from: " + e.getMessage());
        }
    }
    
    /**
     * Recursive helper method to build the caller hierarchy
     */
    private void buildCallerHierarchy(Function func, StringBuilder result, Set<Function> visited,
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
        
        // Get all functions that call this function
        Set<Function> callers = new HashSet<>();
        ReferenceManager refMgr = func.getProgram().getReferenceManager();
        
        for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
            if (ref.getReferenceType().isCall()) {
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = func.getProgram().getFunctionManager().getFunctionContaining(fromAddr);
                if (callerFunc != null && !callerFunc.equals(func)) {
                    callers.add(callerFunc);
                }
            }
        }
        
        // Sort callers by name for consistent output
        List<Function> sortedCallers = new ArrayList<>(callers);
        sortedCallers.sort(Comparator.comparing(Function::getName));
        
        // Recursively process callers
        for (Function caller : sortedCallers) {
            buildCallerHierarchy(caller, result, visited, currentDepth + 1, maxDepth);
        }
    }
}
