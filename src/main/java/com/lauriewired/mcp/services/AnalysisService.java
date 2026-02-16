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
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.TextOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.GhidraUtils;

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

    @McpTool(description = """
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

            StringBuilder result = new StringBuilder();
            result.append("Control Flow Analysis for function: ").append(func.getName())
                  .append(" at ").append(func.getEntryPoint()).append("\n\n");
            
            // Use BasicBlockModel to get the control flow graph
            BasicBlockModel bbModel = new BasicBlockModel(program);
            
            // Get the function's body
            AddressSet functionBody = new AddressSet(func.getBody());
            
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
            
            return new TextOutput(result.toString());
        } catch (Exception e) {
            return StatusOutput.error("Error analyzing control flow: " + e.getMessage());
        }
    }

    @McpTool(description = """
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

            StringBuilder result = new StringBuilder();
            result.append("Data Flow Analysis for variable '").append(variable)
                  .append("' in function ").append(func.getName())
                  .append(" at ").append(func.getEntryPoint()).append("\n\n");

            // Decompile the function to get high-level variable information
            DecompileResults decompResults = GhidraUtils.decompileFunction(func, program);
            if (decompResults == null) {
                return StatusOutput.error("Could not decompile function for data flow analysis");
            }

            HighFunction highFunc = decompResults.getHighFunction();
            if (highFunc == null) {
                return StatusOutput.error("No high function available for data flow analysis");
            }

            // Find the variable by name
            ghidra.program.model.pcode.HighSymbol targetSymbol =
                GhidraUtils.findVariableByName(highFunc, variable);

            if (targetSymbol == null) {
                return StatusOutput.error("Variable '" + variable + "' not found in function");
            }
            
            HighVariable highVar = targetSymbol.getHighVariable();
            if (highVar == null) {
                return StatusOutput.error("No high variable found for '" + variable + "'");
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
            
            return new TextOutput(result.toString());
        } catch (Exception e) {
            return StatusOutput.error("Error analyzing data flow: " + e.getMessage());
        }
    }

    @McpTool(description = """
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

        StringBuilder result = new StringBuilder();
        result.append("Call Graph for ").append(targetFunc.getName())
              .append(" at ").append(targetFunc.getEntryPoint())
              .append(" (direction: ").append(dir)
              .append(", depth: ").append(depth).append(")\n\n");

        if ("callers".equals(dir) || "both".equals(dir)) {
            result.append("CALLERS (functions that call ").append(targetFunc.getName()).append("):\n");
            Set<Function> visited = new HashSet<>();
            buildCallerHierarchy(targetFunc, result, visited, 0, depth);
            result.append("\n");
        }

        if ("callees".equals(dir) || "both".equals(dir)) {
            result.append("CALLEES (functions called by ").append(targetFunc.getName()).append("):\n");
            Set<Function> visited = new HashSet<>();
            buildCallGraph(targetFunc, result, visited, 0, depth);
            result.append("\n");
        }

        return new TextOutput(result.toString());
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

                // Get function containing the reference if it exists
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcName = func != null ? func.getName() : "not in function";

                refs.add(String.format("%s -> %s (from %s in %s)",
                    fromAddr, addr, refType.getName(), funcName));
            }

            if (refs.isEmpty()) {
                return new TextOutput("No references found to " + address + " (address: " + addr + ")");
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

                // Get symbol at destination if it exists
                Symbol destSymbol = program.getSymbolTable().getPrimarySymbol(toAddr);
                String destName = destSymbol != null ? destSymbol.getName() : "unnamed";

                // Get function containing the destination if it exists
                Function func = program.getFunctionManager().getFunctionContaining(toAddr);
                String funcName = func != null ? func.getName() : "not in function";

                refs.add(String.format("%s -> %s (%s) [%s in %s]",
                    addr, toAddr, destName, refType.getName(), funcName));
            }

            if (refs.isEmpty()) {
                return new TextOutput("No references found from " + address + " (address: " + addr + ")");
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
