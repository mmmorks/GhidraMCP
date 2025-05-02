package com.lauriewired.mcp.services;

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
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Service for advanced program analysis operations
 */
public class AnalysisService {
    private final ProgramService programService;

    /**
     * Creates a new AnalysisService
     *
     * @param programService the program service for accessing the current program
     */
    public AnalysisService(ProgramService programService) {
        this.programService = programService;
    }

    /**
     * Analyze the control flow of a function
     * 
     * @param addressStr address of the function to analyze
     * @return detailed control flow analysis
     */
    public String analyzeControlFlow(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = GhidraUtils.getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;
            
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
            
            return result.toString();
        } catch (Exception e) {
            return "Error analyzing control flow: " + e.getMessage();
        }
    }
    
    /**
     * Analyze the data flow for a variable in a function
     * 
     * @param addressStr address of the function containing the variable
     * @param variableName name of the variable to analyze
     * @return detailed data flow analysis
     */
    public String analyzeDataFlow(String addressStr, String variableName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (variableName == null || variableName.isEmpty()) return "Variable name is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = GhidraUtils.getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;
            
            StringBuilder result = new StringBuilder();
            result.append("Data Flow Analysis for variable '").append(variableName)
                  .append("' in function ").append(func.getName())
                  .append(" at ").append(func.getEntryPoint()).append("\n\n");
            
            // Decompile the function to get high-level variable information
            DecompileResults decompResults = GhidraUtils.decompileFunction(func, program);
            if (decompResults == null) {
                return "Could not decompile function for data flow analysis";
            }
            
            HighFunction highFunc = decompResults.getHighFunction();
            if (highFunc == null) {
                return "No high function available for data flow analysis";
            }
            
            // Find the variable by name
            ghidra.program.model.pcode.HighSymbol targetSymbol = 
                GhidraUtils.findVariableByName(highFunc, variableName);
                
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
     * 
     * @param addressStr address of the function to start from
     * @param depth maximum depth to traverse
     * @return hierarchical representation of the call graph
     */
    public String analyzeCallGraph(String addressStr, int depth) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        // Limit depth to prevent excessive output
        depth = Math.min(Math.max(depth, 1), 5);
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function rootFunc = GhidraUtils.getFunctionForAddress(program, addr);
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
    
    /**
     * List all references to a specific address
     * 
     * @param nameOrAddress name or address to find references to
     * @param offset starting index for pagination
     * @param limit maximum number of references to return
     * @return list of references to the specified address
     */
    public String listReferences(String nameOrAddress, int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (nameOrAddress == null) return "Address or name is required";

        List<String> refs = new ArrayList<>();
        try {
            // Try to get the address directly first (if addressStr is a hex address)
            Address addr = program.getAddressFactory().getAddress(nameOrAddress);

            // If addr is null or we couldn't get it directly, try to find it as a symbol name
            if (addr == null) {
                addr = GhidraUtils.getSymbolAddress(program, nameOrAddress);
            }
            
            if (addr == null) {
                return "Could not resolve address for " + nameOrAddress;
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
                return "No references found to " + nameOrAddress + " (address: " + addr + ")";
            }

            Collections.sort(refs);
            
            // Apply pagination
            List<String> paginatedRefs = refs.subList(
                Math.min(offset, refs.size()),
                Math.min(offset + limit, refs.size())
            );
            
            return String.join("\n", paginatedRefs);
        } catch (Exception e) {
            return "Error getting references: " + e.getMessage();
        }
    }
}
