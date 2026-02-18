package com.lauriewired.mcp.services;

import java.util.ArrayList;
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
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.CallGraphResult;
import com.lauriewired.mcp.model.response.ControlFlowResult;
import com.lauriewired.mcp.model.response.DataFlowResult;
import com.lauriewired.mcp.model.response.ReferenceFromItem;
import com.lauriewired.mcp.model.response.ReferenceToItem;
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
    public AnalysisService(final ProgramService programService, final FunctionService functionService) {
        this.programService = programService;
        this.functionService = functionService;
    }

    @McpTool(outputType = JsonOutput.class, responseType = ControlFlowResult.class, description = """
        Analyze the control flow of a function.

        Creates a textual control flow graph (CFG) showing how basic blocks connect.

        Returns: CFG with blocks, successors, and instructions as {address: text} maps

        Note: Basic blocks are instruction sequences with single entry/exit points.
        Essential for understanding branching and loops.

        Example: analyze_control_flow("main") -> "Control Flow Analysis for function:..." """)
    public ToolOutput analyzeControlFlow(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") final String functionIdentifier) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return StatusOutput.error("Function identifier is required");

        try {
            final Function func = functionService.resolveFunction(program, functionIdentifier);
            if (func == null) return StatusOutput.error("Function not found: " + functionIdentifier);

            final BasicBlockModel bbModel = new BasicBlockModel(program);
            final AddressSet functionBody = new AddressSet(func.getBody());
            final CodeBlockIterator blockIterator = bbModel.getCodeBlocksContaining(functionBody, new ConsoleTaskMonitor());

            final List<CodeBlock> blocks = new ArrayList<>();
            while (blockIterator.hasNext()) {
                blocks.add(blockIterator.next());
            }
            blocks.sort(Comparator.comparing(CodeBlock::getFirstStartAddress));

            final List<ControlFlowResult.Block> blockRecords = new ArrayList<>();

            for (final CodeBlock block : blocks) {
                // Build successors list
                final List<ControlFlowResult.Successor> successors = new ArrayList<>();
                final CodeBlockReferenceIterator destIter = block.getDestinations(new ConsoleTaskMonitor());
                while (destIter.hasNext()) {
                    final CodeBlockReference ref = destIter.next();
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
                    successors.add(new ControlFlowResult.Successor(
                            flowType,
                            ref.getDestinationBlock().getFirstStartAddress().toString()));
                }

                // Build instructions list
                final List<Map<String, String>> instrList = new ArrayList<>();
                final Listing listing = program.getListing();
                final InstructionIterator instructions = listing.getInstructions(block, true);
                while (instructions.hasNext()) {
                    final Instruction instr = instructions.next();
                    instrList.add(ControlFlowResult.instruction(
                            instr.getAddress().toString(),
                            instr.toString()));
                }

                blockRecords.add(new ControlFlowResult.Block(
                        block.getFirstStartAddress().toString(),
                        new ControlFlowResult.Range(
                                block.getMinAddress().toString(),
                                block.getMaxAddress().toString()),
                        successors,
                        instrList));
            }

            final ControlFlowResult result = new ControlFlowResult(
                    func.getName(),
                    func.getEntryPoint().toString(),
                    blockRecords);
            return new JsonOutput(result);
        } catch (Exception e) {
            return StatusOutput.error("Error analyzing control flow: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, responseType = DataFlowResult.class, description = """
        Analyze the data flow for a variable in a function.

        Tracks where a variable is defined (written) and used (read) throughout execution paths.

        Returns: Detailed analysis with variable info, definitions and uses

        Note: Helps understand value propagation and useful for analyzing algorithms.

        Example: analyze_data_flow("main", "local_10") -> "Data Flow Analysis..." """)
    public ToolOutput analyzeDataFlow(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") final String functionIdentifier,
            @Param("Variable name to track") final String variable) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return StatusOutput.error("Function identifier is required");
        if (variable == null || variable.isEmpty()) return StatusOutput.error("Variable name is required");

        try {
            final Function func = functionService.resolveFunction(program, functionIdentifier);
            if (func == null) return StatusOutput.error("Function not found: " + functionIdentifier);

            final DecompileResults decompResults = GhidraUtils.decompileFunction(func, program);
            if (decompResults == null) {
                return StatusOutput.error("Could not decompile function for data flow analysis");
            }

            final HighFunction highFunc = decompResults.getHighFunction();
            if (highFunc == null) {
                return StatusOutput.error("No high function available for data flow analysis");
            }

            final ghidra.program.model.pcode.HighSymbol targetSymbol =
                GhidraUtils.findVariableByName(highFunc, variable);

            if (targetSymbol == null) {
                return StatusOutput.error("Variable '" + variable + "' not found in function");
            }

            final HighVariable highVar = targetSymbol.getHighVariable();
            if (highVar == null) {
                return StatusOutput.error("No high variable found for '" + variable + "'");
            }

            // Build storage info
            final Varnode[] instances = highVar.getInstances();
            final StringBuilder storage = new StringBuilder();
            for (int i = 0; i < instances.length; i++) {
                if (i > 0) storage.append(", ");
                storage.append(instances[i].getAddress());
            }

            // Track definitions and uses
            final Map<Address, String[]> defUseMap = new HashMap<>();
            for (final Varnode instance : instances) {
                final PcodeOp defOp = instance.getDef();
                if (defOp != null) {
                    final Address defAddr = defOp.getSeqnum().getTarget();
                    defUseMap.put(defAddr, new String[]{"DEFINE", defOp.getMnemonic()});
                }
                final Iterator<PcodeOp> descendants = instance.getDescendants();
                while (descendants.hasNext()) {
                    final PcodeOp useOp = descendants.next();
                    final Address useAddr = useOp.getSeqnum().getTarget();
                    defUseMap.put(useAddr, new String[]{"USE", useOp.getMnemonic()});
                }
            }

            final List<Address> sortedAddrs = new ArrayList<>(defUseMap.keySet());
            sortedAddrs.sort(Comparator.naturalOrder());

            final Listing listing = program.getListing();
            final List<DataFlowResult.Reference> references = new ArrayList<>();
            for (final Address opAddr : sortedAddrs) {
                final Instruction instr = listing.getInstructionAt(opAddr);
                if (instr != null) {
                    final String[] entry = defUseMap.get(opAddr);
                    references.add(new DataFlowResult.Reference(
                            opAddr.toString(),
                            entry[0],
                            entry[1],
                            instr.toString()));
                }
            }

            final DataFlowResult result = new DataFlowResult(
                    func.getName(),
                    new DataFlowResult.Variable(
                            highVar.getName(),
                            highVar.getDataType().getName(),
                            storage.toString()),
                    references);
            return new JsonOutput(result);
        } catch (Exception e) {
            return StatusOutput.error("Error analyzing data flow: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, responseType = CallGraphResult.class, description = """
        Get the call graph for a function.

        Shows callers (functions that call this one), callees (functions this one calls), or both.

        Returns: Hierarchical call graph with function names and addresses

        Examples:
            get_call_graph("main") -> full call hierarchy for main
            get_call_graph("process_data", direction="callers") -> who calls process_data
            get_call_graph("00401000", depth=3, direction="callees") -> what does this function call """)
    public ToolOutput getCallGraph(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") final String functionIdentifier,
            @Param(value = "Maximum depth to traverse (1-5, default: 2)", defaultValue = "2") int depth,
            @Param(value = "\"callers\" for upstream only, \"callees\" for downstream only, \"both\" for full hierarchy (default: \"both\")", defaultValue = "both") final String direction) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty())
            return StatusOutput.error("Function identifier is required");

        depth = Math.min(Math.max(depth, 1), 5);

        final Function targetFunc = functionService.resolveFunction(program, functionIdentifier);
        if (targetFunc == null) return StatusOutput.error("Function not found: " + functionIdentifier);

        final String dir = (direction == null || direction.isEmpty()) ? "both" : direction.toLowerCase();

        List<CallGraphResult.CallGraphNode> callerNodes = null;
        List<CallGraphResult.CallGraphNode> calleeNodes = null;

        if ("callers".equals(dir) || "both".equals(dir)) {
            final Set<Function> visited = new HashSet<>();
            callerNodes = buildCallerHierarchy(targetFunc, visited, 0, depth);
        }

        if ("callees".equals(dir) || "both".equals(dir)) {
            final Set<Function> visited = new HashSet<>();
            calleeNodes = buildCalleeHierarchy(targetFunc, visited, 0, depth);
        }

        final CallGraphResult result = new CallGraphResult(
                targetFunc.getName(),
                targetFunc.getEntryPoint().toString(),
                depth,
                dir,
                callerNodes,
                calleeNodes);
        return new JsonOutput(result);
    }

    /** Build callees hierarchy and return as a list of CallGraphNode records. */
    private List<CallGraphResult.CallGraphNode> buildCalleeHierarchy(final Function func,
                                     final Set<Function> visited, final int currentDepth, final int maxDepth) {
        final List<CallGraphResult.CallGraphNode> nodes = new ArrayList<>();
        if (visited.contains(func) || currentDepth >= maxDepth) return nodes;
        visited.add(func);

        final Set<Function> calledFunctions = new HashSet<>();
        final ReferenceManager refMgr = func.getProgram().getReferenceManager();
        final AddressIterator addrIter = func.getBody().getAddresses(true);
        while (addrIter.hasNext()) {
            final Address fromAddr = addrIter.next();
            for (final Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                if (ref.getReferenceType().isCall()) {
                    final Function calledFunc = func.getProgram().getFunctionManager().getFunctionAt(ref.getToAddress());
                    if (calledFunc != null) calledFunctions.add(calledFunc);
                }
            }
        }

        final List<Function> sorted = new ArrayList<>(calledFunctions);
        sorted.sort(Comparator.comparing(Function::getName));

        for (final Function calledFunc : sorted) {
            final boolean atMaxDepth = currentDepth + 1 >= maxDepth;
            final List<CallGraphResult.CallGraphNode> childCallees = atMaxDepth
                    ? null : buildCalleeHierarchy(calledFunc, visited, currentDepth + 1, maxDepth);
            nodes.add(new CallGraphResult.CallGraphNode(
                    calledFunc.getName(),
                    calledFunc.getEntryPoint().toString(),
                    null,
                    childCallees));
        }
        return nodes;
    }

    /** Build callers hierarchy and return as a list of CallGraphNode records. */
    private List<CallGraphResult.CallGraphNode> buildCallerHierarchy(final Function func,
                                           final Set<Function> visited, final int currentDepth, final int maxDepth) {
        final List<CallGraphResult.CallGraphNode> nodes = new ArrayList<>();
        if (visited.contains(func) || currentDepth >= maxDepth) return nodes;
        visited.add(func);

        final Set<Function> callers = new HashSet<>();
        final ReferenceManager refMgr = func.getProgram().getReferenceManager();
        for (final Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
            if (ref.getReferenceType().isCall()) {
                final Function callerFunc = func.getProgram().getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (callerFunc != null && !callerFunc.equals(func)) callers.add(callerFunc);
            }
        }

        final List<Function> sorted = new ArrayList<>(callers);
        sorted.sort(Comparator.comparing(Function::getName));

        for (final Function caller : sorted) {
            final boolean atMaxDepth = currentDepth + 1 >= maxDepth;
            final List<CallGraphResult.CallGraphNode> childCallers = atMaxDepth
                    ? null : buildCallerHierarchy(caller, visited, currentDepth + 1, maxDepth);
            nodes.add(new CallGraphResult.CallGraphNode(
                    caller.getName(),
                    caller.getEntryPoint().toString(),
                    childCallers,
                    null));
        }
        return nodes;
    }

    @McpTool(description = """
        List cross-references (xrefs) to the specified address.

        Shows locations where an address is referenced from, helping track usage.

        Returns: References with source address, type, and containing function

        Example: list_references("00401000") -> ['00400f50 -> 00401000 (from CALL in main)', ...] """,
        outputType = ListOutput.class, responseType = ReferenceToItem.class)
    public ToolOutput listReferences(
            @Param("final Target address (e.g., \"00401000\" or \"ram:00401000\")") final String address,
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") final int offset,
            @Param(value = "Maximum references to return", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null) return StatusOutput.error("Address or name is required");

        final List<ReferenceToItem> refs = new ArrayList<>();
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

            final ReferenceManager refMgr = program.getReferenceManager();

            // Get references to this address
            for (final Reference ref : refMgr.getReferencesTo(addr)) {
                final Address fromAddr = ref.getFromAddress();
                final ghidra.program.model.symbol.RefType refType = ref.getReferenceType();

                final Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                final String funcName = func != null ? func.getName() : "not in function";

                refs.add(new ReferenceToItem(
                        fromAddr.toString(),
                        addr.toString(),
                        refType.getName(),
                        funcName));
            }

            if (refs.isEmpty()) {
                return StatusOutput.error("No references found to " + address);
            }

            refs.sort(Comparator.comparing(ReferenceToItem::from));
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
        outputType = ListOutput.class, responseType = ReferenceFromItem.class)
    public ToolOutput listReferencesFrom(
            @Param("final Source address or symbol name (e.g., \"00401000\" or \"main\")") final String address,
            @Param(value = "Starting index for pagination (default: 0)", defaultValue = "0") final int offset,
            @Param(value = "Maximum number of references to return (default: 100)", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null) return StatusOutput.error("Address or name is required");

        final List<ReferenceFromItem> refs = new ArrayList<>();
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

            final ReferenceManager refMgr = program.getReferenceManager();

            // Get references from this address
            for (final Reference ref : refMgr.getReferencesFrom(addr)) {
                final Address toAddr = ref.getToAddress();
                final ghidra.program.model.symbol.RefType refType = ref.getReferenceType();

                final Symbol destSymbol = program.getSymbolTable().getPrimarySymbol(toAddr);
                final String destName = destSymbol != null ? destSymbol.getName() : "unnamed";

                final Function func = program.getFunctionManager().getFunctionContaining(toAddr);
                final String funcName = func != null ? func.getName() : "not in function";

                refs.add(new ReferenceFromItem(
                        addr.toString(),
                        toAddr.toString(),
                        destName,
                        refType.getName(),
                        funcName));
            }

            if (refs.isEmpty()) {
                return StatusOutput.error("No references found from " + address);
            }

            refs.sort(Comparator.comparing(ReferenceFromItem::from));
            return ListOutput.paginate(refs, offset, limit);
        } catch (Exception e) {
            return StatusOutput.error("Error getting references from: " + e.getMessage());
        }
    }
}
