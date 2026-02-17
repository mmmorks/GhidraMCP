package com.lauriewired.mcp.services;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.utils.GhidraUtils;
import com.lauriewired.mcp.utils.ProgramTransaction;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.TextOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.RenameVariablesResult;
import com.lauriewired.mcp.model.response.SetVariableTypesResult;
import com.lauriewired.mcp.model.response.SplitVariableResult;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Spliterators;
import java.util.stream.StreamSupport;

/**
 * Service for variable-related operations
 */
public class VariableService {
    private final ProgramService programService;
    private final FunctionService functionService;

    /**
     * Creates a new VariableService
     *
     * @param programService the program service for accessing the current program
     * @param functionService the function service for resolving function identifiers
     */
    public VariableService(final ProgramService programService, final FunctionService functionService) {
        this.programService = programService;
        this.functionService = functionService;
    }

    @McpTool(post = true, description = """
        Batch rename local variables within a single function.

        All renames are applied in a single transaction \u2014 if any rename fails,
        none are applied (all-or-nothing). The function is decompiled once and
        all renames are executed together for efficiency.

        Returns: JSON with status, renamed pairs, and count

        Note: Variable names must be unique within the function scope.
              Only one function at a time is supported.

        Tip: If the decompiler reuses a single variable name across unrelated usages
             (e.g., the same local is used for a loop counter and later a buffer pointer),
             use split_variable first to give that specific use of memory a distinct identity
             from that point in the function onward, then rename it here.

        Example: rename_variables("main", {"local_10": "buffer_size", "param_1": "argc"}) """,
        outputType = JsonOutput.class, responseType = RenameVariablesResult.class)
    public ToolOutput renameVariables(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") final String functionIdentifier,
            @Param("Map of current variable names to new names") final Map<String, String> renames) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (renames == null || renames.isEmpty()) return StatusOutput.error("No renames specified");

        final var func = functionService.resolveFunction(program, functionIdentifier);
        if (func == null) return StatusOutput.error("Function not found: " + functionIdentifier);

        final var decomp = new DecompInterface();
        decomp.openProgram(program);
        final var result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) return StatusOutput.error("Decompilation failed");

        final var highFunction = result.getHighFunction();
        if (highFunction == null) return StatusOutput.error("Decompilation failed (no high function)");

        final var localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) return StatusOutput.error("Decompilation failed (no local symbol map)");

        // Pre-validate: find all symbols and check for conflicts
        final Map<String, HighSymbol> symbolMap = new LinkedHashMap<>();
        final var existingNames = new HashSet<String>();
        final var symbolsIterator = localSymbolMap.getSymbols();
        while (symbolsIterator.hasNext()) {
            final var symbol = symbolsIterator.next();
            existingNames.add(symbol.getName());
            if (renames.containsKey(symbol.getName())) {
                symbolMap.put(symbol.getName(), symbol);
            }
        }

        // Validate all renames before starting the transaction
        for (final var entry : renames.entrySet()) {
            if (!symbolMap.containsKey(entry.getKey())) {
                return StatusOutput.error("Variable not found: '" + entry.getKey() + "'");
            }
            // Check that the new name doesn't conflict with an existing name
            // (unless it's one we're also renaming away from)
            if (existingNames.contains(entry.getValue()) && !renames.containsKey(entry.getValue())) {
                return StatusOutput.error("Error: A variable with name '" + entry.getValue() + "' already exists in this function");
            }
        }

        boolean commitRequired = false;
        for (final HighSymbol hs : symbolMap.values()) {
            if (GhidraUtils.checkFullCommit(hs, highFunction)) {
                commitRequired = true;
                break;
            }
        }

        // Execute all renames in a single transaction
        try (var tx = ProgramTransaction.start(program, "Batch rename variables")) {
            if (commitRequired) {
                HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                    ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
            }

            for (final var entry : renames.entrySet()) {
                final var highSymbol = symbolMap.get(entry.getKey());
                final var highVariable = highSymbol.getHighVariable();
                final var newHighVariable = highFunction.splitOutMergeGroup(highVariable, highVariable.getRepresentative());
                final var finalHighSymbol = newHighVariable.getSymbol();

                var dataType = finalHighSymbol.getDataType();
                if (Undefined.isUndefined(dataType)) {
                    dataType = AbstractIntegerDataType.getUnsignedDataType(
                        dataType.getLength(), program.getDataTypeManager());
                }

                HighFunctionDBUtil.updateDBVariable(
                    finalHighSymbol, entry.getValue(), dataType, SourceType.USER_DEFINED);
            }
            tx.commit();
        } catch (Exception e) {
            Msg.error(this, "Failed to batch rename variables", e);
            return StatusOutput.error("Failed to rename variables (transaction rolled back): " + e.getMessage());
        }

        return new JsonOutput(new RenameVariablesResult(
                "Variables renamed successfully",
                func.getName(),
                new LinkedHashMap<>(renames),
                renames.size()));
    }

    @McpTool(post = true, description = """
        Split or rename a variable at a specific usage address within a function.

        Useful when the decompiler reuses a single variable name across unrelated usages.
        Splitting assigns a distinct name at one usage site without affecting others.

        Returns: Status of the split operation

        Example: split_variable("main", "local_10", "00401050", "loop_counter") """,
        outputType = JsonOutput.class, responseType = SplitVariableResult.class)
    public ToolOutput splitVariable(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") final String functionIdentifier,
            @Param("Current variable name to split") final String variableName,
            @Param("Address where this specific usage occurs (bare hex, no 0x prefix)") final String usageAddress,
            @Param(value = "New name for the variable at this usage (optional; Ghidra auto-generates if empty)", defaultValue = "") final String newName) {
        final String resolvedName = (newName != null && !newName.isEmpty()) ? newName : variableName + "_split";
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        final var decomp = new DecompInterface();
        decomp.openProgram(program);

        final var func = functionService.resolveFunction(program, functionIdentifier);
        if (func == null) {
            return StatusOutput.error("Function not found: " + functionIdentifier);
        }

        final var result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return StatusOutput.error("Decompilation failed");
        }

        final var highFunction = result.getHighFunction();
        if (highFunction == null) {
            return StatusOutput.error("Decompilation failed (no high function)");
        }

        final var localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return StatusOutput.error("Decompilation failed (no local symbol map)");
        }

        HighSymbol highSymbol = null;
        final var symbolsIterator = localSymbolMap.getSymbols();
        while (symbolsIterator.hasNext()) {
            final var symbol = symbolsIterator.next();
            final var symbolName = symbol.getName();

            if (symbolName.equals(variableName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(resolvedName)) {
                return StatusOutput.error("Error: A variable with name '" + resolvedName + "' already exists in this function");
            }
        }

        if (highSymbol == null) {
            return StatusOutput.error("Variable not found");
        }

        // Find the specific Varnode to split if a usage address is provided
        Varnode specificVarnode = null;
        if (usageAddress != null && !usageAddress.isEmpty()) {
            try {
                final var parsedUsageAddress = program.getAddressFactory().getAddress(usageAddress);
                final var highVariable = highSymbol.getHighVariable();

                // Get all instances of this variable
                final var instances = highVariable.getInstances();

                Msg.info(this, "Searching for variable usage at address: " + parsedUsageAddress);
                Msg.info(this, "Variable " + variableName + " has " + instances.length + " instances");

                // First attempt: Find exact match at the specified address
                specificVarnode = findExactVarnodeMatch(instances, parsedUsageAddress);

                // Second attempt: Find the closest usage within a small range
                if (specificVarnode == null) {
                    Msg.info(this, "No exact match found, looking for nearby usage");
                    specificVarnode = findNearbyVarnodeUsage(instances, parsedUsageAddress, 16); // Search within 16 bytes
                }

                // Third attempt: Find any usage if we still don't have a match
                if (specificVarnode == null) {
                    Msg.info(this, "No nearby match found, using any usage");
                    specificVarnode = findAnyVarnodeUsage(instances);
                }

                if (specificVarnode == null) {
                    return StatusOutput.error("Could not find any variable usage, even after trying fallback strategies");
                }

                Msg.info(this, "Selected varnode " +
                    (specificVarnode.getDef() != null ? "defined at " + specificVarnode.getDef().getSeqnum().getTarget() :
                    "with no definition"));

            } catch (Exception e) {
                return StatusOutput.error("Error finding variable usage: " + e.getMessage());
            }
        }

        final boolean commitRequired = GhidraUtils.checkFullCommit(highSymbol, highFunction);

        final var highVariable = highSymbol.getHighVariable();
        final var finalVarnode = specificVarnode != null ? specificVarnode : highVariable.getRepresentative();

        try (var tx = ProgramTransaction.start(program, "Rename variable")) {
            if (commitRequired) {
                HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                    ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
            }

            final var newHighVariable = highFunction.splitOutMergeGroup(highVariable, finalVarnode);
            final var finalHighSymbol = newHighVariable.getSymbol();

            var dataType = finalHighSymbol.getDataType();
            if (Undefined.isUndefined(dataType)) {
                dataType = AbstractIntegerDataType.getUnsignedDataType(dataType.getLength(), program.getDataTypeManager());
            }

            HighFunctionDBUtil.updateDBVariable(
                finalHighSymbol,
                resolvedName,
                dataType,
                SourceType.USER_DEFINED
            );
            tx.commit();
        } catch (Exception e) {
            Msg.error(this, "Failed to rename variable", e);
            return StatusOutput.error("Failed to rename variable: " + e.getMessage());
        }

        // Get updated variable list after renaming
        try {
            // Re-decompile to get the updated state
            final var updatedResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (updatedResult == null || !updatedResult.decompileCompleted()) {
                return StatusOutput.error("Variable renamed, but failed to get updated variable list");
            }

            final var updatedHighFunction = updatedResult.getHighFunction();
            if (updatedHighFunction == null) {
                return StatusOutput.error("Variable renamed, but failed to get updated high function");
            }

            final var updatedSymbolMap = updatedHighFunction.getLocalSymbolMap();
            if (updatedSymbolMap == null) {
                return StatusOutput.error("Variable renamed, but failed to get updated symbol map");
            }

            // Convert symbols to VarInfo records
            final List<SplitVariableResult.VarInfo> variables = new ArrayList<>();
            updatedSymbolMap.getSymbols().forEachRemaining(symbol -> {
                final String symbolName = symbol.getName();
                final String dataTypeName = symbol.getDataType().getName();
                String storage = null;

                final HighVariable var = symbol.getHighVariable();
                if (var != null && var.getSymbol() != null) {
                    storage = var.getSymbol().getStorage().toString();
                }

                variables.add(new SplitVariableResult.VarInfo(symbolName, dataTypeName, storage));
            });

            // Re-decompile once more to get the updated code after renaming
            var decompiled = "";
            try {
                final var finalResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (finalResult != null && finalResult.decompileCompleted()) {
                    decompiled = finalResult.getDecompiledFunction().getC();
                }
            } catch (Exception e) {
                Msg.warn(this, "Failed to get decompiled code for response: " + e.getMessage());
                decompiled = "Decompilation unavailable";
            }

            return new JsonOutput(new SplitVariableResult(
                    "Variable split and renamed",
                    variableName,
                    resolvedName,
                    (usageAddress != null && !usageAddress.isEmpty()) ? usageAddress : null,
                    variables,
                    decompiled));

        } catch (Exception e) {
            final String errorMsg = "Variable renamed, but failed to collect variable info: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return new TextOutput("Variable renamed");
        }
    }

    /**
     * Set the data type of a local variable in a function
     *
     * @param functionAddrStr address of the function containing the variable
     * @param variableName name of the variable to modify
     * @param newType new data type for the variable
     * @return true if successful, false otherwise
     */
    public boolean setLocalVariableType(final String functionAddrStr, final String variableName, final String newType) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        try {
            final var addr = program.getAddressFactory().getAddress(functionAddrStr);
            final var func = GhidraUtils.getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return false;
            }

            final var results = GhidraUtils.decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return false;
            }

            final var highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return false;
            }

            final var symbol = GhidraUtils.findVariableByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return false;
            }

            final var highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return false;
            }

            Msg.info(this, "Found high variable for: " + variableName +
                     " with current type " + highVar.getDataType().getName());

            final var dataTypeService = new DataTypeService(programService);
            final var dataType = dataTypeService.resolveDataType(program.getDataTypeManager(), newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return false;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            try (var tx = ProgramTransaction.start(program, "Set variable type")) {
                HighFunctionDBUtil.updateDBVariable(
                    symbol,
                    symbol.getName(),
                    dataType,
                    SourceType.USER_DEFINED
                );
                tx.commit();
                Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
                return true;
            }
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
            return false;
        }
    }

    @McpTool(post = true, description = """
        Batch set data types for local variables in a function.

        All type changes are applied in a single transaction \u2014 if any fails,
        none are applied (all-or-nothing). The function is decompiled once and
        all type changes are executed together for efficiency.

        Returns: JSON with status, applied type changes, and count

        Note: Supports built-in types, pointers, and structures. Windows-style types also supported.

        Example: set_variable_types("00401000", {"local_10": "int", "local_14": "char *"}) """,
        outputType = JsonOutput.class, responseType = SetVariableTypesResult.class)
    public ToolOutput setVariableTypes(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") final String functionIdentifier,
            @Param("final Map of variable names to new data types") final Map<String, String> types) {
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return StatusOutput.error("Function identifier is required");
        if (types == null || types.isEmpty()) return StatusOutput.error("No variable types specified");
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        try {
            final var func = functionService.resolveFunction(program, functionIdentifier);
            if (func == null) return StatusOutput.error("Function not found: " + functionIdentifier);

            final var results = GhidraUtils.decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) return StatusOutput.error("Decompilation failed");

            final var highFunction = results.getHighFunction();
            if (highFunction == null) return StatusOutput.error("Decompilation failed (no high function)");

            final var dataTypeService = new DataTypeService(programService);
            final var dtm = program.getDataTypeManager();

            // Pre-validate: find all symbols and resolve all types
            final var symbolMap = new LinkedHashMap<String, HighSymbol>();
            final var resolvedTypes = new LinkedHashMap<String, DataType>();

            for (final var entry : types.entrySet()) {
                final var symbol = GhidraUtils.findVariableByName(highFunction, entry.getKey());
                if (symbol == null) {
                    return StatusOutput.error("Variable not found: '" + entry.getKey() + "'");
                }
                symbolMap.put(entry.getKey(), symbol);

                final var dataType = dataTypeService.resolveDataType(dtm, entry.getValue());
                if (dataType == null) {
                    return StatusOutput.error("Could not resolve data type: '" + entry.getValue() + "' for variable '" + entry.getKey() + "'");
                }
                resolvedTypes.put(entry.getKey(), dataType);
            }

            // Execute all type changes in a single transaction
            try (var tx = ProgramTransaction.start(program, "Batch set variable types")) {
                for (final var entry : types.entrySet()) {
                    final var symbol = symbolMap.get(entry.getKey());
                    final var dataType = resolvedTypes.get(entry.getKey());

                    HighFunctionDBUtil.updateDBVariable(
                        symbol, symbol.getName(), dataType, SourceType.USER_DEFINED);
                }
                tx.commit();
            } catch (Exception e) {
                Msg.error(this, "Failed to batch set variable types", e);
                return StatusOutput.error("Failed to set variable types (transaction rolled back): " + e.getMessage());
            }

            return new JsonOutput(new SetVariableTypesResult(
                    "Variable types set successfully",
                    func.getName(),
                    new LinkedHashMap<>(types),
                    types.size()));
        } catch (Exception e) {
            Msg.error(this, "Error in batch set variable types", e);
            return StatusOutput.error("Error: " + e.getMessage());
        }
    }

    /**
     * Find an exact match for a varnode at the specified address
     *
     * @param instances array of variable instances to search
     * @param usageAddress target address to match
     * @return matching varnode or null if no match found
     */
    private Varnode findExactVarnodeMatch(final Varnode[] instances, final Address usageAddress) {
        return Arrays.stream(instances)
            .filter(instance -> {
                // Check definition
                final PcodeOp defOp = instance.getDef();
                if (defOp != null && defOp.getSeqnum().getTarget().equals(usageAddress)) {
                    Msg.info(this, "Found exact match with definition at " + usageAddress);
                    return true;
                }

                // Check uses
                final var hasMatchingUse = StreamSupport
                    .stream(Spliterators.spliteratorUnknownSize(
                        instance.getDescendants(), java.util.Spliterator.ORDERED), false)
                    .anyMatch(useOp -> {
                        if (useOp.getSeqnum().getTarget().equals(usageAddress)) {
                            Msg.info(this, "Found exact match with usage at " + usageAddress);
                            return true;
                        }
                        return false;
                    });

                return hasMatchingUse;
            })
            .findFirst()
            .orElse(null);
    }

    /**
     * Find a varnode used near the specified address within a given range
     *
     * @param instances array of variable instances to search
     * @param targetAddress the target address to look near
     * @param rangeBytes the range in bytes to search (+/-)
     * @return a varnode near the target address, or null if none found
     */
    private Varnode findNearbyVarnodeUsage(final Varnode[] instances, final Address targetAddress, final int rangeBytes) {
        final var targetOffset = targetAddress.getOffset();

        record DistanceInfo(Varnode varnode, long distance) {}

        return Arrays.stream(instances)
            .map(instance -> {
                long minDistance = Long.MAX_VALUE;

                // Check definition
                final PcodeOp defOp = instance.getDef();
                if (defOp != null) {
                    final long defOffset = defOp.getSeqnum().getTarget().getOffset();
                    final long distance = Math.abs(defOffset - targetOffset);
                    if (distance <= rangeBytes) {
                        minDistance = Math.min(minDistance, distance);
                    }
                }

                // Check all uses
                final Iterator<PcodeOp> uses = instance.getDescendants();
                while (uses.hasNext()) {
                    final PcodeOp useOp = uses.next();
                    final long useOffset = useOp.getSeqnum().getTarget().getOffset();
                    final long distance = Math.abs(useOffset - targetOffset);
                    if (distance <= rangeBytes) {
                        minDistance = Math.min(minDistance, distance);
                    }
                }

                return new DistanceInfo(instance, minDistance);
            })
            .filter(info -> info.distance() <= rangeBytes)
            .min(Comparator.comparingLong(DistanceInfo::distance))
            .map(DistanceInfo::varnode)
            .orElse(null);
    }

    /**
     * Find any usage of a variable when no specific match is found
     *
     * @param instances array of variable instances
     * @return any varnode from the instances array, preferably one with a definition or uses
     */
    private Varnode findAnyVarnodeUsage(final Varnode[] instances) {
        if (instances.length == 0) {
            return null;
        }

        // Try to find varnode with definition, then with uses, then fallback to first
        return Arrays.stream(instances)
            .filter(v -> v.getDef() != null)
            .findFirst()
            .or(() -> Arrays.stream(instances)
                .filter(v -> v.getDescendants().hasNext())
                .findFirst())
            .orElseGet(() -> {
                Msg.info(this, "Using first available varnode instance as fallback");
                return instances[0];
            });
    }
}
