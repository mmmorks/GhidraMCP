package com.lauriewired.mcp.services;

import com.lauriewired.mcp.utils.GhidraUtils;
import com.lauriewired.mcp.utils.HttpUtils;
import com.lauriewired.mcp.utils.ProgramTransaction;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Service for variable-related operations
 */
public class VariableService {
    // Variable information record for cleaner data handling
    private record VariableInfo(String name, String dataType, String storage) {
        VariableInfo(String name, String dataType) {
            this(name, dataType, null);
        }
        
        boolean hasStorage() {
            return storage != null;
        }
        
        String toJson() {
            return String.format("""
                {
                  "name": "%s",
                  "dataType": "%s"%s
                }""",
                HttpUtils.escapeJson(name),
                HttpUtils.escapeJson(dataType),
                hasStorage() ? 
                    String.format(",\n      \"storage\": \"%s\"", HttpUtils.escapeJson(storage)) : ""
            );
        }
    }
    
    private final ProgramService programService;
    private final FunctionService functionService;

    /**
     * Creates a new VariableService
     *
     * @param programService the program service for accessing the current program
     * @param functionService the function service for resolving function identifiers
     */
    public VariableService(ProgramService programService, FunctionService functionService) {
        this.programService = programService;
        this.functionService = functionService;
    }
    
    /**
     * Batch rename variables in a function. All renames happen in a single transaction
     * (all-or-nothing). The function is decompiled once, all renames are applied, then committed.
     *
     * @param functionIdentifier function name or address
     * @param renames map of old variable name to new variable name
     * @return JSON response with operation results
     */
    public String batchRenameVariables(String functionIdentifier, java.util.Map<String, String> renames) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (renames == null || renames.isEmpty()) return "No renames specified";

        var func = functionService.resolveFunction(program, functionIdentifier);
        if (func == null) return "Function not found: " + functionIdentifier;

        var decomp = new DecompInterface();
        decomp.openProgram(program);
        var result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) return "Decompilation failed";

        var highFunction = result.getHighFunction();
        if (highFunction == null) return "Decompilation failed (no high function)";

        var localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) return "Decompilation failed (no local symbol map)";

        // Pre-validate: find all symbols and check for conflicts
        java.util.Map<String, HighSymbol> symbolMap = new java.util.LinkedHashMap<>();
        var existingNames = new java.util.HashSet<String>();
        var symbolsIterator = localSymbolMap.getSymbols();
        while (symbolsIterator.hasNext()) {
            var symbol = symbolsIterator.next();
            existingNames.add(symbol.getName());
            if (renames.containsKey(symbol.getName())) {
                symbolMap.put(symbol.getName(), symbol);
            }
        }

        // Validate all renames before starting the transaction
        for (var entry : renames.entrySet()) {
            if (!symbolMap.containsKey(entry.getKey())) {
                return "Variable not found: '" + entry.getKey() + "'";
            }
            // Check that the new name doesn't conflict with an existing name
            // (unless it's one we're also renaming away from)
            if (existingNames.contains(entry.getValue()) && !renames.containsKey(entry.getValue())) {
                return "Error: A variable with name '" + entry.getValue() + "' already exists in this function";
            }
        }

        boolean commitRequired = false;
        for (HighSymbol hs : symbolMap.values()) {
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

            for (var entry : renames.entrySet()) {
                var highSymbol = symbolMap.get(entry.getKey());
                var highVariable = highSymbol.getHighVariable();
                var newHighVariable = highFunction.splitOutMergeGroup(highVariable, highVariable.getRepresentative());
                var finalHighSymbol = newHighVariable.getSymbol();

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
            return "Failed to rename variables (transaction rolled back): " + e.getMessage();
        }

        // Build response
        var renamed = renames.entrySet().stream()
            .map(e -> String.format("    \"%s\": \"%s\"",
                HttpUtils.escapeJson(e.getKey()), HttpUtils.escapeJson(e.getValue())))
            .collect(Collectors.joining(",\n"));

        return String.format("""
            {
              "status": "Variables renamed successfully",
              "function": "%s",
              "renamed": {
            %s
              },
              "count": %d
            }""",
            HttpUtils.escapeJson(func.getName()),
            renamed,
            renames.size());
    }

    /**
     * Rename or split a variable in a function
     *
     * @param functionIdentifier function name or address
     * @param oldVarName current variable name
     * @param newVarName new variable name
     * @param usageAddressStr optional address where the variable is used (for splitting)
     * @return JSON response with operation result and variable information
     */
    public String renameVariableInFunction(String functionIdentifier, String oldVarName, String newVarName, String usageAddressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        var decomp = new DecompInterface();
        decomp.openProgram(program);

        var func = functionService.resolveFunction(program, functionIdentifier);
        if (func == null) {
            return "Function not found: " + functionIdentifier;
        }
    
        var result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }
    
        var highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }
    
        var localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }
    
        HighSymbol highSymbol = null;
        var symbolsIterator = localSymbolMap.getSymbols();
        while (symbolsIterator.hasNext()) {
            var symbol = symbolsIterator.next();
            var symbolName = symbol.getName();
    
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
    
        // Find the specific Varnode to split if a usage address is provided
        Varnode specificVarnode = null;
        if (usageAddressStr != null && !usageAddressStr.isEmpty()) {
            try {
                var usageAddress = program.getAddressFactory().getAddress(usageAddressStr);
                var highVariable = highSymbol.getHighVariable();
    
                // Get all instances of this variable
                var instances = highVariable.getInstances();
                
                Msg.info(this, "Searching for variable usage at address: " + usageAddress);
                Msg.info(this, "Variable " + oldVarName + " has " + instances.length + " instances");
                
                // First attempt: Find exact match at the specified address
                specificVarnode = findExactVarnodeMatch(instances, usageAddress);
                
                // Second attempt: Find the closest usage within a small range
                if (specificVarnode == null) {
                    Msg.info(this, "No exact match found, looking for nearby usage");
                    specificVarnode = findNearbyVarnodeUsage(instances, usageAddress, 16); // Search within 16 bytes
                }
                
                // Third attempt: Find any usage if we still don't have a match
                if (specificVarnode == null) {
                    Msg.info(this, "No nearby match found, using any usage");
                    specificVarnode = findAnyVarnodeUsage(instances);
                }
    
                if (specificVarnode == null) {
                    return "Could not find any variable usage, even after trying fallback strategies";
                }
                
                Msg.info(this, "Selected varnode " + 
                    (specificVarnode.getDef() != null ? "defined at " + specificVarnode.getDef().getSeqnum().getTarget() : 
                    "with no definition"));
                
            } catch (Exception e) {
                return "Error finding variable usage: " + e.getMessage();
            }
        }
    
        boolean commitRequired = GhidraUtils.checkFullCommit(highSymbol, highFunction);

        var highVariable = highSymbol.getHighVariable();
        var finalVarnode = specificVarnode != null ? specificVarnode : highVariable.getRepresentative();

        try (var tx = ProgramTransaction.start(program, "Rename variable")) {
            if (commitRequired) {
                HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                    ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
            }

            var newHighVariable = highFunction.splitOutMergeGroup(highVariable, finalVarnode);
            var finalHighSymbol = newHighVariable.getSymbol();

            var dataType = finalHighSymbol.getDataType();
            if (Undefined.isUndefined(dataType)) {
                dataType = AbstractIntegerDataType.getUnsignedDataType(dataType.getLength(), program.getDataTypeManager());
            }

            HighFunctionDBUtil.updateDBVariable(
                finalHighSymbol,
                newVarName,
                dataType,
                SourceType.USER_DEFINED
            );
            tx.commit();
        } catch (Exception e) {
            Msg.error(this, "Failed to rename variable", e);
            return "Failed to rename variable: " + e.getMessage();
        }
        
        // Get updated variable list after renaming
        try {
            // Re-decompile to get the updated state
            var updatedResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (updatedResult == null || !updatedResult.decompileCompleted()) {
                return "Variable renamed, but failed to get updated variable list";
            }
            
            var updatedHighFunction = updatedResult.getHighFunction();
            if (updatedHighFunction == null) {
                return "Variable renamed, but failed to get updated high function";
            }
            
            var updatedSymbolMap = updatedHighFunction.getLocalSymbolMap();
            if (updatedSymbolMap == null) {
                return "Variable renamed, but failed to get updated symbol map";
            }
            
            // Convert symbols to VariableInfo records
            List<VariableInfo> variables = new ArrayList<>();
            updatedSymbolMap.getSymbols().forEachRemaining(symbol -> {
                String symbolName = symbol.getName();
                String dataTypeName = symbol.getDataType().getName();
                String storage = null;
                
                HighVariable var = symbol.getHighVariable();
                if (var != null && var.getSymbol() != null) {
                    storage = var.getSymbol().getStorage().toString();
                }
                
                variables.add(new VariableInfo(symbolName, dataTypeName, storage));
            });
            
            // Re-decompile once more to get the updated code after renaming
            var decompiled = "";
            try {
                var finalResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (finalResult != null && finalResult.decompileCompleted()) {
                    decompiled = finalResult.getDecompiledFunction().getC();
                }
            } catch (Exception e) {
                Msg.warn(this, "Failed to get decompiled code for response: " + e.getMessage());
                decompiled = "Decompilation unavailable";
            }

            // Create enhanced JSON response using text blocks
            var variablesJson = variables.stream()
                .map(VariableInfo::toJson)
                .collect(Collectors.joining(",\n    "));
            
            var splitAddressBlock = usageAddressStr != null && !usageAddressStr.isEmpty() 
                ? String.format("  \"splitAddress\": \"%s\",\n", HttpUtils.escapeJson(usageAddressStr))
                : "";
            
            var jsonResponse = String.format("""
                {
                  "status": "Variable split and renamed",
                  "originalVariable": "%s",
                  "newVariable": "%s",
                %s  "variables": [
                    %s
                  ],
                  "decompiled": "%s"
                }""",
                HttpUtils.escapeJson(oldVarName),
                HttpUtils.escapeJson(newVarName),
                splitAddressBlock,
                variablesJson,
                HttpUtils.escapeJson(decompiled));
                
            return jsonResponse;
            
        } catch (Exception e) {
            String errorMsg = "Variable renamed, but failed to collect variable info: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return "Variable renamed";
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
    public boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        Program program = programService.getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() ||
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        try {
            var addr = program.getAddressFactory().getAddress(functionAddrStr);
            var func = GhidraUtils.getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return false;
            }

            var results = GhidraUtils.decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return false;
            }

            var highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return false;
            }

            var symbol = GhidraUtils.findVariableByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return false;
            }

            var highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return false;
            }

            Msg.info(this, "Found high variable for: " + variableName +
                     " with current type " + highVar.getDataType().getName());

            var dataTypeService = new DataTypeService(programService);
            var dataType = dataTypeService.resolveDataType(program.getDataTypeManager(), newType);

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
    
    /**
     * Batch set variable types in a function. All type changes happen in a single transaction
     * (all-or-nothing). The function is decompiled once, all types are validated, then applied.
     *
     * @param functionIdentifier function name or address
     * @param typeMap map of variable name to new data type string
     * @return JSON response with operation results
     */
    public String batchSetVariableTypes(String functionIdentifier, Map<String, String> typeMap) {
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return "Function identifier is required";
        if (typeMap == null || typeMap.isEmpty()) return "No variable types specified";
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            var func = functionService.resolveFunction(program, functionIdentifier);
            if (func == null) return "Function not found: " + functionIdentifier;

            var results = GhidraUtils.decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) return "Decompilation failed";

            var highFunction = results.getHighFunction();
            if (highFunction == null) return "Decompilation failed (no high function)";

            var dataTypeService = new DataTypeService(programService);
            var dtm = program.getDataTypeManager();

            // Pre-validate: find all symbols and resolve all types
            var symbolMap = new java.util.LinkedHashMap<String, HighSymbol>();
            var resolvedTypes = new java.util.LinkedHashMap<String, DataType>();

            for (var entry : typeMap.entrySet()) {
                var symbol = GhidraUtils.findVariableByName(highFunction, entry.getKey());
                if (symbol == null) {
                    return "Variable not found: '" + entry.getKey() + "'";
                }
                symbolMap.put(entry.getKey(), symbol);

                var dataType = dataTypeService.resolveDataType(dtm, entry.getValue());
                if (dataType == null) {
                    return "Could not resolve data type: '" + entry.getValue() + "' for variable '" + entry.getKey() + "'";
                }
                resolvedTypes.put(entry.getKey(), dataType);
            }

            // Execute all type changes in a single transaction
            try (var tx = ProgramTransaction.start(program, "Batch set variable types")) {
                for (var entry : typeMap.entrySet()) {
                    var symbol = symbolMap.get(entry.getKey());
                    var dataType = resolvedTypes.get(entry.getKey());

                    HighFunctionDBUtil.updateDBVariable(
                        symbol, symbol.getName(), dataType, SourceType.USER_DEFINED);
                }
                tx.commit();
            } catch (Exception e) {
                Msg.error(this, "Failed to batch set variable types", e);
                return "Failed to set variable types (transaction rolled back): " + e.getMessage();
            }

            // Build response
            var applied = typeMap.entrySet().stream()
                .map(e -> String.format("    \"%s\": \"%s\"",
                    HttpUtils.escapeJson(e.getKey()), HttpUtils.escapeJson(e.getValue())))
                .collect(Collectors.joining(",\n"));

            return String.format("""
                {
                  "status": "Variable types set successfully",
                  "function": "%s",
                  "applied": {
                %s
                  },
                  "count": %d
                }""",
                HttpUtils.escapeJson(func.getName()),
                applied,
                typeMap.size());
        } catch (Exception e) {
            Msg.error(this, "Error in batch set variable types", e);
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find an exact match for a varnode at the specified address
     * 
     * @param instances array of variable instances to search
     * @param usageAddress target address to match
     * @return matching varnode or null if no match found
     */
    private Varnode findExactVarnodeMatch(Varnode[] instances, Address usageAddress) {
        return Arrays.stream(instances)
            .filter(instance -> {
                // Check definition
                PcodeOp defOp = instance.getDef();
                if (defOp != null && defOp.getSeqnum().getTarget().equals(usageAddress)) {
                    Msg.info(this, "Found exact match with definition at " + usageAddress);
                    return true;
                }
                
                // Check uses
                var hasMatchingUse = StreamSupport
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
     * @param rangeBytes the range in bytes to search (±)
     * @return a varnode near the target address, or null if none found
     */
    private Varnode findNearbyVarnodeUsage(Varnode[] instances, Address targetAddress, int rangeBytes) {
        var targetOffset = targetAddress.getOffset();
        
        record DistanceInfo(Varnode varnode, long distance) {}
        
        return Arrays.stream(instances)
            .map(instance -> {
                long minDistance = Long.MAX_VALUE;
                
                // Check definition
                PcodeOp defOp = instance.getDef();
                if (defOp != null) {
                    long defOffset = defOp.getSeqnum().getTarget().getOffset();
                    long distance = Math.abs(defOffset - targetOffset);
                    if (distance <= rangeBytes) {
                        minDistance = Math.min(minDistance, distance);
                    }
                }
                
                // Check all uses
                Iterator<PcodeOp> uses = instance.getDescendants();
                while (uses.hasNext()) {
                    PcodeOp useOp = uses.next();
                    long useOffset = useOp.getSeqnum().getTarget().getOffset();
                    long distance = Math.abs(useOffset - targetOffset);
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
    private Varnode findAnyVarnodeUsage(Varnode[] instances) {
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
