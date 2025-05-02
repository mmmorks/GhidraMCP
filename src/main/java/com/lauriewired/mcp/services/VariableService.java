package com.lauriewired.mcp.services;

import com.lauriewired.mcp.utils.GhidraUtils;
import com.lauriewired.mcp.utils.HttpUtils;
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

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service for variable-related operations
 */
public class VariableService {
    private final ProgramService programService;
    
    /**
     * Creates a new VariableService
     *
     * @param programService the program service for accessing the current program
     */
    public VariableService(ProgramService programService) {
        this.programService = programService;
    }
    
    /**
     * Rename or split a variable in a function
     *
     * @param functionName name of the function containing the variable
     * @param oldVarName current variable name
     * @param newVarName new variable name
     * @param usageAddressStr optional address where the variable is used (for splitting)
     * @return JSON response with operation result and variable information
     */
    public String renameVariableInFunction(String functionName, String oldVarName, String newVarName, String usageAddressStr) {
        Program program = programService.getCurrentProgram();
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
    
        // Find the specific Varnode to split if a usage address is provided
        Varnode specificVarnode = null;
        if (usageAddressStr != null && !usageAddressStr.isEmpty()) {
            try {
                Address usageAddress = program.getAddressFactory().getAddress(usageAddressStr);
                HighVariable highVariable = highSymbol.getHighVariable();
    
                // Get all instances of this variable
                Varnode[] instances = highVariable.getInstances();
                
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
    
        final Function finalFunction = func;
        final HighVariable highVariable = highSymbol.getHighVariable();
        final Varnode finalVarnode = specificVarnode != null ? specificVarnode : highVariable.getRepresentative();
    
        AtomicBoolean successFlag = new AtomicBoolean(false);
    
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
    
                    // Use the specific Varnode if provided, otherwise use the representative
                    final HighVariable newHighVariable = highFunction.splitOutMergeGroup(highVariable, finalVarnode);
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
            
            // Re-decompile once more to get the updated code after renaming
            String decompiled = "";
            try {
                DecompileResults finalResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (finalResult != null && finalResult.decompileCompleted()) {
                    decompiled = finalResult.getDecompiledFunction().getC();
                }
            } catch (Exception e) {
                Msg.warn(this, "Failed to get decompiled code for response: " + e.getMessage());
                decompiled = "Decompilation unavailable";
            }

            // Create enhanced JSON response
            StringBuilder jsonResponse = new StringBuilder();
            jsonResponse.append("{\n");
            jsonResponse.append("  \"status\": \"Variable split and renamed\",\n");
            jsonResponse.append("  \"originalVariable\": \"").append(HttpUtils.escapeJson(oldVarName)).append("\",\n");
            jsonResponse.append("  \"newVariable\": \"").append(HttpUtils.escapeJson(newVarName)).append("\",\n");
            
            // Include split address if provided
            if (usageAddressStr != null && !usageAddressStr.isEmpty()) {
                jsonResponse.append("  \"splitAddress\": \"").append(HttpUtils.escapeJson(usageAddressStr)).append("\",\n");
            }
            
            jsonResponse.append("  \"variables\": [\n");
            
            for (int i = 0; i < variableList.size(); i++) {
                Map<String, String> varInfo = variableList.get(i);
                jsonResponse.append("    {\n");
                jsonResponse.append("      \"name\": \"").append(HttpUtils.escapeJson(varInfo.get("name"))).append("\",\n");
                jsonResponse.append("      \"dataType\": \"").append(HttpUtils.escapeJson(varInfo.get("dataType"))).append("\"");
                if (varInfo.containsKey("storage")) {
                    jsonResponse.append(",\n      \"storage\": \"").append(HttpUtils.escapeJson(varInfo.get("storage"))).append("\"");
                }
                jsonResponse.append("\n    }");
                if (i < variableList.size() - 1) {
                    jsonResponse.append(",");
                }
                jsonResponse.append("\n");
            }
            
            jsonResponse.append("  ],\n");
            jsonResponse.append("  \"decompiled\": \"").append(HttpUtils.escapeJson(decompiled)).append("\"\n");
            jsonResponse.append("}");
            
            return jsonResponse.toString();
            
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
        
        AtomicBoolean success = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Find the function
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    Function func = GhidraUtils.getFunctionForAddress(program, addr);
                    
                    if (func == null) {
                        Msg.error(this, "Could not find function at address: " + functionAddrStr);
                        return;
                    }
                    
                    DecompileResults results = GhidraUtils.decompileFunction(func, program);
                    if (results == null || !results.decompileCompleted()) {
                        return;
                    }
                    
                    HighFunction highFunction = results.getHighFunction();
                    if (highFunction == null) {
                        Msg.error(this, "No high function available");
                        return;
                    }
                    
                    // Find the symbol by name
                    HighSymbol symbol = GhidraUtils.findVariableByName(highFunction, variableName);
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
                    DataTypeService dataTypeService = new DataTypeService(programService);
                    DataType dataType = dataTypeService.resolveDataType(program.getDataTypeManager(), newType);
                    
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
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }
        
        return success.get();
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
     * Find an exact match for a varnode at the specified address
     * 
     * @param instances array of variable instances to search
     * @param usageAddress target address to match
     * @return matching varnode or null if no match found
     */
    private Varnode findExactVarnodeMatch(Varnode[] instances, Address usageAddress) {
        for (Varnode instance : instances) {
            // Check if this instance is defined at the specified address
            PcodeOp defOp = instance.getDef();
            if (defOp != null && defOp.getSeqnum().getTarget().equals(usageAddress)) {
                Msg.info(this, "Found exact match with definition at " + usageAddress);
                return instance;
            }

            // Check if this instance is used at the specified address
            Iterator<PcodeOp> uses = instance.getDescendants();
            while (uses.hasNext()) {
                PcodeOp useOp = uses.next();
                if (useOp.getSeqnum().getTarget().equals(usageAddress)) {
                    Msg.info(this, "Found exact match with usage at " + usageAddress);
                    return instance;
                }
            }
        }
        return null;
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
        long targetOffset = targetAddress.getOffset();
        Varnode closestVarnode = null;
        long closestDistance = Long.MAX_VALUE;
        
        for (Varnode instance : instances) {
            // Check distance of definition
            PcodeOp defOp = instance.getDef();
            if (defOp != null) {
                long defOffset = defOp.getSeqnum().getTarget().getOffset();
                long distance = Math.abs(defOffset - targetOffset);
                
                if (distance <= rangeBytes && distance < closestDistance) {
                    closestVarnode = instance;
                    closestDistance = distance;
                    Msg.info(this, "Found nearby definition at " + defOp.getSeqnum().getTarget() + 
                             " (distance: " + distance + " bytes)");
                }
            }
            
            // Check distance of uses
            Iterator<PcodeOp> uses = instance.getDescendants();
            while (uses.hasNext()) {
                PcodeOp useOp = uses.next();
                long useOffset = useOp.getSeqnum().getTarget().getOffset();
                long distance = Math.abs(useOffset - targetOffset);
                
                if (distance <= rangeBytes && distance < closestDistance) {
                    closestVarnode = instance;
                    closestDistance = distance;
                    Msg.info(this, "Found nearby usage at " + useOp.getSeqnum().getTarget() + 
                             " (distance: " + distance + " bytes)");
                }
            }
        }
        
        return closestVarnode;
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
        
        // First try to find a varnode with a definition
        for (Varnode instance : instances) {
            if (instance.getDef() != null) {
                Msg.info(this, "Found varnode with definition at " + instance.getDef().getSeqnum().getTarget());
                return instance;
            }
        }
        
        // Then try to find a varnode with any uses
        for (Varnode instance : instances) {
            Iterator<PcodeOp> uses = instance.getDescendants();
            if (uses.hasNext()) {
                Msg.info(this, "Found varnode with uses");
                return instance;
            }
        }
        
        // If all else fails, just return the first varnode
        Msg.info(this, "Using first available varnode instance as fallback");
        return instances[0];
    }
}
