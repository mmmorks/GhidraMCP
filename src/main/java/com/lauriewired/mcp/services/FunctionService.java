package com.lauriewired.mcp.services;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.SwingUtilities;

import com.lauriewired.mcp.model.PrototypeResult;
import com.lauriewired.mcp.utils.GhidraUtils;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * Service class for function-related operations
 */
public class FunctionService {
    private final PluginTool tool;
    private final ProgramService programService;

    /**
     * Creates a new FunctionService
     *
     * @param tool the plugin tool
     * @param programService the program service for accessing the current program
     */
    public FunctionService(PluginTool tool, ProgramService programService) {
        this.tool = tool;
        this.programService = programService;
    }

    /**
     * List all function names with pagination
     *
     * @param offset starting index
     * @param limit maximum number of items to return
     * @return list of function names
     */
    public String getAllFunctionNames(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        
        if (names.isEmpty()) return "";
        
        return String.join("\n", names.subList(
                Math.min(offset, names.size()),
                Math.min(offset + limit, names.size())
        ));
    }

    /**
     * Decompile a function by name
     *
     * @param name function name
     * @return decompiled code or error message
     */
    public String decompileFunctionByName(String name) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    /**
     * Rename a function
     *
     * @param oldName current function name
     * @param newName new function name
     * @return true if successful
     */
    public boolean renameFunction(String oldName, String newName) {
        Program program = programService.getCurrentProgram();
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
                } catch (InvalidInputException | DuplicateNameException | RuntimeException e) {
                    Msg.error(this, "Error renaming function", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    /**
     * Get function details by its address
     *
     * @param addressStr address of the function
     * @return function details or error message
     */
    public String getFunctionByAddress(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = GhidraUtils.getFunctionForAddress(program, addr);
            
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
     * Get the address of the currently selected location in Ghidra GUI
     *
     * @return address or error message
     */
    public String getCurrentAddress() {
        if (tool == null) return "No tool available";
        
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";
        
        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get details of the function at the current cursor position
     *
     * @return function details or error message
     */
    public String getCurrentFunction() {
        if (tool == null) return "No tool available";
        
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";
        
        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";
        
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        
        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();
        
        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions with their addresses
     *
     * @return list of functions
     */
    public String listFunctions() {
        Program program = programService.getCurrentProgram();
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
     * Decompile a function by its address
     *
     * @param addressStr address of the function
     * @return decompiled code or error message
     */
    public String decompileFunctionByAddress(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = GhidraUtils.getFunctionForAddress(program, addr);
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
     *
     * @param addressStr address of the function
     * @return disassembled code or error message
     */
    public String disassembleFunction(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = GhidraUtils.getFunctionForAddress(program, addr);
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
                String comment = listing.getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, instr.getAddress());
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
     * Rename a function by address
     * 
     * @param functionAddrStr function address 
     * @param newName new function name
     * @return true if successful
     */
    public boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }
        
        AtomicBoolean success = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function by address");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    Function func = GhidraUtils.getFunctionForAddress(program, addr);
                    
                    if (func == null) {
                        Msg.error(this, "Could not find function at address: " + functionAddrStr);
                        return;
                    }
                    
                    func.setName(newName, SourceType.USER_DEFINED);
                    success.set(true);
                } catch (InvalidInputException | DuplicateNameException | RuntimeException e) {
                    Msg.error(this, "Error renaming function by address", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }
        
        return success.get();
    }

    /**
     * Search for functions by name
     * 
     * @param searchTerm search term
     * @param offset starting index
     * @param limit maximum number of results
     * @return list of matching functions
     */
    public String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = programService.getCurrentProgram();
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
        
        List<String> subList = matches.subList(
            Math.min(offset, matches.size()),
            Math.min(offset + limit, matches.size())
        );
        
        return String.join("\n", subList);
    }

    /**
     * Set a function's prototype with proper error handling
     * 
     * @param functionAddrStr function address
     * @param prototype function prototype in C style
     * @return result of the operation
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = programService.getCurrentProgram();
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
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Get the address and function
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    Function func = GhidraUtils.getFunctionForAddress(program, addr);
                    
                    if (func == null) {
                        String msg = "Could not find function at address: " + functionAddrStr;
                        errorMessage.append(msg);
                        Msg.error(this, msg);
                        return;
                    }
                    
                    Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);
                    
                    // Store original prototype as a comment for reference
                    addPrototypeComment(program, func, prototype);
                    
                    // Apply the type change
                    parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);
                    
                } catch (Exception e) {
                    String msg = "Error setting function prototype: " + e.getMessage();
                    errorMessage.append(msg);
                    Msg.error(this, msg, e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
        
        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }
    
    /**
     * Parse and apply the function signature with error handling
     */
    @SuppressWarnings("UseSpecificCatch")
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();
            
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
}
