package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.lauriewired.mcp.model.PaginationResult;
import com.lauriewired.mcp.model.PrototypeResult;
import com.lauriewired.mcp.utils.GhidraUtils;
import com.lauriewired.mcp.utils.HttpUtils;
import com.lauriewired.mcp.utils.ProgramTransaction;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.PrettyPrinter;
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
     * List all function names with pagination and LLM-friendly hints
     *
     * @param offset starting index
     * @param limit maximum number of items to return
     * @return paginated list of function names with pagination metadata
     */
    public String getAllFunctionNames(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        
        PaginationResult result = HttpUtils.paginateListWithHints(names, offset, limit);
        return result.getFormattedResult();
    }

    /**
     * Get function code in the specified output mode.
     * Resolves the function by name or address, then returns C pseudocode, assembly, or PCode.
     *
     * @param identifier function name or address (e.g., "main", "00401000")
     * @param mode output mode: "C" (default), "assembly"/"asm", or "pcode"
     * @return the requested code representation or an error message
     */
    public String getFunctionCode(String identifier, String mode) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (identifier == null || identifier.isEmpty()) return "Function identifier is required";

        Function func = resolveFunction(program, identifier);
        if (func == null) return "Function not found: " + identifier;

        // Normalize mode
        String normalizedMode = (mode == null || mode.isEmpty()) ? "c" : mode.toLowerCase().trim();

        return switch (normalizedMode) {
            case "assembly", "asm", "disassembly" -> getAssembly(program, func);
            case "pcode" -> getPcode(program, func);
            default -> getDecompiledC(program, func); // "c", "decompile", or any unrecognized mode
        };
    }

    private String getDecompiledC(Program program, Function func) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        // Use the token tree to get per-line address mappings
        ClangTokenGroup markup = result.getCCodeMarkup();
        if (markup == null) {
            // Fallback to plain text if no markup available
            return result.getDecompiledFunction().getC();
        }

        PrettyPrinter printer = new PrettyPrinter(func, markup, null);
        List<ClangLine> lines = printer.getLines();

        // Determine address column width from the function's entry point
        String sampleAddr = func.getEntryPoint().toString();
        int addrWidth = sampleAddr.length() + 2; // +2 for spacing
        String addrFormat = "%-" + addrWidth + "s";
        String blankPad = " ".repeat(addrWidth);

        StringBuilder sb = new StringBuilder();
        for (ClangLine line : lines) {
            // Find the first address on this line from any token
            Address lineAddr = null;
            for (ClangToken token : line.getAllTokens()) {
                lineAddr = token.getMinAddress();
                if (lineAddr != null) break;
            }

            // Prefix: address or blank padding
            if (lineAddr != null) {
                sb.append(String.format(addrFormat, lineAddr.toString()));
            } else {
                sb.append(blankPad);
            }

            sb.append(PrettyPrinter.getText(line));
            sb.append('\n');
        }
        return sb.toString();
    }

    private String getAssembly(Program program, Function func) {
        StringBuilder result = new StringBuilder();
        Listing listing = program.getListing();
        Address start = func.getEntryPoint();
        Address end = func.getBody().getMaxAddress();

        InstructionIterator instructions = listing.getInstructions(start, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getAddress().compareTo(end) > 0) break;

            String comment = listing.getComment(
                ghidra.program.model.listing.CodeUnit.EOL_COMMENT, instr.getAddress());
            comment = (comment != null) ? "; " + comment : "";

            result.append(String.format("%s: %s %s\n",
                instr.getAddress(), instr.toString(), comment));
        }
        return result.toString();
    }

    private String getPcode(Program program, Function func) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        var highFunction = result.getHighFunction();
        if (highFunction == null) return "No high function available";

        StringBuilder sb = new StringBuilder();
        sb.append("PCode for ").append(func.getName()).append(":\n");
        var iter = highFunction.getPcodeOps();
        while (iter.hasNext()) {
            sb.append(iter.next().toString()).append("\n");
        }
        return sb.toString();
    }

    /**
     * Rename a function identified by name or address.
     * Tries to resolve as an address first, then falls back to name lookup.
     *
     * @param identifier function name or address (e.g., "main", "00401000", "ram:00401000")
     * @param newName new function name
     * @return descriptive result message
     */
    public String renameFunction(String identifier, String newName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (identifier == null || identifier.isEmpty()) return "Function identifier is required";
        if (newName == null || newName.isEmpty()) return "New name is required";

        Function func = resolveFunction(program, identifier);
        if (func == null) {
            return "Function not found: " + identifier;
        }

        try (var tx = ProgramTransaction.start(program, "Rename function")) {
            String oldName = func.getName();
            func.setName(newName, SourceType.USER_DEFINED);
            tx.commit();
            return "Renamed '" + oldName + "' to '" + newName + "' at " + func.getEntryPoint();
        } catch (InvalidInputException | DuplicateNameException | RuntimeException e) {
            Msg.error(this, "Error renaming function", e);
            return "Failed to rename function: " + e.getMessage();
        }
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
     * Resolve a function by identifier — tries address first, then name lookup.
     *
     * @param program the current program
     * @param identifier a function name or address string
     * @return the resolved Function, or null if not found
     */
    public Function resolveFunction(Program program, String identifier) {
        if (program == null || identifier == null || identifier.isEmpty()) {
            return null;
        }

        // Try as address first
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                Function func = GhidraUtils.getFunctionForAddress(program, addr);
                if (func != null) {
                    return func;
                }
            }
        } catch (Exception e) {
            // Not a valid address, fall through to name lookup
        }

        // Fall back to name lookup
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(identifier)) {
                return func;
            }
        }
        return null;
    }

    /**
     * Search for functions by name with pagination and LLM-friendly hints
     *
     * @param searchTerm search term
     * @param offset starting index
     * @param limit maximum number of results
     * @return paginated list of matching functions with pagination metadata
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
        
        PaginationResult result = HttpUtils.paginateListWithHints(matches, offset, limit);
        return result.getFormattedResult();
    }

    /**
     * Set a function's prototype with proper error handling
     *
     * @param functionIdentifier function name or address
     * @param prototype function prototype in C style
     * @return result of the operation
     */
    public PrototypeResult setFunctionPrototype(String functionIdentifier, String prototype) {
        // Input validation
        Program program = programService.getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return new PrototypeResult(false, "Function identifier is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        try {
            Function func = resolveFunction(program, functionIdentifier);
            if (func == null) {
                String msg = "Function not found: " + functionIdentifier;
                Msg.error(this, msg);
                return new PrototypeResult(false, msg);
            }

            Address addr = func.getEntryPoint();
            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);
            return parseFunctionSignatureAndApply(program, addr, prototype);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            Msg.error(this, msg, e);
            return new PrototypeResult(false, msg);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    @SuppressWarnings("UseSpecificCatch")
    private PrototypeResult parseFunctionSignatureAndApply(Program program, Address addr, String prototype) {
        try (var tx = ProgramTransaction.start(program, "Set function prototype")) {
            ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();

            ghidra.app.services.DataTypeManagerService dtms =
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                Msg.error(this, msg);
                return new PrototypeResult(false, msg);
            }

            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                tx.commit();
                Msg.info(this, "Successfully applied function signature");
                return new PrototypeResult(true, "");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                Msg.error(this, msg);
                return new PrototypeResult(false, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            Msg.error(this, msg, e);
            return new PrototypeResult(false, msg);
        }
    }
}
