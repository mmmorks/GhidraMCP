package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
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

    @McpTool(description = """
        List function names in the loaded Ghidra program with pagination.

        Functions are defined subroutines in the binary (both user-defined and auto-discovered).

        Returns: List of function names with pagination info. If more results are available,
                 the response includes clear indicators and instructions for fetching additional pages.

        Example: list_functions(0, 10) -> ['main', 'printf', 'malloc', ..., '--- PAGINATION INFO ---', ...] """)
    public String listFunctions(
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") int offset,
            @Param(value = "Maximum function names to return", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        
        PaginationResult result = HttpUtils.paginateListWithHints(names, offset, limit);
        return result.getFormattedResult();
    }

    @McpTool(description = """
        Get a function's code in the specified representation.

        Resolves the function by name or address, then returns the requested output.

        Returns: Function code in the requested format, or error message

        Examples:
            get_function_code("main") -> C pseudocode for main
            get_function_code("00401000", "assembly") -> assembly listing
            get_function_code("FUN_00401000", "pcode") -> PCode output """)
    public String getFunctionCode(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") String functionIdentifier,
            @Param(value = "Output format - \"C\" for decompiled pseudocode (default), \"assembly\"/\"asm\" for disassembly listing, or \"pcode\" for Ghidra's intermediate representation", defaultValue = "C") String mode) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return "Function identifier is required";

        Function func = resolveFunction(program, functionIdentifier);
        if (func == null) return "Function not found: " + functionIdentifier;

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

    @McpTool(post = true, description = """
        Rename a function identified by name or address.

        Resolves the target function flexibly: pass a current function name
        (e.g., "FUN_00401000") or an address (e.g., "00401000", "ram:00401000").

        Returns: Success or failure message

        Note: Function names must be unique within the program.

        Examples:
            rename_function("FUN_00401000", "initialize_system")
            rename_function("00401000", "initialize_system")
            rename_function("main", "entry_point") """)
    public String renameFunction(
            @Param("Current function name or address") String functionIdentifier,
            @Param("New function name to assign") String newName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return "Function identifier is required";
        if (newName == null || newName.isEmpty()) return "New name is required";

        Function func = resolveFunction(program, functionIdentifier);
        if (func == null) {
            return "Function not found: " + functionIdentifier;
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

    @McpTool(description = """
        Get detailed information about a function at the specified address.

        Retrieves name, signature, entry point and body range for the function.

        Returns: Detailed function information or error message

        Example: get_function_by_address("00401000") -> "Function: main at 00401000..." """)
    public String getFunctionByAddress(
            @Param("Address to look up (e.g., \"00401000\" or \"ram:00401000\")") String address) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (address == null || address.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(address);
            Function func = GhidraUtils.getFunctionForAddress(program, addr);

            if (func == null) return "No function found at address " + address;
            
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

    @McpTool(description = """
        Get the address currently selected by the user in the Ghidra GUI.

        Retrieves cursor location in Code Browser or Decompiler view.

        Returns: Currently selected address or error message

        Note: Requires Ghidra GUI running with a selected location.

        Example: get_current_address() -> "00401234" """)
    public String getCurrentAddress() {
        if (tool == null) return "No tool available";
        
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";
        
        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    @McpTool(description = """
        Get information about the function currently selected in the Ghidra GUI.

        Returns details about function containing the selected address.

        Returns: Current function information (name, entry point, signature) or error

        Note: Requires Ghidra GUI with location selected within a function.

        Example: get_current_function() -> "Function: main at 00401000..." """)
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

    @McpTool(description = """
        Search for functions by partial name match (case-insensitive).

        Helps explore large binaries or find related functionality.

        Returns: Matching functions formatted as "function_name @ address"

        Example: search_functions_by_name("init") -> ['initialize @ 00401000', ...] """)
    public String searchFunctionsByName(
            @Param("Substring to search for in function names") String query,
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") int offset,
            @Param(value = "Maximum matches to return", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (query == null || query.isEmpty()) return "Search term is required";

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(query.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
        
        PaginationResult result = HttpUtils.paginateListWithHints(matches, offset, limit);
        return result.getFormattedResult();
    }

    @McpTool(post = true, description = """
        Set or modify a function's signature/prototype.

        Changes return type, parameter types and names to improve decompiler output.

        Returns: Success or failure message with details

        Note: Function name in prototype is ignored; only types matter. Parameter names are applied.

        Example: set_function_prototype("00401000", "int process_data(char *buffer, size_t length)") """)
    public String setFunctionPrototype(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") String functionIdentifier,
            @Param("C-style function signature (e.g., \"int main(int argc, char **argv)\")") String prototype) {
        // Input validation
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return "Function identifier is required";
        }
        if (prototype == null || prototype.isEmpty()) {
            return "Function prototype is required";
        }

        try {
            Function func = resolveFunction(program, functionIdentifier);
            if (func == null) {
                String msg = "Function not found: " + functionIdentifier;
                Msg.error(this, msg);
                return "Failed to set function prototype: " + msg;
            }

            Address addr = func.getEntryPoint();
            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);
            PrototypeResult result = parseFunctionSignatureAndApply(program, addr, prototype);
            if (result.isSuccess()) {
                String response = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    response += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                return response;
            } else {
                return "Failed to set function prototype: " + result.getErrorMessage();
            }

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            Msg.error(this, msg, e);
            return "Failed to set function prototype: " + msg;
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
