package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.TextOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.CurrentAddressResult;
import com.lauriewired.mcp.model.response.CurrentFunctionResult;
import com.lauriewired.mcp.model.response.FunctionByAddressResult;
import com.lauriewired.mcp.model.response.FunctionItem;
import com.lauriewired.mcp.model.response.FunctionSearchItem;
import com.lauriewired.mcp.utils.GhidraUtils;
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
import ghidra.program.model.listing.CommentType;
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
    public FunctionService(final PluginTool tool, final ProgramService programService) {
        this.tool = tool;
        this.programService = programService;
    }

    @McpTool(description = """
        List function names in the loaded Ghidra program with pagination.

        Functions are defined subroutines in the binary (both user-defined and auto-discovered).

        Returns: List of function names with pagination info. If more results are available,
                 the response includes clear indicators and instructions for fetching additional pages.

        Example: list_functions(0, 10) -> ['main', 'printf', 'malloc', ..., '--- PAGINATION INFO ---', ...] """,
        outputType = ListOutput.class, responseType = FunctionItem.class)
    public ToolOutput listFunctions(
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") final int offset,
            @Param(value = "Maximum function names to return", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        final List<FunctionItem> items = new ArrayList<>();
        for (final Function f : program.getFunctionManager().getFunctions(true)) {
            items.add(new FunctionItem(f.getName()));
        }

        return ListOutput.paginate(items, offset, limit);
    }

    @McpTool(responseType = TextOutput.class, description = """
        Get a function's code in the specified representation.

        Resolves the function by name or address, then returns the requested output.

        Returns: Function code in the requested format, or error message

        Examples:
            get_function_code("main") -> C pseudocode for main
            get_function_code("00401000", "assembly") -> assembly listing
            get_function_code("FUN_00401000", "pcode") -> PCode output """)
    public ToolOutput getFunctionCode(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") final String functionIdentifier,
            @Param(value = "Output format - \"C\" for decompiled pseudocode (default), \"assembly\"/\"asm\" for disassembly listing, or \"pcode\" for Ghidra's intermediate representation", defaultValue = "C") final String mode) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return StatusOutput.error("Function identifier is required");

        final Function func = resolveFunction(program, functionIdentifier);
        if (func == null) return StatusOutput.error("Function not found: " + functionIdentifier);

        // Normalize mode
        final String normalizedMode = (mode == null || mode.isEmpty()) ? "c" : mode.toLowerCase().trim();

        return new TextOutput(switch (normalizedMode) {
            case "assembly", "asm", "disassembly" -> getAssembly(program, func);
            case "pcode" -> getPcode(program, func);
            default -> getDecompiledC(program, func); // "c", "decompile", or any unrecognized mode
        });
    }

    private String getDecompiledC(final Program program, final Function func) {
        final DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        final DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        // Use the token tree to get per-line address mappings
        final ClangTokenGroup markup = result.getCCodeMarkup();
        if (markup == null) {
            // Fallback to plain text if no markup available
            return result.getDecompiledFunction().getC();
        }

        final PrettyPrinter printer = new PrettyPrinter(func, markup, null);
        final List<ClangLine> lines = printer.getLines();

        // Determine address column width from the function's entry point
        final String sampleAddr = func.getEntryPoint().toString();
        final int addrWidth = sampleAddr.length() + 2; // +2 for spacing
        final String addrFormat = "%-" + addrWidth + "s";
        final String blankPad = " ".repeat(addrWidth);

        final StringBuilder sb = new StringBuilder();
        for (final ClangLine line : lines) {
            // Find the first address on this line from any token
            Address lineAddr = null;
            for (final ClangToken token : line.getAllTokens()) {
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

    private String getAssembly(final Program program, final Function func) {
        final StringBuilder result = new StringBuilder();
        final Listing listing = program.getListing();
        final Address start = func.getEntryPoint();
        final Address end = func.getBody().getMaxAddress();

        final InstructionIterator instructions = listing.getInstructions(start, true);
        while (instructions.hasNext()) {
            final Instruction instr = instructions.next();
            if (instr.getAddress().compareTo(end) > 0) break;

            String comment = listing.getComment(
                CommentType.EOL, instr.getAddress());
            comment = (comment != null) ? "; " + comment : "";

            result.append(String.format("%s: %s %s\n",
                instr.getAddress(), instr.toString(), comment));
        }
        return result.toString();
    }

    private String getPcode(final Program program, final Function func) {
        final DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        final DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        final var highFunction = result.getHighFunction();
        if (highFunction == null) return "No high function available";

        final StringBuilder sb = new StringBuilder();
        sb.append("PCode for ").append(func.getName()).append(":\n");
        final var iter = highFunction.getPcodeOps();
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
            rename_function("main", "entry_point") """,
        outputType = StatusOutput.class, responseType = StatusOutput.class)
    public ToolOutput renameFunction(
            @Param("Current function name or address") final String functionIdentifier,
            @Param("New function name to assign") final String newName) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty()) return StatusOutput.error("Function identifier is required");
        if (newName == null || newName.isEmpty()) return StatusOutput.error("New name is required");

        final Function func = resolveFunction(program, functionIdentifier);
        if (func == null) {
            return StatusOutput.error("Function not found: " + functionIdentifier);
        }

        try (var tx = ProgramTransaction.start(program, "Rename function")) {
            final String oldName = func.getName();
            func.setName(newName, SourceType.USER_DEFINED);
            tx.commit();
            return StatusOutput.ok("Renamed '" + oldName + "' to '" + newName + "' at " + func.getEntryPoint());
        } catch (InvalidInputException | DuplicateNameException | RuntimeException e) {
            Msg.error(this, "Error renaming function", e);
            return StatusOutput.error("Failed to rename function: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, responseType = FunctionByAddressResult.class, description = """
        Get detailed information about a function at the specified address.

        Retrieves name, signature, entry point and body range for the function.

        Returns: Detailed function information or error message

        Example: get_function_by_address("00401000") -> "Function: main at 00401000..." """)
    public ToolOutput getFunctionByAddress(
            @Param("Address to look up (e.g., \"00401000\" or \"ram:00401000\")") final String address) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null || address.isEmpty()) return StatusOutput.error("Address is required");

        try {
            final Address addr = program.getAddressFactory().getAddress(address);
            final Function func = GhidraUtils.getFunctionForAddress(program, addr);

            if (func == null) return StatusOutput.error("No function found at address " + address);

            return new JsonOutput(new FunctionByAddressResult(
                    func.getName(),
                    func.getSignature().toString(),
                    func.getEntryPoint().toString(),
                    func.getBody().getMinAddress().toString(),
                    func.getBody().getMaxAddress().toString()));
        } catch (Exception e) {
            return StatusOutput.error("Error getting function: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, responseType = CurrentAddressResult.class, description = """
        Get the address currently selected by the user in the Ghidra GUI.

        Retrieves cursor location in Code Browser or Decompiler view.

        Returns: Currently selected address or error message

        Note: Requires Ghidra GUI running with a selected location.

        Example: get_current_address() -> "00401234" """)
    public ToolOutput getCurrentAddress() {
        if (tool == null) return StatusOutput.error("No tool available");

        final CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return StatusOutput.error("Code viewer service not available");

        final ProgramLocation location = service.getCurrentLocation();
        if (location == null) return StatusOutput.error("No current location");
        return new JsonOutput(new CurrentAddressResult(location.getAddress().toString()));
    }

    @McpTool(outputType = JsonOutput.class, responseType = CurrentFunctionResult.class, description = """
        Get information about the function currently selected in the Ghidra GUI.

        Returns details about function containing the selected address.

        Returns: Current function information (name, entry point, signature) or error

        Note: Requires Ghidra GUI with location selected within a function.

        Example: get_current_function() -> "Function: main at 00401000..." """)
    public ToolOutput getCurrentFunction() {
        if (tool == null) return StatusOutput.error("No tool available");

        final CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return StatusOutput.error("Code viewer service not available");

        final ProgramLocation location = service.getCurrentLocation();
        if (location == null) return StatusOutput.error("No current location");

        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        final Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return StatusOutput.error("No function at current location: " + location.getAddress());

        return new JsonOutput(new CurrentFunctionResult(
                func.getName(),
                func.getEntryPoint().toString(),
                func.getSignature().toString()));
    }


    /**
     * Resolve a function by identifier — tries address first, then name lookup.
     *
     * @param program the current program
     * @param identifier a function name or address string
     * @return the resolved Function, or null if not found
     */
    public Function resolveFunction(final Program program, final String identifier) {
        if (program == null || identifier == null || identifier.isEmpty()) {
            return null;
        }

        // Try as address first
        try {
            final Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                final Function func = GhidraUtils.getFunctionForAddress(program, addr);
                if (func != null) {
                    return func;
                }
            }
        } catch (Exception ignored) {
            // Not a valid address, fall through to name lookup
        }

        // Fall back to name lookup
        for (final Function func : program.getFunctionManager().getFunctions(true)) {
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

        Example: search_functions_by_name("init") -> ['initialize @ 00401000', ...] """,
        outputType = ListOutput.class, responseType = FunctionSearchItem.class)
    public ToolOutput searchFunctionsByName(
            @Param("Substring to search for in function names") final String query,
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") final int offset,
            @Param(value = "Maximum matches to return", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (query == null || query.isEmpty()) return StatusOutput.error("Search term is required");

        final List<FunctionSearchItem> matches = new ArrayList<>();
        for (final Function func : program.getFunctionManager().getFunctions(true)) {
            final String name = func.getName();
            if (name.toLowerCase().contains(query.toLowerCase())) {
                matches.add(new FunctionSearchItem(name, func.getEntryPoint().toString()));
            }
        }

        Collections.sort(matches, (a, b) -> a.name().compareTo(b.name()));

        return ListOutput.paginate(matches, offset, limit);
    }

    @McpTool(post = true, description = """
        Set or modify a function's signature/prototype.

        Changes return type, parameter types and names to improve decompiler output.

        Returns: Success or failure message with details

        Note: Function name in prototype is ignored; only types matter. Parameter names are applied.

        Example: set_function_prototype("00401000", "int process_data(char *buffer, size_t length)") """,
        outputType = StatusOutput.class, responseType = StatusOutput.class)
    public ToolOutput setFunctionPrototype(
            @Param("Function name (e.g., \"main\") or address (e.g., \"00401000\", \"ram:00401000\")") final String functionIdentifier,
            @Param("C-style function signature (e.g., \"int main(int argc, char **argv)\")") final String prototype) {
        // Input validation
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return StatusOutput.error("Function identifier is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return StatusOutput.error("Function prototype is required");
        }

        try {
            final Function func = resolveFunction(program, functionIdentifier);
            if (func == null) {
                final String msg = "Function not found: " + functionIdentifier;
                Msg.error(this, msg);
                return StatusOutput.error("Failed to set function prototype: " + msg);
            }

            final Address addr = func.getEntryPoint();
            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);
            return parseFunctionSignatureAndApply(program, addr, prototype);

        } catch (Exception e) {
            final String msg = "Error setting function prototype: " + e.getMessage();
            Msg.error(this, msg, e);
            return StatusOutput.error("Failed to set function prototype: " + msg);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    @SuppressWarnings("UseSpecificCatch")
    private StatusOutput parseFunctionSignatureAndApply(final Program program, final Address addr, final String prototype) {
        try (var tx = ProgramTransaction.start(program, "Set function prototype")) {
            final ghidra.program.model.data.DataTypeManager dtm = program.getDataTypeManager();

            final ghidra.app.services.DataTypeManagerService dtms =
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            final ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            final ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                final String msg = "Failed to parse function prototype";
                Msg.error(this, msg);
                return StatusOutput.error("Failed to set function prototype: " + msg);
            }

            final ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            final boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                tx.commit();
                Msg.info(this, "Successfully applied function signature");
                return StatusOutput.ok("Function prototype set successfully");
            } else {
                final String msg = "Command failed: " + cmd.getStatusMsg();
                Msg.error(this, msg);
                return StatusOutput.error("Failed to set function prototype: " + msg);
            }
        } catch (Exception e) {
            final String msg = "Error applying function signature: " + e.getMessage();
            Msg.error(this, msg, e);
            return StatusOutput.error("Failed to set function prototype: " + msg);
        }
    }
}
