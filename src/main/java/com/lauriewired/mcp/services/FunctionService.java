package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.CurrentAddressResult;
import com.lauriewired.mcp.model.response.CurrentFunctionResult;
import com.lauriewired.mcp.model.response.FunctionByAddressResult;
import com.lauriewired.mcp.model.response.FunctionCodeResult;
import com.lauriewired.mcp.model.response.FunctionItem;
import com.lauriewired.mcp.model.response.FunctionSearchItem;
import com.lauriewired.mcp.model.response.RenameFunctionsResult;
import com.lauriewired.mcp.utils.GhidraUtils;
import com.lauriewired.mcp.utils.ProgramTransaction;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
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
            items.add(new FunctionItem(f.getName(), f.getEntryPoint().toString()));
        }

        return ListOutput.paginate(items, offset, limit);
    }

    @McpTool(outputType = JsonOutput.class, responseType = FunctionCodeResult.class, description = """
        Get a function's code in the specified representation.

        Resolves the function by name or address, then returns the requested output.

        Returns: Array of single-entry {address: code} objects. Empty string key "" means no mapped address. Assembly comments are inlined as "code ; comment".

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

        final String effectiveFormat;
        final List<Map<String, String>> lines;
        switch (normalizedMode) {
            case "assembly", "asm", "disassembly" -> {
                effectiveFormat = "assembly";
                lines = getAssemblyLines(program, func);
            }
            case "pcode" -> {
                effectiveFormat = "pcode";
                lines = getPcodeLines(program, func);
            }
            default -> {
                effectiveFormat = "C";
                lines = getDecompiledCLines(program, func);
            }
        }

        return new JsonOutput(new FunctionCodeResult(func.getName(), func.getSignature().getPrototypeString(), effectiveFormat, lines));
    }

    private List<Map<String, String>> getDecompiledCLines(final Program program, final Function func) {
        final DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        final DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        final List<Map<String, String>> lines = GhidraUtils.extractDecompiledLines(result, func);
        return !lines.isEmpty() ? lines : List.of(FunctionCodeResult.line(null, "Decompilation failed"));
    }

    private List<Map<String, String>> getAssemblyLines(final Program program, final Function func) {
        final List<Map<String, String>> lines = new ArrayList<>();
        final Listing listing = program.getListing();
        final Address start = func.getEntryPoint();
        final Address end = func.getBody().getMaxAddress();

        final InstructionIterator instructions = listing.getInstructions(start, true);
        while (instructions.hasNext()) {
            final Instruction instr = instructions.next();
            if (instr.getAddress().compareTo(end) > 0) break;

            final String comment = listing.getComment(CommentType.EOL, instr.getAddress());
            final String code = comment != null ? instr.toString() + " ; " + comment : instr.toString();
            lines.add(FunctionCodeResult.line(instr.getAddress().toString(), code));
        }
        return lines;
    }

    private List<Map<String, String>> getPcodeLines(final Program program, final Function func) {
        final DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        final DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return List.of(FunctionCodeResult.line(null, "Decompilation failed"));
        }

        final var highFunction = result.getHighFunction();
        if (highFunction == null) {
            return List.of(FunctionCodeResult.line(null, "No high function available"));
        }

        final List<Map<String, String>> lines = new ArrayList<>();
        final var iter = highFunction.getPcodeOps();
        while (iter.hasNext()) {
            final var op = iter.next();
            final String addr = op.getSeqnum().getTarget().toString();
            lines.add(FunctionCodeResult.line(addr, op.toString()));
        }
        return lines;
    }

    @McpTool(post = true, description = """
        Rename functions in a single atomic transaction.

        Accepts a map of current function identifiers to new names. Each key can be
        a function name (e.g., "FUN_00401000") or address (e.g., "00401000").
        All functions are validated before any renames are applied (all-or-nothing).

        Returns: Structured result with renamed pairs and count

        Note: Function names must be unique within the program.

        Example: rename_functions({"FUN_00401000": "initialize_system", "main": "entry_point"}) """,
        outputType = JsonOutput.class, responseType = RenameFunctionsResult.class)
    public ToolOutput renameFunctions(
            @Param("Map of current function names/addresses to new names") final Map<String, String> renames) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (renames == null || renames.isEmpty()) return StatusOutput.error("No renames specified");

        // Pre-validate: resolve all functions before starting transaction
        final Map<Function, String> resolved = new LinkedHashMap<>();
        for (final var entry : renames.entrySet()) {
            final Function func = resolveFunction(program, entry.getKey());
            if (func == null) {
                return StatusOutput.error("Function not found: " + entry.getKey());
            }
            resolved.put(func, entry.getValue());
        }

        try (var tx = ProgramTransaction.start(program, "Rename functions")) {
            final Map<String, String> renamed = new LinkedHashMap<>();

            for (final var entry : resolved.entrySet()) {
                final Function func = entry.getKey();
                final String newName = entry.getValue();
                final String oldName = func.getName();
                func.setName(newName, SourceType.USER_DEFINED);
                renamed.put(oldName, newName);
            }

            tx.commit();
            return new JsonOutput(new RenameFunctionsResult("Renamed successfully", renamed, renamed.size()));
        } catch (InvalidInputException | DuplicateNameException | RuntimeException e) {
            Msg.error(this, "Error renaming functions", e);
            return StatusOutput.error("Failed to rename functions: " + e.getMessage());
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
