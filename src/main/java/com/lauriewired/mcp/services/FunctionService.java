package com.lauriewired.mcp.services;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.CurrentAddressResult;
import com.lauriewired.mcp.model.response.CurrentFunctionResult;
import com.lauriewired.mcp.model.response.FunctionCodeResult;
import com.lauriewired.mcp.model.response.FunctionItem;
import com.lauriewired.mcp.model.response.FunctionSearchItem;
import com.lauriewired.mcp.model.response.RenameFunctionsResult;
import com.lauriewired.mcp.utils.GhidraUtils;
import com.lauriewired.mcp.utils.ProgramTransaction;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.CodeViewerService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
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
    private final DataTypeService dataTypeService;

    private static final Pattern IDENTIFIER_PATTERN = Pattern.compile("[a-zA-Z_][a-zA-Z0-9_]*");

    /**
     * Creates a new FunctionService
     *
     * @param tool the plugin tool
     * @param programService the program service for accessing the current program
     * @param dataTypeService the data type service for resolving types without modal dialogs
     */
    public FunctionService(final PluginTool tool, final ProgramService programService,
                           final DataTypeService dataTypeService) {
        this.tool = tool;
        this.programService = programService;
        this.dataTypeService = dataTypeService;
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

        Returns: Array of single-entry {address: code} objects. Empty string key "" means no mapped address. Assembly mode includes all comment types: plate and pre comments as "; text" lines before the instruction, EOL and repeatable comments inlined as "code ; comment", and post comments as "; text" lines after the instruction.

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

        Function func = resolveFunction(program, functionIdentifier);
        if (func == null) {
            // Try to auto-create a function if the identifier looks like an address
            func = tryAutoCreateFunction(program, functionIdentifier);
            if (func == null) return StatusOutput.error("Function not found: " + functionIdentifier);
        }

        // Normalize mode
        final String normalizedMode = (mode == null || mode.isEmpty()) ? "c" : mode.toLowerCase().trim();

        final String effectiveFormat;
        final List<Map<String, String>> lines;
        List<FunctionCodeResult.RegisterAssumption> registerAssumptions = null;
        switch (normalizedMode) {
            case "assembly", "asm", "disassembly" -> {
                effectiveFormat = "assembly";
                lines = getAssemblyLines(program, func);
                registerAssumptions = getRegisterAssumptions(program, func.getEntryPoint());
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

        return new JsonOutput(new FunctionCodeResult(func.getName(), func.getSignature().getPrototypeString(), effectiveFormat, registerAssumptions, lines));
    }

    private List<Map<String, String>> getDecompiledCLines(final Program program, final Function func) {
        final DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            final DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            final List<Map<String, String>> lines = GhidraUtils.extractDecompiledLines(result, func);
            return !lines.isEmpty() ? lines : List.of(FunctionCodeResult.line(null, "Decompilation failed"));
        } finally {
            decomp.dispose();
        }
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

            final String addr = instr.getAddress().toString();

            // Plate comment (block header, above instruction)
            addCommentLines(lines, listing.getComment(CommentType.PLATE, instr.getAddress()), addr);
            // Pre comment (above instruction)
            addCommentLines(lines, listing.getComment(CommentType.PRE, instr.getAddress()), addr);

            // Instruction with inline EOL and repeatable comments
            final String eolComment = listing.getComment(CommentType.EOL, instr.getAddress());
            final String repeatableComment = listing.getComment(CommentType.REPEATABLE, instr.getAddress());
            final StringBuilder code = new StringBuilder(instr.toString());
            if (eolComment != null) code.append(" ; ").append(eolComment);
            if (repeatableComment != null) code.append(" ; ").append(repeatableComment);
            lines.add(FunctionCodeResult.line(addr, code.toString()));

            // Post comment (below instruction)
            addCommentLines(lines, listing.getComment(CommentType.POST, instr.getAddress()), addr);
        }
        return lines;
    }

    private static void addCommentLines(final List<Map<String, String>> lines, final String comment, final String addr) {
        if (comment == null) return;
        for (final String line : comment.split("\n")) {
            lines.add(FunctionCodeResult.line(addr, "; " + line));
        }
    }

    private List<Map<String, String>> getPcodeLines(final Program program, final Function func) {
        final DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            final DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (result == null || !result.decompileCompleted()) {
                return List.of(FunctionCodeResult.line(null, "Decompilation failed"));
            }

            final var highFunction = result.getHighFunction();
            if (highFunction == null) {
                return List.of(FunctionCodeResult.line(null, "No high function available"));
            }

            final Listing listing = program.getListing();
            final List<Map<String, String>> lines = new ArrayList<>();
            final var iter = highFunction.getPcodeOps();
            Address prevAddr = null;
            while (iter.hasNext()) {
                final var op = iter.next();
                final Address opAddr = op.getSeqnum().getTarget();
                final String addr = opAddr.toString();

                // Emit comments once per new instruction address
                if (!opAddr.equals(prevAddr)) {
                    // Post comment for previous address (below that instruction's ops)
                    if (prevAddr != null) {
                        addCommentLines(lines, listing.getComment(CommentType.POST, prevAddr), prevAddr.toString());
                    }
                    // Plate, pre, EOL, repeatable before this instruction's ops
                    addCommentLines(lines, listing.getComment(CommentType.PLATE, opAddr), addr);
                    addCommentLines(lines, listing.getComment(CommentType.PRE, opAddr), addr);
                    addCommentLines(lines, listing.getComment(CommentType.EOL, opAddr), addr);
                    addCommentLines(lines, listing.getComment(CommentType.REPEATABLE, opAddr), addr);
                    prevAddr = opAddr;
                }

                lines.add(FunctionCodeResult.line(addr, op.toString()));
            }
            // Post comment for the final address
            if (prevAddr != null) {
                addCommentLines(lines, listing.getComment(CommentType.POST, prevAddr), prevAddr.toString());
            }
            return lines;
        } finally {
            decomp.dispose();
        }
    }

    private List<FunctionCodeResult.RegisterAssumption> getRegisterAssumptions(final Program program, final Address entryPoint) {
        final var context = program.getProgramContext();
        final TreeMap<String, FunctionCodeResult.RegisterAssumption> sorted = new TreeMap<>();

        for (final Register reg : context.getRegisters()) {
            final RegisterValue rv = context.getNonDefaultValue(reg, entryPoint);
            if (rv == null || !rv.hasAnyValue()) continue;

            final BigInteger val = rv.getUnsignedValueIgnoreMask();
            final String hexValue = rv.hasValue()
                    ? "0x" + val.toString(16).toUpperCase()
                    : "0x" + val.toString(16).toUpperCase() + "*";

            sorted.put(reg.getName(), new FunctionCodeResult.RegisterAssumption(reg.getName(), hexValue));
        }

        return sorted.isEmpty() ? null : new ArrayList<>(sorted.values());
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

    @McpTool(post = true, description = """
        Create a function at a specified address.

        The function body is auto-discovered by following code flow from the entry point.
        Useful when auto-analysis misses a function entry point.

        Returns: Success or error message

        Example: create_function("00401000") -> auto-named function
        Example: create_function("00401000", "my_handler") -> named function """,
        outputType = StatusOutput.class, responseType = StatusOutput.class)
    public ToolOutput createFunction(
            @Param("Entry point address for the new function (e.g., \"00401000\", \"ram:00401000\")") final String address,
            @Param(value = "Optional name for the function (auto-generated if empty)", defaultValue = "") final String name) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null || address.isEmpty()) return StatusOutput.error("Address is required");

        final Address entryPoint;
        try {
            entryPoint = program.getAddressFactory().getAddress(address);
        } catch (Exception e) {
            return StatusOutput.error("Invalid address: " + address);
        }
        if (entryPoint == null) return StatusOutput.error("Invalid address: " + address);

        // Check if a function already exists at this address
        if (program.getFunctionManager().getFunctionAt(entryPoint) != null) {
            return StatusOutput.error("Function already exists at " + entryPoint);
        }

        try (var tx = ProgramTransaction.start(program, "Create function")) {
            final CreateFunctionCmd cmd;
            if (name == null || name.isEmpty()) {
                cmd = new CreateFunctionCmd(entryPoint);
            } else {
                cmd = new CreateFunctionCmd(name, entryPoint, null, SourceType.USER_DEFINED);
            }

            if (cmd.applyTo(program, new ConsoleTaskMonitor())) {
                tx.commit();
                final Function created = program.getFunctionManager().getFunctionAt(entryPoint);
                final String createdName = created != null ? created.getName() : (name.isEmpty() ? "auto" : name);
                return StatusOutput.ok("Created function '" + createdName + "' at " + entryPoint);
            } else {
                return StatusOutput.error("Failed to create function: " + cmd.getStatusMsg());
            }
        } catch (Exception e) {
            Msg.error(this, "Error creating function at " + address, e);
            return StatusOutput.error("Failed to create function: " + e.getMessage());
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

    /**
     * Attempt to auto-create a function at the given identifier (treated as an address).
     * Returns the newly created function, or null if the identifier is not a valid address
     * or function creation fails.
     */
    private Function tryAutoCreateFunction(final Program program, final String identifier) {
        final Address entryPoint;
        try {
            entryPoint = program.getAddressFactory().getAddress(identifier);
        } catch (Exception e) {
            return null;
        }
        if (entryPoint == null) return null;

        try (var tx = ProgramTransaction.start(program, "Auto-create function")) {
            // Disassemble first — CreateFunctionCmd needs instructions
            final DisassembleCommand disCmd = new DisassembleCommand(entryPoint, null, true);
            disCmd.applyTo(program, new ConsoleTaskMonitor());

            final CreateFunctionCmd cmd = new CreateFunctionCmd(entryPoint);
            if (cmd.applyTo(program, new ConsoleTaskMonitor())) {
                tx.commit();
                return program.getFunctionManager().getFunctionAt(entryPoint);
            }
        } catch (Exception e) {
            Msg.warn(this, "Auto-create function failed at " + identifier + ": " + e.getMessage());
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
     * Parse and apply a function signature. Tries Ghidra's FunctionSignatureParser first
     * (full C syntax support) with null service to avoid modal dialogs. Falls back to
     * manual parsing with DataTypeService resolution for types the parser can't find.
     */
    @SuppressWarnings("UseSpecificCatch")
    private StatusOutput parseFunctionSignatureAndApply(final Program program, final Address addr, final String prototype) {
        final DataTypeManager dtm = program.getDataTypeManager();

        // Try Ghidra's parser with null service — full C syntax, no modal dialogs
        try {
            final FunctionSignatureParser parser = new FunctionSignatureParser(dtm, null);
            final FunctionDefinitionDataType sig = parser.parse(null, prototype);
            if (sig != null) {
                return applySignature(program, addr, sig);
            }
        } catch (ghidra.util.exception.CancelledException e) {
            Msg.info(this, "FunctionSignatureParser cancelled, trying manual parsing");
        } catch (Exception e) {
            Msg.info(this, "FunctionSignatureParser failed, trying manual parsing: " + e.getMessage());
        }

        // Fallback: manual parsing with DataTypeService resolution (handles ambiguous types)
        return parseAndApplyManually(program, addr, prototype);
    }

    /**
     * Apply a parsed FunctionDefinitionDataType to the function at the given address.
     */
    private StatusOutput applySignature(final Program program, final Address addr,
                                        final FunctionDefinitionDataType sig) {
        try (var tx = ProgramTransaction.start(program, "Set function prototype")) {
            final ApplyFunctionSignatureCmd cmd =
                    new ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED);
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

    /**
     * Manual prototype parsing fallback. Parses the prototype string, resolves each type
     * through DataTypeService (which handles ambiguous types like ushort without dialogs),
     * and builds a FunctionDefinitionDataType.
     */
    @SuppressWarnings("UseSpecificCatch")
    private StatusOutput parseAndApplyManually(final Program program, final Address addr, final String prototype) {
        final ParsedPrototype parsed;
        try {
            parsed = parsePrototype(prototype);
        } catch (IllegalArgumentException e) {
            final String msg = "Failed to parse prototype: " + e.getMessage();
            Msg.error(this, msg);
            return StatusOutput.error("Failed to set function prototype: " + msg);
        }

        final DataTypeManager dtm = program.getDataTypeManager();

        // Resolve return type
        final DataType returnType = dataTypeService.resolveDataType(dtm, parsed.returnType);
        if (returnType == null) {
            return StatusOutput.error("Failed to set function prototype: could not resolve return type '" + parsed.returnType + "'");
        }

        // Resolve parameter types
        final List<ParameterDefinition> paramDefs = new ArrayList<>();
        for (final ParsedParam param : parsed.params) {
            final DataType paramType = dataTypeService.resolveDataType(dtm, param.type);
            if (paramType == null) {
                return StatusOutput.error("Failed to set function prototype: could not resolve type '" +
                        param.type + "' for parameter '" + param.name + "'");
            }
            paramDefs.add(new ParameterDefinitionImpl(param.name, paramType, null));
        }

        final FunctionDefinitionDataType sig = new FunctionDefinitionDataType("tmpSig");
        sig.setReturnType(returnType);
        sig.setArguments(paramDefs.toArray(new ParameterDefinition[0]));
        if (parsed.hasVarArgs) {
            sig.setVarArgs(true);
        }

        return applySignature(program, addr, sig);
    }

    // --- Prototype parsing ---

    /**
     * Parsed representation of a C function prototype.
     */
    static class ParsedPrototype {
        final String returnType;
        final List<ParsedParam> params;
        final boolean hasVarArgs;

        ParsedPrototype(final String returnType, final List<ParsedParam> params, final boolean hasVarArgs) {
            this.returnType = returnType;
            this.params = params;
            this.hasVarArgs = hasVarArgs;
        }
    }

    /**
     * A single parsed parameter (type + name).
     */
    static class ParsedParam {
        final String type;
        final String name;

        ParsedParam(final String type, final String name) {
            this.type = type;
            this.name = name;
        }
    }

    /**
     * Parse a C-style function prototype into return type, parameters, and varargs flag.
     * The function name in the prototype is ignored.
     *
     * @param prototype e.g. "int process_data(char *buffer, size_t length)"
     * @return parsed prototype components
     * @throws IllegalArgumentException if the prototype cannot be parsed
     */
    static ParsedPrototype parsePrototype(final String prototype) {
        final int openParen = prototype.indexOf('(');
        final int closeParen = prototype.lastIndexOf(')');
        if (openParen < 0 || closeParen < 0 || closeParen <= openParen) {
            throw new IllegalArgumentException("missing parentheses");
        }

        // Extract return type from prefix (everything before '(', minus the function name)
        final String prefix = prototype.substring(0, openParen).trim();
        final String returnType = extractReturnType(prefix);

        // Parse parameters
        final String paramStr = prototype.substring(openParen + 1, closeParen).trim();
        final List<ParsedParam> params = new ArrayList<>();
        boolean hasVarArgs = false;

        if (!paramStr.isEmpty() && !paramStr.equalsIgnoreCase("void")) {
            final String[] paramParts = splitParams(paramStr);
            for (final String part : paramParts) {
                final String trimmed = part.trim();
                if (trimmed.isEmpty()) continue;
                if (trimmed.equals("...")) {
                    hasVarArgs = true;
                    continue;
                }
                params.add(parseParam(trimmed));
            }
        }

        return new ParsedPrototype(returnType, params, hasVarArgs);
    }

    /**
     * Extract the return type from the prefix before '('.
     * The last identifier is the function name (ignored); everything before it is the return type.
     */
    static String extractReturnType(final String prefix) {
        final Matcher matcher = IDENTIFIER_PATTERN.matcher(prefix);
        int lastIdentStart = -1;
        while (matcher.find()) {
            lastIdentStart = matcher.start();
        }
        if (lastIdentStart <= 0) {
            throw new IllegalArgumentException("could not determine return type from: " + prefix);
        }

        final String returnType = prefix.substring(0, lastIdentStart).trim();
        if (returnType.isEmpty()) {
            throw new IllegalArgumentException("could not determine return type from: " + prefix);
        }
        return returnType;
    }

    /**
     * Parse a single parameter declaration into type and name.
     * The last identifier is the parameter name; everything before it is the type.
     */
    static ParsedParam parseParam(final String param) {
        final Matcher matcher = IDENTIFIER_PATTERN.matcher(param);
        int lastIdentStart = -1;
        int lastIdentEnd = -1;
        while (matcher.find()) {
            lastIdentStart = matcher.start();
            lastIdentEnd = matcher.end();
        }
        if (lastIdentStart < 0) {
            throw new IllegalArgumentException("could not parse parameter: " + param);
        }

        final String name = param.substring(lastIdentStart, lastIdentEnd);
        final String type = param.substring(0, lastIdentStart).trim();

        // Single identifier with no preceding type — treat as unnamed parameter
        if (type.isEmpty()) {
            return new ParsedParam(name, "");
        }

        return new ParsedParam(type, name);
    }

    /**
     * Split parameter list by commas, respecting nested parentheses.
     */
    static String[] splitParams(final String paramStr) {
        final List<String> params = new ArrayList<>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < paramStr.length(); i++) {
            final char c = paramStr.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') depth--;
            else if (c == ',' && depth == 0) {
                params.add(paramStr.substring(start, i));
                start = i + 1;
            }
        }
        params.add(paramStr.substring(start));
        return params.toArray(new String[0]);
    }
}
