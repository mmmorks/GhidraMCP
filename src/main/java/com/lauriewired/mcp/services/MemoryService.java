package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.AddressDataTypeResult;
import com.lauriewired.mcp.model.response.DataItem;
import com.lauriewired.mcp.model.response.MemoryPermissionsResult;
import com.lauriewired.mcp.model.response.MemorySegmentItem;
import com.lauriewired.mcp.model.response.ReadMemoryResult;
import com.lauriewired.mcp.model.response.ReadMemoryResult.AddressComment;
import com.lauriewired.mcp.model.response.RenameDataResult;
import com.lauriewired.mcp.model.response.SetDataTypesResult;
import com.lauriewired.mcp.utils.HttpUtils;
import com.lauriewired.mcp.utils.ProgramTransaction;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;

/**
 * Service for memory and data-related operations
 */
public class MemoryService {
    private final ProgramService programService;
    private final DataTypeService dataTypeService;

    /**
     * Creates a new MemoryService
     *
     * @param programService the program service for accessing the current program
     */
    public MemoryService(final ProgramService programService) {
        this.programService = programService;
        this.dataTypeService = null;
    }

    /**
     * Creates a new MemoryService with DataTypeService
     *
     * @param programService the program service for accessing the current program
     * @param dataTypeService the data type service for resolving data types
     */
    public MemoryService(final ProgramService programService, final DataTypeService dataTypeService) {
        this.programService = programService;
        this.dataTypeService = dataTypeService;
    }

    @McpTool(description = """
        Get the memory layout of the program (segments/sections).

        Shows distinct regions in the binary's address space (.text, .data, .rodata, etc.)
        with their address ranges, sizes, and read/write/execute permissions.

        Returns: Memory segments with name, address range, size in bytes, and permissions (e.g., "r-x", "rw-")

        Example: get_memory_layout() -> ['.text: 00401000 - 00410000 (r-x)', '.data: 00411000 - 00412000 (rw-)', ...] """,
        outputType = ListOutput.class, responseType = MemorySegmentItem.class)
    public ToolOutput getMemoryLayout(
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") final int offset,
            @Param(value = "Maximum segments to return", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        final List<MemorySegmentItem> items = new ArrayList<>();
        for (final MemoryBlock block : program.getMemory().getBlocks()) {
            final long size = block.getSize();
            final String perms = (block.isRead() ? "r" : "-")
                    + (block.isWrite() ? "w" : "-")
                    + (block.isExecute() ? "x" : "-");
            items.add(new MemorySegmentItem(block.getName(), block.getStart().toString(), block.getEnd().toString(), size, perms));
        }
        return ListOutput.paginate(items, offset, limit);
    }

    @McpTool(description = """
        List defined data labels and their values with pagination.

        Shows memory locations containing data (strings, arrays, structures, primitives).

        Returns: Data items with address, label and value

        Note: Unlabeled items shown as "(unnamed)"

        Example: list_data_items(0, 3) -> ['00410000: hello_msg = "Hello, World!"', ...] """,
        outputType = ListOutput.class, responseType = DataItem.class)
    public ToolOutput listDataItems(
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") final int offset,
            @Param(value = "Maximum data items to return", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        final List<DataItem> items = new ArrayList<>();
        for (final MemoryBlock block : program.getMemory().getBlocks()) {
            final DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                final Data data = it.next();
                if (block.contains(data.getAddress())) {
                    final String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    final String typeName = data.getDataType().getName();
                    final String valRepr = data.getDefaultValueRepresentation();
                    items.add(new DataItem(
                            data.getAddress().toString(),
                            HttpUtils.escapeNonAscii(label),
                            typeName,
                            HttpUtils.escapeNonAscii(valRepr)));
                }
            }
        }

        return ListOutput.paginate(items, offset, limit);
    }

    @McpTool(post = true, description = """
        Rename data labels at the specified addresses in a single atomic transaction.

        Accepts a map of address -> new name pairs. All addresses are validated before
        any renames are applied (all-or-nothing).

        Returns: Structured result with renamed pairs and count

        Note: Each address must point to defined data, not code. Creates a new label if
        none exists at the address.

        Example: rename_data({"00402000": "config_table", "00403000": "key_buffer"}) """,
        outputType = JsonOutput.class, responseType = RenameDataResult.class)
    public ToolOutput renameData(
            @Param("Map of data addresses to new names") final Map<String, String> renames) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (renames == null || renames.isEmpty()) return StatusOutput.error("No renames specified");

        // Pre-validate all addresses
        final Map<Address, String> resolved = new LinkedHashMap<>();
        for (final var entry : renames.entrySet()) {
            final Address addr = program.getAddressFactory().getAddress(entry.getKey());
            if (addr == null) {
                return StatusOutput.error("Invalid address: " + entry.getKey());
            }
            if (program.getListing().getDefinedDataAt(addr) == null) {
                return StatusOutput.error("No defined data at address: " + entry.getKey());
            }
            resolved.put(addr, entry.getValue());
        }

        try (var tx = ProgramTransaction.start(program, "Rename data")) {
            final SymbolTable symTable = program.getSymbolTable();
            final Map<String, String> renamed = new LinkedHashMap<>();

            for (final var entry : resolved.entrySet()) {
                final Address addr = entry.getKey();
                final String newName = entry.getValue();
                final Symbol symbol = symTable.getPrimarySymbol(addr);

                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                } else {
                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                }
                renamed.put(addr.toString(), newName);
            }

            tx.commit();
            return new JsonOutput(new RenameDataResult("Renamed successfully", renamed, renamed.size()));
        } catch (DuplicateNameException | InvalidInputException e) {
            Msg.error(this, "Rename data error", e);
            return StatusOutput.error("Rename failed: " + e.getMessage());
        }
    }

    @McpTool(post = true, description = """
        Set data types at memory addresses in a single atomic transaction.

        Accepts a map of address -> data type name pairs. All addresses and types are
        validated before any changes are applied (all-or-nothing).

        Returns: Structured result with applied types and count

        Note: Data types can be built-in types, structures, enums, or arrays.
        Array syntax: "type[size]" e.g., "char[256]" for a string buffer.
        Use category-qualified paths (e.g., "/generic_clib_64/int") to disambiguate
        when multiple types share the same name.

        Example: set_address_data_type({"00402000": "POINT", "00403000": "int"}) """,
        outputType = JsonOutput.class, responseType = SetDataTypesResult.class)
    public ToolOutput setAddressDataType(
            @Param("Map of memory addresses to data type names") final Map<String, String> types,
            @Param(value = "Whether to clear existing data at addresses first", defaultValue = "false") final boolean clearExisting) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (dataTypeService == null) return StatusOutput.error("DataTypeService not available");
        if (types == null || types.isEmpty()) return StatusOutput.error("No types specified");

        // Pre-validate all addresses and resolve all data types
        final DataTypeManager dtm = program.getDataTypeManager();
        final Map<Address, DataType> resolved = new LinkedHashMap<>();
        for (final var entry : types.entrySet()) {
            final Address addr = program.getAddressFactory().getAddress(entry.getKey());
            if (addr == null) {
                return StatusOutput.error("Invalid address: " + entry.getKey());
            }

            final String typeName = entry.getValue();
            final DataType resolvedDataType = dataTypeService.resolveDataType(dtm, typeName);
            if (resolvedDataType == null) {
                if (typeName.matches(".*\\[\\d+\\]$")) {
                    return StatusOutput.error("Failed to create array data type '" + typeName +
                            "': base type could not be resolved. Check that the base type exists.");
                } else {
                    return StatusOutput.error("Data type '" + typeName + "' not found. " +
                            "Available types include: int, char, short, long, byte, etc.");
                }
            }
            resolved.put(addr, resolvedDataType);
        }

        // Pre-validate code unit conflicts when not clearing existing data
        if (!clearExisting) {
            final Listing preCheckListing = program.getListing();
            for (final Address addr : resolved.keySet()) {
                final Instruction instr = preCheckListing.getInstructionAt(addr);
                if (instr != null) {
                    return StatusOutput.error("Failed at " + addr + ": Instructions exist. " +
                           "Use clear_existing=true to overwrite.");
                }

                final Data existingData = preCheckListing.getDefinedDataAt(addr);
                if (existingData != null) {
                    return StatusOutput.error(String.format("Failed at %s: Existing data '%s'. " +
                           "Use clear_existing=true to overwrite.",
                           addr, existingData.getDataType().getName()));
                }

                // Check for conflicting code units that span this address
                final CodeUnit cu = preCheckListing.getCodeUnitContaining(addr);
                if (cu != null && !cu.getAddress().equals(addr)) {
                    return StatusOutput.error("Failed at " + addr + ": Conflicting code units. " +
                           "Try setting clear_existing=true.");
                }
            }
        }

        try (var tx = ProgramTransaction.start(program, "Set data types")) {
            final Listing listing = program.getListing();
            final Map<String, String> applied = new LinkedHashMap<>();

            for (final var entry : resolved.entrySet()) {
                final Address addr = entry.getKey();
                final DataType resolvedDataType = entry.getValue();

                if (clearExisting) {
                    int sizeNeeded = resolvedDataType.getLength();
                    if (sizeNeeded <= 0) {
                        sizeNeeded = 1;
                    }
                    final Address endAddr = addr.add(sizeNeeded - 1);
                    listing.clearCodeUnits(addr, endAddr, false);
                }

                try {
                    listing.createData(addr, resolvedDataType);
                    applied.put(addr.toString(), resolvedDataType.getName());
                } catch (CodeUnitInsertionException e) {
                    final String errorMsg = e.getMessage();
                    if (errorMsg.contains("Conflicting")) {
                        final CodeUnit cu = listing.getCodeUnitAt(addr);
                        if (cu instanceof Instruction) {
                            return StatusOutput.error("Failed at " + addr + ": Instructions exist. " +
                                   "Use clear_existing=true to overwrite.");
                        } else if (cu instanceof Data existingData) {
                            return StatusOutput.error(String.format("Failed at %s: Existing data '%s'. " +
                                   "Use clear_existing=true to overwrite.",
                                   addr, existingData.getDataType().getName()));
                        } else {
                            return StatusOutput.error("Failed at " + addr + ": Conflicting code units. " +
                                   "Try setting clear_existing=true.");
                        }
                    } else if (errorMsg.contains("Insufficient")) {
                        return StatusOutput.error(String.format("Failed at %s: Insufficient space for '%s' (%d bytes).",
                               addr, resolvedDataType.getName(), resolvedDataType.getLength()));
                    } else {
                        return StatusOutput.error("Failed at " + addr + ": " + errorMsg);
                    }
                }
            }

            tx.commit();
            return new JsonOutput(new SetDataTypesResult("Data types set successfully", applied, applied.size()));
        } catch (RuntimeException e) {
            Msg.error(this, "Error setting data types", e);
            return StatusOutput.error("Failed to set data types: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, responseType = ReadMemoryResult.class, description = """
        Read raw memory contents at a specific address.

        Reads bytes from memory and returns them as structured data.

        Returns: Structured memory contents with rows of address, byte values, and ASCII

        Note: Each row contains the address, an array of formatted byte values, and
        an ASCII representation (for hex and decimal formats).

        Example: read_memory("00401000", 32, "hex") -> Structured memory dump """)
    public ToolOutput readMemory(
            @Param("Memory address to read from (e.g., \"00401000\")") final String address,
            @Param(value = "Number of bytes to read (1-1024, default: 16)", defaultValue = "16") final int size,
            @Param(value = "Output format - \"hex\", \"decimal\", \"binary\", or \"ascii\" (default: \"hex\")", defaultValue = "hex") final String format) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null || address.isEmpty()) return StatusOutput.error("Address is required");
        if (size <= 0 || size > 1024) return StatusOutput.error("Size must be between 1 and 1024 bytes");

        try {
            final Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) return StatusOutput.error("Invalid address: " + address);

            final Memory memory = program.getMemory();
            final MemoryBlock block = memory.getBlock(addr);
            if (block == null) return StatusOutput.error("No memory block at address: " + address);

            // Check if we can read the requested size
            final Address endAddr = addr.add(size - 1);
            if (!block.contains(endAddr)) {
                return StatusOutput.error(String.format("Requested size %d exceeds memory block boundary", size));
            }

            // Read the bytes
            final byte[] bytes = new byte[size];
            try {
                memory.getBytes(addr, bytes);
            } catch (MemoryAccessException e) {
                return StatusOutput.error("Failed to read memory: " + e.getMessage());
            }

            // Format all bytes into a single flat record
            final String normalizedFormat = format.toLowerCase();
            final String effectiveFormat = switch (normalizedFormat) {
                case "decimal", "binary", "ascii" -> normalizedFormat;
                default -> "hex";
            };

            final String formattedBytes = formatBytes(bytes, effectiveFormat);
            final String ascii = ("hex".equals(effectiveFormat) || "decimal".equals(effectiveFormat))
                    ? buildAsciiString(bytes) : null;

            // Collect comments within the address range
            final List<AddressComment> comments = collectComments(program.getListing(), addr, endAddr);

            return new JsonOutput(new ReadMemoryResult(addr.toString(), size, effectiveFormat, formattedBytes, ascii, comments));
        } catch (Exception e) {
            return StatusOutput.error("Error reading memory: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, responseType = MemoryPermissionsResult.class, description = """
        Get memory permissions and block information at an address.

        Shows memory block properties including read/write/execute permissions.

        Returns: Memory block info with permissions and properties

        Note: Helps identify code vs data regions and memory protection.

        Example: get_memory_permissions("00401000") -> "Block: .text, Permissions: R-X" """)
    public ToolOutput getMemoryPermissions(
            @Param("final Memory address to check (e.g., \"00401000\")") final String address) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null || address.isEmpty()) return StatusOutput.error("Address is required");

        try {
            final Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) return StatusOutput.error("Invalid address: " + address);

            final Memory memory = program.getMemory();
            final MemoryBlock block = memory.getBlock(addr);
            if (block == null) return StatusOutput.error("No memory block at address: " + address);

            return new JsonOutput(new MemoryPermissionsResult(
                    block.getName(),
                    block.getStart().toString(),
                    block.getEnd().toString(),
                    block.getSize(),
                    new MemoryPermissionsResult.Permissions(
                            block.isRead(), block.isWrite(), block.isExecute()),
                    block.isInitialized(),
                    block.isVolatile(),
                    block.isOverlay()));
        } catch (Exception e) {
            return StatusOutput.error("Error getting memory permissions: " + e.getMessage());
        }
    }

    @McpTool(outputType = JsonOutput.class, responseType = AddressDataTypeResult.class, description = """
        Get the data type currently defined at a memory address.

        Shows whether address contains instruction, defined data, or is undefined.
        Symmetric counterpart to set_address_data_type.

        Returns: Data type information including type name, size, and value

        Note: Useful for checking if memory has been analyzed/typed.

        Example: get_address_data_type("00402000") -> "Type: DWORD, Value: 0x12345678" """)
    public ToolOutput getAddressDataType(
            @Param("final Memory address to check (e.g., \"00401000\")") final String address) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null || address.isEmpty()) return StatusOutput.error("Address is required");

        try {
            final Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) return StatusOutput.error("Invalid address: " + address);

            final Listing listing = program.getListing();

            // Check if there's an instruction at this address
            final Instruction instr = listing.getInstructionAt(addr);
            if (instr != null) {
                return new JsonOutput(new AddressDataTypeResult(
                        addr.toString(), "Instruction",
                        instr.getMnemonicString(), instr.toString(),
                        null, instr.getLength(), null, null));
            }

            // Check if there's defined data at this address
            final Data data = listing.getDefinedDataAt(addr);
            if (data != null) {
                final DataType dt = data.getDataType();
                final Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                return new JsonOutput(new AddressDataTypeResult(
                        addr.toString(), "Defined Data",
                        null, null,
                        dt.getName(), data.getLength(),
                        data.getDefaultValueRepresentation(),
                        symbol != null ? symbol.getName() : null));
            }

            // Check if it's undefined data
            final Data undefinedData = listing.getDataAt(addr);
            if (undefinedData != null) {
                String value;
                try {
                    final byte b = program.getMemory().getByte(addr);
                    value = String.format("0x%02X", b & 0xFF);
                } catch (MemoryAccessException e) {
                    value = null;
                }
                return new JsonOutput(new AddressDataTypeResult(
                        addr.toString(), "Undefined Data",
                        null, null, null, undefinedData.getLength(), value, null));
            }

            return new JsonOutput(new AddressDataTypeResult(
                    addr.toString(), "No data defined",
                    null, null, null, null, null, null));
        } catch (Exception e) {
            return StatusOutput.error("Error getting data type: " + e.getMessage());
        }
    }

    private static final CommentType[] COMMENT_TYPES = {
        CommentType.PLATE, CommentType.PRE, CommentType.EOL,
        CommentType.POST, CommentType.REPEATABLE
    };

    private static final String[] COMMENT_TYPE_NAMES = {
        "plate", "pre", "eol", "post", "repeatable"
    };

    private List<AddressComment> collectComments(final Listing listing, final Address start, final Address end) {
        final List<AddressComment> comments = new ArrayList<>();
        final CodeUnitIterator it = listing.getCodeUnits(start, true);
        while (it.hasNext()) {
            final CodeUnit cu = it.next();
            if (cu.getAddress().compareTo(end) > 0) break;
            final String addr = cu.getAddress().toString();
            for (int i = 0; i < COMMENT_TYPES.length; i++) {
                final String text = listing.getComment(COMMENT_TYPES[i], cu.getAddress());
                if (text != null) {
                    comments.add(new AddressComment(addr, COMMENT_TYPE_NAMES[i], text));
                }
            }
        }
        return comments;
    }

    private String formatBytes(final byte[] bytes, final String format) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(' ');
            switch (format) {
                case "decimal" -> sb.append(bytes[i] & 0xFF);
                case "binary" -> sb.append(String.format("%8s",
                        Integer.toBinaryString(bytes[i] & 0xFF)).replace(' ', '0'));
                case "ascii" -> {
                    final char c = (char)(bytes[i] & 0xFF);
                    if (c >= 32 && c < 127) sb.append(c);
                    else if (c == '\n') sb.append("\\n");
                    else if (c == '\r') sb.append("\\r");
                    else if (c == '\t') sb.append("\\t");
                    else if (c == 0) sb.append("\\0");
                    else sb.append(String.format("\\x%02X", bytes[i] & 0xFF));
                }
                default -> sb.append(String.format("%02X", bytes[i] & 0xFF)); // hex
            }
        }
        return sb.toString();
    }

    private String buildAsciiString(final byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for (final byte b : bytes) {
            final char c = (char)(b & 0xFF);
            sb.append(c >= 32 && c < 127 ? c : '.');
        }
        return sb.toString();
    }
}
