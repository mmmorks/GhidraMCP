package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.List;

import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.TextOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.HttpUtils;
import com.lauriewired.mcp.utils.ProgramTransaction;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
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
    public MemoryService(ProgramService programService) {
        this.programService = programService;
        this.dataTypeService = null;
    }
    
    /**
     * Creates a new MemoryService with DataTypeService
     *
     * @param programService the program service for accessing the current program
     * @param dataTypeService the data type service for resolving data types
     */
    public MemoryService(ProgramService programService, DataTypeService dataTypeService) {
        this.programService = programService;
        this.dataTypeService = dataTypeService;
    }

    @McpTool(description = """
        Get the memory layout of the program (segments/sections).

        Shows distinct regions in the binary's address space (.text, .data, .rodata, etc.)
        with their address ranges.

        Returns: Memory segments with name and address range

        Example: get_memory_layout() -> ['.text: 00401000 - 00410000', '.data: 00411000 - 00412000', ...] """, outputType = ListOutput.class)
    public ToolOutput getMemoryLayout(
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") int offset,
            @Param(value = "Maximum segments to return", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s",
                block.getName(),
                block.getStart(),
                block.getEnd()));
        }
        return ListOutput.paginate(lines, offset, limit);
    }

    @McpTool(description = """
        List defined data labels and their values with pagination.

        Shows memory locations containing data (strings, arrays, structures, primitives).

        Returns: Data items with address, label and value

        Note: Unlabeled items shown as "(unnamed)"

        Example: list_data_items(0, 3) -> ['00410000: hello_msg = "Hello, World!"', ...] """, outputType = ListOutput.class)
    public ToolOutput listDataItems(
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") int offset,
            @Param(value = "Maximum data items to return", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        HttpUtils.escapeNonAscii(label),
                        HttpUtils.escapeNonAscii(valRepr)
                    ));
                }
            }
        }

        return ListOutput.paginate(lines, offset, limit);
    }

    @McpTool(post = true, description = """
        Rename a data label at the specified address.

        Labels identify data elements (strings, arrays, structures) to improve code readability.

        Returns: Message indicating operation was attempted

        Note: Creates a new label if none exists at the address. Address must point to data, not code.

        Example: rename_data("00402000", "config_table") """, outputType = StatusOutput.class)
    public ToolOutput renameData(
            @Param("Data address (e.g., \"00401000\" or \"ram:00401000\")") String address,
            @Param("New name to assign") String newName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("Rename failed");

        try (var tx = ProgramTransaction.start(program, "Rename data")) {
            Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) {
                Msg.error(this, "Invalid address: " + address);
                return StatusOutput.error("Rename failed");
            }

            if (program.getListing().getDefinedDataAt(addr) == null) {
                Msg.error(this, "No defined data at address: " + address);
                return StatusOutput.error("Rename failed");
            }

            SymbolTable symTable = program.getSymbolTable();
            Symbol symbol = symTable.getPrimarySymbol(addr);

            if (symbol != null) {
                symbol.setName(newName, SourceType.USER_DEFINED);
            } else {
                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
            }
            tx.commit();
            return StatusOutput.ok("Renamed successfully");
        } catch (DuplicateNameException | InvalidInputException e) {
            Msg.error(this, "Rename data error", e);
            return StatusOutput.error("Rename failed");
        }
    }
    
    @McpTool(post = true, description = """
        Set the data type at a specific memory address.

        Creates or modifies data at the specified address with the given type.
        Symmetric counterpart to get_address_data_type.

        Returns: Success message with details or error message

        Note: The data type can be a built-in type, structure, enum, or array.
        Array syntax: "type[size]" e.g., "char[256]" for a string buffer.

        Example: set_address_data_type("00402000", "POINT") -> "Data type 'POINT' set at address 00402000" """, outputType = StatusOutput.class)
    public ToolOutput setAddressDataType(
            @Param("Memory address (e.g., \"00401000\" or \"ram:00401000\")") String address,
            @Param("Data type name (\"int\", \"char[20]\", \"POINT\", etc.)") String dataType,
            @Param(value = "Whether to clear existing data at the address first", defaultValue = "false") boolean clearExisting) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (dataTypeService == null) return StatusOutput.error("DataTypeService not available");

        try (var tx = ProgramTransaction.start(program, "Set memory data type")) {
            Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) {
                return StatusOutput.error("Invalid address: " + address);
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType resolvedDataType = dataTypeService.resolveDataType(dtm, dataType);

            if (resolvedDataType == null) {
                if (dataType.matches(".*\\[\\d+\\]$")) {
                    return StatusOutput.error("Failed to create array data type '" + dataType +
                            "': base type could not be resolved. Check that the base type exists.");
                } else {
                    return StatusOutput.error("Data type '" + dataType + "' not found. " +
                            "Available types include: int, char, short, long, byte, etc.");
                }
            }

            Listing listing = program.getListing();

            if (clearExisting) {
                int sizeNeeded = resolvedDataType.getLength();
                if (sizeNeeded <= 0) {
                    sizeNeeded = 1;
                }
                Address endAddr = addr.add(sizeNeeded - 1);
                listing.clearCodeUnits(addr, endAddr, false);
            }

            try {
                Data newData = listing.createData(addr, resolvedDataType);
                tx.commit();
                return StatusOutput.ok(String.format("Data type '%s' (%d bytes) set at address %s",
                    resolvedDataType.getName(),
                    newData.getLength(),
                    addr.toString()));
            } catch (CodeUnitInsertionException e) {
                String errorMsg = e.getMessage();
                if (errorMsg.contains("Conflicting")) {
                    CodeUnit cu = listing.getCodeUnitAt(addr);
                    if (cu instanceof Instruction) {
                        return StatusOutput.error("Failed to set data type: Instructions exist at address. " +
                               "Use clear_existing=true to overwrite instructions.");
                    } else if (cu instanceof Data existingData) {
                        return StatusOutput.error(String.format("Failed to set data type: Existing data '%s' at address. " +
                               "Use clear_existing=true to overwrite.",
                               existingData.getDataType().getName()));
                    } else {
                        return StatusOutput.error("Failed to set data type: Conflicting code units exist at address. " +
                               "Try setting clear_existing=true to overwrite.");
                    }
                } else if (errorMsg.contains("Insufficient")) {
                    return StatusOutput.error(String.format("Failed to set data type: Insufficient space. " +
                           "The data type '%s' requires %d bytes but there's not enough space available.",
                           resolvedDataType.getName(), resolvedDataType.getLength()));
                } else {
                    return StatusOutput.error("Failed to set data type: " + errorMsg);
                }
            }
        } catch (RuntimeException e) {
            Msg.error(this, "Error setting memory data type", e);
            return StatusOutput.error("Failed to set memory data type: " + e.getMessage());
        }
    }
    
    @McpTool(description = """
        Read raw memory contents at a specific address.

        Reads bytes from memory and formats them for analysis.

        Returns: Formatted memory contents with context

        Note: Shows memory in rows with address, hex bytes, and ASCII representation.

        Example: read_memory("00401000", 32, "hex") -> Memory dump with hex values """)
    public ToolOutput readMemory(
            @Param("Memory address to read from (e.g., \"00401000\")") String address,
            @Param(value = "Number of bytes to read (1-1024, default: 16)", defaultValue = "16") int size,
            @Param(value = "Output format - \"hex\", \"decimal\", \"binary\", or \"ascii\" (default: \"hex\")", defaultValue = "hex") String format) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null || address.isEmpty()) return StatusOutput.error("Address is required");
        if (size <= 0 || size > 1024) return StatusOutput.error("Size must be between 1 and 1024 bytes");

        try {
            Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) return StatusOutput.error("Invalid address: " + address);

            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(addr);
            if (block == null) return StatusOutput.error("No memory block at address: " + address);

            // Check if we can read the requested size
            Address endAddr = addr.add(size - 1);
            if (!block.contains(endAddr)) {
                return StatusOutput.error(String.format("Requested size %d exceeds memory block boundary", size));
            }

            // Read the bytes
            byte[] bytes = new byte[size];
            try {
                memory.getBytes(addr, bytes);
            } catch (MemoryAccessException e) {
                return StatusOutput.error("Failed to read memory: " + e.getMessage());
            }

            // Format the output based on requested format
            StringBuilder result = new StringBuilder();
            result.append(String.format("Memory at %s (%d bytes):\n", addr, size));

            switch (format.toLowerCase()) {
                case "hex":
                default:
                    result.append(formatBytesAsHex(bytes, addr));
                    break;
                case "decimal":
                    result.append(formatBytesAsDecimal(bytes, addr));
                    break;
                case "binary":
                    result.append(formatBytesAsBinary(bytes, addr));
                    break;
                case "ascii":
                    result.append(formatBytesAsAscii(bytes, addr));
                    break;
            }

            return new TextOutput(result.toString());
        } catch (Exception e) {
            return StatusOutput.error("Error reading memory: " + e.getMessage());
        }
    }
    
    @McpTool(description = """
        Get memory permissions and block information at an address.

        Shows memory block properties including read/write/execute permissions.

        Returns: Memory block info with permissions and properties

        Note: Helps identify code vs data regions and memory protection.

        Example: get_memory_permissions("00401000") -> "Block: .text, Permissions: R-X" """)
    public ToolOutput getMemoryPermissions(
            @Param("Memory address to check (e.g., \"00401000\")") String address) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null || address.isEmpty()) return StatusOutput.error("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) return StatusOutput.error("Invalid address: " + address);

            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(addr);
            if (block == null) return StatusOutput.error("No memory block at address: " + address);

            StringBuilder result = new StringBuilder();
            result.append(String.format("Memory permissions at %s:\n", addr));
            result.append(String.format("  Block: %s\n", block.getName()));
            result.append(String.format("  Start: %s\n", block.getStart()));
            result.append(String.format("  End: %s\n", block.getEnd()));
            result.append(String.format("  Size: 0x%X bytes\n", block.getSize()));
            result.append(String.format("  Permissions:\n"));
            result.append(String.format("    Read: %s\n", block.isRead() ? "Yes" : "No"));
            result.append(String.format("    Write: %s\n", block.isWrite() ? "Yes" : "No"));
            result.append(String.format("    Execute: %s\n", block.isExecute() ? "Yes" : "No"));
            result.append(String.format("  Type:\n"));
            result.append(String.format("    Initialized: %s\n", block.isInitialized() ? "Yes" : "No"));
            result.append(String.format("    Volatile: %s\n", block.isVolatile() ? "Yes" : "No"));
            result.append(String.format("    Overlay: %s\n", block.isOverlay() ? "Yes" : "No"));

            return new TextOutput(result.toString());
        } catch (Exception e) {
            return StatusOutput.error("Error getting memory permissions: " + e.getMessage());
        }
    }
    
    @McpTool(description = """
        Get the data type currently defined at a memory address.

        Shows whether address contains instruction, defined data, or is undefined.
        Symmetric counterpart to set_address_data_type.

        Returns: Data type information including type name, size, and value

        Note: Useful for checking if memory has been analyzed/typed.

        Example: get_address_data_type("00402000") -> "Type: DWORD, Value: 0x12345678" """)
    public ToolOutput getAddressDataType(
            @Param("Memory address to check (e.g., \"00401000\")") String address) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (address == null || address.isEmpty()) return StatusOutput.error("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(address);
            if (addr == null) return StatusOutput.error("Invalid address: " + address);

            Listing listing = program.getListing();
            StringBuilder result = new StringBuilder();
            result.append(String.format("Data type at %s:\n", addr));

            // Check if there's an instruction at this address
            Instruction instr = listing.getInstructionAt(addr);
            if (instr != null) {
                result.append("  Type: Instruction\n");
                result.append(String.format("  Mnemonic: %s\n", instr.getMnemonicString()));
                result.append(String.format("  Operands: %s\n", instr.toString()));
                result.append(String.format("  Length: %d bytes\n", instr.getLength()));
                return new TextOutput(result.toString());
            }

            // Check if there's defined data at this address
            Data data = listing.getDefinedDataAt(addr);
            if (data != null) {
                DataType dataType = data.getDataType();
                result.append("  Type: Defined Data\n");
                result.append(String.format("  Data Type: %s\n", dataType.getName()));
                result.append(String.format("  Category: %s\n", dataType.getCategoryPath()));
                result.append(String.format("  Length: %d bytes\n", data.getLength()));
                result.append(String.format("  Value: %s\n", data.getDefaultValueRepresentation()));

                // Add label if present
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                if (symbol != null) {
                    result.append(String.format("  Label: %s\n", symbol.getName()));
                }
            } else {
                // Check if it's undefined data
                Data undefinedData = listing.getDataAt(addr);
                if (undefinedData != null) {
                    result.append("  Type: Undefined Data\n");
                    result.append(String.format("  Length: %d bytes\n", undefinedData.getLength()));

                    // Try to read the byte value
                    try {
                        byte value = program.getMemory().getByte(addr);
                        result.append(String.format("  Value: 0x%02X (%d)\n", value & 0xFF, value & 0xFF));
                    } catch (MemoryAccessException e) {
                        result.append("  Value: <unreadable>\n");
                    }
                } else {
                    result.append("  Type: No data defined\n");
                }
            }

            return new TextOutput(result.toString());
        } catch (Exception e) {
            return StatusOutput.error("Error getting data type: " + e.getMessage());
        }
    }
    
    // Helper methods for formatting bytes
    private String formatBytesAsHex(byte[] bytes, Address startAddr) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 16) {
            // Address
            sb.append(String.format("%s: ", startAddr.add(i)));
            
            // Hex bytes
            for (int j = 0; j < 16 && (i + j) < bytes.length; j++) {
                sb.append(String.format("%02X ", bytes[i + j] & 0xFF));
            }
            
            // Padding if needed
            for (int j = bytes.length - i; j < 16; j++) {
                sb.append("   ");
            }
            
            // ASCII representation
            sb.append(" | ");
            for (int j = 0; j < 16 && (i + j) < bytes.length; j++) {
                char c = (char)(bytes[i + j] & 0xFF);
                if (c >= 32 && c < 127) {
                    sb.append(c);
                } else {
                    sb.append('.');
                }
            }
            sb.append("\n");
        }
        return sb.toString();
    }
    
    private String formatBytesAsDecimal(byte[] bytes, Address startAddr) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i % 8 == 0) {
                if (i > 0) sb.append("\n");
                sb.append(String.format("%s: ", startAddr.add(i)));
            }
            sb.append(String.format("%3d ", bytes[i] & 0xFF));
        }
        sb.append("\n");
        return sb.toString();
    }
    
    private String formatBytesAsBinary(byte[] bytes, Address startAddr) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i % 4 == 0) {
                if (i > 0) sb.append("\n");
                sb.append(String.format("%s: ", startAddr.add(i)));
            }
            sb.append(String.format("%s ", Integer.toBinaryString(bytes[i] & 0xFF)
                .replaceAll("(?=\\b\\d{1,7}\\b)", "0")));
        }
        sb.append("\n");
        return sb.toString();
    }
    
    private String formatBytesAsAscii(byte[] bytes, Address startAddr) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("ASCII at %s:\n", startAddr));
        for (byte b : bytes) {
            char c = (char)(b & 0xFF);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else if (c == 0) {
                sb.append("\\0");
            } else {
                sb.append(String.format("\\x%02X", b & 0xFF));
            }
        }
        sb.append("\n");
        return sb.toString();
    }
}
