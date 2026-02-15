package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.List;

import com.lauriewired.mcp.model.PaginationResult;
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

    /**
     * List memory segments in the program with pagination
     *
     * @param offset starting index
     * @param limit maximum number of segments to return
     * @return list of memory segments with their address ranges
     */
    public String listSegments(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", 
                block.getName(), 
                block.getStart(), 
                block.getEnd()));
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }

    /**
     * List defined data items in the program with pagination and LLM-friendly hints
     *
     * @param offset starting index
     * @param limit maximum number of data items to return
     * @return paginated list of data items with pagination metadata
     */
    public String listDefinedData(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

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
        
        PaginationResult result = HttpUtils.paginateListWithHints(lines, offset, limit);
        return result.getFormattedResult();
    }

    /**
     * Rename a data label at the specified address
     *
     * @param addressStr address of the data to rename
     * @param newName new label name
     * @return true if successful, false otherwise
     */
    public boolean renameDataAtAddress(String addressStr, String newName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return false;

        try (var tx = ProgramTransaction.start(program, "Rename data")) {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                Msg.error(this, "Invalid address: " + addressStr);
                return false;
            }

            if (program.getListing().getDefinedDataAt(addr) == null) {
                Msg.error(this, "No defined data at address: " + addressStr);
                return false;
            }

            SymbolTable symTable = program.getSymbolTable();
            Symbol symbol = symTable.getPrimarySymbol(addr);

            if (symbol != null) {
                symbol.setName(newName, SourceType.USER_DEFINED);
            } else {
                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
            }
            tx.commit();
            return true;
        } catch (DuplicateNameException | InvalidInputException e) {
            Msg.error(this, "Rename data error", e);
            return false;
        }
    }
    
    /**
     * Set the data type at a specific memory address
     *
     * @param addressStr address where to set the data type
     * @param dataTypeName name of the data type to set
     * @param clearExisting whether to clear existing data at the address first
     * @return status message
     */
    public String setMemoryDataType(String addressStr, String dataTypeName, boolean clearExisting) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (dataTypeService == null) return "DataTypeService not available";

        try (var tx = ProgramTransaction.start(program, "Set memory data type")) {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "Invalid address: " + addressStr;
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = dataTypeService.resolveDataType(dtm, dataTypeName);

            if (dataType == null) {
                if (dataTypeName.matches(".*\\[\\d+\\]$")) {
                    return "Failed to create array data type '" + dataTypeName +
                            "': base type could not be resolved. Check that the base type exists.";
                } else {
                    return "Data type '" + dataTypeName + "' not found. " +
                            "Available types include: int, char, short, long, byte, etc.";
                }
            }

            Listing listing = program.getListing();

            if (clearExisting) {
                int sizeNeeded = dataType.getLength();
                if (sizeNeeded <= 0) {
                    sizeNeeded = 1;
                }
                Address endAddr = addr.add(sizeNeeded - 1);
                listing.clearCodeUnits(addr, endAddr, false);
            }

            try {
                Data newData = listing.createData(addr, dataType);
                tx.commit();
                return String.format("Data type '%s' (%d bytes) set at address %s",
                    dataType.getName(),
                    newData.getLength(),
                    addr.toString());
            } catch (CodeUnitInsertionException e) {
                String errorMsg = e.getMessage();
                if (errorMsg.contains("Conflicting")) {
                    CodeUnit cu = listing.getCodeUnitAt(addr);
                    if (cu instanceof Instruction) {
                        return "Failed to set data type: Instructions exist at address. " +
                               "Use clear_existing=true to overwrite instructions.";
                    } else if (cu instanceof Data existingData) {
                        return String.format("Failed to set data type: Existing data '%s' at address. " +
                               "Use clear_existing=true to overwrite.",
                               existingData.getDataType().getName());
                    } else {
                        return "Failed to set data type: Conflicting code units exist at address. " +
                               "Try setting clear_existing=true to overwrite.";
                    }
                } else if (errorMsg.contains("Insufficient")) {
                    return String.format("Failed to set data type: Insufficient space. " +
                           "The data type '%s' requires %d bytes but there's not enough space available.",
                           dataType.getName(), dataType.getLength());
                } else {
                    return "Failed to set data type: " + errorMsg;
                }
            }
        } catch (RuntimeException e) {
            Msg.error(this, "Error setting memory data type", e);
            return "Failed to set memory data type: " + e.getMessage();
        }
    }
    
    /**
     * Read raw memory contents at a specific address
     *
     * @param addressStr address to read from
     * @param size number of bytes to read
     * @param format output format: "hex", "decimal", "binary", "ascii"
     * @return formatted memory contents
     */
    public String readMemory(String addressStr, int size, String format) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (size <= 0 || size > 1024) return "Size must be between 1 and 1024 bytes";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            
            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(addr);
            if (block == null) return "No memory block at address: " + addressStr;
            
            // Check if we can read the requested size
            Address endAddr = addr.add(size - 1);
            if (!block.contains(endAddr)) {
                return String.format("Requested size %d exceeds memory block boundary", size);
            }
            
            // Read the bytes
            byte[] bytes = new byte[size];
            try {
                memory.getBytes(addr, bytes);
            } catch (MemoryAccessException e) {
                return "Failed to read memory: " + e.getMessage();
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
            
            return result.toString();
        } catch (Exception e) {
            return "Error reading memory: " + e.getMessage();
        }
    }
    
    /**
     * Get memory permissions at a specific address
     *
     * @param addressStr address to check
     * @return memory permissions information
     */
    public String getMemoryPermissions(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            
            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(addr);
            if (block == null) return "No memory block at address: " + addressStr;
            
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
            
            return result.toString();
        } catch (Exception e) {
            return "Error getting memory permissions: " + e.getMessage();
        }
    }
    
    /**
     * Get the data type currently defined at an address
     *
     * @param addressStr address to check
     * @return data type information
     */
    public String getDataTypeAt(String addressStr) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "Invalid address: " + addressStr;
            
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
                return result.toString();
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
            
            return result.toString();
        } catch (Exception e) {
            return "Error getting data type: " + e.getMessage();
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
