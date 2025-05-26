package com.lauriewired.mcp.services;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.SwingUtilities;

import com.lauriewired.mcp.utils.HttpUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
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
     * List defined data items in the program with pagination
     *
     * @param offset starting index
     * @param limit maximum number of data items to return
     * @return list of data items with their addresses, labels, and values
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
        return HttpUtils.paginateList(lines, offset, limit);
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

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        Msg.error(this, "Invalid address: " + addressStr);
                        return;
                    }
                    
                    // Check if data exists at this address
                    if (program.getListing().getDefinedDataAt(addr) != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                        } else {
                            try {
                                symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                                successFlag.set(true);
                            } catch (InvalidInputException e) {
                                Msg.error(this, "Failed to create label: " + e.getMessage());
                            }
                        }
                    } else {
                        Msg.error(this, "No defined data at address: " + addressStr);
                    }
                }
                catch (DuplicateNameException | InvalidInputException e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
        return successFlag.get();
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
        
        AtomicReference<String> resultMessage = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set memory data type");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        resultMessage.set("Invalid address: " + addressStr);
                        return;
                    }
                    
                    // Get the data type manager and resolve the type
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = dataTypeService.resolveDataType(dtm, dataTypeName);
                    
                    if (dataType == null) {
                        resultMessage.set("Data type not found: " + dataTypeName);
                        return;
                    }
                    
                    Listing listing = program.getListing();
                    
                    // Clear existing data if requested
                    if (clearExisting) {
                        Data existingData = listing.getDataAt(addr);
                        if (existingData != null) {
                            listing.clearCodeUnits(addr, addr.add(existingData.getLength() - 1), false);
                        }
                    }
                    
                    // Create the data at the address
                    try {
                        Data newData = listing.createData(addr, dataType);
                        resultMessage.set(String.format("Data type '%s' (%d bytes) set at address %s",
                            dataType.getName(),
                            newData.getLength(),
                            addr.toString()));
                    } catch (CodeUnitInsertionException e) {
                        // Try to provide more specific error information
                        if (e.getMessage().contains("Conflicting")) {
                            resultMessage.set("Failed to set data type: Conflicting data exists at address. " +
                                           "Try setting clear_existing=true to overwrite.");
                        } else if (e.getMessage().contains("Insufficient")) {
                            resultMessage.set("Failed to set data type: Insufficient space. " +
                                           "The data type requires more bytes than available.");
                        } else {
                            resultMessage.set("Failed to set data type: " + e.getMessage());
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error setting memory data type", e);
                    resultMessage.set("Failed to set memory data type: " + e.getMessage());
                }
                finally {
                    program.endTransaction(tx, resultMessage.get() != null &&
                                          resultMessage.get().contains("set at address"));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute set memory data type on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        
        return resultMessage.get();
    }
}
