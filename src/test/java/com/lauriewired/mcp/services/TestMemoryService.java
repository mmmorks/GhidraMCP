package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.List;

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
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test-friendly version of MemoryService that uses TestProgramService
 */
public class TestMemoryService extends MemoryService {
    private final TestProgramService testProgramService;
    private final TestDataTypeService testDataTypeService;

    /**
     * Creates a new TestMemoryService
     *
     * @param testProgramService the test program service for accessing the current program
     */
    public TestMemoryService(TestProgramService testProgramService) {
        super(testProgramService);
        this.testProgramService = testProgramService;
        this.testDataTypeService = null;
    }
    
    /**
     * Creates a new TestMemoryService with DataTypeService
     *
     * @param testProgramService the test program service for accessing the current program
     * @param testDataTypeService the test data type service for resolving data types
     */
    public TestMemoryService(TestProgramService testProgramService, TestDataTypeService testDataTypeService) {
        super(testProgramService, testDataTypeService);
        this.testProgramService = testProgramService;
        this.testDataTypeService = testDataTypeService;
    }

    /**
     * List memory segments in the program with pagination
     *
     * @param offset starting index
     * @param limit maximum number of segments to return
     * @return list of memory segments with their address ranges
     */
    @Override
    public String listSegments(int offset, int limit) {
        Program program = testProgramService.getCurrentProgram();
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
    @Override
    public String listDefinedData(int offset, int limit) {
        Program program = testProgramService.getCurrentProgram();
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
     * For testing, we'll simplify this to avoid Swing threading issues
     *
     * @param addressStr address of the data to rename
     * @param newName new label name
     * @return true if successful, false otherwise
     */
    @Override
    public boolean renameDataAtAddress(String addressStr, String newName) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return false;

        // For testing, we'll run directly without Swing
        int tx = program.startTransaction("Rename data");
        boolean success = false;
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return false;
            }
            
            // Check if data exists at this address
            if (program.getListing().getDefinedDataAt(addr) != null) {
                SymbolTable symTable = program.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);
                
                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                    success = true;
                } else {
                    try {
                        symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        success = true;
                    } catch (InvalidInputException e) {
                        // Error creating label
                    }
                }
            }
        }
        catch (DuplicateNameException | InvalidInputException e) {
            // Rename error
        }
        finally {
            program.endTransaction(tx, success);
        }
        return success;
    }
    
    /**
     * Set the data type at a specific memory address
     * For testing, we'll simplify this to avoid Swing threading issues
     *
     * @param addressStr address where to set the data type
     * @param dataTypeName name of the data type to set
     * @param clearExisting whether to clear existing data at the address first
     * @return status message
     */
    @Override
    public String setMemoryDataType(String addressStr, String dataTypeName, boolean clearExisting) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (testDataTypeService == null) return "DataTypeService not available";
        
        // For testing, we'll run directly without Swing
        int tx = program.startTransaction("Set memory data type");
        String resultMessage;
        boolean success = false;
        
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                resultMessage = "Invalid address: " + addressStr;
                return resultMessage;
            }
            
            // Get the data type manager and resolve the type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = testDataTypeService.resolveDataType(dtm, dataTypeName);
            
            if (dataType == null) {
                resultMessage = "Data type not found: " + dataTypeName;
                return resultMessage;
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
                resultMessage = String.format("Data type '%s' (%d bytes) set at address %s",
                    dataType.getName(),
                    newData.getLength(),
                    addr.toString());
                success = true;
            } catch (CodeUnitInsertionException e) {
                // Try to provide more specific error information
                if (e.getMessage().contains("Conflicting")) {
                    resultMessage = "Failed to set data type: Conflicting data exists at address. " +
                                   "Try setting clear_existing=true to overwrite.";
                } else if (e.getMessage().contains("Insufficient")) {
                    resultMessage = "Failed to set data type: Insufficient space. " +
                                   "The data type requires more bytes than available.";
                } else {
                    resultMessage = "Failed to set data type: " + e.getMessage();
                }
            }
        }
        catch (Exception e) {
            resultMessage = "Failed to set memory data type: " + e.getMessage();
        }
        finally {
            program.endTransaction(tx, success);
        }
        
        return resultMessage;
    }
}