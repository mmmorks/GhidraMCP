package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.List;

import com.lauriewired.mcp.utils.HttpUtils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test-friendly version of MemoryService that uses TestProgramService
 */
public class TestMemoryService extends MemoryService {
    private final TestProgramService testProgramService;

    /**
     * Creates a new TestMemoryService
     *
     * @param testProgramService the test program service for accessing the current program
     */
    public TestMemoryService(TestProgramService testProgramService) {
        super(testProgramService);
        this.testProgramService = testProgramService;
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
}