package com.lauriewired.mcp.services;

import com.lauriewired.mcp.utils.HttpUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service for memory and data-related operations
 */
public class MemoryService {
    private final ProgramService programService;

    /**
     * Creates a new MemoryService
     *
     * @param programService the program service for accessing the current program
     */
    public MemoryService(ProgramService programService) {
        this.programService = programService;
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
                            } catch (Exception e) {
                                Msg.error(this, "Failed to create label: " + e.getMessage());
                            }
                        }
                    } else {
                        Msg.error(this, "No defined data at address: " + addressStr);
                    }
                }
                catch (Exception e) {
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
}
