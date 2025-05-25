package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import com.lauriewired.mcp.utils.HttpUtils;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;

/**
 * Test-friendly version of DataTypeService that uses TestProgramService
 */
public class TestDataTypeService extends DataTypeService {
    private final TestProgramService testProgramService;

    /**
     * Creates a new TestDataTypeService
     *
     * @param testProgramService the test program service for accessing the current program
     */
    public TestDataTypeService(TestProgramService testProgramService) {
        super(testProgramService);
        this.testProgramService = testProgramService;
    }

    /**
     * List all structure/type definitions in the program with pagination
     *
     * @param offset starting index
     * @param limit maximum number of structures to return
     * @return list of structures
     */
    @Override
    public String listStructures(int offset, int limit) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return "No program loaded";

        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        List<Structure> structs = new ArrayList<>();
        // Get all structures from the data type manager
        dtm.getAllStructures().forEachRemaining((struct) -> {
            structs.add(struct);
        });
        Collections.sort(structs, Comparator.comparing(Structure::getName));  
        List<String> lines = new ArrayList<>();
        for (Structure struct : structs) {
            StringBuilder sb = new StringBuilder();
            sb.append(struct.getName()).append(": {");
            for (int i = 0; i < struct.getNumComponents(); i++) {
                DataTypeComponent comp = struct.getComponent(i);
                if (i > 0) sb.append(", ");
                sb.append(comp.getDataType().getName())
                .append(" ")
                .append(comp.getFieldName());
            }
            sb.append("}");
            lines.add(sb.toString());
        }
        return HttpUtils.paginateList(lines, offset, limit);
    }

    /**
     * Rename a field within a structure data type
     * Simplified for testing without Swing threading
     *
     * @param structName structure name
     * @param oldFieldName current field name
     * @param newFieldName new field name
     * @return status message
     */
    @Override
    public String renameStructField(String structName, String oldFieldName, String newFieldName) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || oldFieldName == null || newFieldName == null) {
            return "Structure name, old field name, and new field name are required";
        }

        boolean success = false;
        int tx = program.startTransaction("Rename struct field");
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            Structure struct = (Structure) dtm.getDataType("/" + structName);
            if (struct != null) {
                // Check if oldFieldName matches pattern "field<N>_0x<offset>"
                if (oldFieldName.matches("field\\d+_0x[0-9a-fA-F]+")) {
                    // Extract index number from field name
                    int index = Integer.parseInt(oldFieldName.substring(5, oldFieldName.indexOf('_')));
                    if (index >= 0 && index < struct.getNumComponents()) {
                        DataTypeComponent component = struct.getComponent(index);
                        struct.replace(index, component.getDataType(), component.getLength(), 
                                    newFieldName, component.getComment());
                        success = true;
                    }
                } else {
                    // Original logic for named fields
                    for (int i = 0; i < struct.getNumComponents(); i++) {
                        DataTypeComponent component = struct.getComponent(i);
                        if ((component.getFieldName() != null) && 
                            component.getFieldName().equals(oldFieldName)) {
                            struct.replace(i, component.getDataType(), component.getLength(),
                                        newFieldName, component.getComment());
                            success = true;
                            break;
                        }
                    }
                }
            }
        }
        catch (Exception e) {
            // Error renaming struct field
        }
        finally {
            program.endTransaction(tx, success);
        }

        return success ? "Field renamed successfully" : "Failed to rename field";
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     *
     * @param dtm data type manager
     * @param typeName name of the data type to find
     * @return the data type if found, null otherwise
     */
    @Override
    public DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        if (dtm == null || typeName == null || typeName.isEmpty()) {
            return null;
        }
        
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }
        
        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }
    
    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    /**
     * Resolve a data type name to a DataType object
     * Handles built-in types, pointer types, and user-defined types
     *
     * @param dtm data type manager
     * @param typeName name of the data type to resolve
     * @return resolved data type or default type if not found
     */
    @Override
    public DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (dtm == null || typeName == null || typeName.isEmpty()) {
            return null;
        }
        
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            return dataType;
        }
        
        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
        }
        
        // Return null if not found
        return null;
    }
}