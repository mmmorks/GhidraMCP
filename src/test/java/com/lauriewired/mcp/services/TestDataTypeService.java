package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import com.lauriewired.mcp.utils.HttpUtils;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
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

    /**
     * Create a new structure data type
     * Simplified for testing without Swing threading
     *
     * @param structName name of the structure to create
     * @param size size of the structure in bytes (0 for auto-size)
     * @param categoryPath category path for the structure (e.g., "/MyStructures")
     * @return status message
     */
    @Override
    public String createStructure(String structName, int size, String categoryPath) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) {
            return "Structure name is required";
        }

        String resultMessage = null;
        int tx = program.startTransaction("Create structure");
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            
            // Check if structure already exists
            DataType existing = findDataTypeByNameInAllCategories(dtm, structName);
            if (existing != null && existing instanceof Structure) {
                resultMessage = "Structure '" + structName + "' already exists";
                return resultMessage;
            }
            
            // Create category path if specified
            CategoryPath catPath = CategoryPath.ROOT;
            if (categoryPath != null && !categoryPath.isEmpty()) {
                catPath = new CategoryPath(categoryPath);
            }
            
            // Create the structure
            StructureDataType struct = new StructureDataType(catPath, structName, size, dtm);
            
            // Add the structure to the data type manager
            DataType addedType = dtm.addDataType(struct, null);
            
            resultMessage = "Structure '" + structName + "' created successfully at " +
                            addedType.getCategoryPath().getPath();
        }
        catch (Exception e) {
            resultMessage = "Failed to create structure: " + e.getMessage();
        }
        finally {
            program.endTransaction(tx, resultMessage != null &&
                                 resultMessage.contains("successfully"));
        }

        return resultMessage;
    }

    /**
     * Add a field to an existing structure
     * Simplified for testing without Swing threading
     *
     * @param structName name of the structure
     * @param fieldName name of the field to add
     * @param fieldType data type of the field
     * @param fieldSize size of the field (for fixed-size types)
     * @param offset offset in the structure (-1 to append)
     * @param comment optional comment for the field
     * @return status message
     */
    @Override
    public String addStructureField(String structName, String fieldName, String fieldType,
                                  int fieldSize, int offset, String comment) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || fieldType == null) {
            return "Structure name and field type are required";
        }

        String resultMessage = null;
        int tx = program.startTransaction("Add structure field");
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            
            // Find the structure
            DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
            if (!(dt instanceof Structure)) {
                resultMessage = "Structure '" + structName + "' not found";
                return resultMessage;
            }
            
            Structure struct = (Structure) dt;
            
            // Resolve the field data type
            DataType fieldDataType = resolveDataType(dtm, fieldType);
            if (fieldDataType == null) {
                resultMessage = "Failed to resolve data type: " + fieldType;
                return resultMessage;
            }
            
            // Add the field
            if (offset >= 0) {
                // Insert at specific offset
                struct.insertAtOffset(offset, fieldDataType, fieldSize, fieldName, comment);
            } else {
                // Append to end
                struct.add(fieldDataType, fieldSize, fieldName, comment);
            }
            
            resultMessage = "Field '" + (fieldName != null ? fieldName : "unnamed") +
                            "' added to structure '" + structName + "'";
        }
        catch (Exception e) {
            resultMessage = "Failed to add field: " + e.getMessage();
        }
        finally {
            program.endTransaction(tx, resultMessage != null &&
                                 resultMessage.contains("added"));
        }

        return resultMessage;
    }

    /**
     * Create a new enum data type
     * Simplified for testing without Swing threading
     *
     * @param enumName name of the enum to create
     * @param size size of the enum in bytes (1, 2, 4, or 8)
     * @param categoryPath category path for the enum (e.g., "/MyEnums")
     * @return status message
     */
    @Override
    public String createEnum(String enumName, int size, String categoryPath) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || enumName.isEmpty()) {
            return "Enum name is required";
        }
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return "Enum size must be 1, 2, 4, or 8 bytes";
        }

        String resultMessage = null;
        int tx = program.startTransaction("Create enum");
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            
            // Check if enum already exists
            DataType existing = findDataTypeByNameInAllCategories(dtm, enumName);
            if (existing != null && existing instanceof EnumDataType) {
                resultMessage = "Enum '" + enumName + "' already exists";
                return resultMessage;
            }
            
            // Create category path if specified
            CategoryPath catPath = CategoryPath.ROOT;
            if (categoryPath != null && !categoryPath.isEmpty()) {
                catPath = new CategoryPath(categoryPath);
            }
            
            // Create the enum
            EnumDataType enumType = new EnumDataType(catPath, enumName, size, dtm);
            
            // Add the enum to the data type manager
            DataType addedType = dtm.addDataType(enumType, null);
            
            resultMessage = "Enum '" + enumName + "' created successfully at " +
                            addedType.getCategoryPath().getPath();
        }
        catch (Exception e) {
            resultMessage = "Failed to create enum: " + e.getMessage();
        }
        finally {
            program.endTransaction(tx, resultMessage != null &&
                                 resultMessage.contains("successfully"));
        }

        return resultMessage;
    }

    /**
     * Add a value to an existing enum
     * Simplified for testing without Swing threading
     *
     * @param enumName name of the enum
     * @param valueName name of the enum value
     * @param value numeric value
     * @return status message
     */
    @Override
    public String addEnumValue(String enumName, String valueName, long value) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || valueName == null) {
            return "Enum name and value name are required";
        }

        String resultMessage = null;
        int tx = program.startTransaction("Add enum value");
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            
            // Find the enum
            DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
            if (!(dt instanceof EnumDataType)) {
                resultMessage = "Enum '" + enumName + "' not found";
                return resultMessage;
            }
            
            EnumDataType enumType = (EnumDataType) dt;
            
            // Add the value
            enumType.add(valueName, value);
            
            resultMessage = "Value '" + valueName + "' (" + value +
                            ") added to enum '" + enumName + "'";
        }
        catch (Exception e) {
            resultMessage = "Failed to add enum value: " + e.getMessage();
        }
        finally {
            program.endTransaction(tx, resultMessage != null &&
                                 resultMessage.contains("added"));
        }

        return resultMessage;
    }

    /**
     * List all enums in the program with pagination
     *
     * @param offset starting index
     * @param limit maximum number of enums to return
     * @return list of enums
     */
    @Override
    public String listEnums(int offset, int limit) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return "No program loaded";

        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        List<EnumDataType> enums = new ArrayList<>();
        
        // Get all enums from the data type manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt instanceof EnumDataType) {
                enums.add((EnumDataType) dt);
            }
        }
        
        Collections.sort(enums, Comparator.comparing(EnumDataType::getName));
        
        List<String> lines = new ArrayList<>();
        for (EnumDataType enumType : enums) {
            StringBuilder sb = new StringBuilder();
            sb.append(enumType.getName()).append(" (").append(enumType.getLength()).append(" bytes): {");
            
            String[] names = enumType.getNames();
            for (int i = 0; i < names.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append(names[i]).append("=").append(enumType.getValue(names[i]));
            }
            sb.append("}");
            lines.add(sb.toString());
        }
        
        return HttpUtils.paginateList(lines, offset, limit);
    }
}