package com.lauriewired.mcp.services;

import java.util.Iterator;
import java.util.Map;

import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.TextOutput;
import com.lauriewired.mcp.model.ToolOutput;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
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
     * Bulk update a structure
     * Simplified for testing without ProgramTransaction (uses manual transaction)
     */
    @Override
    public ToolOutput updateStructure(String name, String newName, Integer size,
                                   Map<String, String> fieldRenames,
                                   Map<String, String> typeChanges) {
        if (name == null || name.isEmpty()) {
            return StatusOutput.error("Structure name is required");
        }
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        int tx = program.startTransaction("Update structure");
        boolean success = false;
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByNameInAllCategories(dtm, name);
            if (!(dt instanceof Structure)) {
                return StatusOutput.error("Structure '" + name + "' not found");
            }
            Structure struct = (Structure) dt;

            // Delegate field-level logic to the parent class helper
            // For testing, we re-implement the core logic inline
            java.util.List<String> results = new java.util.ArrayList<>();
            int succeeded = 0;
            int failed = 0;

            java.util.Set<String> existingNames = new java.util.HashSet<>();
            for (int i = 0; i < struct.getNumComponents(); i++) {
                DataTypeComponent comp = struct.getComponent(i);
                String fn = comp.getFieldName();
                if (fn != null) existingNames.add(fn);
            }

            java.util.Map<String, String> reverseRenames = new java.util.HashMap<>();
            if (fieldRenames != null) {
                for (var entry : fieldRenames.entrySet()) {
                    reverseRenames.put(entry.getValue(), entry.getKey());
                }
            }

            java.util.Map<String, String> resolvedTypeChanges = new java.util.LinkedHashMap<>();
            if (typeChanges != null) {
                for (var entry : typeChanges.entrySet()) {
                    String key = entry.getKey();
                    String resolved = resolveFieldKey(key, reverseRenames, existingNames);
                    if (resolved.startsWith("ERROR:")) {
                        results.add("  " + key + " -> " + resolved.substring(6) + " [FAILED]");
                        failed++;
                    } else {
                        resolvedTypeChanges.put(resolved, entry.getValue());
                    }
                }
            }

            if (fieldRenames != null) {
                for (var entry : fieldRenames.entrySet()) {
                    String oldFieldName = entry.getKey();
                    String newFieldName = entry.getValue();
                    String newTypeName = resolvedTypeChanges.remove(oldFieldName);

                    int idx = -1;
                    for (int i = 0; i < struct.getNumComponents(); i++) {
                        DataTypeComponent comp = struct.getComponent(i);
                        if (comp.getFieldName() != null && comp.getFieldName().equals(oldFieldName)) {
                            idx = i;
                            break;
                        }
                    }
                    if (idx < 0) {
                        results.add("  " + oldFieldName + " -> not found [FAILED]");
                        failed++;
                        continue;
                    }

                    DataTypeComponent comp = struct.getComponent(idx);
                    DataType fieldType = comp.getDataType();
                    int fieldLen = comp.getLength();

                    if (newTypeName != null) {
                        DataType resolved = resolveDataType(dtm, newTypeName);
                        if (resolved != null) {
                            fieldType = resolved;
                            fieldLen = resolved.getLength();
                        }
                    }

                    struct.replace(idx, fieldType, fieldLen, newFieldName, comp.getComment());
                    StringBuilder msg = new StringBuilder("  " + oldFieldName + " -> renamed to '" + newFieldName + "'");
                    if (newTypeName != null) msg.append(", type changed to '").append(newTypeName).append("'");
                    msg.append(" [OK]");
                    results.add(msg.toString());
                    succeeded++;
                }
            }

            for (var entry : resolvedTypeChanges.entrySet()) {
                String fieldName = entry.getKey();
                String newTypeName = entry.getValue();
                int idx = -1;
                for (int i = 0; i < struct.getNumComponents(); i++) {
                    DataTypeComponent comp = struct.getComponent(idx != -1 ? idx : i);
                    if (comp.getFieldName() != null && comp.getFieldName().equals(fieldName)) {
                        idx = i;
                        break;
                    }
                }
                if (idx < 0) {
                    results.add("  " + fieldName + " -> not found [FAILED]");
                    failed++;
                    continue;
                }
                DataTypeComponent comp = struct.getComponent(idx);
                DataType resolved = resolveDataType(dtm, newTypeName);
                if (resolved == null) {
                    results.add("  " + fieldName + " -> type '" + newTypeName + "' not found [FAILED]");
                    failed++;
                    continue;
                }
                struct.replace(idx, resolved, resolved.getLength(), comp.getFieldName(), comp.getComment());
                results.add("  " + fieldName + " -> type changed to '" + newTypeName + "' [OK]");
                succeeded++;
            }

            if (size != null && size > struct.getLength()) {
                struct.growStructure(size - struct.getLength());
                results.add("Size changed to " + size + " bytes");
            }

            if (newName != null && !newName.isEmpty()) {
                try {
                    dt.setName(newName);
                    results.add("Struct renamed from '" + name + "' to '" + newName + "'");
                } catch (Exception e) {
                    results.add("Struct rename failed: " + e.getMessage() + " [FAILED]");
                    failed++;
                }
            }

            success = true;

            StringBuilder sb = new StringBuilder("Updated structure '" + name + "':\n");
            for (String r : results) sb.append(r).append("\n");
            sb.append("Summary: ").append(succeeded).append(" succeeded, ").append(failed).append(" failed");
            return new TextOutput(sb.toString());
        } catch (Exception e) {
            return StatusOutput.error("Failed to update structure: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success);
        }
    }

    /**
     * Bulk update an enum
     * Simplified for testing without ProgramTransaction (uses manual transaction)
     */
    @Override
    public ToolOutput updateEnum(String name, String newName, Integer size,
                              Map<String, String> valueRenames,
                              Map<String, Long> valueChanges) {
        if (name == null || name.isEmpty()) {
            return StatusOutput.error("Enum name is required");
        }
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        int tx = program.startTransaction("Update enum");
        boolean success = false;
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByNameInAllCategories(dtm, name);
            if (!(dt instanceof Enum)) {
                return StatusOutput.error("Enum '" + name + "' not found");
            }
            Enum enumType = (Enum) dt;

            java.util.List<String> results = new java.util.ArrayList<>();
            int succeeded = 0;
            int failed = 0;

            java.util.Set<String> existingNames = new java.util.HashSet<>();
            for (String n : enumType.getNames()) {
                existingNames.add(n);
            }

            java.util.Map<String, String> reverseRenames = new java.util.HashMap<>();
            if (valueRenames != null) {
                for (var entry : valueRenames.entrySet()) {
                    reverseRenames.put(entry.getValue(), entry.getKey());
                }
            }

            java.util.Map<String, Long> resolvedValueChanges = new java.util.LinkedHashMap<>();
            if (valueChanges != null) {
                for (var entry : valueChanges.entrySet()) {
                    String key = entry.getKey();
                    String resolved = resolveFieldKey(key, reverseRenames, existingNames);
                    if (resolved.startsWith("ERROR:")) {
                        results.add("  " + key + " -> " + resolved.substring(6) + " [FAILED]");
                        failed++;
                    } else {
                        resolvedValueChanges.put(resolved, entry.getValue());
                    }
                }
            }

            if (valueRenames != null) {
                for (var entry : valueRenames.entrySet()) {
                    String oldValName = entry.getKey();
                    String newValName = entry.getValue();
                    if (!existingNames.contains(oldValName)) {
                        results.add("  " + oldValName + " -> not found [FAILED]");
                        failed++;
                        continue;
                    }
                    long currentValue = enumType.getValue(oldValName);
                    Long newValue = resolvedValueChanges.remove(oldValName);
                    long finalValue = (newValue != null) ? newValue : currentValue;
                    enumType.remove(oldValName);
                    enumType.add(newValName, finalValue);
                    StringBuilder msg = new StringBuilder("  " + oldValName + " -> renamed to '" + newValName + "'");
                    if (newValue != null) msg.append(", value changed to ").append(finalValue);
                    msg.append(" [OK]");
                    results.add(msg.toString());
                    succeeded++;
                }
            }

            for (var entry : resolvedValueChanges.entrySet()) {
                String valName = entry.getKey();
                long newValue = entry.getValue();
                if (!existingNames.contains(valName)) {
                    results.add("  " + valName + " -> not found [FAILED]");
                    failed++;
                    continue;
                }
                enumType.remove(valName);
                enumType.add(valName, newValue);
                results.add("  " + valName + " -> value changed to " + newValue + " [OK]");
                succeeded++;
            }

            if (newName != null && !newName.isEmpty()) {
                try {
                    dt.setName(newName);
                    results.add("Enum renamed from '" + name + "' to '" + newName + "'");
                } catch (Exception e) {
                    results.add("Enum rename failed: " + e.getMessage() + " [FAILED]");
                    failed++;
                }
            }

            success = true;

            StringBuilder sb = new StringBuilder("Updated enum '" + name + "':\n");
            for (String r : results) sb.append(r).append("\n");
            sb.append("Summary: ").append(succeeded).append(" succeeded, ").append(failed).append(" failed");
            return new TextOutput(sb.toString());
        } catch (Exception e) {
            return StatusOutput.error("Failed to update enum: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success);
        }
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
    public ToolOutput addStructureField(String structName, String fieldName, String fieldType,
                                  int fieldSize, int offset, String comment) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (structName == null || fieldType == null) {
            return StatusOutput.error("Structure name and field type are required");
        }

        String resultMessage = null;
        int tx = program.startTransaction("Add structure field");
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            
            // Find the structure
            DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
            if (!(dt instanceof Structure)) {
                resultMessage = "Structure '" + structName + "' not found";
                return StatusOutput.error(resultMessage);
            }
            
            Structure struct = (Structure) dt;
            
            // Resolve the field data type
            DataType fieldDataType = resolveDataType(dtm, fieldType);
            if (fieldDataType == null) {
                resultMessage = "Failed to resolve data type: " + fieldType;
                return StatusOutput.error(resultMessage);
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

        if (resultMessage != null && resultMessage.contains("added")) {
            return StatusOutput.ok(resultMessage);
        }
        return StatusOutput.error(resultMessage);
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
    public ToolOutput addEnumValue(String enumName, String valueName, long value) {
        Program program = testProgramService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (enumName == null || valueName == null) {
            return StatusOutput.error("Enum name and value name are required");
        }

        String resultMessage = null;
        int tx = program.startTransaction("Add enum value");
        try {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            
            // Find the enum
            DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
            if (!(dt instanceof EnumDataType)) {
                resultMessage = "Enum '" + enumName + "' not found";
                return StatusOutput.error(resultMessage);
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

        if (resultMessage != null && resultMessage.contains("added")) {
            return StatusOutput.ok(resultMessage);
        }
        return StatusOutput.error(resultMessage);
    }

}