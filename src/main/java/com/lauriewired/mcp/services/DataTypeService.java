package com.lauriewired.mcp.services;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.PaginationResult;
import com.lauriewired.mcp.utils.HttpUtils;
import com.lauriewired.mcp.utils.ProgramTransaction;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.UniversalID;

/**
 * Service for data type and structure-related operations
 */
public class DataTypeService {
    private final ProgramService programService;
    
    // Pattern to match array syntax like "type[size]"
    private static final Pattern ARRAY_PATTERN = Pattern.compile("^(.+?)\\[([0-9]+)\\]$");

    /**
     * Creates a new DataTypeService
     *
     * @param programService the program service for accessing the current program
     */
    public DataTypeService(ProgramService programService) {
        this.programService = programService;
    }

    /**
     * List all structure/type definitions in the program with pagination and LLM-friendly hints
     *
     * @param offset starting index
     * @param limit maximum number of structures to return
     * @return paginated list of structures with pagination metadata
     */
    public String listStructures(int offset, int limit) {
        Program program = programService.getCurrentProgram();
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
        
        PaginationResult result = HttpUtils.paginateListWithHints(lines, offset, limit);
        return result.getFormattedResult();
    }

    @McpTool(post = true, description = """
        Bulk update a structure: rename fields, change field types, resize, and/or rename.

        All changes are applied in a single transaction with per-field error reporting.

        Returns: Per-field results with success/failure status and summary

        Note: For auto-generated field names like "field1_0x10", the number after "field"
        is the component index. type_changes keys are resolved against both existing field
        names and rename targets; ambiguous keys produce an error for that entry.

        Example: update_structure("MyStruct", field_renames={"field0_0x0": "width"},
                                  type_changes={"width": "int"}) """)
    public String updateStructure(
            @Param("Current structure name") String name,
            @Param(value = "New name for the structure (optional)", defaultValue = "") String newName,
            @Param(value = "New size in bytes (optional, only grows)", defaultValue = "") Integer size,
            @Param(value = "Map of old field name to new field name", defaultValue = "") Map<String, String> fieldRenames,
            @Param(value = "Map of field name to new data type", defaultValue = "") Map<String, String> typeChanges) {
        if (name == null || name.isEmpty()) {
            return "Structure name is required";
        }
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        try (var tx = ProgramTransaction.start(program, "Update structure")) {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByNameInAllCategories(dtm, name);
            if (!(dt instanceof Structure)) {
                return "Structure '" + name + "' not found";
            }
            Structure struct = (Structure) dt;

            List<String> results = new ArrayList<>();
            int succeeded = 0;
            int failed = 0;

            // Build set of existing field names
            Set<String> existingNames = new HashSet<>();
            for (int i = 0; i < struct.getNumComponents(); i++) {
                DataTypeComponent comp = struct.getComponent(i);
                String fn = comp.getFieldName();
                if (fn != null) existingNames.add(fn);
            }

            // Build reverse lookup: new_name -> old_name from fieldRenames
            Map<String, String> reverseRenames = new HashMap<>();
            if (fieldRenames != null) {
                for (Map.Entry<String, String> entry : fieldRenames.entrySet()) {
                    reverseRenames.put(entry.getValue(), entry.getKey());
                }
            }

            // Resolve typeChanges keys to old field names
            Map<String, String> resolvedTypeChanges = new LinkedHashMap<>();
            if (typeChanges != null) {
                for (Map.Entry<String, String> entry : typeChanges.entrySet()) {
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

            // Apply field renames and type changes
            if (fieldRenames != null) {
                for (Map.Entry<String, String> entry : fieldRenames.entrySet()) {
                    String oldFieldName = entry.getKey();
                    String newFieldName = entry.getValue();
                    String newTypeName = resolvedTypeChanges.remove(oldFieldName);

                    int idx = findComponentIndex(struct, oldFieldName);
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
                        } else {
                            results.add("  " + oldFieldName + " -> renamed to '" + newFieldName +
                                    "', type '" + newTypeName + "' not found [PARTIAL]");
                            struct.replace(idx, comp.getDataType(), comp.getLength(),
                                    newFieldName, comp.getComment());
                            succeeded++;
                            continue;
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

            // Apply remaining type-only changes (not covered by renames)
            for (Map.Entry<String, String> entry : resolvedTypeChanges.entrySet()) {
                String fieldName = entry.getKey();
                String newTypeName = entry.getValue();

                int idx = findComponentIndex(struct, fieldName);
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

                struct.replace(idx, resolved, resolved.getLength(),
                        comp.getFieldName(), comp.getComment());
                results.add("  " + fieldName + " -> type changed to '" + newTypeName + "' [OK]");
                succeeded++;
            }

            // Apply size change
            if (size != null && size > struct.getLength()) {
                struct.growStructure(size - struct.getLength());
                results.add("Size changed to " + size + " bytes");
            }

            // Rename struct last
            if (newName != null && !newName.isEmpty()) {
                try {
                    dt.setName(newName);
                    results.add("Struct renamed from '" + name + "' to '" + newName + "'");
                } catch (Exception e) {
                    results.add("Struct rename failed: " + e.getMessage() + " [FAILED]");
                    failed++;
                }
            }

            tx.commit();

            StringBuilder sb = new StringBuilder("Updated structure '" + name + "':\n");
            for (String r : results) sb.append(r).append("\n");
            sb.append("Summary: ").append(succeeded).append(" succeeded, ").append(failed).append(" failed");
            return sb.toString();
        } catch (Exception e) {
            Msg.error(this, "Error updating structure", e);
            return "Failed to update structure: " + e.getMessage();
        }
    }

    @McpTool(post = true, description = """
        Bulk update an enum: rename values, change numeric values, resize, and/or rename.

        All changes are applied in a single transaction with per-entry error reporting.

        Returns: Per-entry results with success/failure status and summary

        Note: value_changes keys are resolved against both existing value names and
        rename targets; ambiguous keys produce an error for that entry.

        Example: update_enum("MyFlags", new_name="FilePermissions",
                             value_renames={"OLD_VAL": "NEW_VAL"},
                             value_changes={"NEW_VAL": 42}) """)
    public String updateEnum(
            @Param("Current enum name") String name,
            @Param(value = "New name for the enum (optional)", defaultValue = "") String newName,
            @Param(value = "New size in bytes \u2014 must be 1, 2, 4, or 8 (optional)", defaultValue = "") Integer size,
            @Param(value = "Map of old value name to new value name", defaultValue = "") Map<String, String> valueRenames,
            @Param(value = "Map of value name to new numeric value", defaultValue = "") Map<String, Long> valueChanges) {
        if (name == null || name.isEmpty()) {
            return "Enum name is required";
        }
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        try (var tx = ProgramTransaction.start(program, "Update enum")) {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByNameInAllCategories(dtm, name);
            if (!(dt instanceof Enum)) {
                return "Enum '" + name + "' not found";
            }
            Enum enumType = (Enum) dt;

            List<String> results = new ArrayList<>();
            int succeeded = 0;
            int failed = 0;

            // Build set of existing value names
            Set<String> existingNames = new HashSet<>();
            for (String n : enumType.getNames()) {
                existingNames.add(n);
            }

            // Build reverse lookup: new_name -> old_name from valueRenames
            Map<String, String> reverseRenames = new HashMap<>();
            if (valueRenames != null) {
                for (Map.Entry<String, String> entry : valueRenames.entrySet()) {
                    reverseRenames.put(entry.getValue(), entry.getKey());
                }
            }

            // Resolve valueChanges keys to old value names
            Map<String, Long> resolvedValueChanges = new LinkedHashMap<>();
            if (valueChanges != null) {
                for (Map.Entry<String, Long> entry : valueChanges.entrySet()) {
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

            // Phase 1: Gather current values and remove entries that need updating
            // Phase 2: Re-add with new names/values
            if (valueRenames != null) {
                for (Map.Entry<String, String> entry : valueRenames.entrySet()) {
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

            // Apply remaining value-only changes
            for (Map.Entry<String, Long> entry : resolvedValueChanges.entrySet()) {
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

            // Apply size change
            if (size != null) {
                if (size != 1 && size != 2 && size != 4 && size != 8) {
                    results.add("Invalid enum size: " + size + " (must be 1, 2, 4, or 8) [FAILED]");
                    failed++;
                } else {
                    // Ghidra doesn't expose a direct setLength — we update via internal API
                    // The Enum interface doesn't have setLength, but we can cast if needed
                    // For now, report size change only if it differs
                    if (size != enumType.getLength()) {
                        results.add("Size change to " + size + " bytes not supported on existing enum [FAILED]");
                        failed++;
                    }
                }
            }

            // Rename enum last
            if (newName != null && !newName.isEmpty()) {
                try {
                    dt.setName(newName);
                    results.add("Enum renamed from '" + name + "' to '" + newName + "'");
                } catch (Exception e) {
                    results.add("Enum rename failed: " + e.getMessage() + " [FAILED]");
                    failed++;
                }
            }

            tx.commit();

            StringBuilder sb = new StringBuilder("Updated enum '" + name + "':\n");
            for (String r : results) sb.append(r).append("\n");
            sb.append("Summary: ").append(succeeded).append(" succeeded, ").append(failed).append(" failed");
            return sb.toString();
        } catch (Exception e) {
            Msg.error(this, "Error updating enum", e);
            return "Failed to update enum: " + e.getMessage();
        }
    }

    /**
     * Resolve a key that may be an existing field/value name or a new name from a rename map.
     *
     * @param key the key to resolve
     * @param reverseRenames map of new_name -> old_name
     * @param existingNames set of currently existing names
     * @return the resolved old name, or "ERROR:message" if ambiguous or not found
     */
    String resolveFieldKey(String key, Map<String, String> reverseRenames, Set<String> existingNames) {
        boolean isExisting = existingNames.contains(key);
        String oldFromRename = reverseRenames.get(key);
        boolean isNewName = oldFromRename != null;

        if (isExisting && isNewName && !key.equals(oldFromRename)) {
            return "ERROR:Ambiguous key '" + key + "': matches existing field '" + key +
                    "' and rename target from '" + oldFromRename + "'";
        }
        if (isExisting) return key;
        if (isNewName) return oldFromRename;
        return "ERROR:Field '" + key + "' not found";
    }

    /**
     * Find the component index for a field by name, supporting auto-generated names like "field0_0x0".
     */
    private int findComponentIndex(Structure struct, String fieldName) {
        if (fieldName.matches("field\\d+_0x[0-9a-fA-F]+")) {
            int index = Integer.parseInt(fieldName.substring(5, fieldName.indexOf('_')));
            if (index >= 0 && index < struct.getNumComponents()) return index;
            return -1;
        }
        for (int i = 0; i < struct.getNumComponents(); i++) {
            DataTypeComponent comp = struct.getComponent(i);
            if (comp.getFieldName() != null && comp.getFieldName().equals(fieldName)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     *
     * @param dtm data type manager
     * @param typeName name of the data type to find
     * @return the data type if found, null otherwise
     */
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
    public DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (dtm == null || typeName == null || typeName.isEmpty()) {
            return null;
        }
        
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            return dataType;
        }
        
        // Check for array syntax like "type[size]"
        Matcher arrayMatcher = ARRAY_PATTERN.matcher(typeName);
        if (arrayMatcher.matches()) {
            String baseTypeName = arrayMatcher.group(1);
            String sizeStr = arrayMatcher.group(2);
            
            try {
                int arraySize = Integer.parseInt(sizeStr);
                if (arraySize > 0 && arraySize <= 1000000) { // Reasonable size limits
                    // Recursively resolve the base type
                    DataType baseType = resolveDataType(dtm, baseTypeName);
                    if (baseType != null) {
                        ArrayDataType arrayType = new ArrayDataType(baseType, arraySize, baseType.getLength(), dtm);
                        return arrayType;
                    }
                }
            } catch (NumberFormatException e) {
                // Invalid array size format, will fall through to other type resolution
            }
        }
        
        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);
            
            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new ghidra.program.model.data.PointerDataType(dtm.getDataType("/void"));
            }
            
            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new ghidra.program.model.data.PointerDataType(baseType);
            }
            
            // Base type not found, fall back to void*
            return new ghidra.program.model.data.PointerDataType(dtm.getDataType("/void"));
        }
        
        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int", "long" -> {
                return dtm.getDataType("/int");
            }
            case "uint", "unsigned int", "unsigned long", "dword" -> {
                return dtm.getDataType("/uint");
            }
            case "short" -> {
                return dtm.getDataType("/short");
            }
            case "ushort", "unsigned short", "word" -> {
                return dtm.getDataType("/ushort");
            }
            case "char", "byte" -> {
                return dtm.getDataType("/char");
            }
            case "uchar", "unsigned char" -> {
                return dtm.getDataType("/uchar");
            }
            case "longlong", "__int64" -> {
                return dtm.getDataType("/longlong");
            }
            case "ulonglong", "unsigned __int64" -> {
                return dtm.getDataType("/ulonglong");
            }
            case "bool", "boolean" -> {
                return dtm.getDataType("/bool");
            }
            case "void" -> {
                return dtm.getDataType("/void");
            }
            default -> {
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }
                
                // Could not resolve type
                return null;
            }
        }
    }

    /**
     * Create a new structure data type
     *
     * @param structName name of the structure to create
     * @param size size of the structure in bytes (0 for auto-size)
     * @param categoryPath category path for the structure (e.g., "/MyStructures")
     * @return status message
     */
    public String createStructure(String structName, int size, String categoryPath) {
        return createStructure(structName, size, categoryPath, null);
    }

    @McpTool(post = true, description = """
        Create a new structure data type in Ghidra, optionally with inline fields.

        Creates a structure with the specified name, and when fields are provided,
        adds all fields in a single transaction \u2014 avoiding the multi-step
        create \u2192 add_field \u2192 add_field dance.

        Returns: Success message with path or error message

        Note: Structure names must be unique. Use add_structure_field to add fields to existing structs.

        Example: create_structure("POINT", 0, "", [["x", "int"], ["y", "int"]]) """)
    public String createStructure(
            @Param("Name of the structure to create") String name,
            @Param(value = "Size in bytes (0 for auto-size based on fields)", defaultValue = "0") int size,
            @Param(value = "Category path like \"/MyStructures\" (empty for root)", defaultValue = "") String categoryPath,
            @Param(value = "Optional list of [field_name, data_type] pairs to add immediately", defaultValue = "") List<String[]> fields) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) {
            return "Structure name is required";
        }

        try (var tx = ProgramTransaction.start(program, "Create structure")) {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

            DataType existing = findDataTypeByNameInAllCategories(dtm, name);
            if (existing != null && existing instanceof Structure) {
                return "Structure '" + name + "' already exists";
            }

            CategoryPath catPath = CategoryPath.ROOT;
            if (categoryPath != null && !categoryPath.isEmpty()) {
                catPath = new CategoryPath(categoryPath);
            }

            StructureDataType struct = new StructureDataType(catPath, name, size, dtm);

            // Add inline fields if provided
            if (fields != null && !fields.isEmpty()) {
                for (String[] field : fields) {
                    if (field.length < 2) continue;
                    String fieldName = field[0];
                    String fieldTypeName = field[1];
                    DataType fieldType = resolveDataType(dtm, fieldTypeName);
                    if (fieldType == null) {
                        return "Failed to resolve field type '" + fieldTypeName +
                               "' for field '" + fieldName + "'";
                    }
                    struct.add(fieldType, -1, fieldName, null);
                }
            }

            DataType addedType = dtm.addDataType(struct, null);

            tx.commit();
            String msg = "Structure '" + name + "' created successfully at " +
                    addedType.getCategoryPath().getPath();
            if (fields != null && !fields.isEmpty()) {
                msg += " with " + fields.size() + " fields";
            }
            return msg;
        } catch (Exception e) {
            Msg.error(this, "Error creating structure", e);
            return "Failed to create structure: " + e.getMessage();
        }
    }

    @McpTool(post = true, description = """
        Add a field to an existing structure.

        Adds a new field with specified type at given offset or appends to end.

        Returns: Success or error message

        Note: Field types can be built-in types, typedefs, or other structures/enums.

        Example: add_structure_field("MY_STRUCT", "count", "int") -> "Field 'count' added to structure 'MY_STRUCT'" """)
    public String addStructureField(
            @Param("Name of the structure to modify") String structName,
            @Param("Name for the new field") String fieldName,
            @Param("Data type like \"int\", \"char\", \"DWORD\", or another struct name") String fieldType,
            @Param(value = "Size in bytes for fixed-size types (-1 for default)", defaultValue = "-1") int fieldSize,
            @Param(value = "Offset in structure to insert at (-1 to append)", defaultValue = "-1") int offset,
            @Param(value = "Optional comment for the field", defaultValue = "") String comment) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || fieldType == null) {
            return "Structure name and field type are required";
        }

        try (var tx = ProgramTransaction.start(program, "Add structure field")) {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

            DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
            if (!(dt instanceof Structure)) {
                return "Structure '" + structName + "' not found";
            }

            Structure struct = (Structure) dt;

            DataType fieldDataType = resolveDataType(dtm, fieldType);
            if (fieldDataType == null) {
                return "Failed to resolve data type: " + fieldType;
            }

            if (offset >= 0) {
                struct.insertAtOffset(offset, fieldDataType, fieldSize, fieldName, comment);
            } else {
                struct.add(fieldDataType, fieldSize, fieldName, comment);
            }

            tx.commit();
            return "Field '" + (fieldName != null ? fieldName : "unnamed") +
                    "' added to structure '" + structName + "'";
        } catch (RuntimeException e) {
            Msg.error(this, "Error adding structure field", e);
            return "Failed to add field: " + e.getMessage();
        }
    }

    /**
     * Create a new enum data type
     *
     * @param enumName name of the enum to create
     * @param size size of the enum in bytes (1, 2, 4, or 8)
     * @param categoryPath category path for the enum (e.g., "/MyEnums")
     * @return status message
     */
    public String createEnum(String enumName, int size, String categoryPath) {
        return createEnum(enumName, size, categoryPath, null);
    }

    @McpTool(post = true, description = """
        Create a new enum data type in Ghidra, optionally with inline values.

        Creates an enumeration with the specified name, and when values are provided,
        adds all values in a single transaction \u2014 avoiding the multi-step
        create \u2192 add_value \u2192 add_value dance.

        Returns: Success message with path or error message

        Note: Enum names must be unique. Use add_enum_value to add values to existing enums.

        Example: create_enum("FILE_FLAGS", 4, "", {"FLAG_READ": 1, "FLAG_WRITE": 2}) """)
    public String createEnum(
            @Param("Name of the enum to create") String name,
            @Param(value = "Size in bytes - must be 1, 2, 4, or 8 (default: 4)", defaultValue = "4") int size,
            @Param(value = "Category path like \"/MyEnums\" (empty for root)", defaultValue = "") String categoryPath,
            @Param(value = "Optional dictionary mapping value names to numeric values", defaultValue = "") Map<String, Long> values) {
        if (name == null || name.isEmpty()) {
            return "Enum name is required";
        }
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return "Enum size must be 1, 2, 4, or 8 bytes";
        }

        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        try (var tx = ProgramTransaction.start(program, "Create enum")) {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

            DataType existing = findDataTypeByNameInAllCategories(dtm, name);
            if (existing != null && existing instanceof Enum) {
                return "Enum '" + name + "' already exists";
            }

            CategoryPath catPath = CategoryPath.ROOT;
            if (categoryPath != null && !categoryPath.isEmpty()) {
                catPath = new CategoryPath(categoryPath);
            }

            EnumDataType enumType = new EnumDataType(catPath, name, size, dtm);

            // Add inline values if provided
            if (values != null && !values.isEmpty()) {
                for (var entry : values.entrySet()) {
                    enumType.add(entry.getKey(), entry.getValue());
                }
            }

            DataType addedType = dtm.addDataType(enumType, null);

            tx.commit();
            String msg = "Enum '" + name + "' created successfully at " +
                    addedType.getCategoryPath().getPath();
            if (values != null && !values.isEmpty()) {
                msg += " with " + values.size() + " values";
            }
            return msg;
        } catch (Exception e) {
            Msg.error(this, "Error creating enum", e);
            return "Failed to create enum: " + e.getMessage();
        }
    }

    @McpTool(post = true, description = """
        Add a value to an existing enum.

        Adds a named constant with numeric value to the enumeration.

        Returns: Success or error message

        Note: Value names must be unique within the enum. Values can be negative.

        Example: add_enum_value("MY_FLAGS", "FLAG_ENABLED", 0x01) -> "Value 'FLAG_ENABLED' (1) added to enum 'MY_FLAGS'" """)
    public String addEnumValue(
            @Param("Name of the enum to modify") String enumName,
            @Param("Name for the enum constant") String valueName,
            @Param("Numeric value for the constant") long value) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || valueName == null) {
            return "Enum name and value name are required";
        }

        try (var tx = ProgramTransaction.start(program, "Add enum value")) {
            ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

            DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
            if (dt instanceof Enum enumType) {
                enumType.add(valueName, value);
                tx.commit();
                return "Value '" + valueName + "' (" + value +
                        ") added to enum '" + enumName + "'";
            } else {
                return "Enum '" + enumName + "' not found";
            }
        } catch (Exception e) {
            Msg.error(this, "Error adding enum value", e);
            return "Failed to add enum value: " + e.getMessage();
        }
    }

    /**
     * List all enums in the program with pagination and LLM-friendly hints
     *
     * @param offset starting index
     * @param limit maximum number of enums to return
     * @return paginated list of enums with pagination metadata
     */
    public String listEnums(int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        List<Enum> enums = new ArrayList<>();
        
        // Get all enums from the data type manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt instanceof Enum enumDataType) {
                enums.add(enumDataType);
            }
        }
        
        Collections.sort(enums, Comparator.comparing(Enum::getName));
        
        List<String> lines = new ArrayList<>();
        for (Enum enumType : enums) {
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
        
        PaginationResult result = HttpUtils.paginateListWithHints(lines, offset, limit);
        return result.getFormattedResult();
    }
    
    /**
     * Get detailed information about a structure including all fields
     *
     * @param structureName name of the structure to get details for
     * @return detailed structure information
     */
    public String getStructureDetails(String structureName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        
        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        
        // Find the structure by name
        DataType dataType = dtm.getDataType("/" + structureName);
        if (dataType == null) {
            // Try searching in all categories
            Iterator<DataType> allTypes = dtm.getAllDataTypes();
            while (allTypes.hasNext()) {
                DataType dt = allTypes.next();
                if (dt.getName().equals(structureName) && dt instanceof Structure) {
                    dataType = dt;
                    break;
                }
            }
        }
        
        if (dataType == null || !(dataType instanceof Structure)) {
            return "Structure not found: " + structureName;
        }
        
        Structure struct = (Structure) dataType;
        StringBuilder result = new StringBuilder();
        
        // Structure header information
        result.append("Structure: ").append(struct.getName()).append("\n");
        result.append("Category: ").append(struct.getCategoryPath()).append("\n");
        result.append("Size: ").append(struct.getLength()).append(" bytes\n");
        result.append("Alignment: ").append(struct.getAlignment()).append("\n");
        result.append("Packed: ").append(struct.isPackingEnabled() ? "Yes" : "No").append("\n");
        result.append("Description: ").append(struct.getDescription() != null ? struct.getDescription() : "None").append("\n");
        result.append("\nFields:\n");
        
        // List all fields
        DataTypeComponent[] components = struct.getComponents();
        if (components.length == 0) {
            result.append("  (no fields defined)\n");
        } else {
            for (DataTypeComponent comp : components) {
                result.append(String.format("  [%04X] %s: %s (%d bytes)",
                    comp.getOffset(),
                    comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)",
                    comp.getDataType().getName(),
                    comp.getLength()));
                
                if (comp.getComment() != null) {
                    result.append(" // ").append(comp.getComment());
                }
                result.append("\n");
            }
        }
        
        // Show undefined components if any
        DataTypeComponent[] definedComponents = struct.getDefinedComponents();
        if (definedComponents.length < components.length) {
            result.append("\nUndefined regions:\n");
            int lastEnd = 0;
            for (DataTypeComponent comp : definedComponents) {
                if (comp.getOffset() > lastEnd) {
                    result.append(String.format("  [%04X-%04X] undefined (%d bytes)\n",
                        lastEnd, comp.getOffset() - 1, comp.getOffset() - lastEnd));
                }
                lastEnd = comp.getOffset() + comp.getLength();
            }
            if (lastEnd < struct.getLength()) {
                result.append(String.format("  [%04X-%04X] undefined (%d bytes)\n",
                    lastEnd, struct.getLength() - 1, struct.getLength() - lastEnd));
            }
        }
        
        return result.toString();
    }
    
    /**
     * Get detailed information about an enum including all values
     *
     * @param enumName name of the enum to get details for
     * @return detailed enum information
     */
    public String getEnumDetails(String enumName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || enumName.isEmpty()) return "Enum name is required";
        
        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        
        // Find the enum by name
        DataType dataType = dtm.getDataType("/" + enumName);
        if (dataType == null) {
            // Try searching in all categories
            Iterator<DataType> allTypes = dtm.getAllDataTypes();
            while (allTypes.hasNext()) {
                DataType dt = allTypes.next();
                if (dt.getName().equals(enumName) && dt instanceof Enum) {
                    dataType = dt;
                    break;
                }
            }
        }
        
        if (dataType == null || !(dataType instanceof Enum)) {
            return "Enum not found: " + enumName;
        }
        
        Enum enumType = (Enum) dataType;
        StringBuilder result = new StringBuilder();
        
        // Enum header information
        result.append("Enum: ").append(enumType.getName()).append("\n");
        result.append("Category: ").append(enumType.getCategoryPath()).append("\n");
        result.append("Size: ").append(enumType.getLength()).append(" bytes\n");
        result.append("Description: ").append(enumType.getDescription() != null ? enumType.getDescription() : "None").append("\n");
        result.append("\nValues:\n");
        
        // List all values sorted by numeric value
        String[] names = enumType.getNames();
        List<Map.Entry<String, Long>> entries = new ArrayList<>();
        for (String name : names) {
            entries.add(Map.entry(name, enumType.getValue(name)));
        }
        entries.sort(Map.Entry.comparingByValue());
        
        if (entries.isEmpty()) {
            result.append("  (no values defined)\n");
        } else {
            for (Map.Entry<String, Long> entry : entries) {
                result.append(String.format("  %s = 0x%X (%d)\n",
                    entry.getKey(),
                    entry.getValue(),
                    entry.getValue()));
            }
        }
        
        return result.toString();
    }
    
    /**
     * List all fields of a structure
     *
     * @param structureName name of the structure
     * @return list of structure fields with detailed information
     */
    public String listStructureFields(String structureName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structureName == null || structureName.isEmpty()) return "Structure name is required";
        
        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        
        // Find the structure by name
        DataType dataType = dtm.getDataType("/" + structureName);
        if (dataType == null) {
            // Try searching in all categories
            Iterator<DataType> allTypes = dtm.getAllDataTypes();
            while (allTypes.hasNext()) {
                DataType dt = allTypes.next();
                if (dt.getName().equals(structureName) && dt instanceof Structure) {
                    dataType = dt;
                    break;
                }
            }
        }
        
        if (dataType == null || !(dataType instanceof Structure)) {
            return "Structure not found: " + structureName;
        }
        
        Structure struct = (Structure) dataType;
        DataTypeComponent[] components = struct.getComponents();
        
        if (components.length == 0) {
            return "Structure " + structureName + " has no fields defined";
        }
        
        List<String> fields = new ArrayList<>();
        for (DataTypeComponent comp : components) {
            String fieldInfo = String.format("Offset: 0x%04X, Name: %s, Type: %s, Size: %d bytes",
                comp.getOffset(),
                comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)",
                comp.getDataType().getName(),
                comp.getLength());
            
            if (comp.getComment() != null) {
                fieldInfo += ", Comment: " + comp.getComment();
            }
            
            fields.add(fieldInfo);
        }
        
        return String.join("\n", fields);
    }

    @McpTool(description = """
        List data types (structures and/or enums) in the program with pagination.

        Returns: Data types with summary info, prefixed with [struct] or [enum]

        Example: list_data_types("struct", 0, 5) -> ['[struct] POINT: {int x, int y}', ...] """)
    public String listDataTypes(
            @Param(value = "Filter by type \u2014 \"all\" (default), \"struct\", or \"enum\"", defaultValue = "all") String kind,
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") int offset,
            @Param(value = "Maximum data types to return", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        String normalizedKind = (kind == null || kind.isEmpty()) ? "all" : kind.toLowerCase();

        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        List<String> lines = new ArrayList<>();

        if ("all".equals(normalizedKind) || "struct".equals(normalizedKind)) {
            List<Structure> structs = new ArrayList<>();
            dtm.getAllStructures().forEachRemaining(structs::add);
            Collections.sort(structs, Comparator.comparing(Structure::getName));
            for (Structure struct : structs) {
                StringBuilder sb = new StringBuilder();
                sb.append("[struct] ").append(struct.getName()).append(": {");
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
        }

        if ("all".equals(normalizedKind) || "enum".equals(normalizedKind)) {
            List<Enum> enums = new ArrayList<>();
            Iterator<DataType> allTypes = dtm.getAllDataTypes();
            while (allTypes.hasNext()) {
                DataType dt = allTypes.next();
                if (dt instanceof Enum enumDataType) {
                    enums.add(enumDataType);
                }
            }
            Collections.sort(enums, Comparator.comparing(Enum::getName));
            for (Enum enumType : enums) {
                StringBuilder sb = new StringBuilder();
                sb.append("[enum] ").append(enumType.getName())
                  .append(" (").append(enumType.getLength()).append(" bytes): {");
                String[] names = enumType.getNames();
                for (int i = 0; i < names.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(names[i]).append("=").append(enumType.getValue(names[i]));
                }
                sb.append("}");
                lines.add(sb.toString());
            }
        }

        PaginationResult result = HttpUtils.paginateListWithHints(lines, offset, limit);
        return result.getFormattedResult();
    }

    @McpTool(description = """
        Get detailed information about a named data type (auto-detects struct vs enum).

        For structures: returns full field layout with offsets, types, sizes, and comments.
        For enums: returns all values sorted numerically with hex and decimal representation.

        Returns: Detailed data type information

        Example: get_data_type("POINT") -> "Structure: POINT\\nSize: 8 bytes\\nFields:\\n  [0000] x: int..." """)
    public String getDataType(
            @Param("Name of the data type to examine (e.g., \"POINT\", \"FILE_FLAGS\")") String name) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Data type name is required";

        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByNameInAllCategories(dtm, name);
        if (dataType == null) {
            return "Data type not found: " + name;
        }

        if (dataType instanceof Structure struct) {
            return formatStructureDetails(struct);
        } else if (dataType instanceof Enum enumType) {
            return formatEnumDetails(enumType);
        } else {
            // Generic type info
            StringBuilder result = new StringBuilder();
            result.append("Data Type: ").append(dataType.getName()).append("\n");
            result.append("Category: ").append(dataType.getCategoryPath()).append("\n");
            result.append("Size: ").append(dataType.getLength()).append(" bytes\n");
            result.append("Kind: ").append(dataType.getClass().getSimpleName()).append("\n");
            if (dataType.getDescription() != null) {
                result.append("Description: ").append(dataType.getDescription()).append("\n");
            }
            return result.toString();
        }
    }

    private String formatStructureDetails(Structure struct) {
        StringBuilder result = new StringBuilder();
        result.append("Structure: ").append(struct.getName()).append("\n");
        result.append("Category: ").append(struct.getCategoryPath()).append("\n");
        result.append("Size: ").append(struct.getLength()).append(" bytes\n");
        result.append("Alignment: ").append(struct.getAlignment()).append("\n");
        result.append("Packed: ").append(struct.isPackingEnabled() ? "Yes" : "No").append("\n");
        result.append("Description: ").append(struct.getDescription() != null ? struct.getDescription() : "None").append("\n");
        result.append("\nFields:\n");

        DataTypeComponent[] components = struct.getComponents();
        if (components.length == 0) {
            result.append("  (no fields defined)\n");
        } else {
            for (DataTypeComponent comp : components) {
                result.append(String.format("  [%04X] %s: %s (%d bytes)",
                    comp.getOffset(),
                    comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)",
                    comp.getDataType().getName(),
                    comp.getLength()));
                if (comp.getComment() != null) {
                    result.append(" // ").append(comp.getComment());
                }
                result.append("\n");
            }
        }
        return result.toString();
    }

    private String formatEnumDetails(Enum enumType) {
        StringBuilder result = new StringBuilder();
        result.append("Enum: ").append(enumType.getName()).append("\n");
        result.append("Category: ").append(enumType.getCategoryPath()).append("\n");
        result.append("Size: ").append(enumType.getLength()).append(" bytes\n");
        result.append("Description: ").append(enumType.getDescription() != null ? enumType.getDescription() : "None").append("\n");
        result.append("\nValues:\n");

        String[] names = enumType.getNames();
        List<Map.Entry<String, Long>> entries = new ArrayList<>();
        for (String n : names) {
            entries.add(Map.entry(n, enumType.getValue(n)));
        }
        entries.sort(Map.Entry.comparingByValue());

        if (entries.isEmpty()) {
            result.append("  (no values defined)\n");
        } else {
            for (Map.Entry<String, Long> entry : entries) {
                result.append(String.format("  %s = 0x%X (%d)\n",
                    entry.getKey(), entry.getValue(), entry.getValue()));
            }
        }
        return result.toString();
    }

    /**
     * Unwrap Array, Pointer, and TypeDef wrappers to get the underlying base data type.
     *
     * @param dt the data type to unwrap
     * @return the base data type after removing all wrappers
     */
    private DataType getBaseDataType(DataType dt) {
        while (dt != null) {
            if (dt instanceof TypeDef) {
                dt = ((TypeDef) dt).getBaseDataType();
            } else if (dt instanceof Pointer) {
                dt = ((Pointer) dt).getDataType();
            } else if (dt instanceof Array) {
                dt = ((Array) dt).getDataType();
            } else {
                break;
            }
        }
        return dt;
    }

    /**
     * Compare two data types for equality using the same logic as Ghidra's
     * ReferenceUtils.dataTypesMatch(): compare by UniversalID for user-defined types,
     * and by class identity for built-in types.
     *
     * @param a first data type
     * @param b second data type
     * @return true if the types match
     */
    private boolean dataTypesMatch(DataType a, DataType b) {
        if (a == null || b == null) return false;
        if (a == b) return true;

        UniversalID idA = a.getUniversalID();
        UniversalID idB = b.getUniversalID();

        // User-defined types have non-null UIDs — compare by UID
        if (idA != null && idB != null) {
            return idA.equals(idB);
        }

        // Built-in types (no UID) — compare by exact class + name
        return a.getClass().equals(b.getClass()) && a.getName().equals(b.getName());
    }

    @McpTool(description = """
        Find all locations where a data type is used in the program.

        Searches defined data items and function signatures (return types, parameters,
        local variables) for usages of the specified type, including through pointers,
        arrays, and typedefs.

        When field_name is provided and the type is a struct/union, restricts the search
        to locations where that specific field is referenced (similar to Ghidra's
        "Find References to Field" feature).

        Returns: List of usage locations with context (data labels, function signatures)

        Example: find_data_type_usage("POINT") -> ['Data: origin @ 00402000 (type: POINT)', ...] """)
    public String findDataTypeUsage(
            @Param("Name of the data type to search for (e.g., \"POINT\", \"MyStruct\")") String typeName,
            @Param(value = "Optional field name to restrict search to", defaultValue = "") String fieldName,
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") int offset,
            @Param(value = "Maximum results to return", defaultValue = "100") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

        // Normalize empty field name to null
        if (fieldName != null && fieldName.isEmpty()) fieldName = null;

        ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        DataType targetType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (targetType == null) {
            return "Data type not found: " + typeName;
        }

        // Unwrap the target so we compare base-to-base
        DataType targetBase = getBaseDataType(targetType);

        // If a field name is given, validate it exists in the composite type
        int fieldOffset = -1;
        if (fieldName != null && !fieldName.isEmpty()) {
            if (!(targetBase instanceof Composite)) {
                return "Field search requires a composite (struct/union) type, but " +
                        typeName + " is " + targetBase.getClass().getSimpleName();
            }
            Composite composite = (Composite) targetBase;
            DataTypeComponent fieldComp = findFieldByName(composite, fieldName);
            if (fieldComp == null) {
                return "Field '" + fieldName + "' not found in " + typeName;
            }
            fieldOffset = fieldComp.getOffset();
        }

        List<String> results = new ArrayList<>();
        Listing listing = program.getListing();

        // --- 1. Search defined data ---
        Iterator<Data> dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            collectDataTypeMatches(results, data, targetBase, fieldName, fieldOffset);
        }

        // --- 2. Search function signatures ---
        // When searching for a specific field, function return types and variable
        // types still matter (the whole composite is used), but we skip them to
        // match Ghidra's FieldMatcher behaviour which only reports field-level hits.
        if (fieldName == null || fieldName.isEmpty()) {
            FunctionIterator funcIter = listing.getFunctions(true);
            while (funcIter.hasNext()) {
                Function func = funcIter.next();
                String funcDesc = func.getName() + " @ " + func.getEntryPoint();

                // Check return type
                DataType retBase = getBaseDataType(func.getReturnType());
                if (dataTypesMatch(retBase, targetBase)) {
                    results.add("Return type: " + funcDesc +
                            " (returns " + func.getReturnType().getName() + ")");
                }

                // Check all variables (parameters + locals)
                for (Variable var : func.getAllVariables()) {
                    DataType varBase = getBaseDataType(var.getDataType());
                    if (dataTypesMatch(varBase, targetBase)) {
                        String kind = (var instanceof Parameter) ? "Param" : "Local";
                        results.add(kind + " variable: " + var.getName() +
                                " in " + funcDesc +
                                " (type: " + var.getDataType().getName() + ")");
                    }
                }
            }
        }

        if (results.isEmpty()) {
            String target = fieldName != null && !fieldName.isEmpty()
                    ? typeName + "." + fieldName
                    : typeName;
            return "No usages found for data type: " + target;
        }

        PaginationResult paginationResult = HttpUtils.paginateListWithHints(results, offset, limit);
        return paginationResult.getFormattedResult();
    }


    /**
     * Find a named field within a Composite (struct/union) data type.
     *
     * @param composite the composite type to search
     * @param name      the field name to find
     * @return the matching component, or null if not found
     */
    private DataTypeComponent findFieldByName(Composite composite, String name) {
        for (DataTypeComponent comp : composite.getComponents()) {
            String compName = comp.getFieldName();
            if (compName != null && compName.equals(name)) {
                return comp;
            }
        }
        return null;
    }

    /**
     * Collect matches from a Data item and its sub-components into the results list.
     * Reports the specific sub-component address when a match is found inside a composite,
     * mirroring Ghidra's native behaviour of reporting field-level addresses.
     * Skips individual array elements for performance (same optimisation Ghidra uses).
     *
     * @param results     accumulator for result strings
     * @param data        the data item to inspect
     * @param targetBase  the unwrapped target type to match against
     * @param fieldName   optional field name filter (null to match any)
     * @param fieldOffset byte offset of the field within the composite (-1 if no filter)
     */
    private void collectDataTypeMatches(List<String> results, Data data,
            DataType targetBase, String fieldName, int fieldOffset) {
        DataType base = getBaseDataType(data.getDataType());

        // Direct match at top level (only when not filtering by field)
        if (fieldOffset < 0 && dataTypesMatch(base, targetBase)) {
            String label = data.getLabel();
            String addr = data.getMinAddress().toString();
            String dtName = data.getDataType().getName();
            results.add("Data: " + (label != null ? label : "(unnamed)") +
                    " @ " + addr + " (type: " + dtName + ")");
            return;
        }

        // Recurse into sub-components (struct fields, etc.)
        int numComponents = data.getNumComponents();
        for (int i = 0; i < numComponents; i++) {
            Data child = data.getComponent(i);
            if (child == null) continue;

            // Skip array sub-elements for performance — only check the first element
            if (data.getDataType() instanceof Array) {
                collectDataTypeMatches(results, child, targetBase, fieldName, fieldOffset);
                return;
            }

            // Field-specific filtering: only report components at the matching offset/name
            if (fieldOffset >= 0) {
                String childFieldName = child.getFieldName();
                boolean nameMatch = childFieldName != null && childFieldName.equals(fieldName);
                boolean offsetMatch = child.getParentOffset() == fieldOffset;
                if (!(nameMatch || offsetMatch)) {
                    continue;
                }
            }

            DataType childBase = getBaseDataType(child.getDataType());
            if (dataTypesMatch(childBase, targetBase) || fieldOffset >= 0) {
                // Report the specific sub-component address
                String label = data.getLabel();
                String parentName = label != null ? label : "(unnamed)";
                String addr = child.getMinAddress().toString();
                String childField = child.getFieldName();
                String fieldDesc = childField != null ? childField : ("offset_0x" +
                        Integer.toHexString(child.getParentOffset()));
                results.add("Data: " + parentName + "." + fieldDesc +
                        " @ " + addr + " (type: " + child.getDataType().getName() + ")");
            } else {
                // Recurse deeper for nested composites
                collectDataTypeMatches(results, child, targetBase, fieldName, fieldOffset);
            }
        }
    }
}
