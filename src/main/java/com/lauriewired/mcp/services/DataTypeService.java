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
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.DataTypeDetailResult;
import com.lauriewired.mcp.model.response.DataTypeItem;
import com.lauriewired.mcp.model.response.DataTypeUsageItem;
import com.lauriewired.mcp.model.response.UpdateResult;
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
    public DataTypeService(final ProgramService programService) {
        this.programService = programService;
    }

    @McpTool(post = true, outputType = JsonOutput.class, responseType = UpdateResult.class, description = """
        Bulk update a structure: rename fields, change field types, resize, and/or rename.

        All changes are applied in a single transaction with per-field error reporting.

        Returns: Per-field results with success/failure status and summary

        Note: For auto-generated field names like "field1_0x10", the number after "field"
        is the component index. type_changes keys are resolved against both existing field
        names and rename targets; ambiguous keys produce an error for that entry.

        Example: update_structure("MyStruct", field_renames={"field0_0x0": "width"},
                                  type_changes={"width": "int"}) """)
    public ToolOutput updateStructure(
            @Param("final Current structure name") final String name,
            @Param(value = "New name for the structure (optional)", defaultValue = "") final String newName,
            @Param(value = "final New size in bytes (optional, only grows)", defaultValue = "") final Integer size,
            @Param(value = "Map of old field name to new field name", defaultValue = "") final Map<String, String> fieldRenames,
            @Param(value = "Map of field name to new data type", defaultValue = "") final Map<String, String> typeChanges) {
        if (name == null || name.isEmpty()) {
            return StatusOutput.error("Structure name is required");
        }
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        try (var tx = ProgramTransaction.start(program, "Update structure")) {
            final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            final DataType dt = findDataTypeByNameInAllCategories(dtm, name);
            if (!(dt instanceof Structure)) {
                return StatusOutput.error("Structure '" + name + "' not found");
            }
            final Structure struct = (Structure) dt;

            final List<String> results = new ArrayList<>();
            int succeeded = 0;
            int failed = 0;

            // Build set of existing field names
            final Set<String> existingNames = new HashSet<>();
            for (int i = 0; i < struct.getNumComponents(); i++) {
                final DataTypeComponent comp = struct.getComponent(i);
                final String fn = comp.getFieldName();
                if (fn != null) existingNames.add(fn);
            }

            // Build reverse lookup: new_name -> old_name from fieldRenames
            final Map<String, String> reverseRenames = new HashMap<>();
            if (fieldRenames != null) {
                // Pre-validate: detect rename target collisions with fields not being renamed away
                final Set<String> renameTargets = new HashSet<>();
                for (final Map.Entry<String, String> entry : fieldRenames.entrySet()) {
                    final String newFieldName = entry.getValue();
                    if (!renameTargets.add(newFieldName)) {
                        return StatusOutput.error("Duplicate rename target: multiple fields renamed to '" + newFieldName + "'");
                    }
                    // Collision: new name matches an existing field that isn't being renamed away
                    if (existingNames.contains(newFieldName) && !fieldRenames.containsKey(newFieldName)) {
                        return StatusOutput.error("Rename collision: '" + newFieldName +
                                "' already exists as a field and is not being renamed");
                    }
                }
                for (final Map.Entry<String, String> entry : fieldRenames.entrySet()) {
                    reverseRenames.put(entry.getValue(), entry.getKey());
                }
            }

            // Resolve typeChanges keys to old field names
            final Map<String, String> resolvedTypeChanges = new LinkedHashMap<>();
            if (typeChanges != null) {
                for (final Map.Entry<String, String> entry : typeChanges.entrySet()) {
                    final String key = entry.getKey();
                    final String resolved = resolveFieldKey(key, reverseRenames, existingNames);
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
                for (final Map.Entry<String, String> entry : fieldRenames.entrySet()) {
                    final String oldFieldName = entry.getKey();
                    final String newFieldName = entry.getValue();
                    final String newTypeName = resolvedTypeChanges.remove(oldFieldName);

                    final int idx = findComponentIndex(struct, oldFieldName);
                    if (idx < 0) {
                        results.add("  " + oldFieldName + " -> not found [FAILED]");
                        failed++;
                        continue;
                    }

                    final DataTypeComponent comp = struct.getComponent(idx);
                    DataType fieldType = comp.getDataType();
                    int fieldLen = comp.getLength();

                    if (newTypeName != null) {
                        final DataType resolved = resolveDataType(dtm, newTypeName);
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
                    final StringBuilder msg = new StringBuilder("  " + oldFieldName + " -> renamed to '" + newFieldName + "'");
                    if (newTypeName != null) msg.append(", type changed to '").append(newTypeName).append("'");
                    msg.append(" [OK]");
                    results.add(msg.toString());
                    succeeded++;
                }
            }

            // Apply remaining type-only changes (not covered by renames)
            for (final Map.Entry<String, String> entry : resolvedTypeChanges.entrySet()) {
                final String fieldName = entry.getKey();
                final String newTypeName = entry.getValue();

                final int idx = findComponentIndex(struct, fieldName);
                if (idx < 0) {
                    results.add("  " + fieldName + " -> not found [FAILED]");
                    failed++;
                    continue;
                }

                final DataTypeComponent comp = struct.getComponent(idx);
                final DataType resolved = resolveDataType(dtm, newTypeName);
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

            final UpdateResult result = new UpdateResult(name, results,
                    new UpdateResult.Summary(succeeded, failed));
            return new JsonOutput(result);
        } catch (Exception e) {
            Msg.error(this, "Error updating structure", e);
            return StatusOutput.error("Failed to update structure: " + e.getMessage());
        }
    }

    @McpTool(post = true, outputType = JsonOutput.class, responseType = UpdateResult.class, description = """
        Bulk update an enum: rename values, change numeric values, resize, and/or rename.

        All changes are applied in a single transaction with per-entry error reporting.

        Returns: Per-entry results with success/failure status and summary

        Note: value_changes keys are resolved against both existing value names and
        rename targets; ambiguous keys produce an error for that entry.

        Example: update_enum("MyFlags", new_name="FilePermissions",
                             value_renames={"OLD_VAL": "NEW_VAL"},
                             value_changes={"NEW_VAL": 42}) """)
    public ToolOutput updateEnum(
            @Param("final Current enum name") final String name,
            @Param(value = "New name for the enum (optional)", defaultValue = "") final String newName,
            @Param(value = "final New size in bytes \u2014 must be 1, 2, 4, or 8 (optional)", defaultValue = "") final Integer size,
            @Param(value = "Map of old value name to new value name", defaultValue = "") final Map<String, String> valueRenames,
            @Param(value = "Map of value name to new numeric value", defaultValue = "") final Map<String, Long> valueChanges) {
        if (name == null || name.isEmpty()) {
            return StatusOutput.error("Enum name is required");
        }
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        try (var tx = ProgramTransaction.start(program, "Update enum")) {
            final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
            final DataType dt = findDataTypeByNameInAllCategories(dtm, name);
            if (!(dt instanceof Enum)) {
                return StatusOutput.error("Enum '" + name + "' not found");
            }
            final Enum enumType = (Enum) dt;

            final List<String> results = new ArrayList<>();
            int succeeded = 0;
            int failed = 0;

            // Build set of existing value names
            final Set<String> existingNames = new HashSet<>();
            for (final String n : enumType.getNames()) {
                existingNames.add(n);
            }

            // Build reverse lookup: new_name -> old_name from valueRenames
            final Map<String, String> reverseRenames = new HashMap<>();
            if (valueRenames != null) {
                // Pre-validate: detect rename target collisions with values not being renamed away
                final Set<String> renameTargets = new HashSet<>();
                for (final Map.Entry<String, String> entry : valueRenames.entrySet()) {
                    final String newValName = entry.getValue();
                    if (!renameTargets.add(newValName)) {
                        return StatusOutput.error("Duplicate rename target: multiple values renamed to '" + newValName + "'");
                    }
                    if (existingNames.contains(newValName) && !valueRenames.containsKey(newValName)) {
                        return StatusOutput.error("Rename collision: '" + newValName +
                                "' already exists as a value and is not being renamed");
                    }
                }
                for (final Map.Entry<String, String> entry : valueRenames.entrySet()) {
                    reverseRenames.put(entry.getValue(), entry.getKey());
                }
            }

            // Resolve valueChanges keys to old value names
            final Map<String, Long> resolvedValueChanges = new LinkedHashMap<>();
            if (valueChanges != null) {
                for (final Map.Entry<String, Long> entry : valueChanges.entrySet()) {
                    final String key = entry.getKey();
                    final String resolved = resolveFieldKey(key, reverseRenames, existingNames);
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
                for (final Map.Entry<String, String> entry : valueRenames.entrySet()) {
                    final String oldValName = entry.getKey();
                    final String newValName = entry.getValue();

                    if (!existingNames.contains(oldValName)) {
                        results.add("  " + oldValName + " -> not found [FAILED]");
                        failed++;
                        continue;
                    }

                    final long currentValue = enumType.getValue(oldValName);
                    final Long newValue = resolvedValueChanges.remove(oldValName);
                    final long finalValue = (newValue != null) ? newValue : currentValue;

                    enumType.remove(oldValName);
                    enumType.add(newValName, finalValue);

                    final StringBuilder msg = new StringBuilder("  " + oldValName + " -> renamed to '" + newValName + "'");
                    if (newValue != null) msg.append(", value changed to ").append(finalValue);
                    msg.append(" [OK]");
                    results.add(msg.toString());
                    succeeded++;
                }
            }

            // Apply remaining value-only changes
            for (final Map.Entry<String, Long> entry : resolvedValueChanges.entrySet()) {
                final String valName = entry.getKey();
                final long newValue = entry.getValue();

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

            final UpdateResult result = new UpdateResult(name, results,
                    new UpdateResult.Summary(succeeded, failed));
            return new JsonOutput(result);
        } catch (Exception e) {
            Msg.error(this, "Error updating enum", e);
            return StatusOutput.error("Failed to update enum: " + e.getMessage());
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
    String resolveFieldKey(final String key, final Map<String, String> reverseRenames, final Set<String> existingNames) {
        final boolean isExisting = existingNames.contains(key);
        final String oldFromRename = reverseRenames.get(key);
        final boolean isNewName = oldFromRename != null;

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
    private int findComponentIndex(final Structure struct, final String fieldName) {
        if (fieldName.matches("field\\d+_0x[0-9a-fA-F]+")) {
            final int index = Integer.parseInt(fieldName.substring(5, fieldName.indexOf('_')));
            if (index >= 0 && index < struct.getNumComponents()) return index;
            return -1;
        }
        for (int i = 0; i < struct.getNumComponents(); i++) {
            final DataTypeComponent comp = struct.getComponent(i);
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
    public DataType findDataTypeByNameInAllCategories(final DataTypeManager dtm, final String typeName) {
        if (dtm == null || typeName == null || typeName.isEmpty()) {
            return null;
        }

        // Try exact match first
        final DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(final DataTypeManager dtm, final String name) {
        // Get all data types from the manager
        final Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            final DataType dt = allTypes.next();
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
    public DataType resolveDataType(final DataTypeManager dtm, final String typeName) {
        if (dtm == null || typeName == null || typeName.isEmpty()) {
            return null;
        }

        // First try to find exact match in all categories
        final DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            return dataType;
        }

        // Check for array syntax like "type[size]"
        final Matcher arrayMatcher = ARRAY_PATTERN.matcher(typeName);
        if (arrayMatcher.matches()) {
            final String baseTypeName = arrayMatcher.group(1);
            final String sizeStr = arrayMatcher.group(2);

            try {
                final int arraySize = Integer.parseInt(sizeStr);
                if (arraySize > 0 && arraySize <= 1000000) { // Reasonable size limits
                    // Recursively resolve the base type
                    final DataType baseType = resolveDataType(dtm, baseTypeName);
                    if (baseType != null) {
                        final ArrayDataType arrayType = new ArrayDataType(baseType, arraySize, baseType.getLength(), dtm);
                        return arrayType;
                    }
                }
            } catch (NumberFormatException ignored) {
                // Invalid array size format, fall through to other type resolution
            }
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            final String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new ghidra.program.model.data.PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            final DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
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
                final DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Could not resolve type
                return null;
            }
        }
    }

    @McpTool(post = true, outputType = StatusOutput.class, responseType = StatusOutput.class, description = """
        Create a new structure data type in Ghidra, optionally with inline fields.

        Creates a structure with the specified name, and when fields are provided,
        adds all fields in a single transaction \u2014 avoiding the multi-step
        create \u2192 add_field \u2192 add_field dance.

        Returns: Success message with path or error message

        Note: Structure names must be unique. Use add_structure_field to add fields to existing structs.

        Example: create_structure("POINT", 0, "", [["x", "int"], ["y", "int"]]) """)
    public ToolOutput createStructure(
            @Param("Name of the structure to create") final String name,
            @Param(value = "Size in bytes (0 for auto-size based on fields)", defaultValue = "0") final int size,
            @Param(value = "Category path like \"/MyStructures\" (empty for root)", defaultValue = "") final String categoryPath,
            @Param(value = "Optional list of [field_name, data_type] pairs to add immediately", defaultValue = "") final List<String[]> fields) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (name == null || name.isEmpty()) {
            return StatusOutput.error("Structure name is required");
        }

        try (var tx = ProgramTransaction.start(program, "Create structure")) {
            final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

            final DataType existing = findDataTypeByNameInAllCategories(dtm, name);
            if (existing != null && existing instanceof Structure) {
                return StatusOutput.error("Structure '" + name + "' already exists");
            }

            CategoryPath catPath = CategoryPath.ROOT;
            if (categoryPath != null && !categoryPath.isEmpty()) {
                catPath = new CategoryPath(categoryPath);
            }

            final StructureDataType struct = new StructureDataType(catPath, name, size, dtm);

            // Add inline fields if provided
            if (fields != null && !fields.isEmpty()) {
                for (final String[] field : fields) {
                    if (field.length < 2) continue;
                    final String fieldName = field[0];
                    final String fieldTypeName = field[1];
                    final DataType fieldType = resolveDataType(dtm, fieldTypeName);
                    if (fieldType == null) {
                        return StatusOutput.error("Failed to resolve field type '" + fieldTypeName +
                               "' for field '" + fieldName + "'");
                    }
                    struct.add(fieldType, -1, fieldName, null);
                }
            }

            final DataType addedType = dtm.addDataType(struct, null);

            tx.commit();
            String msg = "Structure '" + name + "' created successfully at " +
                    addedType.getCategoryPath().getPath();
            if (fields != null && !fields.isEmpty()) {
                msg += " with " + fields.size() + " fields";
            }
            return StatusOutput.ok(msg);
        } catch (Exception e) {
            Msg.error(this, "Error creating structure", e);
            return StatusOutput.error("Failed to create structure: " + e.getMessage());
        }
    }

    @McpTool(post = true, outputType = StatusOutput.class, responseType = StatusOutput.class, description = """
        Add a field to an existing structure.

        Adds a new field with specified type at given offset or appends to end.

        Returns: Success or error message

        Note: Field types can be built-in types, typedefs, or other structures/enums.

        Example: add_structure_field("MY_STRUCT", "count", "int") -> "Field 'count' added to structure 'MY_STRUCT'" """)
    public ToolOutput addStructureField(
            @Param("Name of the structure to modify") final String structName,
            @Param("Name for the new field") final String fieldName,
            @Param("Data type like \"int\", \"char\", \"DWORD\", or another struct name") final String fieldType,
            @Param(value = "Size in bytes for fixed-size types (-1 for default)", defaultValue = "-1") final int fieldSize,
            @Param(value = "Offset in structure to insert at (-1 to append)", defaultValue = "-1") final int offset,
            @Param(value = "final Optional comment for the field", defaultValue = "") final String comment) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (structName == null || fieldType == null) {
            return StatusOutput.error("Structure name and field type are required");
        }

        try (var tx = ProgramTransaction.start(program, "Add structure field")) {
            final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

            final DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
            if (!(dt instanceof Structure)) {
                return StatusOutput.error("Structure '" + structName + "' not found");
            }

            final Structure struct = (Structure) dt;

            final DataType fieldDataType = resolveDataType(dtm, fieldType);
            if (fieldDataType == null) {
                return StatusOutput.error("Failed to resolve data type: " + fieldType);
            }

            if (offset >= 0) {
                struct.insertAtOffset(offset, fieldDataType, fieldSize, fieldName, comment);
            } else {
                struct.add(fieldDataType, fieldSize, fieldName, comment);
            }

            tx.commit();
            return StatusOutput.ok("Field '" + (fieldName != null ? fieldName : "unnamed") +
                    "' added to structure '" + structName + "'");
        } catch (RuntimeException e) {
            Msg.error(this, "Error adding structure field", e);
            return StatusOutput.error("Failed to add field: " + e.getMessage());
        }
    }

    @McpTool(post = true, outputType = StatusOutput.class, responseType = StatusOutput.class, description = """
        Create a new enum data type in Ghidra, optionally with inline values.

        Creates an enumeration with the specified name, and when values are provided,
        adds all values in a single transaction \u2014 avoiding the multi-step
        create \u2192 add_value \u2192 add_value dance.

        Returns: Success message with path or error message

        Note: Enum names must be unique. Use add_enum_value to add values to existing enums.

        Example: create_enum("FILE_FLAGS", 4, "", {"FLAG_READ": 1, "FLAG_WRITE": 2}) """)
    public ToolOutput createEnum(
            @Param("Name of the enum to create") final String name,
            @Param(value = "Size in bytes - must be 1, 2, 4, or 8 (default: 4)", defaultValue = "4") final int size,
            @Param(value = "Category path like \"/MyEnums\" (empty for root)", defaultValue = "") final String categoryPath,
            @Param(value = "final Optional dictionary mapping value names to numeric values", defaultValue = "") final Map<String, Long> values) {
        if (name == null || name.isEmpty()) {
            return StatusOutput.error("Enum name is required");
        }
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return StatusOutput.error("Enum size must be 1, 2, 4, or 8 bytes");
        }

        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        try (var tx = ProgramTransaction.start(program, "Create enum")) {
            final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

            final DataType existing = findDataTypeByNameInAllCategories(dtm, name);
            if (existing != null && existing instanceof Enum) {
                return StatusOutput.error("Enum '" + name + "' already exists");
            }

            CategoryPath catPath = CategoryPath.ROOT;
            if (categoryPath != null && !categoryPath.isEmpty()) {
                catPath = new CategoryPath(categoryPath);
            }

            final EnumDataType enumType = new EnumDataType(catPath, name, size, dtm);

            // Add inline values if provided
            if (values != null && !values.isEmpty()) {
                for (final var entry : values.entrySet()) {
                    enumType.add(entry.getKey(), entry.getValue());
                }
            }

            final DataType addedType = dtm.addDataType(enumType, null);

            tx.commit();
            String msg = "Enum '" + name + "' created successfully at " +
                    addedType.getCategoryPath().getPath();
            if (values != null && !values.isEmpty()) {
                msg += " with " + values.size() + " values";
            }
            return StatusOutput.ok(msg);
        } catch (Exception e) {
            Msg.error(this, "Error creating enum", e);
            return StatusOutput.error("Failed to create enum: " + e.getMessage());
        }
    }

    @McpTool(post = true, outputType = StatusOutput.class, responseType = StatusOutput.class, description = """
        Add a value to an existing enum.

        Adds a named constant with numeric value to the enumeration.

        Returns: Success or error message

        Note: Value names must be unique within the enum. Values can be negative.

        Example: add_enum_value("MY_FLAGS", "FLAG_ENABLED", 0x01) -> "Value 'FLAG_ENABLED' (1) added to enum 'MY_FLAGS'" """)
    public ToolOutput addEnumValue(
            @Param("Name of the enum to modify") final String enumName,
            @Param("Name for the enum constant") final String valueName,
            @Param("final Numeric value for the constant") final long value) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (enumName == null || valueName == null) {
            return StatusOutput.error("Enum name and value name are required");
        }

        try (var tx = ProgramTransaction.start(program, "Add enum value")) {
            final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();

            final DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
            if (dt instanceof Enum enumType) {
                enumType.add(valueName, value);
                tx.commit();
                return StatusOutput.ok("Value '" + valueName + "' (" + value +
                        ") added to enum '" + enumName + "'");
            } else {
                return StatusOutput.error("Enum '" + enumName + "' not found");
            }
        } catch (Exception e) {
            Msg.error(this, "Error adding enum value", e);
            return StatusOutput.error("Failed to add enum value: " + e.getMessage());
        }
    }

    @McpTool(outputType = ListOutput.class, responseType = DataTypeItem.class, description = """
        List data types (structures and/or enums) in the program with pagination.

        Returns: Data types with summary info, prefixed with [struct] or [enum]

        Example: list_data_types("struct", 0, 5) -> ['[struct] POINT: {int x, int y}', ...] """)
    public ToolOutput listDataTypes(
            @Param(value = "Filter by type \u2014 \"all\" (default), \"struct\", or \"enum\"", defaultValue = "all") final String kind,
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") final int offset,
            @Param(value = "Maximum data types to return", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");

        final String normalizedKind = (kind == null || kind.isEmpty()) ? "all" : kind.toLowerCase();

        final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        final List<DataTypeItem> items = new ArrayList<>();

        if ("all".equals(normalizedKind) || "struct".equals(normalizedKind)) {
            final List<Structure> structs = new ArrayList<>();
            dtm.getAllStructures().forEachRemaining(structs::add);
            Collections.sort(structs, Comparator.comparing(Structure::getName));
            for (final Structure struct : structs) {
                final StringBuilder summary = new StringBuilder("{");
                for (int i = 0; i < struct.getNumComponents(); i++) {
                    final DataTypeComponent comp = struct.getComponent(i);
                    if (i > 0) summary.append(", ");
                    summary.append(comp.getDataType().getName())
                           .append(" ")
                           .append(comp.getFieldName());
                }
                summary.append("}");
                items.add(new DataTypeItem("struct", struct.getName(), summary.toString(), null));
            }
        }

        if ("all".equals(normalizedKind) || "enum".equals(normalizedKind)) {
            final List<Enum> enums = new ArrayList<>();
            final Iterator<DataType> allTypes = dtm.getAllDataTypes();
            while (allTypes.hasNext()) {
                final DataType dt = allTypes.next();
                if (dt instanceof Enum enumDataType) {
                    enums.add(enumDataType);
                }
            }
            Collections.sort(enums, Comparator.comparing(Enum::getName));
            for (final Enum enumType : enums) {
                final StringBuilder summary = new StringBuilder("{");
                final String[] names = enumType.getNames();
                for (int i = 0; i < names.length; i++) {
                    if (i > 0) summary.append(", ");
                    summary.append(names[i]).append("=").append(enumType.getValue(names[i]));
                }
                summary.append("}");
                items.add(new DataTypeItem("enum", enumType.getName(), summary.toString(), enumType.getLength()));
            }
        }

        return ListOutput.paginate(items, offset, limit);
    }

    @McpTool(outputType = JsonOutput.class, responseType = DataTypeDetailResult.class, description = """
        Get detailed information about a named data type (auto-detects struct vs enum).

        For structures: returns full field layout with offsets, types, sizes, and comments.
        For enums: returns all values sorted numerically with hex and decimal representation.

        Returns: Detailed data type information

        Example: get_data_type("POINT") -> "Structure: POINT\\nSize: 8 bytes\\nFields:\\n  [0000] x: int..." """)
    public ToolOutput getDataType(
            @Param("Name of the data type to examine (e.g., \"POINT\", \"FILE_FLAGS\")") final String name) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (name == null || name.isEmpty()) return StatusOutput.error("Data type name is required");

        final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        final DataType dataType = findDataTypeByNameInAllCategories(dtm, name);
        if (dataType == null) {
            return StatusOutput.error("Data type not found: " + name);
        }

        if (dataType instanceof Structure struct) {
            return new JsonOutput(formatStructureResult(struct));
        } else if (dataType instanceof Enum enumType) {
            return new JsonOutput(formatEnumResult(enumType));
        } else {
            final DataTypeDetailResult result = new DataTypeDetailResult(
                    dataType.getClass().getSimpleName(),
                    dataType.getName(),
                    dataType.getLength(),
                    dataType.getDescription(),
                    null,
                    null);
            return new JsonOutput(result);
        }
    }

    private DataTypeDetailResult formatStructureResult(final Structure struct) {
        final List<DataTypeDetailResult.Field> fields = new ArrayList<>();
        for (final DataTypeComponent comp : struct.getComponents()) {
            fields.add(new DataTypeDetailResult.Field(
                    comp.getOffset(),
                    comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)",
                    comp.getDataType().getName(),
                    comp.getLength(),
                    comp.getComment()));
        }

        return new DataTypeDetailResult(
                "struct",
                struct.getName(),
                struct.getLength(),
                null,
                fields,
                null);
    }

    private DataTypeDetailResult formatEnumResult(final Enum enumType) {
        final String[] names = enumType.getNames();
        final List<Map.Entry<String, Long>> entries = new ArrayList<>();
        for (final String n : names) {
            entries.add(Map.entry(n, enumType.getValue(n)));
        }
        entries.sort(Map.Entry.comparingByValue());

        final List<DataTypeDetailResult.Value> values = new ArrayList<>();
        for (final Map.Entry<String, Long> entry : entries) {
            values.add(new DataTypeDetailResult.Value(entry.getKey(), entry.getValue()));
        }

        return new DataTypeDetailResult(
                "enum",
                enumType.getName(),
                enumType.getLength(),
                null,
                null,
                values);
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
    private boolean dataTypesMatch(final DataType a, final DataType b) {
        if (a == null || b == null) return false;
        if (a == b) return true;

        final UniversalID idA = a.getUniversalID();
        final UniversalID idB = b.getUniversalID();

        // User-defined types have non-null UIDs — compare by UID
        if (idA != null && idB != null) {
            return idA.equals(idB);
        }

        // Built-in types (no UID) — compare by exact class + name
        return a.getClass().equals(b.getClass()) && a.getName().equals(b.getName());
    }

    @McpTool(outputType = ListOutput.class, responseType = DataTypeUsageItem.class, description = """
        Find all locations where a data type is used in the program.

        Searches defined data items and function signatures (return types, parameters,
        local variables) for usages of the specified type, including through pointers,
        arrays, and typedefs.

        When field_name is provided and the type is a struct/union, restricts the search
        to locations where that specific field is referenced (similar to Ghidra's
        "Find References to Field" feature).

        Returns: List of usage locations with context (data labels, function signatures)

        Example: find_data_type_usage("POINT") -> ['Data: origin @ 00402000 (type: POINT)', ...] """)
    public ToolOutput findDataTypeUsage(
            @Param("Name of the data type to search for (e.g., \"POINT\", \"MyStruct\")") final String typeName,
            @Param(value = "Optional field name to restrict search to", defaultValue = "") String fieldName,
            @Param(value = "Starting index for pagination (0-based)", defaultValue = "0") final int offset,
            @Param(value = "Maximum results to return", defaultValue = "100") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (typeName == null || typeName.isEmpty()) return StatusOutput.error("Type name is required");

        // Normalize empty field name to null
        if (fieldName != null && fieldName.isEmpty()) fieldName = null;

        final ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
        final DataType targetType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (targetType == null) {
            return StatusOutput.error("Data type not found: " + typeName);
        }

        // Unwrap the target so we compare base-to-base
        final DataType targetBase = getBaseDataType(targetType);

        // If a field name is given, validate it exists in the composite type
        int fieldOffset = -1;
        if (fieldName != null && !fieldName.isEmpty()) {
            if (!(targetBase instanceof Composite)) {
                return StatusOutput.error("Field search requires a composite (struct/union) type, but " +
                        typeName + " is " + targetBase.getClass().getSimpleName());
            }
            final Composite composite = (Composite) targetBase;
            final DataTypeComponent fieldComp = findFieldByName(composite, fieldName);
            if (fieldComp == null) {
                return StatusOutput.error("Field '" + fieldName + "' not found in " + typeName);
            }
            fieldOffset = fieldComp.getOffset();
        }

        final List<DataTypeUsageItem> results = new ArrayList<>();
        final Listing listing = program.getListing();

        // --- 1. Search defined data ---
        final Iterator<Data> dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext()) {
            final Data data = dataIter.next();
            collectDataTypeMatches(results, data, targetBase, fieldName, fieldOffset);
        }

        // --- 2. Search function signatures ---
        // When searching for a specific field, function return types and variable
        // types still matter (the whole composite is used), but we skip them to
        // match Ghidra's FieldMatcher behaviour which only reports field-level hits.
        if (fieldName == null || fieldName.isEmpty()) {
            final FunctionIterator funcIter = listing.getFunctions(true);
            while (funcIter.hasNext()) {
                final Function func = funcIter.next();

                // Check return type
                final DataType retBase = getBaseDataType(func.getReturnType());
                if (dataTypesMatch(retBase, targetBase)) {
                    results.add(new DataTypeUsageItem(
                            "Return type",
                            func.getEntryPoint().toString(),
                            null,
                            func.getReturnType().getName(),
                            func.getName()));
                }

                // Check all variables (parameters + locals)
                for (final Variable var : func.getAllVariables()) {
                    final DataType varBase = getBaseDataType(var.getDataType());
                    if (dataTypesMatch(varBase, targetBase)) {
                        final String varKind = (var instanceof Parameter) ? "Param" : "Local";
                        results.add(new DataTypeUsageItem(
                                varKind + " variable",
                                func.getEntryPoint().toString(),
                                var.getName(),
                                var.getDataType().getName(),
                                func.getName()));
                    }
                }
            }
        }

        if (results.isEmpty()) {
            final String target = fieldName != null && !fieldName.isEmpty()
                    ? typeName + "." + fieldName
                    : typeName;
            return StatusOutput.error("No usages found for data type: " + target);
        }

        return ListOutput.paginate(results, offset, limit);
    }


    /**
     * Find a named field within a Composite (struct/union) data type.
     *
     * @param composite the composite type to search
     * @param name      the field name to find
     * @return the matching component, or null if not found
     */
    private DataTypeComponent findFieldByName(final Composite composite, final String name) {
        for (final DataTypeComponent comp : composite.getComponents()) {
            final String compName = comp.getFieldName();
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
     * @param results     accumulator for result items
     * @param data        the data item to inspect
     * @param targetBase  the unwrapped target type to match against
     * @param fieldName   optional field name filter (null to match any)
     * @param fieldOffset byte offset of the field within the composite (-1 if no filter)
     */
    private void collectDataTypeMatches(final List<DataTypeUsageItem> results, final Data data,
            final DataType targetBase, final String fieldName, final int fieldOffset) {
        final DataType base = getBaseDataType(data.getDataType());

        // Direct match at top level (only when not filtering by field)
        if (fieldOffset < 0 && dataTypesMatch(base, targetBase)) {
            final String label = data.getLabel();
            results.add(new DataTypeUsageItem(
                    "Data",
                    data.getMinAddress().toString(),
                    label != null ? label : "(unnamed)",
                    data.getDataType().getName(),
                    null));
            return;
        }

        // Recurse into sub-components (struct fields, etc.)
        final int numComponents = data.getNumComponents();
        for (int i = 0; i < numComponents; i++) {
            final Data child = data.getComponent(i);
            if (child == null) continue;

            // Skip array sub-elements for performance — only check the first element
            if (data.getDataType() instanceof Array) {
                collectDataTypeMatches(results, child, targetBase, fieldName, fieldOffset);
                return;
            }

            // Field-specific filtering: only report components at the matching offset/name
            if (fieldOffset >= 0) {
                final String childFieldName = child.getFieldName();
                final boolean nameMatch = childFieldName != null && childFieldName.equals(fieldName);
                final boolean offsetMatch = child.getParentOffset() == fieldOffset;
                if (!(nameMatch || offsetMatch)) {
                    continue;
                }
            }

            final DataType childBase = getBaseDataType(child.getDataType());
            if (dataTypesMatch(childBase, targetBase) || fieldOffset >= 0) {
                final String label = data.getLabel();
                final String parentName = label != null ? label : "(unnamed)";
                final String childField = child.getFieldName();
                final String fieldDesc = childField != null ? childField : ("offset_0x" +
                        Integer.toHexString(child.getParentOffset()));
                results.add(new DataTypeUsageItem(
                        "Data",
                        child.getMinAddress().toString(),
                        parentName + "." + fieldDesc,
                        child.getDataType().getName(),
                        null));
            } else {
                // Recurse deeper for nested composites
                collectDataTypeMatches(results, child, targetBase, fieldName, fieldOffset);
            }
        }
    }
}
