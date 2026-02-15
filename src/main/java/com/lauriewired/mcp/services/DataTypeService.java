package com.lauriewired.mcp.services;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.SwingUtilities;

import com.lauriewired.mcp.model.PaginationResult;
import com.lauriewired.mcp.utils.HttpUtils;

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

    /**
     * Rename a field within a structure data type
     *
     * @param structName structure name
     * @param oldFieldName current field name
     * @param newFieldName new field name
     * @return status message
     */
    public String renameStructField(String structName, String oldFieldName, String newFieldName) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || oldFieldName == null || newFieldName == null) {
            return "Structure name, old field name, and new field name are required";
        }

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename struct field");
                try {
                    ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    Structure struct = (dt instanceof Structure) ? (Structure) dt : null;
                    if (struct != null) {
                        // Check if oldFieldName matches pattern "field<N>_0x<offset>"
                        if (oldFieldName.matches("field\\d+_0x[0-9a-fA-F]+")) {
                            // Extract index number from field name
                            int index = Integer.parseInt(oldFieldName.substring(5, oldFieldName.indexOf('_')));
                            if (index >= 0 && index < struct.getNumComponents()) {
                                DataTypeComponent component = struct.getComponent(index);
                                struct.replace(index, component.getDataType(), component.getLength(), 
                                            newFieldName, component.getComment());
                                successFlag.set(true);
                            }
                        } else {
                            // Original logic for named fields
                            for (int i = 0; i < struct.getNumComponents(); i++) {
                                DataTypeComponent component = struct.getComponent(i);
                                if ((component.getFieldName() != null) && 
                                    component.getFieldName().equals(oldFieldName)) {
                                    struct.replace(i, component.getDataType(), component.getLength(),
                                                newFieldName, component.getComment());
                                    successFlag.set(true);
                                    break;
                                }
                            }
                        }
                    }
                }
                catch (RuntimeException e) {
                    Msg.error(this, "Error renaming struct field", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            // If the operation already succeeded inside the lambda, don't report an error
            if (successFlag.get()) {
                return "Field renamed successfully";
            }
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String errorMsg = "Failed to execute rename on Swing thread: " + cause.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }

        return successFlag.get() ? "Field renamed successfully" : "Failed to rename field";
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
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) {
            return "Structure name is required";
        }

        AtomicReference<String> resultMessage = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create structure");
                try {
                    ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
                    
                    // Check if structure already exists
                    DataType existing = findDataTypeByNameInAllCategories(dtm, structName);
                    if (existing != null && existing instanceof Structure) {
                        resultMessage.set("Structure '" + structName + "' already exists");
                        return;
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
                    
                    resultMessage.set("Structure '" + structName + "' created successfully at " +
                                    addedType.getCategoryPath().getPath());
                }
                catch (Exception e) {
                    Msg.error(this, "Error creating structure", e);
                    resultMessage.set("Failed to create structure: " + e.getMessage());
                }
                finally {
                    program.endTransaction(tx, resultMessage.get() != null &&
                                         resultMessage.get().contains("successfully"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            if (resultMessage.get() != null) {
                return resultMessage.get();
            }
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String errorMsg = "Failed to execute create structure on Swing thread: " + cause.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }

        return resultMessage.get();
    }

    /**
     * Add a field to an existing structure
     *
     * @param structName name of the structure
     * @param fieldName name of the field to add
     * @param fieldType data type of the field
     * @param fieldSize size of the field (for fixed-size types)
     * @param offset offset in the structure (-1 to append)
     * @param comment optional comment for the field
     * @return status message
     */
    public String addStructureField(String structName, String fieldName, String fieldType,
                                  int fieldSize, int offset, String comment) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || fieldType == null) {
            return "Structure name and field type are required";
        }

        AtomicReference<String> resultMessage = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add structure field");
                try {
                    ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
                    
                    // Find the structure
                    DataType dt = findDataTypeByNameInAllCategories(dtm, structName);
                    if (!(dt instanceof Structure)) {
                        resultMessage.set("Structure '" + structName + "' not found");
                        return;
                    }
                    
                    Structure struct = (Structure) dt;
                    
                    // Resolve the field data type
                    DataType fieldDataType = resolveDataType(dtm, fieldType);
                    if (fieldDataType == null) {
                        resultMessage.set("Failed to resolve data type: " + fieldType);
                        return;
                    }
                    
                    // Add the field
                    if (offset >= 0) {
                        // Insert at specific offset
                        struct.insertAtOffset(offset, fieldDataType, fieldSize, fieldName, comment);
                    } else {
                        // Append to end
                        struct.add(fieldDataType, fieldSize, fieldName, comment);
                    }
                    
                    resultMessage.set("Field '" + (fieldName != null ? fieldName : "unnamed") +
                                    "' added to structure '" + structName + "'");
                }
                catch (RuntimeException e) {
                    Msg.error(this, "Error adding structure field", e);
                    resultMessage.set("Failed to add field: " + e.getMessage());
                }
                finally {
                    program.endTransaction(tx, resultMessage.get() != null &&
                                         resultMessage.get().contains("added"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            if (resultMessage.get() != null) {
                return resultMessage.get();
            }
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String errorMsg = "Failed to execute add field on Swing thread: " + cause.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }

        return resultMessage.get();
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
        if (enumName == null || enumName.isEmpty()) {
            return "Enum name is required";
        }
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return "Enum size must be 1, 2, 4, or 8 bytes";
        }
        
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";

        AtomicReference<String> resultMessage = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum");
                try {
                    ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
                    
                    // Check if enum already exists
                    DataType existing = findDataTypeByNameInAllCategories(dtm, enumName);
                    if (existing != null && existing instanceof Enum) {
                        resultMessage.set("Enum '" + enumName + "' already exists");
                        return;
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
                    
                    resultMessage.set("Enum '" + enumName + "' created successfully at " +
                                    addedType.getCategoryPath().getPath());
                }
                catch (Exception e) {
                    Msg.error(this, "Error creating enum", e);
                    resultMessage.set("Failed to create enum: " + e.getMessage());
                }
                finally {
                    program.endTransaction(tx, resultMessage.get() != null &&
                                         resultMessage.get().contains("successfully"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            if (resultMessage.get() != null) {
                return resultMessage.get();
            }
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String errorMsg = "Failed to execute create enum on Swing thread: " + cause.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }

        return resultMessage.get();
    }

    /**
     * Add a value to an existing enum
     *
     * @param enumName name of the enum
     * @param valueName name of the enum value
     * @param value numeric value
     * @return status message
     */
    public String addEnumValue(String enumName, String valueName, long value) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || valueName == null) {
            return "Enum name and value name are required";
        }

        AtomicReference<String> resultMessage = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add enum value");
                try {
                    ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
                    
                    // Find the enum
                    DataType dt = findDataTypeByNameInAllCategories(dtm, enumName);
                    if (dt instanceof Enum enumType) {
                        enumType.add(valueName, value);
                        resultMessage.set("Value '" + valueName + "' (" + value +
                                    ") added to enum '" + enumName + "'");
                    } else {
                        resultMessage.set("Enum '" + enumName + "' not found");
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error adding enum value", e);
                    resultMessage.set("Failed to add enum value: " + e.getMessage());
                }
                finally {
                    program.endTransaction(tx, resultMessage.get() != null &&
                                         resultMessage.get().contains("added"));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            if (resultMessage.get() != null) {
                return resultMessage.get();
            }
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            String errorMsg = "Failed to execute add enum value on Swing thread: " + cause.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }

        return resultMessage.get();
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

    /**
     * Find all locations where a data type is used in the program.
     * Mirrors Ghidra's ReferenceUtils.doFindDataTypeReferences() algorithm:
     *   1. Search defined data items (including sub-components)
     *   2. Search function signatures (return types, parameters, locals)
     *
     * Optionally filters to a specific field name within a composite type,
     * mirroring Ghidra's FieldMatcher / findDataTypeFieldReferences().
     *
     * @param typeName  name of the data type to find usages of
     * @param fieldName optional field name to restrict search to (null for all uses)
     * @param offset    pagination offset
     * @param limit     pagination limit
     * @return paginated list of usage locations
     */
    public String findDataTypeUsage(String typeName, String fieldName, int offset, int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

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
