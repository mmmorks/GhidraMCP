package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

/**
 * Integration tests for DataTypeService.findDataTypeUsage using ProgramBuilder.
 */
public class FindDataTypeUsageTest {

    @BeforeAll
    static void initGhidra() {
        GhidraTestEnv.initialize();
    }

    private ProgramBuilder builder;
    private ProgramDB program;
    private DataTypeService dataTypeService;

    /** MyStruct resolved from the program DTM after registration. */
    private DataType myStructDt;

    @BeforeEach
    void setUp() throws Exception {
        builder = new ProgramBuilder("test", ProgramBuilder._X64);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createMemory(".data", "0x402000", 0x1000);

        program = builder.getProgram();

        // Register MyStruct {int x; int y;} and OtherStruct {int a;}
        int tx = program.startTransaction("register types");
        try {
            var dtm = program.getDataTypeManager();

            StructureDataType myStruct = new StructureDataType("MyStruct", 0);
            myStruct.add(IntegerDataType.dataType, "x", null);
            myStruct.add(IntegerDataType.dataType, "y", null);
            dtm.addDataType(myStruct, null);

            StructureDataType otherStruct = new StructureDataType("OtherStruct", 0);
            otherStruct.add(IntegerDataType.dataType, "a", null);
            dtm.addDataType(otherStruct, null);
        } finally {
            program.endTransaction(tx, true);
        }

        // Look up the resolved MyStruct from the DTM
        myStructDt = program.getDataTypeManager().getDataType("/MyStruct");

        // Create two empty functions
        builder.createEmptyFunction("func_alpha", "0x401000", 0x50, DataType.DEFAULT);
        builder.createEmptyFunction("func_beta", "0x401100", 0x50, DataType.DEFAULT);

        ProgramService ps = GhidraTestEnv.programService(program);
        dataTypeService = new DataTypeService(ps);
    }

    @AfterEach
    void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    // ===== Input validation tests =====

    @Test
    @DisplayName("findDataTypeUsage returns error for null type name with program loaded")
    void testNullTypeName_WithProgram() {
        String result = dataTypeService.findDataTypeUsage(null, null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Type name is required\""));
    }

    @Test
    @DisplayName("findDataTypeUsage returns error for empty type name with program loaded")
    void testEmptyTypeName_WithProgram() {
        String result = dataTypeService.findDataTypeUsage("", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Type name is required\""));
    }

    @Test
    @DisplayName("findDataTypeUsage returns error when type not found")
    void testTypeNotFound() {
        String result = dataTypeService.findDataTypeUsage("NonExistentType", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Data type not found: NonExistentType\""));
    }

    // ===== No usages found =====

    @Test
    @DisplayName("findDataTypeUsage returns no-usages message when type exists but is unused")
    void testNoUsagesFound() {
        // MyStruct is registered but not applied anywhere
        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No usages found for data type: MyStruct\""));
    }

    // ===== Defined data matches =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in defined data with label")
    void testFindsDataUsage_WithLabel() throws Exception {
        builder.setBytes("0x402000", "00 00 00 00 00 00 00 00", false);
        builder.applyDataType("0x402000", myStructDt);
        builder.createLabel("0x402000", "globalVar");

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\":\"globalVar\"") && result.contains("00402000"),
                "Should find labeled data usage, got: " + result);
    }

    @Test
    @DisplayName("findDataTypeUsage finds usage in defined data without label")
    void testFindsDataUsage_WithoutLabel() throws Exception {
        builder.setBytes("0x402100", "00 00 00 00 00 00 00 00", false);
        builder.applyDataType("0x402100", myStructDt);
        // No label created

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("00402100"), "Should find data at address, got: " + result);
    }

    // ===== Function return type matches =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in function return type")
    void testFindsReturnTypeUsage() throws Exception {
        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        int tx = program.startTransaction("set return type");
        try {
            func.setReturnType(myStructDt, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"category\":\"Return type\"") && result.contains("\"function\":\"func_alpha\""),
                "Should find return type usage, got: " + result);
    }

    // ===== Function variable matches =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in stack local variable")
    void testFindsLocalVariableUsage() throws Exception {
        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        int tx = program.startTransaction("add local var");
        try {
            LocalVariableImpl local = new LocalVariableImpl("local_struct", myStructDt, -0x10, program);
            func.addLocalVariable(local, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"category\":\"Local variable\"") && result.contains("\"name\":\"local_struct\""),
                "Should find local variable usage, got: " + result);
    }

    @Test
    @DisplayName("findDataTypeUsage finds usage in non-stack parameter variable")
    void testFindsParamVariableUsage() throws Exception {
        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        int tx = program.startTransaction("add param");
        try {
            func.addParameter(
                new ParameterImpl("p1", myStructDt, program),
                SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"category\":\"Param variable\"") && result.contains("\"name\":\"p1\""),
                "Should find param variable usage, got: " + result);
    }

    // ===== Pointer/TypeDef unwrapping =====

    @Test
    @DisplayName("findDataTypeUsage finds usage through pointer wrapping")
    void testFindsUsageThroughPointer() throws Exception {
        PointerDataType ptrType = new PointerDataType(myStructDt);

        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        int tx = program.startTransaction("add ptr param");
        try {
            func.addParameter(
                new ParameterImpl("ptr_param", ptrType, program),
                SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\":\"ptr_param\""),
                "Should find through pointer, got: " + result);
    }

    @Test
    @DisplayName("findDataTypeUsage finds usage through typedef wrapping")
    void testFindsUsageThroughTypedef() throws Exception {
        // Register the typedef in the DTM
        int tx = program.startTransaction("add typedef");
        DataType resolvedTypedef;
        try {
            TypedefDataType td = new TypedefDataType("MY_STRUCT_T", myStructDt);
            resolvedTypedef = program.getDataTypeManager().addDataType(td, null);
        } finally {
            program.endTransaction(tx, true);
        }

        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        tx = program.startTransaction("set typedef return");
        try {
            func.setReturnType(resolvedTypedef, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"function\":\"func_alpha\"") && result.contains("MY_STRUCT_T"),
                "Should find through typedef, got: " + result);
    }

    // ===== Data sub-component matching =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in struct sub-component")
    void testFindsUsageInSubComponent() throws Exception {
        // Register InnerStruct and OuterStruct containing it
        int tx = program.startTransaction("register nested structs");
        DataType outerDt;
        try {
            var dtm = program.getDataTypeManager();

            StructureDataType inner = new StructureDataType("InnerStruct", 0);
            inner.add(IntegerDataType.dataType, "val", null);
            dtm.addDataType(inner, null);

            DataType resolvedInner = dtm.getDataType("/InnerStruct");

            StructureDataType outer = new StructureDataType("OuterStruct", 0);
            outer.add(IntegerDataType.dataType, "padding", null);
            outer.add(resolvedInner, "inner", null);
            outerDt = dtm.addDataType(outer, null);
        } finally {
            program.endTransaction(tx, true);
        }

        builder.setBytes("0x402000", "00 00 00 00 00 00 00 00", false);
        builder.applyDataType("0x402000", outerDt);
        builder.createLabel("0x402000", "outer_var");

        String result = dataTypeService.findDataTypeUsage("InnerStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\":\"outer_var.inner\""),
                "Should find sub-component, got: " + result);
    }

    // ===== Array element optimization =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in array of target type")
    void testFindsUsageInArray() throws Exception {
        int tx = program.startTransaction("register array type");
        DataType arrayDt;
        try {
            ArrayDataType arr = new ArrayDataType(myStructDt, 3, myStructDt.getLength());
            arrayDt = program.getDataTypeManager().addDataType(arr, null);
        } finally {
            program.endTransaction(tx, true);
        }

        // Need enough bytes for 3 elements
        builder.setBytes("0x402000",
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", false);
        builder.applyDataType("0x402000", arrayDt);
        builder.createLabel("0x402000", "struct_array");

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\":\"struct_array\"") || result.contains("00402000"),
                "Should find array usage, got: " + result);
    }

    // ===== Multiple results combined =====

    @Test
    @DisplayName("findDataTypeUsage combines data and function results")
    void testCombinesDataAndFunctionResults() throws Exception {
        // 1. Apply MyStruct to data
        builder.setBytes("0x402000", "00 00 00 00 00 00 00 00", false);
        builder.applyDataType("0x402000", myStructDt);
        builder.createLabel("0x402000", "g_struct");

        // 2. Set return type + add local variable
        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        int tx = program.startTransaction("set func signature");
        try {
            func.setReturnType(myStructDt, SourceType.USER_DEFINED);
            LocalVariableImpl local = new LocalVariableImpl("temp", myStructDt, -0x10, program);
            func.addLocalVariable(local, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\":\"g_struct\"") && result.contains("00402000"),
                "Should find data usage, got: " + result);
        assertTrue(result.contains("\"category\":\"Return type\"") && result.contains("\"function\":\"func_alpha\""),
                "Should find return type, got: " + result);
        assertTrue(result.contains("\"category\":\"Local variable\"") && result.contains("\"name\":\"temp\""),
                "Should find local variable, got: " + result);
    }

    // ===== Pagination =====

    @Test
    @DisplayName("findDataTypeUsage respects pagination offset and limit")
    void testPagination() throws Exception {
        // Create 5 functions with MyStruct return type (use offsets that don't clash with setUp's functions)
        for (int i = 0; i < 5; i++) {
            String addr = String.format("0x40%04x", 0x1200 + i * 0x80);
            builder.createEmptyFunction("pfunc_" + i, addr, 0x20, DataType.DEFAULT);
        }

        int tx = program.startTransaction("set return types");
        try {
            for (int i = 0; i < 5; i++) {
                String addr = String.format("0x40%04x", 0x1200 + i * 0x80);
                Function f = program.getFunctionManager().getFunctionAt(builder.addr(addr));
                if (f != null) {
                    f.setReturnType(myStructDt, SourceType.USER_DEFINED);
                }
            }
        } finally {
            program.endTransaction(tx, true);
        }

        // Request offset=1, limit=2
        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 1, 2).toStructuredJson();
        // With 5 results and offset=1 limit=2, we should get items at index 1 and 2
        // The exact function names depend on iteration order, but we should have exactly 2 items
        assertTrue(result.contains("\"items\""), "Should have items, got: " + result);
        // Count occurrences of "Return type" — should be exactly 2
        int count = 0;
        int idx = 0;
        while ((idx = result.indexOf("\"category\":\"Return type\"", idx)) != -1) {
            count++;
            idx++;
        }
        assertEquals(2, count, "Pagination should return exactly 2 items, got: " + result);
    }

    // ===== Built-in type matching (no UID) =====

    @Test
    @DisplayName("findDataTypeUsage matches built-in types by class and name")
    void testBuiltInTypeMatching() throws Exception {
        // "int" is a built-in type with no UID
        DataType intDt = dataTypeService.resolveDataType(program.getDataTypeManager(), "int");
        if (intDt == null) {
            // Skip if built-in "int" cannot be resolved in this Ghidra install
            return;
        }

        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        int tx = program.startTransaction("set int return");
        try {
            func.setReturnType(intDt, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("int", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"category\":\"Return type\"") && result.contains("\"function\":\"func_alpha\""),
                "Should find built-in type usage, got: " + result);
    }

    // ===== Non-matching data is excluded =====

    @Test
    @DisplayName("findDataTypeUsage excludes data with different type")
    void testExcludesNonMatchingData() throws Exception {
        // Apply OtherStruct, then search for MyStruct
        DataType otherDt = program.getDataTypeManager().getDataType("/OtherStruct");
        builder.setBytes("0x402000", "00 00 00 00", false);
        builder.applyDataType("0x402000", otherDt);

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No usages found for data type: MyStruct\""),
                "Should not find OtherStruct as MyStruct, got: " + result);
    }

    // ===== Field-specific search tests =====

    @Test
    @DisplayName("field search returns error for non-composite type")
    void testFieldSearch_NonCompositeType() throws Exception {
        // Register an enum (non-composite) and search for a field on it
        int tx = program.startTransaction("register enum");
        try {
            EnumDataType enumDt = new EnumDataType("MyEnum", 4);
            enumDt.add("VAL_A", 1);
            program.getDataTypeManager().addDataType(enumDt, null);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("MyEnum", "x", 0, 100).toStructuredJson();
        assertTrue(result.contains("Field search requires a composite (struct/union) type"),
                "Should report non-composite error, got: " + result);
    }

    @Test
    @DisplayName("field search returns error when field not found in struct")
    void testFieldSearch_FieldNotFound() {
        // MyStruct has fields "x" and "y", search for "nonexistent"
        String result = dataTypeService.findDataTypeUsage("MyStruct", "nonexistent", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"Field 'nonexistent' not found in MyStruct\""),
                "Should report field not found, got: " + result);
    }

    @Test
    @DisplayName("field search finds matching field in defined data")
    void testFieldSearch_FindsMatchingField() throws Exception {
        // Register POINT struct with x and y fields
        int tx = program.startTransaction("register POINT");
        DataType pointDt;
        try {
            var dtm = program.getDataTypeManager();
            StructureDataType point = new StructureDataType("POINT", 0);
            point.add(IntegerDataType.dataType, "x", null);
            point.add(IntegerDataType.dataType, "y", null);
            pointDt = dtm.addDataType(point, null);
        } finally {
            program.endTransaction(tx, true);
        }

        builder.setBytes("0x402000", "00 00 00 00 00 00 00 00", false);
        builder.applyDataType("0x402000", pointDt);
        builder.createLabel("0x402000", "origin");

        String result = dataTypeService.findDataTypeUsage("POINT", "x", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\":\"origin.x\"") && result.contains("00402000"),
                "Should find field x in origin, got: " + result);
        assertFalse(result.contains("origin.y"),
                "Should not find field y, got: " + result);
    }

    @Test
    @DisplayName("field search skips function signatures")
    void testFieldSearch_SkipsFunctionSignatures() throws Exception {
        // Register POINT
        int tx = program.startTransaction("register POINT");
        DataType pointDt;
        try {
            var dtm = program.getDataTypeManager();
            StructureDataType point = new StructureDataType("POINT_SKIP", 0);
            point.add(IntegerDataType.dataType, "x", null);
            pointDt = dtm.addDataType(point, null);
        } finally {
            program.endTransaction(tx, true);
        }

        // Set a function return type to POINT_SKIP — field search should skip it
        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        tx = program.startTransaction("set return type");
        try {
            func.setReturnType(pointDt, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("POINT_SKIP", "x", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No usages found for data type: POINT_SKIP.x\""),
                "Field search should skip function signatures, got: " + result);
    }

    @Test
    @DisplayName("field search no-usages message includes field name")
    void testFieldSearch_NoUsagesMessageIncludesField() throws Exception {
        // Register RECT with a "top" field
        int tx = program.startTransaction("register RECT");
        try {
            var dtm = program.getDataTypeManager();
            StructureDataType rect = new StructureDataType("RECT", 0);
            rect.add(IntegerDataType.dataType, "top", null);
            dtm.addDataType(rect, null);
        } finally {
            program.endTransaction(tx, true);
        }

        String result = dataTypeService.findDataTypeUsage("RECT", "top", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No usages found for data type: RECT.top\""),
                "No-usages message should include field name, got: " + result);
    }
}
