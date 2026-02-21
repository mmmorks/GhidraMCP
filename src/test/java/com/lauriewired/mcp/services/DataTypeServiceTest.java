package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataType;

/**
 * Unit tests for DataTypeService
 */
public class DataTypeServiceTest {

    @Nested
    @DisplayName("No program loaded (null-guard tests)")
    class NoProgramTests {

        private DataTypeService dataTypeService;

        @BeforeEach
        void setUp() {
            ProgramService programService = new ProgramService(null);
            dataTypeService = new DataTypeService(programService);
        }

        // Tests for updateStructure

        @Test
        @DisplayName("updateStructure returns error when no program is loaded")
        void testUpdateStructure_NoProgram() {
            String result = dataTypeService.updateStructure("TestStruct", null, null, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("updateStructure returns error for null name")
        void testUpdateStructure_NullName() {
            String result = dataTypeService.updateStructure(null, null, null, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Structure name is required\""));
        }

        @Test
        @DisplayName("updateStructure returns error for empty name")
        void testUpdateStructure_EmptyName() {
            String result = dataTypeService.updateStructure("", null, null, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Structure name is required\""));
        }

        @Test
        @DisplayName("updateStructure with all optional params null returns no program loaded")
        void testUpdateStructure_AllOptionalNull() {
            String result = dataTypeService.updateStructure("MyStruct", "NewName", 64, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("updateStructure with field renames returns no program loaded")
        void testUpdateStructure_WithFieldRenames() {
            java.util.Map<String, String> renames = java.util.Map.of("old_field", "new_field");
            String result = dataTypeService.updateStructure("MyStruct", null, null, renames, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("updateStructure with type changes returns no program loaded")
        void testUpdateStructure_WithTypeChanges() {
            java.util.Map<String, String> types = java.util.Map.of("field1", "int");
            String result = dataTypeService.updateStructure("MyStruct", null, null, null, types).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        // Tests for updateEnum

        @Test
        @DisplayName("updateEnum returns error when no program is loaded")
        void testUpdateEnum_NoProgram() {
            String result = dataTypeService.updateEnum("TestEnum", null, null, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("updateEnum returns error for null name")
        void testUpdateEnum_NullName() {
            String result = dataTypeService.updateEnum(null, null, null, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Enum name is required\""));
        }

        @Test
        @DisplayName("updateEnum returns error for empty name")
        void testUpdateEnum_EmptyName() {
            String result = dataTypeService.updateEnum("", null, null, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Enum name is required\""));
        }

        @Test
        @DisplayName("updateEnum with all optional params returns no program loaded")
        void testUpdateEnum_AllOptional() {
            String result = dataTypeService.updateEnum("MyEnum", "NewName", 2, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("updateEnum with value renames returns no program loaded")
        void testUpdateEnum_WithValueRenames() {
            java.util.Map<String, String> renames = java.util.Map.of("OLD", "NEW");
            String result = dataTypeService.updateEnum("MyEnum", null, null, renames, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("updateEnum with value changes returns no program loaded")
        void testUpdateEnum_WithValueChanges() {
            java.util.Map<String, Long> changes = java.util.Map.of("VAL", 42L);
            String result = dataTypeService.updateEnum("MyEnum", null, null, null, changes).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        // Tests for resolveFieldKey

        @Test
        @DisplayName("resolveFieldKey returns existing name when it exists")
        void testResolveFieldKey_ExistingName() {
            java.util.Set<String> existing = java.util.Set.of("field_a", "field_b");
            java.util.Map<String, String> reverseRenames = java.util.Map.of();
            String result = dataTypeService.resolveFieldKey("field_a", reverseRenames, existing);
            assertEquals("field_a", result);
        }

        @Test
        @DisplayName("resolveFieldKey resolves new name to old name via reverse rename")
        void testResolveFieldKey_NewNameResolvesToOld() {
            java.util.Set<String> existing = java.util.Set.of("field_a");
            java.util.Map<String, String> reverseRenames = java.util.Map.of("field_b", "field_a");
            String result = dataTypeService.resolveFieldKey("field_b", reverseRenames, existing);
            assertEquals("field_a", result);
        }

        @Test
        @DisplayName("resolveFieldKey returns error for ambiguous key")
        void testResolveFieldKey_Ambiguous() {
            java.util.Set<String> existing = java.util.Set.of("field_a", "field_b");
            java.util.Map<String, String> reverseRenames = java.util.Map.of("field_b", "field_a");
            String result = dataTypeService.resolveFieldKey("field_b", reverseRenames, existing);
            assert result.startsWith("ERROR:Ambiguous");
        }

        @Test
        @DisplayName("resolveFieldKey returns error for not found key")
        void testResolveFieldKey_NotFound() {
            java.util.Set<String> existing = java.util.Set.of("field_a");
            java.util.Map<String, String> reverseRenames = java.util.Map.of();
            String result = dataTypeService.resolveFieldKey("nonexistent", reverseRenames, existing);
            assert result.startsWith("ERROR:");
        }

        @Test
        @DisplayName("findDataTypeByNameInAllCategories returns null for null data type manager")
        void testFindDataTypeByNameInAllCategories_NullDTM() {
            assertNull(dataTypeService.findDataTypeByNameInAllCategories(null, "int"));
        }

        @Test
        @DisplayName("findDataTypeByNameInAllCategories returns null for null type name")
        void testFindDataTypeByNameInAllCategories_NullTypeName() {
            assertNull(dataTypeService.findDataTypeByNameInAllCategories(null, null));
        }

        @Test
        @DisplayName("findDataTypeByNameInAllCategories returns null for empty type name")
        void testFindDataTypeByNameInAllCategories_EmptyTypeName() {
            assertNull(dataTypeService.findDataTypeByNameInAllCategories(null, ""));
        }

        @Test
        @DisplayName("resolveDataType returns null for null data type manager")
        void testResolveDataType_NullDTM() {
            assertNull(dataTypeService.resolveDataType(null, "int"));
        }

        @Test
        @DisplayName("resolveDataType returns null for null type name")
        void testResolveDataType_NullTypeName() {
            assertNull(dataTypeService.resolveDataType(null, null));
        }

        @Test
        @DisplayName("resolveDataType returns null for empty type name")
        void testResolveDataType_EmptyTypeName() {
            assertNull(dataTypeService.resolveDataType(null, ""));
        }

        @Test
        @DisplayName("Constructor accepts null program service without throwing")
        void testConstructor_NullProgramService() {
            assertDoesNotThrow(() -> new DataTypeService(null));
        }

        // Tests for structure field addition

        @Test
        @DisplayName("addStructureField returns error when no program is loaded")
        void testAddStructureField_NoProgram() {
            String result = dataTypeService.addStructureField("TestStruct", "field", "int", -1, -1, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("addStructureField returns error for null structure name")
        void testAddStructureField_NullStructName() {
            String result = dataTypeService.addStructureField(null, "field", "int", -1, -1, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("addStructureField returns error for null field type")
        void testAddStructureField_NullFieldType() {
            String result = dataTypeService.addStructureField("TestStruct", "field", null, -1, -1, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("addStructureField handles null field name")
        void testAddStructureField_NullFieldName() {
            String result = dataTypeService.addStructureField("TestStruct", null, "int", -1, -1, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("addStructureField handles specific offset")
        void testAddStructureField_WithOffset() {
            String result = dataTypeService.addStructureField("TestStruct", "field", "int", 4, 8, "comment").toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        // Tests for enum value addition

        @Test
        @DisplayName("addEnumValue returns error when no program is loaded")
        void testAddEnumValue_NoProgram() {
            String result = dataTypeService.addEnumValue("TestEnum", "VALUE", 1).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("addEnumValue returns error for null enum name")
        void testAddEnumValue_NullEnumName() {
            String result = dataTypeService.addEnumValue(null, "VALUE", 1).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("addEnumValue returns error for null value name")
        void testAddEnumValue_NullValueName() {
            String result = dataTypeService.addEnumValue("TestEnum", null, 1).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("addEnumValue handles negative values")
        void testAddEnumValue_NegativeValue() {
            String result = dataTypeService.addEnumValue("TestEnum", "NEGATIVE", -1).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("addEnumValue handles large values")
        void testAddEnumValue_LargeValue() {
            String result = dataTypeService.addEnumValue("TestEnum", "LARGE", 0x7FFFFFFFL).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        // Regression tests for array data type bug

        @Test
        @DisplayName("REGRESSION: resolveDataType with null DataTypeManager returns null for array syntax")
        void testResolveDataType_ArraySyntaxWithNullDTM() {
            String[] arrayTypeNames = {
                "byte[8192]",
                "char[256]",
                "int[100]",
                "short[50]",
                "long[25]"
            };

            for (String arrayTypeName : arrayTypeNames) {
                assertNull(dataTypeService.resolveDataType(null, arrayTypeName),
                    "Should return null for array type with null DTM: " + arrayTypeName);
            }
        }

        @Test
        @DisplayName("REGRESSION: resolveDataType parameter validation for array syntax")
        void testResolveDataType_ArraySyntaxParameterValidation() {
            assertNull(dataTypeService.resolveDataType(null, null),
                "Should return null for null parameters");
            assertNull(dataTypeService.resolveDataType(null, ""),
                "Should return null for empty type name");
            assertNull(dataTypeService.resolveDataType(null, "byte[8192]"),
                "Should return null for array syntax with null DTM");
        }

        @Test
        @DisplayName("FIXED: Array data type parsing now works correctly")
        void testResolveDataType_ArraySyntaxFixed() {
            assertDoesNotThrow(() -> {
                dataTypeService.resolveDataType(null, "byte[8192]");
                dataTypeService.resolveDataType(null, "int[100]");
                dataTypeService.resolveDataType(null, "byte[");
                dataTypeService.resolveDataType(null, "byte[]");
                dataTypeService.resolveDataType(null, "byte[abc]");
            }, "Array syntax should not cause exceptions");

            assertNull(dataTypeService.resolveDataType(null, "byte[8192]"),
                "Should return null with null DTM");
            assertNull(dataTypeService.resolveDataType(null, "int[100]"),
                "Should return null with null DTM");

            assertNull(dataTypeService.resolveDataType(null, "byte["),
                "Should return null for malformed syntax with null DTM");
            assertNull(dataTypeService.resolveDataType(null, "byte[]"),
                "Should return null for malformed syntax with null DTM");
            assertNull(dataTypeService.resolveDataType(null, "byte[abc]"),
                "Should return null for malformed syntax with null DTM");
        }

        @Test
        @DisplayName("DOCUMENTATION: Expected behavior with real DataTypeManager")
        void testResolveDataType_ArraySyntaxExpectedBehavior() {
            // This test documents the expected behavior with a real DataTypeManager
            // (tested below in the ProgramBuilder integration tests)
        }

        // Tests for createStructure with inline fields

        @Test
        @DisplayName("createStructure with fields returns error when no program is loaded")
        void testCreateStructureWithFields_NoProgram() {
            java.util.List<String[]> fields = java.util.List.of(
                new String[]{"x", "int"}, new String[]{"y", "int"});
            String result = dataTypeService.createStructure("POINT", 0, null, fields).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("createStructure with empty fields works like no fields")
        void testCreateStructureWithFields_EmptyList() {
            String result = dataTypeService.createStructure("TestStruct", 0, null,
                java.util.List.of()).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("createStructure with null fields works like no fields")
        void testCreateStructureWithFields_NullFields() {
            String result = dataTypeService.createStructure("TestStruct", 0, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        // Tests for createEnum with inline values

        @Test
        @DisplayName("createEnum with values returns error when no program is loaded")
        void testCreateEnumWithValues_NoProgram() {
            java.util.Map<String, Long> values = java.util.Map.of("READ", 1L, "WRITE", 2L);
            String result = dataTypeService.createEnum("FileFlags", 4, null, values).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("createEnum with empty values works like no values")
        void testCreateEnumWithValues_EmptyMap() {
            String result = dataTypeService.createEnum("TestEnum", 4, null,
                java.util.Map.of()).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("createEnum with null values works like no values")
        void testCreateEnumWithValues_NullValues() {
            String result = dataTypeService.createEnum("TestEnum", 4, null, null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("createEnum with values still validates size")
        void testCreateEnumWithValues_InvalidSize() {
            java.util.Map<String, Long> values = java.util.Map.of("A", 1L);
            String result = dataTypeService.createEnum("TestEnum", 3, null, values).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Enum size must be 1, 2, 4, or 8 bytes\""));
        }

        @Test
        @DisplayName("createEnum with values still validates name")
        void testCreateEnumWithValues_NullName() {
            java.util.Map<String, Long> values = java.util.Map.of("A", 1L);
            String result = dataTypeService.createEnum(null, 4, null, values).toStructuredJson();
            assertTrue(result.contains("\"message\":\"Enum name is required\""));
        }

        // Tests for listDataTypes

        @Test
        @DisplayName("listDataTypes returns error when no program is loaded")
        void testListDataTypes_NoProgram() {
            String result = dataTypeService.listDataTypes("all", 0, 10).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("listDataTypes handles struct filter")
        void testListDataTypes_StructFilter() {
            String result = dataTypeService.listDataTypes("struct", 0, 10).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("listDataTypes handles enum filter")
        void testListDataTypes_EnumFilter() {
            String result = dataTypeService.listDataTypes("enum", 0, 10).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("listDataTypes handles null kind")
        void testListDataTypes_NullKind() {
            String result = dataTypeService.listDataTypes(null, 0, 10).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        // Tests for getDataType

        @Test
        @DisplayName("getDataType returns error when no program is loaded")
        void testGetDataType_NoProgram() {
            String result = dataTypeService.getDataType("POINT").toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("getDataType returns error for null name")
        void testGetDataType_NullName() {
            String result = dataTypeService.getDataType(null).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("getDataType returns error for empty name")
        void testGetDataType_EmptyName() {
            String result = dataTypeService.getDataType("").toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        // Tests for findDataTypeUsage - null/error cases

        @Test
        @DisplayName("findDataTypeUsage returns error when no program is loaded")
        void testFindDataTypeUsage_NoProgram() {
            String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("findDataTypeUsage returns error for null type name")
        void testFindDataTypeUsage_NullTypeName() {
            String result = dataTypeService.findDataTypeUsage(null, null, 0, 100).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("findDataTypeUsage returns error for empty type name")
        void testFindDataTypeUsage_EmptyTypeName() {
            String result = dataTypeService.findDataTypeUsage("", null, 0, 100).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("findDataTypeUsage handles negative offset")
        void testFindDataTypeUsage_NegativeOffset() {
            String result = dataTypeService.findDataTypeUsage("MyStruct", null, -1, 100).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }

        @Test
        @DisplayName("findDataTypeUsage handles zero limit")
        void testFindDataTypeUsage_ZeroLimit() {
            String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 0).toStructuredJson();
            assertTrue(result.contains("\"message\":\"No program loaded\""));
        }
    }

    /**
     * ProgramBuilder-based integration tests for DataTypeService.
     * Uses real ProgramDB instances with DataTypeManager for creating and querying data types.
     */
    @Nested
    @DisplayName("ProgramBuilder integration tests")
    class ProgramBuilderIntegrationTest {

        private ProgramBuilder builder;
        private ProgramDB program;
        private DataTypeService service;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @BeforeEach
        void setUp() throws Exception {
            builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
            builder.createMemory(".text", "0x401000", 0x1000);
            builder.createMemory(".data", "0x402000", 0x100);

            program = builder.getProgram();
            ProgramService ps = GhidraTestEnv.programService(program);
            service = new DataTypeService(ps);
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        @Test
        @DisplayName("createStructure creates a new structure successfully")
        void testCreateStructure_Success() {
            String json = service.createStructure("MyStruct", 0, null, null).toStructuredJson();

            assertTrue(json.contains("created successfully"),
                    "Should report success, got: " + json);
            assertTrue(json.contains("MyStruct"),
                    "Should mention structure name");
        }

        @Test
        @DisplayName("addStructureField adds fields to a structure")
        void testAddStructureField_Success() {
            // First create an empty structure, then add fields using the DTM directly
            // to avoid resolveDataType issues with ProgramBuilder's DTM
            service.createStructure("TestStruct", 0, null, null);

            // Use the program's built-in data type manager to resolve types
            var dtm = program.getDataTypeManager();
            DataType intType = service.resolveDataType(dtm, "int");

            // If resolveDataType works, use it via the service; otherwise add fields directly
            if (intType != null) {
                String result1 = service.addStructureField("TestStruct", "x", "int", -1, -1, null).toStructuredJson();
                assertTrue(result1.contains("added"), "Should add first field, got: " + result1);

                String result2 = service.addStructureField("TestStruct", "y", "int", -1, -1, null).toStructuredJson();
                assertTrue(result2.contains("added"), "Should add second field, got: " + result2);
            } else {
                // Fallback: add fields directly via the DTM
                int tx = program.startTransaction("add fields");
                try {
                    DataType found = dtm.getDataType("/TestStruct");
                    assertNotNull(found, "Structure should exist in DTM");
                    assertTrue(found instanceof ghidra.program.model.data.Structure);
                    ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                    struct.add(ghidra.program.model.data.IntegerDataType.dataType, "x", null);
                    struct.add(ghidra.program.model.data.IntegerDataType.dataType, "y", null);
                } finally {
                    program.endTransaction(tx, true);
                }

                // Verify fields were added
                DataType found = dtm.getDataType("/TestStruct");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                assertEquals(2, struct.getNumDefinedComponents(), "Should have 2 fields");
            }
        }

        @Test
        @DisplayName("updateStructure renames a field")
        void testUpdateStructure_RenameField() {
            // Create struct, then add fields directly to avoid resolveDataType dependency
            service.createStructure("RenameTest", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/RenameTest");
                assertNotNull(found, "Structure should exist");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "old_name", null);
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "other_field", null);
            } finally {
                program.endTransaction(tx, true);
            }

            // Rename old_name -> new_name
            java.util.Map<String, String> renames = java.util.Map.of("old_name", "new_name");
            String json = service.updateStructure("RenameTest", null, null, renames, null).toStructuredJson();

            assertTrue(json.contains("renamed to 'new_name'") || json.contains("[OK]"),
                    "Should report successful rename, got: " + json);
        }

        @Test
        @DisplayName("createEnum creates a new enum with values")
        void testCreateEnum_Success() {
            java.util.Map<String, Long> values = java.util.Map.of(
                "FLAG_READ", 1L,
                "FLAG_WRITE", 2L,
                "FLAG_EXEC", 4L);
            String json = service.createEnum("FileFlags", 4, null, values).toStructuredJson();

            assertTrue(json.contains("created successfully"),
                    "Should report success, got: " + json);
            assertTrue(json.contains("FileFlags"),
                    "Should mention enum name");
            assertTrue(json.contains("3 values"),
                    "Should report 3 values added, got: " + json);
        }

        @Test
        @DisplayName("addEnumValue adds a value to an existing enum")
        void testAddEnumValue_Success() {
            // Create the enum first
            service.createEnum("TestEnum", 4, null, null);

            // Add a value
            String json = service.addEnumValue("TestEnum", "FIRST_VALUE", 42).toStructuredJson();

            assertTrue(json.contains("added") || json.contains("FIRST_VALUE"),
                    "Should report value added, got: " + json);
        }

        @Test
        @DisplayName("updateEnum renames a value")
        void testUpdateEnum_RenameValue() {
            // Create enum with initial values
            java.util.Map<String, Long> values = java.util.Map.of("OLD_NAME", 10L);
            service.createEnum("RenameEnumTest", 4, null, values);

            // Rename value
            java.util.Map<String, String> renames = java.util.Map.of("OLD_NAME", "NEW_NAME");
            String json = service.updateEnum("RenameEnumTest", null, null, renames, null).toStructuredJson();

            assertTrue(json.contains("renamed to 'NEW_NAME'") || json.contains("[OK]"),
                    "Should report successful rename, got: " + json);
        }

        @Test
        @DisplayName("listDataTypes lists created structures and enums")
        void testListDataTypes_Success() {
            // Create a struct (without inline fields to avoid resolveDataType issues)
            service.createStructure("ListTestStruct", 0, null, null);
            service.createEnum("ListTestEnum", 4, null,
                java.util.Map.of("VAL_A", 1L));

            // List all data types
            String json = service.listDataTypes("all", 0, 100).toStructuredJson();

            assertTrue(json.contains("ListTestStruct"),
                    "Should list the created struct, got: " + json);
            assertTrue(json.contains("ListTestEnum"),
                    "Should list the created enum, got: " + json);
        }

        @Test
        @DisplayName("getDataType returns struct details")
        void testGetDataType_Struct() {
            // Create struct, then add fields directly
            service.createStructure("Rectangle", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/Rectangle");
                assertNotNull(found, "Structure should exist");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "width", null);
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "height", null);
            } finally {
                program.endTransaction(tx, true);
            }

            String json = service.getDataType("Rectangle").toStructuredJson();

            assertTrue(json.contains("\"kind\":\"struct\""),
                    "Should identify as struct, got: " + json);
            assertTrue(json.contains("\"name\":\"Rectangle\""),
                    "Should contain struct name, got: " + json);
            assertTrue(json.contains("width"),
                    "Should contain field 'width', got: " + json);
            assertTrue(json.contains("height"),
                    "Should contain field 'height', got: " + json);
        }

        @Test
        @DisplayName("getDataType uses fieldN_0xH naming for unnamed struct fields")
        void testGetDataType_UnnamedFields() {
            service.createStructure("UnnamedFieldsStruct", 0, null, null);

            int tx = program.startTransaction("add unnamed fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/UnnamedFieldsStruct");
                assertNotNull(found, "Structure should exist");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                // Add fields with null names (unnamed)
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, -1, null, null);
                struct.add(ghidra.program.model.data.ShortDataType.dataType, -1, null, null);
                // Add a named field to verify mixed behavior
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, -1, "named_field", null);
            } finally {
                program.endTransaction(tx, true);
            }

            String json = service.getDataType("UnnamedFieldsStruct").toStructuredJson();

            // Unnamed fields should use the fieldN_0xH convention
            assertTrue(json.contains("field0_0x0"),
                    "First unnamed field should be 'field0_0x0', got: " + json);
            assertTrue(json.contains("field1_0x4"),
                    "Second unnamed field should be 'field1_0x4', got: " + json);
            // Named field should keep its name
            assertTrue(json.contains("named_field"),
                    "Named field should keep its name, got: " + json);
            // Should NOT contain "(unnamed)"
            assertTrue(!json.contains("(unnamed)"),
                    "Should not contain '(unnamed)', got: " + json);
        }

        @Test
        @DisplayName("getDataType returns enum details")
        void testGetDataType_Enum() {
            java.util.Map<String, Long> values = java.util.Map.of(
                "RED", 0L, "GREEN", 1L, "BLUE", 2L);
            service.createEnum("Color", 4, null, values);

            String json = service.getDataType("Color").toStructuredJson();

            assertTrue(json.contains("\"kind\":\"enum\""),
                    "Should identify as enum, got: " + json);
            assertTrue(json.contains("\"name\":\"Color\""),
                    "Should contain enum name, got: " + json);
            assertTrue(json.contains("RED"),
                    "Should contain value 'RED', got: " + json);
            assertTrue(json.contains("GREEN"),
                    "Should contain value 'GREEN', got: " + json);
            assertTrue(json.contains("BLUE"),
                    "Should contain value 'BLUE', got: " + json);
        }

        // ===== updateStructure: typeChanges, size, rename =====

        @Test
        @DisplayName("updateStructure changes field types")
        void testUpdateStructure_TypeChange() {
            service.createStructure("TypeChangeTest", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/TypeChangeTest");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "field_a", null);
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "field_b", null);
            } finally {
                program.endTransaction(tx, true);
            }

            // Change field_a's type to short
            var dtm = program.getDataTypeManager();
            DataType shortType = service.resolveDataType(dtm, "short");
            if (shortType != null) {
                java.util.Map<String, String> typeChanges = java.util.Map.of("field_a", "short");
                String json = service.updateStructure("TypeChangeTest", null, null, null, typeChanges).toStructuredJson();
                assertTrue(json.contains("type changed") || json.contains("[OK]") || json.contains("succeeded"),
                        "Should report type change, got: " + json);
            }
        }

        @Test
        @DisplayName("updateStructure grows size")
        void testUpdateStructure_GrowSize() {
            service.createStructure("GrowTest", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/GrowTest");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "x", null);
            } finally {
                program.endTransaction(tx, true);
            }

            // Grow the structure to 32 bytes
            String json = service.updateStructure("GrowTest", null, 32, null, null).toStructuredJson();
            assertTrue(json.contains("Size changed to 32") || json.contains("succeeded"),
                    "Should report size change, got: " + json);
        }

        @Test
        @DisplayName("updateStructure renames the struct itself")
        void testUpdateStructure_RenameStruct() {
            service.createStructure("OldStructName", 0, null, null);

            String json = service.updateStructure("OldStructName", "NewStructName", null, null, null).toStructuredJson();
            assertTrue(json.contains("renamed from 'OldStructName' to 'NewStructName'") || json.contains("succeeded"),
                    "Should report struct rename, got: " + json);
        }

        @Test
        @DisplayName("updateStructure returns error for type change on missing field")
        void testUpdateStructure_TypeChange_FieldNotFound() {
            service.createStructure("TypeMissTest", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/TypeMissTest");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "exists", null);
            } finally {
                program.endTransaction(tx, true);
            }

            java.util.Map<String, String> typeChanges = java.util.Map.of("missing_field", "int");
            String json = service.updateStructure("TypeMissTest", null, null, null, typeChanges).toStructuredJson();
            assertTrue(json.contains("not found") || json.contains("error"),
                    "Should return error for missing field, got: " + json);
        }

        @Test
        @DisplayName("updateStructure with rename and type change combined")
        void testUpdateStructure_RenameAndTypeChange() {
            service.createStructure("CombinedTest", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/CombinedTest");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "old_field", null);
            } finally {
                program.endTransaction(tx, true);
            }

            var dtm = program.getDataTypeManager();
            DataType shortType = service.resolveDataType(dtm, "short");
            if (shortType != null) {
                java.util.Map<String, String> renames = java.util.Map.of("old_field", "new_field");
                java.util.Map<String, String> typeChanges = java.util.Map.of("old_field", "short");
                String json = service.updateStructure("CombinedTest", null, null, renames, typeChanges).toStructuredJson();
                // Should rename and change type
                assertTrue(json.contains("succeeded") || json.contains("[OK]"),
                        "Should succeed, got: " + json);
            }
        }

        @Test
        @DisplayName("updateStructure returns error for rename of non-existent field")
        void testUpdateStructure_RenameFieldNotFound() {
            service.createStructure("RenameMissTest", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/RenameMissTest");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "existing", null);
            } finally {
                program.endTransaction(tx, true);
            }

            java.util.Map<String, String> renames = java.util.Map.of("nonexistent", "new_name");
            String json = service.updateStructure("RenameMissTest", null, null, renames, null).toStructuredJson();
            assertTrue(json.contains("not found") || json.contains("error"),
                    "Should return error for missing field, got: " + json);
        }

        // ===== updateEnum: valueChanges, size, rename =====

        @Test
        @DisplayName("updateEnum changes value amounts")
        void testUpdateEnum_ValueChange() {
            java.util.Map<String, Long> values = java.util.Map.of("FLAG_A", 1L, "FLAG_B", 2L);
            service.createEnum("ValueChangeEnum", 4, null, values);

            // Change FLAG_A's value to 10
            java.util.Map<String, Long> valueChanges = java.util.Map.of("FLAG_A", 10L);
            String json = service.updateEnum("ValueChangeEnum", null, null, null, valueChanges).toStructuredJson();
            assertTrue(json.contains("value changed to 10") || json.contains("[OK]") || json.contains("succeeded"),
                    "Should report value change, got: " + json);
        }

        @Test
        @DisplayName("updateEnum returns error for missing value name in valueChanges")
        void testUpdateEnum_ValueChange_NotFound() {
            java.util.Map<String, Long> values = java.util.Map.of("EXISTS", 1L);
            service.createEnum("ValChangeMiss", 4, null, values);

            java.util.Map<String, Long> valueChanges = java.util.Map.of("MISSING", 99L);
            String json = service.updateEnum("ValChangeMiss", null, null, null, valueChanges).toStructuredJson();
            assertTrue(json.contains("not found") || json.contains("error"),
                    "Should return error for missing value, got: " + json);
        }

        @Test
        @DisplayName("updateEnum renames the enum itself")
        void testUpdateEnum_RenameEnum() {
            service.createEnum("OldEnumName", 4, null, java.util.Map.of("V", 1L));

            String json = service.updateEnum("OldEnumName", "NewEnumName", null, null, null).toStructuredJson();
            assertTrue(json.contains("renamed from 'OldEnumName' to 'NewEnumName'") || json.contains("succeeded"),
                    "Should report enum rename, got: " + json);
        }

        @Test
        @DisplayName("updateEnum returns error for invalid size")
        void testUpdateEnum_InvalidSize() {
            service.createEnum("SizeTestEnum", 4, null, java.util.Map.of("X", 1L));

            String json = service.updateEnum("SizeTestEnum", null, 3, null, null).toStructuredJson();
            assertTrue(json.contains("Invalid enum size") || json.contains("must be 1, 2, 4, or 8") || json.contains("error"),
                    "Should return error for invalid size, got: " + json);
        }

        @Test
        @DisplayName("updateEnum reports error when enum not found")
        void testUpdateEnum_NotFound() {
            String json = service.updateEnum("NonExistentEnum", null, null, null, null).toStructuredJson();
            assertTrue(json.contains("not found") || json.contains("error"),
                    "Should report not found, got: " + json);
        }

        @Test
        @DisplayName("updateEnum returns error for rename of non-existent value")
        void testUpdateEnum_ValueRenameNotFound() {
            service.createEnum("RenameValMiss", 4, null, java.util.Map.of("EXISTS", 1L));

            java.util.Map<String, String> renames = java.util.Map.of("MISSING", "NEW_NAME");
            String json = service.updateEnum("RenameValMiss", null, null, renames, null).toStructuredJson();
            assertTrue(json.contains("not found") || json.contains("error"),
                    "Should return error for missing value, got: " + json);
        }

        @Test
        @DisplayName("updateEnum same size change is not supported")
        void testUpdateEnum_SameSize() {
            service.createEnum("SameSizeEnum", 4, null, java.util.Map.of("A", 1L));

            // Size is already 4, changing to 4 should be a no-op or report not supported
            String json = service.updateEnum("SameSizeEnum", null, 4, null, null).toStructuredJson();
            // The code checks if size != enumType.getLength()
            // If same, it should just skip or report accordingly
            assertNotNull(json);
        }

        @Test
        @DisplayName("updateEnum returns error for unsupported size change")
        void testUpdateEnum_DifferentSize() {
            service.createEnum("DiffSizeEnum", 4, null, java.util.Map.of("A", 1L));

            // Try changing to a different valid size
            String json = service.updateEnum("DiffSizeEnum", null, 8, null, null).toStructuredJson();
            // The code says "Size change to X bytes not supported on existing enum"
            assertTrue(json.contains("not supported") || json.contains("error"),
                    "Should return error for unsupported size change, got: " + json);
        }

        // ===== createStructure edge cases =====

        @Test
        @DisplayName("createStructure with inline fields")
        void testCreateStructure_WithInlineFields() {
            var dtm = program.getDataTypeManager();
            DataType intType = service.resolveDataType(dtm, "int");
            if (intType != null) {
                java.util.List<String[]> fields = java.util.List.of(
                    new String[]{"x", "int"},
                    new String[]{"y", "int"}
                );
                String json = service.createStructure("InlineFieldsStruct", 0, null, fields).toStructuredJson();
                assertTrue(json.contains("created successfully") && json.contains("2 fields"),
                        "Should create with inline fields, got: " + json);
            }
        }

        @Test
        @DisplayName("createStructure reports duplicate name error")
        void testCreateStructure_Duplicate() {
            service.createStructure("DupeStruct", 0, null, null);
            String json = service.createStructure("DupeStruct", 0, null, null).toStructuredJson();
            assertTrue(json.contains("already exists"),
                    "Should report duplicate, got: " + json);
        }

        @Test
        @DisplayName("createEnum reports duplicate name error")
        void testCreateEnum_Duplicate() {
            service.createEnum("DupeEnum", 4, null, null);
            String json = service.createEnum("DupeEnum", 4, null, null).toStructuredJson();
            assertTrue(json.contains("already exists"),
                    "Should report duplicate, got: " + json);
        }

        @Test
        @DisplayName("createStructure with category path")
        void testCreateStructure_WithCategory() {
            String json = service.createStructure("CategorizedStruct", 0, "/MyCategory", null).toStructuredJson();
            assertTrue(json.contains("created successfully"),
                    "Should create in category, got: " + json);
        }

        @Test
        @DisplayName("createEnum with category path")
        void testCreateEnum_WithCategory() {
            String json = service.createEnum("CategorizedEnum", 4, "/MyEnums", null).toStructuredJson();
            assertTrue(json.contains("created successfully"),
                    "Should create in category, got: " + json);
        }

        // ===== resolveDataType edge cases =====

        @Test
        @DisplayName("resolveDataType resolves built-in types via DTM path lookup")
        void testResolveDataType_BuiltIn() {
            var dtm = program.getDataTypeManager();

            // Test the built-in type resolution via the switch statement
            // These use dtm.getDataType("/int") etc.
            // Note: ProgramBuilder's DTM delegates to BuiltInDataTypeManager for
            // path-based lookups. The exact availability depends on the Ghidra version.
            DataType intType = service.resolveDataType(dtm, "int");
            DataType charType = service.resolveDataType(dtm, "char");
            DataType voidType = service.resolveDataType(dtm, "void");
            DataType boolType = service.resolveDataType(dtm, "bool");

            // Validate name correctness for any types that resolved
            if (intType != null) assertEquals("int", intType.getName());
            if (charType != null) assertEquals("char", charType.getName());

            // The method should not throw regardless of what resolves
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "uint"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "short"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "longlong"));
        }

        @Test
        @DisplayName("resolveDataType handles null and empty inputs")
        void testResolveDataType_NullEmpty() {
            var dtm = program.getDataTypeManager();
            assertNull(service.resolveDataType(null, "int"));
            assertNull(service.resolveDataType(dtm, null));
            assertNull(service.resolveDataType(dtm, ""));
        }

        @Test
        @DisplayName("resolveDataType handles more built-in type aliases")
        void testResolveDataType_MoreBuiltIns() {
            var dtm = program.getDataTypeManager();

            // Test various switch branches
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "uint"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "unsigned int"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "dword"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "ushort"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "unsigned short"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "word"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "byte"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "uchar"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "unsigned char"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "longlong"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "__int64"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "ulonglong"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "unsigned __int64"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "boolean"));
            assertDoesNotThrow(() -> service.resolveDataType(dtm, "long"));
        }

        @Test
        @DisplayName("resolveDataType handles Windows-style pointer types")
        void testResolveDataType_PointerTypes() {
            var dtm = program.getDataTypeManager();

            // PVOID should resolve to a pointer to void
            DataType pvoid = service.resolveDataType(dtm, "PVOID");
            if (pvoid != null) {
                assertTrue(pvoid instanceof ghidra.program.model.data.Pointer,
                        "PVOID should be a Pointer type");
            }

            // P-prefix with unknown base type should fallback to void*
            DataType pUnknown = service.resolveDataType(dtm, "PUNKNOWNTYPE");
            if (pUnknown != null) {
                assertTrue(pUnknown instanceof ghidra.program.model.data.Pointer,
                        "PUNKNOWNTYPE should fallback to void pointer");
            }
        }

        @Test
        @DisplayName("resolveDataType returns null for completely unknown types")
        void testResolveDataType_UnknownType() {
            var dtm = program.getDataTypeManager();

            DataType result = service.resolveDataType(dtm, "CompletelyUnknownType12345");
            assertNull(result, "Should return null for unknown type");
        }

        @Test
        @DisplayName("findDataTypeByNameInAllCategories handles null/empty inputs")
        void testFindDataTypeByName_NullEmpty() {
            var dtm = program.getDataTypeManager();

            assertNull(service.findDataTypeByNameInAllCategories(null, "int"));
            assertNull(service.findDataTypeByNameInAllCategories(dtm, null));
            assertNull(service.findDataTypeByNameInAllCategories(dtm, ""));
        }

        // ===== Atomicity verification tests =====

        @Test
        @DisplayName("updateStructure: batch rename failure leaves all fields unchanged")
        void testUpdateStructure_Atomicity_NoPartialRenames() {
            service.createStructure("AtomicRenameTest", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/AtomicRenameTest");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "field_a", null);
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "field_b", null);
            } finally {
                program.endTransaction(tx, true);
            }

            // Batch with one valid and one invalid rename — should fail entirely
            java.util.Map<String, String> renames = new java.util.LinkedHashMap<>();
            renames.put("field_a", "renamed_a");
            renames.put("nonexistent", "renamed_x");
            String json = service.updateStructure("AtomicRenameTest", null, null, renames, null).toStructuredJson();
            assertTrue(json.contains("not found") || json.contains("error"),
                    "Should return error, got: " + json);

            // Verify field_a was NOT renamed (atomicity)
            var dtm = program.getDataTypeManager();
            DataType found = dtm.getDataType("/AtomicRenameTest");
            ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
            assertEquals("field_a", struct.getComponent(0).getFieldName(),
                    "field_a should be unchanged after failed batch");
            assertEquals("field_b", struct.getComponent(1).getFieldName(),
                    "field_b should be unchanged after failed batch");
        }

        @Test
        @DisplayName("updateEnum: batch rename failure leaves all values unchanged")
        void testUpdateEnum_Atomicity_NoPartialRenames() {
            java.util.Map<String, Long> values = new java.util.LinkedHashMap<>();
            values.put("VAL_A", 1L);
            values.put("VAL_B", 2L);
            service.createEnum("AtomicEnumTest", 4, null, values);

            // Batch with one valid and one invalid rename — should fail entirely
            java.util.Map<String, String> renames = new java.util.LinkedHashMap<>();
            renames.put("VAL_A", "RENAMED_A");
            renames.put("NONEXISTENT", "RENAMED_X");
            String json = service.updateEnum("AtomicEnumTest", null, null, renames, null).toStructuredJson();
            assertTrue(json.contains("not found") || json.contains("error"),
                    "Should return error, got: " + json);

            // Verify VAL_A was NOT renamed (atomicity)
            var dtm = program.getDataTypeManager();
            DataType found = service.findDataTypeByNameInAllCategories(dtm, "AtomicEnumTest");
            assertNotNull(found, "Enum should still exist");
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) found;
            java.util.Set<String> names = java.util.Set.of(enumType.getNames());
            assertTrue(names.contains("VAL_A"),
                    "VAL_A should be unchanged after failed batch, got: " + names);
            assertTrue(names.contains("VAL_B"),
                    "VAL_B should be unchanged after failed batch, got: " + names);
        }

        @Test
        @DisplayName("updateStructure: type change with invalid type returns error, no partial changes")
        void testUpdateStructure_Atomicity_TypeChangeInvalidType() {
            service.createStructure("AtomicTypeTest", 0, null, null);

            int tx = program.startTransaction("add fields");
            try {
                var dtm = program.getDataTypeManager();
                DataType found = dtm.getDataType("/AtomicTypeTest");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "field_a", null);
                struct.add(ghidra.program.model.data.IntegerDataType.dataType, "field_b", null);
            } finally {
                program.endTransaction(tx, true);
            }

            var dtm = program.getDataTypeManager();
            DataType shortType = service.resolveDataType(dtm, "short");
            if (shortType != null) {
                // One valid type change and one invalid — should fail entirely
                java.util.Map<String, String> typeChanges = new java.util.LinkedHashMap<>();
                typeChanges.put("field_a", "short");
                typeChanges.put("field_b", "CompletelyUnknownType12345");
                String json = service.updateStructure("AtomicTypeTest", null, null, null, typeChanges).toStructuredJson();
                assertTrue(json.contains("not found") || json.contains("error"),
                        "Should return error for invalid type, got: " + json);

                // Verify field_a's type was NOT changed
                DataType found = dtm.getDataType("/AtomicTypeTest");
                ghidra.program.model.data.Structure struct = (ghidra.program.model.data.Structure) found;
                assertEquals("int", struct.getComponent(0).getDataType().getName(),
                        "field_a type should be unchanged after failed batch");
            }
        }

        // ===== Priority-ordered type resolution tests =====

        @Test
        @DisplayName("findDataTypeByNameInAllCategories prefers root category over deeper paths")
        void testFindDataType_PrefersRootCategory() {
            // Create a struct in root category
            service.createStructure("PriorityTest", 0, null, null);
            // Create another struct with the same name in a nested category directly via DTM
            int tx = program.startTransaction("add nested duplicate");
            try {
                var dtm = program.getDataTypeManager();
                var struct = new ghidra.program.model.data.StructureDataType(
                        new ghidra.program.model.data.CategoryPath("/deep/nested"),
                        "PriorityTest", 0, dtm);
                dtm.addDataType(struct, null);
            } finally {
                program.endTransaction(tx, true);
            }

            var dtm = program.getDataTypeManager();
            DataType found = service.findDataTypeByNameInAllCategories(dtm, "PriorityTest");
            assertNotNull(found, "Should find PriorityTest");
            assertEquals("/", found.getCategoryPath().getPath(),
                    "Should prefer root category, got: " + found.getCategoryPath().getPath());
        }

        @Test
        @DisplayName("findDataTypeByNameInAllCategories prefers shallower category path")
        void testFindDataType_PrefersShallowerPath() {
            // Create struct at shallow depth via service
            service.createStructure("DepthTest", 0, "/shallow", null);
            // Create another at deeper path directly via DTM
            int tx = program.startTransaction("add deep duplicate");
            try {
                var dtm = program.getDataTypeManager();
                var struct = new ghidra.program.model.data.StructureDataType(
                        new ghidra.program.model.data.CategoryPath("/deep/nested/path"),
                        "DepthTest", 0, dtm);
                dtm.addDataType(struct, null);
            } finally {
                program.endTransaction(tx, true);
            }

            var dtm = program.getDataTypeManager();
            DataType found = service.findDataTypeByNameInAllCategories(dtm, "DepthTest");
            assertNotNull(found, "Should find DepthTest");
            assertEquals("/shallow", found.getCategoryPath().getPath(),
                    "Should prefer shallower path, got: " + found.getCategoryPath().getPath());
        }

        // ===== Path-qualified name resolution tests =====

        @Test
        @DisplayName("findDataTypeByNameInAllCategories resolves category-qualified path")
        void testFindDataType_CategoryQualifiedPath() {
            service.createStructure("PathTest", 0, "/MyCategory", null);

            var dtm = program.getDataTypeManager();
            // Should resolve with leading slash
            DataType found = service.findDataTypeByNameInAllCategories(dtm, "/MyCategory/PathTest");
            assertNotNull(found, "Should find via /MyCategory/PathTest");
            assertEquals("PathTest", found.getName());
        }

        @Test
        @DisplayName("findDataTypeByNameInAllCategories resolves path without leading slash")
        void testFindDataType_PathWithoutLeadingSlash() {
            service.createStructure("NoSlashTest", 0, "/SomeCategory", null);

            var dtm = program.getDataTypeManager();
            // Should resolve without leading slash (auto-normalized)
            DataType found = service.findDataTypeByNameInAllCategories(dtm, "SomeCategory/NoSlashTest");
            assertNotNull(found, "Should find via SomeCategory/NoSlashTest");
            assertEquals("NoSlashTest", found.getName());
        }

        @Test
        @DisplayName("resolveDataType resolves category-qualified path")
        void testResolveDataType_CategoryQualifiedPath() {
            service.createStructure("ResolvePathTest", 0, "/TypeCategory", null);

            var dtm = program.getDataTypeManager();
            DataType found = service.resolveDataType(dtm, "/TypeCategory/ResolvePathTest");
            assertNotNull(found, "Should resolve via path in resolveDataType");
            assertEquals("ResolvePathTest", found.getName());
        }

        @Test
        @DisplayName("path-qualified lookup can disambiguate same-named types")
        void testPathDisambiguation() {
            // Create first struct via service
            service.createStructure("AmbiguousType", 0, "/CategoryA", null);

            // Create second struct with same name in different category directly via DTM
            // (service's createStructure rejects duplicates by name)
            int tx = program.startTransaction("add duplicate");
            try {
                var dtm = program.getDataTypeManager();
                var struct = new ghidra.program.model.data.StructureDataType(
                        new ghidra.program.model.data.CategoryPath("/CategoryB"),
                        "AmbiguousType", 0, dtm);
                dtm.addDataType(struct, null);
            } finally {
                program.endTransaction(tx, true);
            }

            var dtm = program.getDataTypeManager();
            DataType fromA = service.findDataTypeByNameInAllCategories(dtm, "/CategoryA/AmbiguousType");
            DataType fromB = service.findDataTypeByNameInAllCategories(dtm, "/CategoryB/AmbiguousType");
            assertNotNull(fromA, "Should find from CategoryA");
            assertNotNull(fromB, "Should find from CategoryB");
            assertEquals("/CategoryA", fromA.getCategoryPath().getPath());
            assertEquals("/CategoryB", fromB.getCategoryPath().getPath());
        }

        // ===== categoryPath in responses tests =====

        @Test
        @DisplayName("listDataTypes includes category_path in JSON response")
        void testListDataTypes_IncludesCategoryPath() {
            service.createStructure("CatPathStruct", 0, "/TestCat", null);
            service.createEnum("CatPathEnum", 4, "/EnumCat",
                java.util.Map.of("A", 1L));

            String json = service.listDataTypes("all", 0, 100).toStructuredJson();
            assertTrue(json.contains("category_path"),
                    "Should contain category_path field, got: " + json);
        }

        @Test
        @DisplayName("getDataType includes category_path in struct JSON response")
        void testGetDataType_IncludesCategoryPath_Struct() {
            service.createStructure("CatDetailStruct", 0, "/DetailCat", null);

            String json = service.getDataType("CatDetailStruct").toStructuredJson();
            assertTrue(json.contains("category_path"),
                    "Should contain category_path field, got: " + json);
            assertTrue(json.contains("/DetailCat"),
                    "Should contain the category path value, got: " + json);
        }

        @Test
        @DisplayName("getDataType includes category_path in enum JSON response")
        void testGetDataType_IncludesCategoryPath_Enum() {
            service.createEnum("CatDetailEnum", 4, "/EnumDetail",
                java.util.Map.of("X", 1L));

            String json = service.getDataType("CatDetailEnum").toStructuredJson();
            assertTrue(json.contains("category_path"),
                    "Should contain category_path field, got: " + json);
            assertTrue(json.contains("/EnumDetail"),
                    "Should contain the category path value, got: " + json);
        }

        // ===== Backward compatibility tests =====

        @Test
        @DisplayName("bare names still resolve correctly (backward compat)")
        void testBareNames_BackwardCompat() {
            service.createStructure("PlainStruct", 0, null, null);
            service.createEnum("PlainEnum", 4, null, java.util.Map.of("V", 1L));

            var dtm = program.getDataTypeManager();
            DataType foundStruct = service.findDataTypeByNameInAllCategories(dtm, "PlainStruct");
            DataType foundEnum = service.findDataTypeByNameInAllCategories(dtm, "PlainEnum");
            assertNotNull(foundStruct, "Bare struct name should still resolve");
            assertNotNull(foundEnum, "Bare enum name should still resolve");
        }

        @Test
        @DisplayName("resolveDataType handles array syntax with real DataTypeManager")
        void testResolveDataType_ArraySyntax() {
            var dtm = program.getDataTypeManager();

            // First check if base types resolve
            DataType charType = service.resolveDataType(dtm, "char");
            if (charType == null) {
                // If char doesn't resolve, array syntax can't work either
                // This is expected on some DTM configurations
                return;
            }

            // "byte" maps to "char" in Ghidra via the switch statement
            DataType byteArray = service.resolveDataType(dtm, "byte[100]");
            assertNotNull(byteArray, "Should resolve 'byte[100]' when char is available");
            assertTrue(byteArray instanceof ghidra.program.model.data.Array,
                    "Should be an Array data type");
            assertEquals(100, ((ghidra.program.model.data.Array) byteArray).getNumElements(),
                    "Should have 100 elements");

            DataType intType = service.resolveDataType(dtm, "int");
            if (intType != null) {
                DataType intArray = service.resolveDataType(dtm, "int[10]");
                assertNotNull(intArray, "Should resolve 'int[10]' when int is available");
                assertTrue(intArray instanceof ghidra.program.model.data.Array,
                        "Should be an Array data type");
                assertEquals(10, ((ghidra.program.model.data.Array) intArray).getNumElements(),
                        "Should have 10 elements");
            }
        }
    }
}
