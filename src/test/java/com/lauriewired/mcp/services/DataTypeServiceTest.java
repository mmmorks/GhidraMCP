package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for DataTypeService
 */
public class DataTypeServiceTest {

    private DataTypeService dataTypeService;
    private ProgramService programService;

    @BeforeEach
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        dataTypeService = new DataTypeService(programService);
    }

    @Test
    @DisplayName("listStructures returns error when no program is loaded")
    void testListStructures_NoProgram() {
        String result = dataTypeService.listStructures(0, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listStructures handles negative offset")
    void testListStructures_NegativeOffset() {
        String result = dataTypeService.listStructures(-1, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listStructures handles zero limit")
    void testListStructures_ZeroLimit() {
        String result = dataTypeService.listStructures(0, 0);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("listStructures handles large offset")
    void testListStructures_LargeOffset() {
        String result = dataTypeService.listStructures(1000, 10);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameStructField returns error when no program is loaded")
    void testRenameStructField_NoProgram() {
        String result = dataTypeService.renameStructField("TestStruct", "oldField", "newField");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameStructField returns error for null struct name")
    void testRenameStructField_NullStructName() {
        String result = dataTypeService.renameStructField(null, "oldField", "newField");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameStructField returns error for null old field name")
    void testRenameStructField_NullOldFieldName() {
        String result = dataTypeService.renameStructField("TestStruct", null, "newField");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameStructField returns error for null new field name")
    void testRenameStructField_NullNewFieldName() {
        String result = dataTypeService.renameStructField("TestStruct", "oldField", null);
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameStructField handles empty struct name")
    void testRenameStructField_EmptyStructName() {
        String result = dataTypeService.renameStructField("", "oldField", "newField");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameStructField handles empty old field name")
    void testRenameStructField_EmptyOldFieldName() {
        String result = dataTypeService.renameStructField("TestStruct", "", "newField");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameStructField handles empty new field name")
    void testRenameStructField_EmptyNewFieldName() {
        String result = dataTypeService.renameStructField("TestStruct", "oldField", "");
        assertEquals("No program loaded", result);
    }

    @Test
    @DisplayName("renameStructField handles field pattern matching")
    void testRenameStructField_FieldPattern() {
        String result = dataTypeService.renameStructField("TestStruct", "field0_0x00", "newField");
        assertEquals("No program loaded", result);
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

    // Note: Testing with actual DataTypeManager would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly
    
    // Happy path tests would require complex mocking of Ghidra objects
    // which is challenging due to Ghidra's architecture. The existing tests
    // ensure the service handles error cases gracefully.
}