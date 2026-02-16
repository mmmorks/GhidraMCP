package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.UniversalID;

/**
 * Unit tests for DataTypeService.findDataTypeUsage with mocked Ghidra components
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class FindDataTypeUsageTest {

    /**
     * Warm up ByteBuddy's mock factory for DataType on JDK 25.
     * The first inline mock creation for certain Ghidra interfaces can fail
     * with "class redefinition failed" on JDK 25; a retry succeeds.
     */
    @BeforeAll
    static void warmUpMockFactory() {
        try {
            mock(DataType.class);
        } catch (Exception ignored) {
            // First attempt may fail on JDK 25; subsequent calls succeed
        }
    }

    @Mock private MockablePluginTool mockTool;
    @Mock private ProgramManager mockProgramManager;
    @Mock private Program mockProgram;
    @Mock private ProgramBasedDataTypeManager mockDtm;
    @Mock private Listing mockListing;
    @Mock private FunctionIterator mockFuncIterator;
    @Mock private DataIterator mockDataIterator;

    // Pre-created DataType mocks to avoid JDK 25 ByteBuddy issues with inline mock(DataType.class)
    @Mock private DataType targetDataType;
    @Mock private DataType otherDataType;

    private DataTypeService dataTypeService;
    private TestProgramService programService;

    @BeforeEach
    void setUp() {
        programService = new TestProgramService(mockTool);
        dataTypeService = new DataTypeService(programService);
    }

    private void setupProgramMocks() {
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getDataTypeManager()).thenReturn(mockDtm);
    }

    private void setupListingMocks() {
        when(mockProgram.getListing()).thenReturn(mockListing);
    }

    private void setupTargetType(String name, long uid) {
        when(targetDataType.getName()).thenReturn(name);
        when(targetDataType.getUniversalID()).thenReturn(new UniversalID(uid));
    }

    private void setupOtherType(String name, long uid) {
        when(otherDataType.getName()).thenReturn(name);
        when(otherDataType.getUniversalID()).thenReturn(new UniversalID(uid));
    }

    /**
     * Set up the DTM to return the given types when iterating
     */
    private void setupDtmTypes(DataType... types) {
        when(mockDtm.getAllDataTypes()).thenAnswer(invocation -> List.of(types).iterator());
    }

    /**
     * Set up data iterator to return the given data items
     */
    private void setupDataIterator(Data... items) {
        if (items.length == 0) {
            when(mockDataIterator.hasNext()).thenReturn(false);
        } else {
            Boolean[] hasNextValues = new Boolean[items.length + 1];
            for (int i = 0; i < items.length; i++) {
                hasNextValues[i] = true;
            }
            hasNextValues[items.length] = false;
            when(mockDataIterator.hasNext()).thenReturn(hasNextValues[0],
                java.util.Arrays.copyOfRange(hasNextValues, 1, hasNextValues.length));

            if (items.length == 1) {
                when(mockDataIterator.next()).thenReturn(items[0]);
            } else {
                Data[] rest = java.util.Arrays.copyOfRange(items, 1, items.length);
                when(mockDataIterator.next()).thenReturn(items[0], rest);
            }
        }
        when(mockListing.getDefinedData(true)).thenReturn(mockDataIterator);
    }

    /**
     * Set up empty function iterator
     */
    private void setupEmptyFuncIterator() {
        when(mockFuncIterator.hasNext()).thenReturn(false);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);
    }

    /**
     * Set up empty data and function iterators on the listing
     */
    private void setupEmptyListing() {
        setupDataIterator(); // empty
        setupEmptyFuncIterator();
    }

    // ===== Input validation tests =====

    @Test
    @DisplayName("findDataTypeUsage returns error for null type name with program loaded")
    void testNullTypeName_WithProgram() {
        setupProgramMocks();
        String result = dataTypeService.findDataTypeUsage(null, null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\": \"Type name is required\""));
    }

    @Test
    @DisplayName("findDataTypeUsage returns error for empty type name with program loaded")
    void testEmptyTypeName_WithProgram() {
        setupProgramMocks();
        String result = dataTypeService.findDataTypeUsage("", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\": \"Type name is required\""));
    }

    @Test
    @DisplayName("findDataTypeUsage returns error when type not found")
    void testTypeNotFound() {
        setupProgramMocks();
        setupDtmTypes();
        String result = dataTypeService.findDataTypeUsage("NonExistentType", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\": \"Data type not found: NonExistentType\""));
    }

    // ===== No usages found =====

    @Test
    @DisplayName("findDataTypeUsage returns no-usages message when type exists but is unused")
    void testNoUsagesFound() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);
        setupEmptyListing();

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\": \"No usages found for data type: MyStruct\""));
    }

    // ===== Defined data matches =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in defined data with label")
    void testFindsDataUsage_WithLabel() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);

        Data mockData = mock(Data.class);
        Address mockAddr = mock(Address.class);
        when(mockAddr.toString()).thenReturn("00402000");
        when(mockData.getDataType()).thenReturn(targetDataType);
        when(mockData.getLabel()).thenReturn("globalVar");
        when(mockData.getMinAddress()).thenReturn(mockAddr);
        when(mockData.getNumComponents()).thenReturn(0);

        setupDataIterator(mockData);
        setupEmptyFuncIterator();

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\": \"globalVar\"") && result.contains("\"address\": \"00402000\""));
    }

    @Test
    @DisplayName("findDataTypeUsage finds usage in defined data without label")
    void testFindsDataUsage_WithoutLabel() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);

        Data mockData = mock(Data.class);
        Address mockAddr = mock(Address.class);
        when(mockAddr.toString()).thenReturn("00403000");
        when(mockData.getDataType()).thenReturn(targetDataType);
        when(mockData.getLabel()).thenReturn(null);
        when(mockData.getMinAddress()).thenReturn(mockAddr);
        when(mockData.getNumComponents()).thenReturn(0);

        setupDataIterator(mockData);
        setupEmptyFuncIterator();

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\": \"(unnamed)\"") && result.contains("\"address\": \"00403000\""));
    }

    // ===== Function return type matches =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in function return type")
    void testFindsReturnTypeUsage() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);

        setupDataIterator(); // empty

        Function mockFunc = mock(Function.class);
        Address mockEntryPoint = mock(Address.class);
        when(mockEntryPoint.toString()).thenReturn("00401000");
        when(mockFunc.getName()).thenReturn("create_struct");
        when(mockFunc.getEntryPoint()).thenReturn(mockEntryPoint);
        when(mockFunc.getReturnType()).thenReturn(targetDataType);
        when(mockFunc.getAllVariables()).thenReturn(new Variable[0]);

        when(mockFuncIterator.hasNext()).thenReturn(true, false);
        when(mockFuncIterator.next()).thenReturn(mockFunc);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"category\": \"Return type\"") && result.contains("\"function\": \"create_struct\""));
    }

    // ===== Function variable matches =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in stack local variable")
    void testFindsLocalVariableUsage() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupOtherType("int", 99L);
        setupDtmTypes(targetDataType);

        setupDataIterator(); // empty

        Function mockFunc = mock(Function.class);
        Address mockEntryPoint = mock(Address.class);
        when(mockEntryPoint.toString()).thenReturn("00401000");
        when(mockFunc.getName()).thenReturn("process");
        when(mockFunc.getEntryPoint()).thenReturn(mockEntryPoint);
        when(mockFunc.getReturnType()).thenReturn(otherDataType);

        Variable mockVar = mock(Variable.class);
        when(mockVar.getName()).thenReturn("local_struct");
        when(mockVar.getDataType()).thenReturn(targetDataType);
        when(mockVar.isStackVariable()).thenReturn(true);
        when(mockFunc.getAllVariables()).thenReturn(new Variable[]{mockVar});

        when(mockFuncIterator.hasNext()).thenReturn(true, false);
        when(mockFuncIterator.next()).thenReturn(mockFunc);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"category\": \"Local variable\"") && result.contains("\"name\": \"local_struct\""));
    }

    @Test
    @DisplayName("findDataTypeUsage finds usage in non-stack parameter variable")
    void testFindsParamVariableUsage() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupOtherType("void", 99L);
        setupDtmTypes(targetDataType);

        setupDataIterator(); // empty

        Function mockFunc = mock(Function.class);
        Address mockEntryPoint = mock(Address.class);
        when(mockEntryPoint.toString()).thenReturn("00401500");
        when(mockFunc.getName()).thenReturn("draw_line");
        when(mockFunc.getEntryPoint()).thenReturn(mockEntryPoint);
        when(mockFunc.getReturnType()).thenReturn(otherDataType);

        Parameter mockParam = mock(Parameter.class);
        when(mockParam.getName()).thenReturn("p1");
        when(mockParam.getDataType()).thenReturn(targetDataType);
        when(mockFunc.getAllVariables()).thenReturn(new Variable[]{mockParam});

        when(mockFuncIterator.hasNext()).thenReturn(true, false);
        when(mockFuncIterator.next()).thenReturn(mockFunc);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"category\": \"Param variable\"") && result.contains("\"name\": \"p1\""));
    }

    // ===== Pointer/TypeDef unwrapping =====

    @Test
    @DisplayName("findDataTypeUsage finds usage through pointer wrapping")
    void testFindsUsageThroughPointer() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);

        Pointer ptrType = mock(Pointer.class);
        when(ptrType.getName()).thenReturn("MyStruct *");
        when(ptrType.getUniversalID()).thenReturn(new UniversalID(200L));
        when(ptrType.getDataType()).thenReturn(targetDataType);

        setupDataIterator(); // empty

        Function mockFunc = mock(Function.class);
        Address mockEntryPoint = mock(Address.class);
        when(mockEntryPoint.toString()).thenReturn("00401000");
        when(mockFunc.getName()).thenReturn("use_ptr");
        when(mockFunc.getEntryPoint()).thenReturn(mockEntryPoint);

        setupOtherType("void", 99L);
        when(mockFunc.getReturnType()).thenReturn(otherDataType);

        Parameter mockVar = mock(Parameter.class);
        when(mockVar.getName()).thenReturn("ptr_param");
        when(mockVar.getDataType()).thenReturn(ptrType);
        when(mockFunc.getAllVariables()).thenReturn(new Variable[]{mockVar});

        when(mockFuncIterator.hasNext()).thenReturn(true, false);
        when(mockFuncIterator.next()).thenReturn(mockFunc);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\": \"ptr_param\"") && result.contains("\"type\": \"MyStruct *\""));
    }

    @Test
    @DisplayName("findDataTypeUsage finds usage through typedef wrapping")
    void testFindsUsageThroughTypedef() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);

        TypeDef tdType = mock(TypeDef.class);
        when(tdType.getName()).thenReturn("MY_STRUCT_T");
        when(tdType.getUniversalID()).thenReturn(new UniversalID(300L));
        when(tdType.getBaseDataType()).thenReturn(targetDataType);

        setupDataIterator(); // empty

        Function mockFunc = mock(Function.class);
        Address mockEntryPoint = mock(Address.class);
        when(mockEntryPoint.toString()).thenReturn("00401000");
        when(mockFunc.getName()).thenReturn("use_typedef");
        when(mockFunc.getEntryPoint()).thenReturn(mockEntryPoint);

        when(mockFunc.getReturnType()).thenReturn(tdType);
        when(mockFunc.getAllVariables()).thenReturn(new Variable[0]);

        when(mockFuncIterator.hasNext()).thenReturn(true, false);
        when(mockFuncIterator.next()).thenReturn(mockFunc);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"function\": \"use_typedef\"") && result.contains("\"type\": \"MY_STRUCT_T\""));
    }

    // ===== Data sub-component matching =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in struct sub-component")
    void testFindsUsageInSubComponent() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("InnerStruct", 42L);

        // The outer struct is a different type — use otherDataType as a Structure mock
        Structure outerType = mock(Structure.class);
        when(outerType.getName()).thenReturn("OuterStruct");
        when(outerType.getUniversalID()).thenReturn(new UniversalID(99L));

        setupDtmTypes(targetDataType);

        Data mockData = mock(Data.class);
        Address mockAddr = mock(Address.class);
        when(mockAddr.toString()).thenReturn("00404000");
        when(mockData.getDataType()).thenReturn(outerType);
        when(mockData.getLabel()).thenReturn("outer_var");
        when(mockData.getMinAddress()).thenReturn(mockAddr);
        when(mockData.getNumComponents()).thenReturn(1);

        Data childData = mock(Data.class);
        Address childAddr = mock(Address.class);
        when(childAddr.toString()).thenReturn("00404008");
        when(childData.getDataType()).thenReturn(targetDataType);
        when(childData.getMinAddress()).thenReturn(childAddr);
        when(childData.getFieldName()).thenReturn("inner");
        when(childData.getParentOffset()).thenReturn(8);
        when(childData.getNumComponents()).thenReturn(0);
        when(mockData.getComponent(0)).thenReturn(childData);

        setupDataIterator(mockData);
        setupEmptyFuncIterator();

        String result = dataTypeService.findDataTypeUsage("InnerStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\": \"outer_var.inner\"") && result.contains("\"address\": \"00404008\""));
    }

    // ===== Array element optimization =====

    @Test
    @DisplayName("findDataTypeUsage finds usage in array of target type")
    void testFindsUsageInArray() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);

        Array arrayType = mock(Array.class);
        when(arrayType.getName()).thenReturn("MyStruct[10]");
        when(arrayType.getUniversalID()).thenReturn(new UniversalID(500L));
        when(arrayType.getDataType()).thenReturn(targetDataType);

        Data mockData = mock(Data.class);
        Address mockAddr = mock(Address.class);
        when(mockAddr.toString()).thenReturn("00405000");
        when(mockData.getDataType()).thenReturn(arrayType);
        when(mockData.getLabel()).thenReturn("struct_array");
        when(mockData.getMinAddress()).thenReturn(mockAddr);
        when(mockData.getNumComponents()).thenReturn(0);

        setupDataIterator(mockData);
        setupEmptyFuncIterator();

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\": \"struct_array\"") && result.contains("\"address\": \"00405000\""));
    }

    // ===== Multiple results combined =====

    @Test
    @DisplayName("findDataTypeUsage combines data and function results")
    void testCombinesDataAndFunctionResults() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);

        Data mockData = mock(Data.class);
        Address dataAddr = mock(Address.class);
        when(dataAddr.toString()).thenReturn("00402000");
        when(mockData.getDataType()).thenReturn(targetDataType);
        when(mockData.getLabel()).thenReturn("g_struct");
        when(mockData.getMinAddress()).thenReturn(dataAddr);
        when(mockData.getNumComponents()).thenReturn(0);

        setupDataIterator(mockData);

        Function mockFunc = mock(Function.class);
        Address funcAddr = mock(Address.class);
        when(funcAddr.toString()).thenReturn("00401000");
        when(mockFunc.getName()).thenReturn("get_struct");
        when(mockFunc.getEntryPoint()).thenReturn(funcAddr);
        when(mockFunc.getReturnType()).thenReturn(targetDataType);

        Variable mockLocal = mock(Variable.class);
        when(mockLocal.getName()).thenReturn("temp");
        when(mockLocal.getDataType()).thenReturn(targetDataType);
        when(mockLocal.isStackVariable()).thenReturn(true);
        when(mockFunc.getAllVariables()).thenReturn(new Variable[]{mockLocal});

        when(mockFuncIterator.hasNext()).thenReturn(true, false);
        when(mockFuncIterator.next()).thenReturn(mockFunc);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\": \"g_struct\"") && result.contains("\"address\": \"00402000\""));
        assertTrue(result.contains("\"category\": \"Return type\"") && result.contains("\"function\": \"get_struct\""));
        assertTrue(result.contains("\"category\": \"Local variable\"") && result.contains("\"name\": \"temp\""));
    }

    // ===== Pagination =====

    @Test
    @DisplayName("findDataTypeUsage respects pagination offset and limit")
    void testPagination() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupDtmTypes(targetDataType);

        setupDataIterator(); // empty

        Function[] funcs = new Function[5];
        for (int i = 0; i < 5; i++) {
            funcs[i] = mock(Function.class);
            Address addr = mock(Address.class);
            when(addr.toString()).thenReturn("0040" + (1000 + i));
            when(funcs[i].getName()).thenReturn("func_" + i);
            when(funcs[i].getEntryPoint()).thenReturn(addr);
            when(funcs[i].getReturnType()).thenReturn(targetDataType);
            when(funcs[i].getAllVariables()).thenReturn(new Variable[0]);
        }

        when(mockFuncIterator.hasNext()).thenReturn(true, true, true, true, true, false);
        when(mockFuncIterator.next()).thenReturn(funcs[0], funcs[1], funcs[2], funcs[3], funcs[4]);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        // Request offset=1, limit=2
        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 1, 2).toStructuredJson();
        assertFalse(result.contains("func_0"));
        assertTrue(result.contains("func_1"));
        assertTrue(result.contains("func_2"));
        assertFalse(result.contains("func_3"));
    }

    // ===== Built-in type matching (no UID) =====

    @Test
    @DisplayName("findDataTypeUsage matches built-in types by class and name")
    void testBuiltInTypeMatching() {
        setupProgramMocks();
        setupListingMocks();

        // Built-in types have null UIDs — use targetDataType as the built-in
        when(targetDataType.getName()).thenReturn("int");
        when(targetDataType.getUniversalID()).thenReturn(null);
        setupDtmTypes(targetDataType);

        setupDataIterator(); // empty

        // otherDataType as another "int" instance with same class and name
        when(otherDataType.getName()).thenReturn("int");
        when(otherDataType.getUniversalID()).thenReturn(null);

        Function mockFunc = mock(Function.class);
        Address funcAddr = mock(Address.class);
        when(funcAddr.toString()).thenReturn("00401000");
        when(mockFunc.getName()).thenReturn("get_count");
        when(mockFunc.getEntryPoint()).thenReturn(funcAddr);
        when(mockFunc.getReturnType()).thenReturn(otherDataType);
        when(mockFunc.getAllVariables()).thenReturn(new Variable[0]);

        when(mockFuncIterator.hasNext()).thenReturn(true, false);
        when(mockFuncIterator.next()).thenReturn(mockFunc);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        String result = dataTypeService.findDataTypeUsage("int", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"category\": \"Return type\"") && result.contains("\"function\": \"get_count\""));
    }

    // ===== Non-matching data is excluded =====

    @Test
    @DisplayName("findDataTypeUsage excludes data with different type")
    void testExcludesNonMatchingData() {
        setupProgramMocks();
        setupListingMocks();

        setupTargetType("MyStruct", 42L);
        setupOtherType("OtherStruct", 99L);
        setupDtmTypes(targetDataType);

        Data mockData = mock(Data.class);
        when(mockData.getDataType()).thenReturn(otherDataType);
        when(mockData.getNumComponents()).thenReturn(0);

        setupDataIterator(mockData);
        setupEmptyFuncIterator();

        String result = dataTypeService.findDataTypeUsage("MyStruct", null, 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\": \"No usages found for data type: MyStruct\""));
    }

    // ===== Field-specific search tests =====

    @Test
    @DisplayName("field search returns error for non-composite type")
    void testFieldSearch_NonCompositeType() {
        setupProgramMocks();

        // targetDataType is a plain DataType mock (not a Structure)
        setupTargetType("int", 42L);
        setupDtmTypes(targetDataType);

        String result = dataTypeService.findDataTypeUsage("int", "x", 0, 100).toStructuredJson();
        assertTrue(result.contains("Field search requires a composite (struct/union) type"));
    }

    @Test
    @DisplayName("field search returns error when field not found in struct")
    void testFieldSearch_FieldNotFound() {
        setupProgramMocks();

        Structure structType = mock(Structure.class);
        when(structType.getName()).thenReturn("MyStruct");
        when(structType.getUniversalID()).thenReturn(new UniversalID(42L));
        when(structType.getComponents()).thenReturn(new DataTypeComponent[0]);
        setupDtmTypes(structType);

        String result = dataTypeService.findDataTypeUsage("MyStruct", "nonexistent", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\": \"Field 'nonexistent' not found in MyStruct\""));
    }

    @Test
    @DisplayName("field search finds matching field in defined data")
    void testFieldSearch_FindsMatchingField() {
        setupProgramMocks();
        setupListingMocks();

        // Set up a Structure with two fields: x at offset 0, y at offset 4
        Structure structType = mock(Structure.class);
        when(structType.getName()).thenReturn("POINT");
        when(structType.getUniversalID()).thenReturn(new UniversalID(42L));

        DataTypeComponent xComp = mock(DataTypeComponent.class);
        when(xComp.getFieldName()).thenReturn("x");
        when(xComp.getOffset()).thenReturn(0);

        DataTypeComponent yComp = mock(DataTypeComponent.class);
        when(yComp.getFieldName()).thenReturn("y");
        when(yComp.getOffset()).thenReturn(4);

        when(structType.getComponents()).thenReturn(new DataTypeComponent[]{xComp, yComp});
        setupDtmTypes(structType);

        // Set up a defined data item of type POINT with two child components
        Data mockData = mock(Data.class);
        when(mockData.getDataType()).thenReturn(structType);
        when(mockData.getLabel()).thenReturn("origin");
        when(mockData.getNumComponents()).thenReturn(2);

        DataType intType = mock(DataType.class);
        when(intType.getName()).thenReturn("int");
        when(intType.getUniversalID()).thenReturn(new UniversalID(99L));

        Data childX = mock(Data.class);
        Address addrX = mock(Address.class);
        when(addrX.toString()).thenReturn("00402000");
        when(childX.getFieldName()).thenReturn("x");
        when(childX.getParentOffset()).thenReturn(0);
        when(childX.getMinAddress()).thenReturn(addrX);
        when(childX.getDataType()).thenReturn(intType);
        when(childX.getNumComponents()).thenReturn(0);

        Data childY = mock(Data.class);
        Address addrY = mock(Address.class);
        when(addrY.toString()).thenReturn("00402004");
        when(childY.getFieldName()).thenReturn("y");
        when(childY.getParentOffset()).thenReturn(4);
        when(childY.getMinAddress()).thenReturn(addrY);
        when(childY.getDataType()).thenReturn(intType);
        when(childY.getNumComponents()).thenReturn(0);

        when(mockData.getComponent(0)).thenReturn(childX);
        when(mockData.getComponent(1)).thenReturn(childY);

        setupDataIterator(mockData);

        String result = dataTypeService.findDataTypeUsage("POINT", "x", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"name\": \"origin.x\"") && result.contains("\"address\": \"00402000\""));
        assertFalse(result.contains("origin.y"));
    }

    @Test
    @DisplayName("field search skips function signatures")
    void testFieldSearch_SkipsFunctionSignatures() {
        setupProgramMocks();
        setupListingMocks();

        Structure structType = mock(Structure.class);
        when(structType.getName()).thenReturn("POINT");
        when(structType.getUniversalID()).thenReturn(new UniversalID(42L));

        DataTypeComponent xComp = mock(DataTypeComponent.class);
        when(xComp.getFieldName()).thenReturn("x");
        when(xComp.getOffset()).thenReturn(0);
        when(structType.getComponents()).thenReturn(new DataTypeComponent[]{xComp});

        setupDtmTypes(structType);
        setupDataIterator(); // empty data

        // Even though a function returns POINT, field search should not report it
        Function mockFunc = mock(Function.class);
        Address funcAddr = mock(Address.class);
        when(funcAddr.toString()).thenReturn("00401000");
        when(mockFunc.getName()).thenReturn("get_origin");
        when(mockFunc.getEntryPoint()).thenReturn(funcAddr);
        when(mockFunc.getReturnType()).thenReturn(structType);
        when(mockFunc.getAllVariables()).thenReturn(new Variable[0]);

        when(mockFuncIterator.hasNext()).thenReturn(true, false);
        when(mockFuncIterator.next()).thenReturn(mockFunc);
        when(mockListing.getFunctions(true)).thenReturn(mockFuncIterator);

        String result = dataTypeService.findDataTypeUsage("POINT", "x", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\": \"No usages found for data type: POINT.x\""));
    }

    @Test
    @DisplayName("field search no-usages message includes field name")
    void testFieldSearch_NoUsagesMessageIncludesField() {
        setupProgramMocks();
        setupListingMocks();

        Structure structType = mock(Structure.class);
        when(structType.getName()).thenReturn("RECT");
        when(structType.getUniversalID()).thenReturn(new UniversalID(42L));

        DataTypeComponent topComp = mock(DataTypeComponent.class);
        when(topComp.getFieldName()).thenReturn("top");
        when(topComp.getOffset()).thenReturn(0);
        when(structType.getComponents()).thenReturn(new DataTypeComponent[]{topComp});

        setupDtmTypes(structType);
        setupDataIterator(); // empty

        String result = dataTypeService.findDataTypeUsage("RECT", "top", 0, 100).toStructuredJson();
        assertTrue(result.contains("\"message\": \"No usages found for data type: RECT.top\""));
    }
}
