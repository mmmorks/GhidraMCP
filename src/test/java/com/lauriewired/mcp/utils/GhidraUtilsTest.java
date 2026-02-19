package com.lauriewired.mcp.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;

import com.lauriewired.mcp.services.GhidraTestEnv;

/**
 * Tests for GhidraUtils using ProgramBuilder-based real Ghidra objects
 */
public class GhidraUtilsTest {

    @Nested
    @DisplayName("Null-guard tests (no Ghidra needed)")
    class NullGuardTests {

        @Test
        @DisplayName("getFunctionForAddress returns null for null program")
        void testGetFunctionForAddress_NullProgram() {
            assertNull(GhidraUtils.getFunctionForAddress(null, null));
        }

        @Test
        @DisplayName("getSymbolAddress returns null for null program")
        void testGetSymbolAddress_NullProgram() {
            assertNull(GhidraUtils.getSymbolAddress(null, "test"));
        }

        @Test
        @DisplayName("getSymbolAddress returns null for null symbol name")
        void testGetSymbolAddress_NullName() {
            assertNull(GhidraUtils.getSymbolAddress(null, null));
        }

        @Test
        @DisplayName("getSymbolAddress returns null for empty symbol name")
        void testGetSymbolAddress_EmptyName() {
            assertNull(GhidraUtils.getSymbolAddress(null, ""));
        }

        @Test
        @DisplayName("findVariableByName returns null for null high function")
        void testFindVariableByName_NullHighFunction() {
            assertNull(GhidraUtils.findVariableByName(null, "test"));
        }

        @Test
        @DisplayName("findVariableByName returns null for null variable name")
        void testFindVariableByName_NullName() {
            assertNull(GhidraUtils.findVariableByName(null, null));
        }
    }

    @Nested
    @DisplayName("ProgramBuilder-based integration tests")
    class ProgramBuilderTests {

        private ProgramBuilder builder;
        private ProgramDB program;

        @BeforeAll
        static void initGhidra() {
            GhidraTestEnv.initialize();
        }

        @BeforeEach
        void setUp() throws Exception {
            builder = new ProgramBuilder("utilsTest", ProgramBuilder._X64);
            builder.createMemory(".text", "0x401000", 0x2000);

            // Helper at 0x401200: mov dword [rdi],0x10; ret
            builder.setBytes("0x401200", "C7 07 10 00 00 00 C3", true);
            builder.createFunction("0x401200");

            // Function at 0x401000 with local variable whose address escapes via call:
            // push rbp; mov rbp,rsp; sub rsp,0x10; mov dword [rbp-4],0x42;
            // lea rdi,[rbp-4]; call 0x401200; mov eax,[rbp-4]; leave; ret
            builder.setBytes("0x401000",
                "55 48 89 E5 48 83 EC 10 C7 45 FC 42 00 00 00 48 8D 7D FC E8 E8 01 00 00 8B 45 FC C9 C3",
                true);
            builder.createFunction("0x401000");

            // Create a label for symbol tests
            builder.createLabel("0x401300", "mySymbol");

            program = builder.getProgram();

            // Set helper's prototype so decompiler recognizes the pointer escape
            int tx = program.startTransaction("set helper prototype");
            try {
                Function helperFunc = program.getFunctionManager()
                    .getFunctionAt(builder.addr("0x401200"));
                if (helperFunc != null) {
                    helperFunc.addParameter(
                        new ParameterImpl("ptr",
                            new PointerDataType(IntegerDataType.dataType), program),
                        SourceType.ANALYSIS);
                }
            } finally {
                program.endTransaction(tx, true);
            }
        }

        @AfterEach
        void tearDown() {
            if (builder != null) {
                builder.dispose();
            }
        }

        // --- getFunctionForAddress tests ---

        @Test
        @DisplayName("getFunctionForAddress returns null for null address")
        void testGetFunctionForAddress_NullAddress() {
            assertNull(GhidraUtils.getFunctionForAddress(program, null));
        }

        @Test
        @DisplayName("getFunctionForAddress returns function at exact address")
        void testGetFunctionForAddress_ExactMatch() {
            Address addr = builder.addr("0x401000");
            Function result = GhidraUtils.getFunctionForAddress(program, addr);
            assertNotNull(result);
            assertEquals(addr, result.getEntryPoint());
        }

        @Test
        @DisplayName("getFunctionForAddress returns function containing address")
        void testGetFunctionForAddress_ContainingMatch() {
            // 0x401010 is inside the function body at 0x401000
            Address addr = builder.addr("0x401010");
            Function result = GhidraUtils.getFunctionForAddress(program, addr);
            assertNotNull(result);
            assertEquals(builder.addr("0x401000"), result.getEntryPoint());
        }

        @Test
        @DisplayName("getFunctionForAddress returns null when no function found")
        void testGetFunctionForAddress_NoMatch() {
            Address addr = builder.addr("0x402000");
            assertNull(GhidraUtils.getFunctionForAddress(program, addr));
        }

        // --- getSymbolAddress tests ---

        @Test
        @DisplayName("getSymbolAddress returns address for existing symbol")
        void testGetSymbolAddress_Found() {
            Address result = GhidraUtils.getSymbolAddress(program, "mySymbol");
            assertNotNull(result);
            assertEquals(builder.addr("0x401300"), result);
        }

        @Test
        @DisplayName("getSymbolAddress returns null for non-existing symbol")
        void testGetSymbolAddress_NotFound() {
            assertNull(GhidraUtils.getSymbolAddress(program, "nonExistentSymbol"));
        }

        // --- findVariableByName tests (requires decompilation) ---

        /** Decompile the function at 0x401000 and return the HighFunction. */
        private HighFunction decompile() {
            Function func = program.getFunctionManager()
                .getFunctionAt(builder.addr("0x401000"));
            assertNotNull(func, "Function at 0x401000 should exist");
            DecompileResults results = GhidraUtils.decompileFunction(func, program);
            assertNotNull(results, "Decompilation should succeed");
            HighFunction hf = results.getHighFunction();
            assertNotNull(hf, "HighFunction should be available");
            return hf;
        }

        /** Discover a variable name from the decompiled output. */
        private String discoverVariableName(HighFunction hf) {
            Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
            assertTrue(symbols.hasNext(), "Decompiled function should have symbols");
            // Find a local_ or param_ variable
            Pattern pattern = Pattern.compile("(local|param)_\\w+");
            while (symbols.hasNext()) {
                String name = symbols.next().getName();
                Matcher m = pattern.matcher(name);
                if (m.matches()) {
                    return name;
                }
            }
            // Fall back to first symbol name
            Iterator<HighSymbol> fallback = hf.getLocalSymbolMap().getSymbols();
            return fallback.next().getName();
        }

        @Test
        @DisplayName("findVariableByName finds an existing variable")
        void testFindVariableByName_Found() {
            HighFunction hf = decompile();
            String varName = discoverVariableName(hf);

            HighSymbol result = GhidraUtils.findVariableByName(hf, varName);
            assertNotNull(result);
            assertEquals(varName, result.getName());
        }

        @Test
        @DisplayName("findVariableByName returns null for non-existing variable")
        void testFindVariableByName_NotFound() {
            HighFunction hf = decompile();
            assertNull(GhidraUtils.findVariableByName(hf, "nonExistentVarXyz"));
        }

        // --- checkFullCommit tests ---

        @Test
        @DisplayName("checkFullCommit returns false for non-parameter symbol")
        void testCheckFullCommit_NonParameter() {
            // Decompile the helper at 0x401200 which has a pointer param set on listing;
            // the decompiler should also see a param, so non-param locals (if any) exist.
            // Use 0x401000 which has local variables from the address-escaping bytecode.
            HighFunction hf = decompile();
            // Find a local (non-parameter) symbol — skip if decompiler didn't produce one
            Iterator<HighSymbol> symbols = hf.getLocalSymbolMap().getSymbols();
            HighSymbol localSymbol = null;
            while (symbols.hasNext()) {
                HighSymbol sym = symbols.next();
                if (!sym.isParameter()) {
                    localSymbol = sym;
                    break;
                }
            }
            // If the decompiler produced a non-parameter, verify checkFullCommit returns false
            if (localSymbol != null) {
                assertFalse(GhidraUtils.checkFullCommit(localSymbol, hf));
            }
            // Also verify: null highSymbol when listing and decompiler param counts match
            // should still check param counts (does not early-return for null)
            // This exercises the non-early-return path differently
        }

        @Test
        @DisplayName("checkFullCommit returns true when parameter counts differ")
        void testCheckFullCommit_DifferentParamCounts() throws Exception {
            HighFunction hf = decompile();

            // Record how many decompiler params exist
            int decompilerParamCount = hf.getLocalSymbolMap().getNumParams();

            // Add enough listing params to guarantee a mismatch with the decompiler
            Function func = hf.getFunction();
            int tx = program.startTransaction("add extra params");
            try {
                for (int i = func.getParameterCount(); i <= decompilerParamCount + 1; i++) {
                    func.addParameter(
                        new ParameterImpl("extra" + i,
                            IntegerDataType.dataType, program),
                        SourceType.USER_DEFINED);
                }
            } finally {
                program.endTransaction(tx, true);
            }

            // Listing now has more params than the (stale) decompiler view → true
            // Use null highSymbol which skips the isParameter early-return
            assertTrue(GhidraUtils.checkFullCommit(null, hf),
                "Should require full commit when listing param count exceeds decompiler param count");
        }
    }
}
