package com.lauriewired.mcp.model.response;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import com.lauriewired.mcp.model.JsonOutput;

/**
 * Tests for toDisplayText() on response records with low coverage.
 * These are pure data-class tests — no Ghidra infrastructure needed.
 */
class ResponseRecordDisplayTextTest {

    // --- ProgramInfoResult ---

    @Nested
    @DisplayName("ProgramInfoResult")
    class ProgramInfoResultTests {

        @Test
        @DisplayName("toDisplayText includes all fields")
        void testFullDisplay() {
            var result = new ProgramInfoResult(
                "test.exe", "PE", "x86", "x86:LE:64:default", "Little",
                64, "Visual Studio", "00400000", "00400000", "0040FFFF",
                "00401000", 5, 100);
            String text = result.toDisplayText();

            assertTrue(text.contains("Program: test.exe"));
            assertTrue(text.contains("Format: PE"));
            assertTrue(text.contains("Processor: x86"));
            assertTrue(text.contains("Architecture: x86:LE:64:default"));
            assertTrue(text.contains("Endian: Little"));
            assertTrue(text.contains("Address Size: 64"));
            assertTrue(text.contains("Compiler: Visual Studio"));
            assertTrue(text.contains("Image Base: 00400000"));
            assertTrue(text.contains("Address Range: 00400000 - 0040FFFF"));
            assertTrue(text.contains("Entry Point: 00401000"));
            assertTrue(text.contains("Functions: 5"));
            assertTrue(text.contains("Symbols: 100"));
        }

        @Test
        @DisplayName("toDisplayText omits entry point when null")
        void testNullEntryPoint() {
            var result = new ProgramInfoResult(
                "lib.so", "ELF", "ARM", "ARM:LE:32", "Little",
                32, "gcc", "00000000", "00000000", "0000FFFF",
                null, 3, 50);
            String text = result.toDisplayText();

            assertTrue(!text.contains("Entry Point:"));
            assertTrue(text.contains("Functions: 3"));
        }
    }

    // --- DataTypeDetailResult ---

    @Nested
    @DisplayName("DataTypeDetailResult")
    class DataTypeDetailResultTests {

        @Test
        @DisplayName("toDisplayText for Structure with fields")
        void testStructureWithFields() {
            var fields = List.of(
                new DataTypeDetailResult.Field(0, "x", "int", 4, "x coordinate"),
                new DataTypeDetailResult.Field(4, "y", "int", 4, null)
            );
            var result = new DataTypeDetailResult("Structure", "POINT", 8, "A 2D point", null, fields, null);
            String text = result.toDisplayText();

            assertTrue(text.contains("Structure: POINT"));
            assertTrue(text.contains("Size: 8 bytes"));
            assertTrue(text.contains("Description: A 2D point"));
            assertTrue(text.contains("[0000] x: int (4 bytes) // x coordinate"));
            assertTrue(text.contains("[0004] y: int (4 bytes)"));
            assertTrue(!text.contains("// \n")); // no trailing comment for null
        }

        @Test
        @DisplayName("toDisplayText for Structure with no fields")
        void testStructureEmpty() {
            var result = new DataTypeDetailResult("Structure", "EMPTY", 0, null, null, List.of(), null);
            String text = result.toDisplayText();

            assertTrue(text.contains("Structure: EMPTY"));
            assertTrue(text.contains("(no fields defined)"));
            assertTrue(!text.contains("Description:"));
        }

        @Test
        @DisplayName("toDisplayText for Structure with unnamed field")
        void testStructureUnnamedField() {
            var fields = List.of(
                new DataTypeDetailResult.Field(0, null, "byte", 1, null)
            );
            var result = new DataTypeDetailResult("Structure", "S", 1, null, null, fields, null);
            String text = result.toDisplayText();

            assertTrue(text.contains("(unnamed)"));
        }

        @Test
        @DisplayName("toDisplayText for Enum with values")
        void testEnumWithValues() {
            var values = List.of(
                new DataTypeDetailResult.Value("READ", 1),
                new DataTypeDetailResult.Value("WRITE", 2),
                new DataTypeDetailResult.Value("EXEC", 4)
            );
            var result = new DataTypeDetailResult("Enum", "Permissions", 4, "File permissions", null, null, values);
            String text = result.toDisplayText();

            assertTrue(text.contains("Enum: Permissions"));
            assertTrue(text.contains("Size: 4 bytes"));
            assertTrue(text.contains("Description: File permissions"));
            assertTrue(text.contains("READ = 0x1 (1)"));
            assertTrue(text.contains("WRITE = 0x2 (2)"));
            assertTrue(text.contains("EXEC = 0x4 (4)"));
        }

        @Test
        @DisplayName("toDisplayText for Enum with no values")
        void testEnumEmpty() {
            var result = new DataTypeDetailResult("Enum", "Empty", 4, null, null, null, List.of());
            String text = result.toDisplayText();

            assertTrue(text.contains("Enum: Empty"));
            assertTrue(text.contains("(no values defined)"));
        }

        @Test
        @DisplayName("toDisplayText for other data type kinds")
        void testOtherKind() {
            var result = new DataTypeDetailResult("Typedef", "DWORD", 4, "Unsigned 32-bit", null, null, null);
            String text = result.toDisplayText();

            assertTrue(text.contains("Data Type: DWORD"));
            assertTrue(text.contains("Kind: Typedef"));
            assertTrue(text.contains("Size: 4 bytes"));
            assertTrue(text.contains("Description: Unsigned 32-bit"));
        }

        @Test
        @DisplayName("toDisplayText for other kind without description")
        void testOtherKindNoDescription() {
            var result = new DataTypeDetailResult("Pointer", "int *", 8, null, null, null, null);
            String text = result.toDisplayText();

            assertTrue(text.contains("Data Type: int *"));
            assertTrue(text.contains("Kind: Pointer"));
            assertTrue(!text.contains("Description:"));
        }
    }

    // --- CallGraphResult ---

    @Nested
    @DisplayName("CallGraphResult")
    class CallGraphResultTests {

        @Test
        @DisplayName("toDisplayText with callers and callees")
        void testFullCallGraph() {
            var callerChild = new CallGraphResult.CallGraphNode("grandparent", "00400000", null, null);
            var caller = new CallGraphResult.CallGraphNode("parent", "00400100",
                List.of(callerChild), null);
            var callee = new CallGraphResult.CallGraphNode("child", "00400300", null, null);

            var result = new CallGraphResult("main", "00400200", 2, "both",
                List.of(caller), List.of(callee));
            String text = result.toDisplayText();

            assertTrue(text.contains("Call Graph for main at 00400200"));
            assertTrue(text.contains("direction: both"));
            assertTrue(text.contains("depth: 2"));
            assertTrue(text.contains("CALLERS (functions that call main):"));
            assertTrue(text.contains("- parent at 00400100"));
            assertTrue(text.contains("  - grandparent at 00400000")); // indented
            assertTrue(text.contains("CALLEES (functions called by main):"));
            assertTrue(text.contains("- child at 00400300"));
        }

        @Test
        @DisplayName("toDisplayText with empty callers/callees")
        void testEmptyCallGraph() {
            var result = new CallGraphResult("isolated", "00400000", 1, "both",
                List.of(), List.of());
            String text = result.toDisplayText();

            assertTrue(text.contains("Call Graph for isolated"));
            assertTrue(!text.contains("CALLERS"));
            assertTrue(!text.contains("CALLEES"));
        }

        @Test
        @DisplayName("toDisplayText with null callers list")
        void testNullCallers() {
            var callee = new CallGraphResult.CallGraphNode("printf", "00400500", null, null);
            var result = new CallGraphResult("main", "00400000", 1, "callees",
                null, List.of(callee));
            String text = result.toDisplayText();

            assertTrue(!text.contains("CALLERS"));
            assertTrue(text.contains("CALLEES"));
            assertTrue(text.contains("- printf at 00400500"));
        }
    }

    // --- ControlFlowResult ---

    @Nested
    @DisplayName("ControlFlowResult")
    class ControlFlowResultTests {

        @Test
        @DisplayName("toDisplayText with blocks, successors, instructions")
        void testFullControlFlow() {
            var succ = new ControlFlowResult.Successor("FALL_THROUGH", "00401010");
            var instr1 = ControlFlowResult.instruction("00401000", "PUSH RBP");
            var instr2 = ControlFlowResult.instruction("00401001", "MOV RBP,RSP");
            var block = new ControlFlowResult.Block("00401000",
                new ControlFlowResult.Range("00401000", "00401005"),
                List.of(succ), List.of(instr1, instr2));

            var result = new ControlFlowResult("main", "00401000", List.of(block));
            String text = result.toDisplayText();

            assertTrue(text.contains("Control Flow Analysis for function: main at 00401000"));
            assertTrue(text.contains("Block at 00401000 (00401000 - 00401005)"));
            assertTrue(text.contains("FALL_THROUGH to 00401010"));
            assertTrue(text.contains("Instructions:"));
            assertTrue(text.contains("00401000: PUSH RBP"));
            assertTrue(text.contains("00401001: MOV RBP,RSP"));
        }

        @Test
        @DisplayName("toDisplayText with terminal block (no successors)")
        void testTerminalBlock() {
            var instr = ControlFlowResult.instruction("00401050", "RET");
            var block = new ControlFlowResult.Block("00401050",
                new ControlFlowResult.Range("00401050", "00401050"),
                List.of(), List.of(instr));

            var result = new ControlFlowResult("main", "00401000", List.of(block));
            String text = result.toDisplayText();

            assertTrue(text.contains("Terminal block (no successors)"));
        }

        @Test
        @DisplayName("instruction() with null address uses empty string key")
        void testInstructionNullAddress() {
            Map<String, String> instr = ControlFlowResult.instruction(null, "NOP");
            assertEquals("NOP", instr.get(""));
        }
    }

    // --- DataFlowResult ---

    @Nested
    @DisplayName("DataFlowResult")
    class DataFlowResultTests {

        @Test
        @DisplayName("toDisplayText shows variable info and references")
        void testFullDataFlow() {
            var variable = new DataFlowResult.Variable("counter", "int", "Stack[-0x4]");
            var refs = List.of(
                new DataFlowResult.Reference("00401010", "WRITE", "store", "MOV [RBP-4],EAX"),
                new DataFlowResult.Reference("00401020", "READ", "load", "CMP [RBP-4],0x10")
            );
            var result = new DataFlowResult("main", variable, refs);
            String text = result.toDisplayText();

            assertTrue(text.contains("Data Flow Analysis for variable 'counter' in function main"));
            assertTrue(text.contains("Name: counter"));
            assertTrue(text.contains("Type: int"));
            assertTrue(text.contains("Storage: Stack[-0x4]"));
            assertTrue(text.contains("00401010: WRITE: store - MOV [RBP-4],EAX"));
            assertTrue(text.contains("00401020: READ: load - CMP [RBP-4],0x10"));
        }

        @Test
        @DisplayName("toDisplayText handles null storage")
        void testNullStorage() {
            var variable = new DataFlowResult.Variable("x", "int", null);
            var result = new DataFlowResult("func", variable, List.of());
            String text = result.toDisplayText();

            assertTrue(text.contains("Storage: No storage information available"));
        }
    }

    // --- SearchDisassemblyResult ---

    @Nested
    @DisplayName("SearchDisassemblyResult")
    class SearchDisassemblyResultTests {

        @Test
        @DisplayName("toDisplayText with matches")
        void testWithMatches() {
            var ctx = List.of(
                new SearchDisassemblyResult.ContextLine("00401000", "PUSH RBP", false),
                new SearchDisassemblyResult.ContextLine("00401001", "MOV RBP,RSP", true)
            );
            var match = new SearchDisassemblyResult.DisasmMatch("00401001", "main", "MOV RBP,RSP", ctx);
            var result = new SearchDisassemblyResult("MOV", 1, List.of(match));
            String text = result.toDisplayText();

            assertTrue(text.contains("Location: 00401001 (in function main)"));
            assertTrue(text.contains("----------------------------------------"));
            // Arrow prefix for match line
            assertTrue(text.contains("\u2192 00401001: MOV RBP,RSP"));
            // Space prefix for non-match
            assertTrue(text.contains("  00401000: PUSH RBP"));
        }

        @Test
        @DisplayName("toDisplayText with no function context")
        void testNoFunction() {
            var ctx = List.of(new SearchDisassemblyResult.ContextLine("00401000", "NOP", true));
            var match = new SearchDisassemblyResult.DisasmMatch("00401000", null, "NOP", ctx);
            var result = new SearchDisassemblyResult("NOP", 1, List.of(match));
            String text = result.toDisplayText();

            assertTrue(text.contains("Location: 00401000\n"));
            assertTrue(!text.contains("in function"));
        }

        @Test
        @DisplayName("toDisplayText with no matches")
        void testNoMatches() {
            var result = new SearchDisassemblyResult("INVALID", 0, List.of());
            String text = result.toDisplayText();

            assertEquals("No matches found for pattern: INVALID", text);
        }
    }

    // --- SearchMemoryResult ---

    @Nested
    @DisplayName("SearchMemoryResult")
    class SearchMemoryResultTests {

        @Test
        @DisplayName("toDisplayText with matches including block and label")
        void testFullMatch() {
            var match = new SearchMemoryResult.MemoryMatch("00401000", ".text", "myFunc", "48 65 6C 6C 6F");
            var result = new SearchMemoryResult("Hello", 1, List.of(match));
            String text = result.toDisplayText();

            assertTrue(text.contains("Match at: 00401000 (.text)"));
            assertTrue(text.contains("Label: myFunc"));
            assertTrue(text.contains("Context:\n48 65 6C 6C 6F"));
        }

        @Test
        @DisplayName("toDisplayText with null block, label, context")
        void testMinimalMatch() {
            var match = new SearchMemoryResult.MemoryMatch("00402000", null, null, null);
            var result = new SearchMemoryResult("test", 1, List.of(match));
            String text = result.toDisplayText();

            assertTrue(text.contains("Match at: 00402000"));
            assertTrue(!text.contains("(.text)"));
            assertTrue(!text.contains("Label:"));
            assertTrue(!text.contains("Context:"));
        }

        @Test
        @DisplayName("toDisplayText with no matches")
        void testNoMatches() {
            var result = new SearchMemoryResult("missing", 0, List.of());
            assertEquals("No matches found for query: missing", result.toDisplayText());
        }

        @Test
        @DisplayName("toDisplayText with multiple matches has separator")
        void testMultipleMatches() {
            var m1 = new SearchMemoryResult.MemoryMatch("00401000", null, null, null);
            var m2 = new SearchMemoryResult.MemoryMatch("00402000", null, null, null);
            var result = new SearchMemoryResult("test", 2, List.of(m1, m2));
            String text = result.toDisplayText();

            assertTrue(text.contains("Match at: 00401000"));
            assertTrue(text.contains("Match at: 00402000"));
        }
    }

    // --- SearchDecompiledResult ---

    @Nested
    @DisplayName("SearchDecompiledResult")
    class SearchDecompiledResultTests {

        @Test
        @DisplayName("toDisplayText with matches")
        void testWithMatches() {
            var match = new SearchDecompiledResult.DecompiledMatch(
                "main", "00401000", "int x = 0;",
                List.of("void main() {", "  int x = 0;", "  return;", "}"));
            var result = new SearchDecompiledResult("x = 0", 1, List.of(match));
            String text = result.toDisplayText();

            assertTrue(text.contains("Function: main at 00401000"));
            assertTrue(text.contains("----------------------------------------"));
            assertTrue(text.contains("void main() {"));
            assertTrue(text.contains("  int x = 0;"));
        }

        @Test
        @DisplayName("toDisplayText with no matches")
        void testNoMatches() {
            var result = new SearchDecompiledResult("notfound", 0, List.of());
            assertEquals("No matches found for pattern: notfound", result.toDisplayText());
        }
    }

    // --- UpdateResult ---

    @Nested
    @DisplayName("UpdateResult")
    class UpdateResultTests {

        @Test
        @DisplayName("toDisplayText shows name, results, and summary")
        void testFullUpdate() {
            var result = new UpdateResult("MyStruct",
                List.of("  field_x -> renamed to posX [OK]", "  field_z -> not found [FAILED]"),
                new UpdateResult.Summary(1, 1));
            String text = result.toDisplayText();

            assertTrue(text.contains("Updated 'MyStruct':"));
            assertTrue(text.contains("field_x -> renamed to posX [OK]"));
            assertTrue(text.contains("field_z -> not found [FAILED]"));
            assertTrue(text.contains("Summary: 1 succeeded, 1 failed"));
        }
    }

    // --- RenameFunctionsResult ---

    @Nested
    @DisplayName("RenameFunctionsResult")
    class RenameFunctionsResultTests {

        @Test
        @DisplayName("toDisplayText shows renamed pairs and count")
        void testDisplay() {
            var renamed = new LinkedHashMap<String, String>();
            renamed.put("FUN_001", "initialize");
            renamed.put("FUN_002", "cleanup");
            var result = new RenameFunctionsResult("Renamed successfully", renamed, 2);
            String text = result.toDisplayText();

            assertTrue(text.contains("Renamed successfully"));
            assertTrue(text.contains("FUN_001 -> initialize"));
            assertTrue(text.contains("FUN_002 -> cleanup"));
            assertTrue(text.contains("Count: 2"));
        }
    }

    // --- RenameDataResult ---

    @Nested
    @DisplayName("RenameDataResult")
    class RenameDataResultTests {

        @Test
        @DisplayName("toDisplayText shows renamed pairs and count")
        void testDisplay() {
            var renamed = new LinkedHashMap<String, String>();
            renamed.put("00402000", "config_table");
            var result = new RenameDataResult("Renamed successfully", renamed, 1);
            String text = result.toDisplayText();

            assertTrue(text.contains("Renamed successfully"));
            assertTrue(text.contains("00402000 -> config_table"));
            assertTrue(text.contains("Count: 1"));
        }
    }

    // --- SetVariableTypesResult ---

    @Nested
    @DisplayName("SetVariableTypesResult")
    class SetVariableTypesResultTests {

        @Test
        @DisplayName("toDisplayText shows function, applied types, count")
        void testDisplay() {
            var applied = new LinkedHashMap<String, String>();
            applied.put("param_1", "char *");
            applied.put("local_8", "int");
            var result = new SetVariableTypesResult("Types applied", "main", applied, 2);
            String text = result.toDisplayText();

            assertTrue(text.contains("Types applied in main"));
            assertTrue(text.contains("param_1 -> char *"));
            assertTrue(text.contains("local_8 -> int"));
            assertTrue(text.contains("Count: 2"));
        }
    }

    // --- MemoryPermissionsResult ---

    @Nested
    @DisplayName("MemoryPermissionsResult")
    class MemoryPermissionsResultTests {

        @Test
        @DisplayName("toDisplayText shows all memory block properties")
        void testFullPermissions() {
            var perms = new MemoryPermissionsResult.Permissions(true, false, true);
            var result = new MemoryPermissionsResult(".text", "00401000", "00401FFF",
                0x1000, perms, true, false, false);
            String text = result.toDisplayText();

            assertTrue(text.contains("Memory permissions at 00401000:"));
            assertTrue(text.contains("Block: .text"));
            assertTrue(text.contains("Start: 00401000"));
            assertTrue(text.contains("End: 00401FFF"));
            assertTrue(text.contains("Size: 0x1000 bytes"));
            assertTrue(text.contains("Read: Yes"));
            assertTrue(text.contains("Write: No"));
            assertTrue(text.contains("Execute: Yes"));
            assertTrue(text.contains("Initialized: Yes"));
            assertTrue(text.contains("Volatile: No"));
            assertTrue(text.contains("Overlay: No"));
        }

        @Test
        @DisplayName("toDisplayText with writable volatile overlay block")
        void testWritableVolatileOverlay() {
            var perms = new MemoryPermissionsResult.Permissions(true, true, false);
            var result = new MemoryPermissionsResult(".bss", "00500000", "00500FFF",
                0x1000, perms, false, true, true);
            String text = result.toDisplayText();

            assertTrue(text.contains("Write: Yes"));
            assertTrue(text.contains("Execute: No"));
            assertTrue(text.contains("Initialized: No"));
            assertTrue(text.contains("Volatile: Yes"));
            assertTrue(text.contains("Overlay: Yes"));
        }
    }

    // --- AddressDataTypeResult ---

    @Nested
    @DisplayName("AddressDataTypeResult")
    class AddressDataTypeResultTests {

        @Test
        @DisplayName("toDisplayText for instruction")
        void testInstruction() {
            var result = new AddressDataTypeResult("00401000", "Instruction",
                "MOV", "RBP,RSP", null, 3, null, null);
            String text = result.toDisplayText();

            assertTrue(text.contains("Data type at 00401000:"));
            assertTrue(text.contains("Type: Instruction"));
            assertTrue(text.contains("Mnemonic: MOV"));
            assertTrue(text.contains("Operands: RBP,RSP"));
            assertTrue(text.contains("Length: 3 bytes"));
        }

        @Test
        @DisplayName("toDisplayText for defined data with label")
        void testDefinedData() {
            var result = new AddressDataTypeResult("00402000", "Defined Data",
                null, null, "int", 4, "0x42", "myVariable");
            String text = result.toDisplayText();

            assertTrue(text.contains("Type: Defined Data"));
            assertTrue(text.contains("Data Type: int"));
            assertTrue(text.contains("Length: 4 bytes"));
            assertTrue(text.contains("Value: 0x42"));
            assertTrue(text.contains("Label: myVariable"));
            assertTrue(!text.contains("Mnemonic:"));
            assertTrue(!text.contains("Operands:"));
        }

        @Test
        @DisplayName("toDisplayText for minimal result (all optional null)")
        void testMinimal() {
            var result = new AddressDataTypeResult("00403000", "No data defined",
                null, null, null, null, null, null);
            String text = result.toDisplayText();

            assertTrue(text.contains("Data type at 00403000:"));
            assertTrue(text.contains("Type: No data defined"));
            assertTrue(!text.contains("Mnemonic:"));
            assertTrue(!text.contains("Length:"));
        }
    }

    // --- CurrentFunctionResult ---

    @Nested
    @DisplayName("CurrentFunctionResult")
    class CurrentFunctionResultTests {

        @Test
        @DisplayName("toDisplayText format")
        void testDisplay() {
            var result = new CurrentFunctionResult("main", "00401000", "int main(int argc, char **argv)");
            String text = result.toDisplayText();

            assertEquals("Function: main at 00401000\nSignature: int main(int argc, char **argv)", text);
        }
    }

    // --- CurrentAddressResult ---

    @Nested
    @DisplayName("CurrentAddressResult")
    class CurrentAddressResultTests {

        @Test
        @DisplayName("toDisplayText returns address")
        void testDisplay() {
            var result = new CurrentAddressResult("00401234");
            assertEquals("00401234", result.toDisplayText());
        }
    }

    // --- SymbolAddressResult ---

    @Nested
    @DisplayName("SymbolAddressResult")
    class SymbolAddressResultTests {

        @Test
        @DisplayName("toDisplayText format")
        void testDisplay() {
            var result = new SymbolAddressResult("main", "00401000");
            assertEquals("Symbol 'main' found at address: 00401000", result.toDisplayText());
        }
    }

    // --- JsonOutput wrapping ---

    @Nested
    @DisplayName("JsonOutput delegates toDisplayText to Displayable records")
    class JsonOutputDelegation {

        @Test
        @DisplayName("JsonOutput.toDisplayText calls underlying record's toDisplayText")
        void testDelegation() {
            var result = new CurrentAddressResult("00401000");
            var output = new JsonOutput(result);

            assertEquals("00401000", output.toDisplayText());
            assertNotNull(output.toStructuredJson());
            assertTrue(output.toStructuredJson().contains("00401000"));
        }
    }
}
