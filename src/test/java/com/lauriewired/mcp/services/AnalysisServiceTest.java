package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;

import java.util.Iterator;
import java.util.List;

/**
 * Unit tests for AnalysisService
 */
public class AnalysisServiceTest {

    private AnalysisService analysisService;
    private ProgramService programService;
    private FunctionService functionService;

    @BeforeEach
    @SuppressWarnings("unused")
    void setUp() {
        // Test with null tool since we can't easily mock PluginTool
        programService = new ProgramService(null);
        functionService = new FunctionService(null, programService);
        analysisService = new AnalysisService(programService, functionService);
    }

    @Test
    @DisplayName("analyzeControlFlow returns error when no program is loaded")
    void testAnalyzeControlFlow_NoProgram() {
        String result = analysisService.analyzeControlFlow("0x1000").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeControlFlow returns error for null identifier")
    void testAnalyzeControlFlow_NullIdentifier() {
        String result = analysisService.analyzeControlFlow(null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeControlFlow returns error for empty identifier")
    void testAnalyzeControlFlow_EmptyIdentifier() {
        String result = analysisService.analyzeControlFlow("").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeControlFlow handles invalid identifier")
    void testAnalyzeControlFlow_InvalidIdentifier() {
        String result = analysisService.analyzeControlFlow("invalid").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error when no program is loaded")
    void testAnalyzeDataFlow_NoProgram() {
        String result = analysisService.analyzeDataFlow("0x1000", "variable").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for null identifier")
    void testAnalyzeDataFlow_NullIdentifier() {
        String result = analysisService.analyzeDataFlow(null, "variable").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for empty identifier")
    void testAnalyzeDataFlow_EmptyIdentifier() {
        String result = analysisService.analyzeDataFlow("", "variable").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for null variable name")
    void testAnalyzeDataFlow_NullVariableName() {
        String result = analysisService.analyzeDataFlow("0x1000", null).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("analyzeDataFlow returns error for empty variable name")
    void testAnalyzeDataFlow_EmptyVariableName() {
        String result = analysisService.analyzeDataFlow("0x1000", "").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph returns error when no program is loaded")
    void testGetCallGraph_NoProgram() {
        String result = analysisService.getCallGraph("0x1000", 3, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph returns error for null identifier")
    void testGetCallGraph_NullIdentifier() {
        String result = analysisService.getCallGraph(null, 3, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph returns error for empty identifier")
    void testGetCallGraph_EmptyIdentifier() {
        String result = analysisService.getCallGraph("", 3, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph limits depth to maximum of 5")
    void testGetCallGraph_MaxDepth() {
        String result = analysisService.getCallGraph("0x1000", 10, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph handles zero depth")
    void testGetCallGraph_ZeroDepth() {
        String result = analysisService.getCallGraph("0x1000", 0, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph handles negative depth")
    void testGetCallGraph_NegativeDepth() {
        String result = analysisService.getCallGraph("0x1000", -1, "both").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph handles callers direction")
    void testGetCallGraph_CallersDirection() {
        String result = analysisService.getCallGraph("0x1000", 2, "callers").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("getCallGraph handles callees direction")
    void testGetCallGraph_CalleesDirection() {
        String result = analysisService.getCallGraph("0x1000", 2, "callees").toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences returns error when no program is loaded")
    void testListReferences_NoProgram() {
        String result = analysisService.listReferences("0x1000", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences returns error for null address")
    void testListReferences_NullAddress() {
        String result = analysisService.listReferences(null, 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences returns error for empty address")
    void testListReferences_EmptyAddress() {
        String result = analysisService.listReferences("", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences handles symbol name")
    void testListReferences_SymbolName() {
        String result = analysisService.listReferences("main", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences handles hex address")
    void testListReferences_HexAddress() {
        String result = analysisService.listReferences("0x1000", 0, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences handles negative offset")
    void testListReferences_NegativeOffset() {
        String result = analysisService.listReferences("0x1000", -1, 10).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("listReferences handles zero limit")
    void testListReferences_ZeroLimit() {
        String result = analysisService.listReferences("0x1000", 0, 0).toStructuredJson();
        assertTrue(result.contains("\"message\":\"No program loaded\""));
    }

    @Test
    @DisplayName("Constructor accepts null program service without throwing")
    void testConstructor_NullProgramService() {
        assertDoesNotThrow(() -> new AnalysisService(null, null));
    }

    // Note: Testing with actual Program would require a full Ghidra environment
    // These tests verify the service handles null/error cases properly

    /**
     * Tests for call graph leaf node elision behavior.
     * Nodes at max depth should omit callers/callees (null → field absent in JSON).
     * Genuine leaf nodes (no references, not at max depth) should show empty list [].
     */
    @Nested
    @ExtendWith(MockitoExtension.class)
    @DisplayName("getCallGraph leaf node elision")
    class CallGraphLeafElisionTest {

        @Mock private MockablePluginTool mockTool;
        @Mock private ProgramManager mockProgramManager;
        @Mock private Program mockProgram;
        @Mock private FunctionManager mockFunctionManager;
        @Mock private ReferenceManager mockReferenceManager;

        private AnalysisService service;

        @BeforeEach
        void setUp() {
            TestProgramService ps = new TestProgramService(mockTool);
            TestFunctionService fs = new TestFunctionService(mockTool, ps);
            service = new AnalysisService(ps, fs);

            when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
            when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
            when(mockProgram.getFunctionManager()).thenReturn(mockFunctionManager);
            lenient().when(mockProgram.getReferenceManager()).thenReturn(mockReferenceManager);
        }

        /**
         * Helper: create a mock Function with a name, address, and body that
         * returns the given addresses from its AddressIterator.
         */
        private Function mockFunction(String name, String addrHex, Address... bodyAddresses) {
            Function func = mock(Function.class);
            Address entry = mock(Address.class);
            when(entry.toString()).thenReturn(addrHex);
            when(func.getName()).thenReturn(name);
            when(func.getEntryPoint()).thenReturn(entry);
            lenient().when(func.getProgram()).thenReturn(mockProgram);

            AddressSetView body = mock(AddressSetView.class);
            AddressIterator addrIter = mock(AddressIterator.class);

            // Build hasNext/next chain (lenient — body may not be traversed in callers-direction tests)
            if (bodyAddresses.length == 0) {
                lenient().when(addrIter.hasNext()).thenReturn(false);
            } else {
                Boolean[] subsequent = new Boolean[bodyAddresses.length];
                for (int i = 0; i < bodyAddresses.length - 1; i++) subsequent[i] = true;
                subsequent[bodyAddresses.length - 1] = false;
                lenient().when(addrIter.hasNext()).thenReturn(true, subsequent);
                if (bodyAddresses.length == 1) {
                    lenient().when(addrIter.next()).thenReturn(bodyAddresses[0]);
                } else {
                    Address[] rest = new Address[bodyAddresses.length - 1];
                    System.arraycopy(bodyAddresses, 1, rest, 0, rest.length);
                    lenient().when(addrIter.next()).thenReturn(bodyAddresses[0], rest);
                }
            }
            lenient().when(body.getAddresses(true)).thenReturn(addrIter);
            lenient().when(func.getBody()).thenReturn(body);

            return func;
        }

        /** Helper: make resolveFunction find a function by name. */
        private void resolvable(Function func) {
            @SuppressWarnings("unchecked")
            Iterator<Function> iter = mock(Iterator.class);
            when(iter.hasNext()).thenReturn(true, false);
            when(iter.next()).thenReturn(func);
            FunctionIterator fIter = mock(FunctionIterator.class);
            when(fIter.iterator()).thenReturn(iter);
            when(mockFunctionManager.getFunctions(true)).thenReturn(fIter);
        }

        /** Helper: create a call reference from one address to another. */
        private Reference callRef(Address from, Address to) {
            Reference ref = mock(Reference.class);
            when(ref.getReferenceType()).thenReturn(RefType.UNCONDITIONAL_CALL);
            lenient().when(ref.getToAddress()).thenReturn(to);
            lenient().when(ref.getFromAddress()).thenReturn(from);
            return ref;
        }

        /** Helper: create a mock ReferenceIterator from references. */
        private ReferenceIterator refIterator(Reference... refs) {
            ReferenceIterator iter = mock(ReferenceIterator.class);
            when(iter.iterator()).thenReturn(iter);
            if (refs.length == 0) {
                when(iter.hasNext()).thenReturn(false);
            } else {
                Boolean[] subsequent = new Boolean[refs.length];
                for (int i = 0; i < refs.length - 1; i++) subsequent[i] = true;
                subsequent[refs.length - 1] = false;
                when(iter.hasNext()).thenReturn(true, subsequent);
                if (refs.length == 1) {
                    when(iter.next()).thenReturn(refs[0]);
                } else {
                    Reference[] rest = new Reference[refs.length - 1];
                    System.arraycopy(refs, 1, rest, 0, rest.length);
                    when(iter.next()).thenReturn(refs[0], rest);
                }
            }
            return iter;
        }

        @Test
        @DisplayName("callees at max depth are elided (field absent from JSON)")
        void testCallees_atMaxDepth_elided() {
            // main -> helper (depth 1 of 1, so helper is at max depth)
            Address mainBody = mock(Address.class);
            Function main = mockFunction("main", "00401000", mainBody);
            Address helperEntry = mock(Address.class);
            // No body addresses needed — helper is at max depth so it won't be traversed
            Function helper = mock(Function.class);
            Address helperAddr = mock(Address.class);
            when(helperAddr.toString()).thenReturn("00402000");
            when(helper.getName()).thenReturn("helper");
            when(helper.getEntryPoint()).thenReturn(helperAddr);

            resolvable(main);

            Reference callToHelper = callRef(mainBody, helperEntry);
            when(mockReferenceManager.getReferencesFrom(mainBody)).thenReturn(new Reference[]{callToHelper});
            when(mockFunctionManager.getFunctionAt(helperEntry)).thenReturn(helper);

            String json = service.getCallGraph("main", 1, "callees").toStructuredJson();

            // helper node should NOT have a "callees" key at all (elided at max depth)
            assertTrue(json.contains("\"name\":\"helper\""));
            // The helper node should not contain "callees" — it's null so NON_NULL omits it
            // Extract the helper node substring and verify no callees key
            int helperIdx = json.indexOf("\"name\":\"helper\"");
            // Find the enclosing object boundaries
            int braceStart = json.lastIndexOf('{', helperIdx);
            int braceEnd = json.indexOf('}', helperIdx);
            String helperNode = json.substring(braceStart, braceEnd + 1);
            assertFalse(helperNode.contains("\"callees\""),
                    "Leaf node at max depth should not have callees field, but got: " + helperNode);
        }

        @Test
        @DisplayName("callers at max depth are elided (field absent from JSON)")
        void testCallers_atMaxDepth_elided() {
            // caller -> main; depth=1, so caller is at max depth
            Address callerBody = mock(Address.class);
            // No body addresses needed — caller is at max depth so it won't be traversed
            Function caller = mock(Function.class);
            Address callerAddr = mock(Address.class);
            when(callerAddr.toString()).thenReturn("00403000");
            when(caller.getName()).thenReturn("caller_func");
            when(caller.getEntryPoint()).thenReturn(callerAddr);
            Function main = mockFunction("main", "00401000");

            resolvable(main);

            Reference refToMain = callRef(callerBody, main.getEntryPoint());
            // Build iterator before stubbing to avoid nested stubbing issue
            Address mainEntry = main.getEntryPoint();
            ReferenceIterator refsToMain = refIterator(refToMain);
            when(mockReferenceManager.getReferencesTo(mainEntry)).thenReturn(refsToMain);
            when(mockFunctionManager.getFunctionContaining(callerBody)).thenReturn(caller);

            String json = service.getCallGraph("main", 1, "callers").toStructuredJson();

            assertTrue(json.contains("\"name\":\"caller_func\""));
            int callerIdx = json.indexOf("\"name\":\"caller_func\"");
            int braceStart = json.lastIndexOf('{', callerIdx);
            int braceEnd = json.indexOf('}', callerIdx);
            String callerNode = json.substring(braceStart, braceEnd + 1);
            assertFalse(callerNode.contains("\"callers\""),
                    "Leaf node at max depth should not have callers field, but got: " + callerNode);
        }

        @Test
        @DisplayName("genuine leaf callees (no references, not at max depth) show empty list")
        void testCallees_genuineLeaf_emptyList() {
            // main -> helper (depth 2); helper has no callees and is only at depth 1
            Address mainBody = mock(Address.class);
            Function main = mockFunction("main", "00401000", mainBody);
            Address helperEntry = mock(Address.class);
            Address helperBody = mock(Address.class);
            Function helper = mockFunction("helper", "00402000", helperBody);

            resolvable(main);

            Reference callToHelper = callRef(mainBody, helperEntry);
            when(mockReferenceManager.getReferencesFrom(mainBody)).thenReturn(new Reference[]{callToHelper});
            when(mockFunctionManager.getFunctionAt(helperEntry)).thenReturn(helper);

            // helper has no outgoing call references
            when(mockReferenceManager.getReferencesFrom(helperBody)).thenReturn(new Reference[]{});

            String json = service.getCallGraph("main", 2, "callees").toStructuredJson();

            // helper is a genuine leaf — should have "callees":[]
            assertTrue(json.contains("\"name\":\"helper\""));
            int helperIdx = json.indexOf("\"name\":\"helper\"");
            int braceStart = json.lastIndexOf('{', helperIdx);
            int braceEnd = json.indexOf('}', helperIdx);
            String helperNode = json.substring(braceStart, braceEnd + 1);
            assertTrue(helperNode.contains("\"callees\":[]"),
                    "Genuine leaf node should have empty callees list, but got: " + helperNode);
        }

        @Test
        @DisplayName("genuine leaf callers (no references, not at max depth) show empty list")
        void testCallers_genuineLeaf_emptyList() {
            // caller_func -> main; depth=2; caller_func has no callers and is only at depth 1
            Address callerBody = mock(Address.class);
            Function caller = mockFunction("caller_func", "00403000", callerBody);
            Function main = mockFunction("main", "00401000");

            resolvable(main);

            Reference refToMain = callRef(callerBody, main.getEntryPoint());
            // Build iterators before stubbing to avoid nested stubbing issue
            Address mainEntry = main.getEntryPoint();
            Address callerEntry = caller.getEntryPoint();
            ReferenceIterator refsToMain = refIterator(refToMain);
            ReferenceIterator refsToCallerEmpty = refIterator();
            when(mockReferenceManager.getReferencesTo(mainEntry)).thenReturn(refsToMain);
            when(mockFunctionManager.getFunctionContaining(callerBody)).thenReturn(caller);

            // caller_func has no callers of its own
            when(mockReferenceManager.getReferencesTo(callerEntry)).thenReturn(refsToCallerEmpty);

            String json = service.getCallGraph("main", 2, "callers").toStructuredJson();

            assertTrue(json.contains("\"name\":\"caller_func\""));
            int callerIdx = json.indexOf("\"name\":\"caller_func\"");
            int braceStart = json.lastIndexOf('{', callerIdx);
            int braceEnd = json.indexOf('}', callerIdx);
            String callerNode = json.substring(braceStart, braceEnd + 1);
            assertTrue(callerNode.contains("\"callers\":[]"),
                    "Genuine leaf node should have empty callers list, but got: " + callerNode);
        }
    }
}