package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;

import org.junit.jupiter.api.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.GModule;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * Proof of concept: using Ghidra's ProgramBuilder to create real Program
 * instances for testing, instead of mocking every Ghidra API surface.
 *
 * Requires a Ghidra installation. Skips gracefully if none is found.
 */
class ProgramBuilderProofOfConceptTest {

    private static File ghidraInstallDir;
    private ProgramBuilder builder;

    @BeforeAll
    static void initGhidra() {
        ghidraInstallDir = findGhidraInstall();
        assumeTrue(ghidraInstallDir != null,
            "Skipping: no Ghidra installation found (set GHIDRA_INSTALL_DIR)");

        if (!Application.isInitialized()) {
            try {
                TestApplicationLayout layout = new TestApplicationLayout(ghidraInstallDir);
                Application.initializeApplication(layout, new HeadlessGhidraApplicationConfiguration());
            } catch (Exception e) {
                fail("Failed to initialize Ghidra application: " + e.getMessage());
            }
        }
    }

    @AfterEach
    void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    @DisplayName("ProgramBuilder creates a real program with memory and functions")
    void testCreateProgramWithFunctions() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        builder.createEmptyFunction("main", "0x401000", 0x50, DataType.DEFAULT);
        builder.createEmptyFunction("helper", "0x401100", 0x30, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();

        // Real FunctionManager — no mocks
        FunctionManager fm = program.getFunctionManager();
        assertEquals(2, fm.getFunctionCount());

        Function main = fm.getFunctionAt(builder.addr("0x401000"));
        assertNotNull(main);
        assertEquals("main", main.getName());

        Function helper = fm.getFunctionAt(builder.addr("0x401100"));
        assertNotNull(helper);
        assertEquals("helper", helper.getName());
    }

    @Test
    @DisplayName("ProgramBuilder creates real memory blocks")
    void testMemoryBlocks() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createMemory(".data", "0x402000", 0x500);

        ProgramDB program = builder.getProgram();
        MemoryBlock textBlock = program.getMemory().getBlock(".text");
        MemoryBlock dataBlock = program.getMemory().getBlock(".data");

        assertNotNull(textBlock);
        assertEquals(0x1000, textBlock.getSize());
        assertNotNull(dataBlock);
        assertEquals(0x500, dataBlock.getSize());
    }

    @Test
    @DisplayName("ProgramBuilder supports real transactions for writes")
    void testTransactions() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x100);
        builder.createEmptyFunction("myFunc", "0x401000", 0x20, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        Function f = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        assertEquals("myFunc", f.getName());

        // Rename via transaction — exactly like GhidraMCP's services do
        int tx = program.startTransaction("rename");
        try {
            f.setName("renamedFunc", ghidra.program.model.symbol.SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }

        assertEquals("renamedFunc", f.getName());
    }

    @Test
    @DisplayName("ProgramBuilder supports comments")
    void testComments() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x100);
        builder.createComment("0x401000", "This is an EOL comment", CommentType.EOL);
        builder.createComment("0x401000", "Pre comment", CommentType.PRE);

        ProgramDB program = builder.getProgram();
        Listing listing = program.getListing();

        assertEquals("This is an EOL comment",
            listing.getComment(CommentType.EOL, builder.addr("0x401000")));
        assertEquals("Pre comment",
            listing.getComment(CommentType.PRE, builder.addr("0x401000")));
    }

    @Test
    @DisplayName("ProgramBuilder supports data types")
    void testDataTypes() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".data", "0x402000", 0x100);

        StructureDataType myStruct = new StructureDataType("MyStruct", 0);
        myStruct.add(IntegerDataType.dataType, "field1", "first field");
        myStruct.add(IntegerDataType.dataType, "field2", "second field");
        builder.addDataType(myStruct);

        ProgramDB program = builder.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();
        DataType found = dtm.getDataType("/MyStruct");

        assertNotNull(found);
        assertInstanceOf(Structure.class, found);
        assertEquals(2, ((Structure) found).getNumDefinedComponents());
    }

    @Test
    @DisplayName("ProgramBuilder supports x86 byte disassembly and function creation")
    void testDisassembly() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        // MIPS: simple function (Pattern A)
        builder.setBytes("0x401000",
            "27 BD FF F8 AF BF 00 04 00 00 00 00 8F BF 00 04 27 BD 00 08 03 E0 00 08 00 00 00 00",
            true);
        builder.createFunction("0x401000");

        ProgramDB program = builder.getProgram();
        Function f = program.getFunctionManager().getFunctionAt(builder.addr("0x401000"));
        assertNotNull(f, "Function should be created from disassembled bytes");

        // Verify real instructions exist
        Instruction first = program.getListing().getInstructionAt(builder.addr("0x401000"));
        assertNotNull(first);
        assertTrue(first.getMnemonicString().equalsIgnoreCase("ADDIU"));
    }

    @Test
    @DisplayName("Real listing iteration works")
    void testListingIteration() throws Exception {
        builder = new ProgramBuilder("test", GhidraTestEnv.LANG);
        builder.createMemory(".text", "0x401000", 0x1000);

        builder.createEmptyFunction("alpha", "0x401000", 0x10, DataType.DEFAULT);
        builder.createEmptyFunction("beta", "0x401020", 0x10, DataType.DEFAULT);
        builder.createEmptyFunction("gamma", "0x401040", 0x10, DataType.DEFAULT);

        ProgramDB program = builder.getProgram();
        FunctionIterator iter = program.getFunctionManager().getFunctions(true);

        List<String> names = new ArrayList<>();
        while (iter.hasNext()) {
            names.add(iter.next().getName());
        }

        assertEquals(List.of("alpha", "beta", "gamma"), names);
    }

    // --- Ghidra install detection (mirrors setup_ghidra_jars.sh logic) ---

    private static File findGhidraInstall() {
        // 1. Env var
        String envDir = System.getenv("GHIDRA_INSTALL_DIR");
        if (envDir != null) {
            File dir = new File(envDir);
            if (isGhidraInstall(dir)) return dir;
        }

        // 2. macOS .app bundle
        File macApp = new File("/Applications/Ghidra.app/Contents/app");
        if (isGhidraInstall(macApp)) return macApp;

        return null;
    }

    private static boolean isGhidraInstall(File dir) {
        return dir.isDirectory() && new File(dir, "Ghidra/Framework").isDirectory();
    }

    // --- Minimal ApplicationLayout ---

    static class TestApplicationLayout extends ApplicationLayout {
        TestApplicationLayout(File ghidraInstallDir) throws IOException {
            ResourceFile installDir = new ResourceFile(ghidraInstallDir);
            ResourceFile appRoot = new ResourceFile(installDir, "Ghidra");
            applicationRootDirs = List.of(appRoot);
            applicationProperties = new ApplicationProperties(applicationRootDirs);
            applicationInstallationDir = installDir;

            File tmpDir = Files.createTempDirectory("ghidramcp-test").toFile();
            tmpDir.deleteOnExit();
            userTempDir = tmpDir;
            userCacheDir = tmpDir;
            userSettingsDir = tmpDir;

            extensionArchiveDir = null;
            extensionInstallationDirs = List.of();
            patchDir = null;

            // Discover modules (Processors/x86, Framework/SoftwareModeling, etc.)
            Collection<ResourceFile> roots =
                ModuleUtilities.findModuleRootDirectories(applicationRootDirs);
            modules = ModuleUtilities.findModules(applicationRootDirs, roots);
        }
    }
}
