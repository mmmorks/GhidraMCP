package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collection;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.database.ProgramBuilder;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Program;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * Shared Ghidra bootstrap for ProgramBuilder-based integration tests.
 *
 * Call {@link #initialize()} from a {@code @BeforeAll} method. The first call
 * boots the Ghidra application; subsequent calls are a no-op because
 * {@code Application.isInitialized()} returns true.
 *
 * If no Ghidra installation is found, JUnit's {@code assumeTrue} skips the
 * test class gracefully.
 */
public final class GhidraTestEnv {
    /** Shared language ID for all ProgramBuilder-based tests. */
    public static final String LANG = ProgramBuilder._MIPS;

    private GhidraTestEnv() {}

    /** Boot Ghidra headlessly; skips via assumption if no install is found. */
    public static synchronized void initialize() {
        File installDir = findGhidraInstall();
        assumeTrue(installDir != null,
            "Skipping: no Ghidra installation found (set GHIDRA_INSTALL_DIR)");

        if (!Application.isInitialized()) {
            try {
                Application.initializeApplication(
                    new TestLayout(installDir),
                    new HeadlessGhidraApplicationConfiguration());
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize Ghidra application", e);
            }
        }
    }

    /** Simple ProgramService that wraps a Program directly (no PluginTool). */
    static ProgramService programService(Program program) {
        return new ProgramService(null) {
            @Override
            public Program getCurrentProgram() {
                return program;
            }
        };
    }

    // --- Ghidra install detection ---

    private static File findGhidraInstall() {
        String envDir = System.getenv("GHIDRA_INSTALL_DIR");
        if (envDir != null) {
            File dir = new File(envDir);
            if (isGhidraInstall(dir)) return dir;
        }
        File macApp = new File("/Applications/Ghidra.app/Contents/app");
        if (isGhidraInstall(macApp)) return macApp;
        return null;
    }

    private static boolean isGhidraInstall(File dir) {
        return dir.isDirectory() && new File(dir, "Ghidra/Framework").isDirectory();
    }

    // --- Minimal ApplicationLayout ---

    static class TestLayout extends ApplicationLayout {
        TestLayout(File ghidraInstallDir) throws IOException {
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

            Collection<ResourceFile> roots =
                ModuleUtilities.findModuleRootDirectories(applicationRootDirs);
            modules = ModuleUtilities.findModules(applicationRootDirs, roots);
        }
    }
}
