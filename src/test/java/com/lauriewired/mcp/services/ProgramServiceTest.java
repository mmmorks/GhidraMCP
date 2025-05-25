package com.lauriewired.mcp.services;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

/**
 * Unit tests for ProgramService with mocked Ghidra components
 */
@ExtendWith(MockitoExtension.class)
public class ProgramServiceTest {

    @Mock
    private MockablePluginTool mockTool;
    
    @Mock
    private ProgramManager mockProgramManager;
    
    @Mock
    private Program mockProgram;
    
    private TestProgramService programService;

    @BeforeEach
    void setUp() {
        // Default setup - tests can override as needed
        programService = new TestProgramService(mockTool);
    }

    @Test
    @DisplayName("getCurrentProgram returns null when tool is null")
    void testGetCurrentProgram_NullTool() {
        programService = new TestProgramService((MockablePluginTool) null);
        Program result = programService.getCurrentProgram();
        assertNull(result);
    }

    @Test
    @DisplayName("Constructor accepts null tool without throwing")
    void testConstructor_NullTool() {
        assertDoesNotThrow(() -> new TestProgramService((MockablePluginTool) null));
    }
    
    @Test
    @DisplayName("getCurrentProgram returns null when ProgramManager service is not available")
    void testGetCurrentProgram_NoProgramManagerService() {
        // Mock tool returns null for ProgramManager service
        when(mockTool.getService(ProgramManager.class)).thenReturn(null);
        
        Program result = programService.getCurrentProgram();
        
        assertNull(result);
        verify(mockTool).getService(ProgramManager.class);
    }
    
    @Test
    @DisplayName("getCurrentProgram returns null when no program is loaded in ProgramManager")
    void testGetCurrentProgram_NoProgramLoaded() {
        // Mock tool returns ProgramManager
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        // Mock ProgramManager returns null for current program
        when(mockProgramManager.getCurrentProgram()).thenReturn(null);
        
        Program result = programService.getCurrentProgram();
        
        assertNull(result);
        verify(mockTool).getService(ProgramManager.class);
        verify(mockProgramManager).getCurrentProgram();
    }
    
    @Test
    @DisplayName("getCurrentProgram successfully returns the current program")
    void testGetCurrentProgram_Success() {
        // Mock tool returns ProgramManager
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        // Mock ProgramManager returns a program
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        Program result = programService.getCurrentProgram();
        
        assertNotNull(result);
        assertEquals(mockProgram, result);
        verify(mockTool).getService(ProgramManager.class);
        verify(mockProgramManager).getCurrentProgram();
    }
    
    @Test
    @DisplayName("getCurrentProgram can be called multiple times")
    void testGetCurrentProgram_MultipleCalls() {
        // Mock tool returns ProgramManager
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        // Mock ProgramManager returns a program
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        // Call multiple times
        Program result1 = programService.getCurrentProgram();
        Program result2 = programService.getCurrentProgram();
        Program result3 = programService.getCurrentProgram();
        
        // All calls should return the same program
        assertNotNull(result1);
        assertNotNull(result2);
        assertNotNull(result3);
        assertEquals(mockProgram, result1);
        assertEquals(mockProgram, result2);
        assertEquals(mockProgram, result3);
        
        // Verify the service was called each time
        verify(mockTool, times(3)).getService(ProgramManager.class);
        verify(mockProgramManager, times(3)).getCurrentProgram();
    }
    
    @Test
    @DisplayName("getCurrentProgram handles program change correctly")
    void testGetCurrentProgram_ProgramChange() {
        // Create a second mock program
        Program mockProgram2 = mock(Program.class);
        
        // Mock tool returns ProgramManager
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        
        // First call returns first program
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        Program result1 = programService.getCurrentProgram();
        assertEquals(mockProgram, result1);
        
        // Simulate program change - now returns second program
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram2);
        Program result2 = programService.getCurrentProgram();
        assertEquals(mockProgram2, result2);
        
        // Verify interactions
        verify(mockTool, times(2)).getService(ProgramManager.class);
        verify(mockProgramManager, times(2)).getCurrentProgram();
    }
    
    @Test
    @DisplayName("ProgramService can be used with different MockablePluginTool instances")
    void testProgramService_DifferentTools() {
        // Create second mock tool and program manager
        MockablePluginTool mockTool2 = mock(MockablePluginTool.class);
        ProgramManager mockProgramManager2 = mock(ProgramManager.class);
        Program mockProgram2 = mock(Program.class);
        
        // Setup first tool
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        
        // Setup second tool
        when(mockTool2.getService(ProgramManager.class)).thenReturn(mockProgramManager2);
        when(mockProgramManager2.getCurrentProgram()).thenReturn(mockProgram2);
        
        // Create two ProgramService instances
        TestProgramService service1 = new TestProgramService(mockTool);
        TestProgramService service2 = new TestProgramService(mockTool2);
        
        // Each should return their respective programs
        assertEquals(mockProgram, service1.getCurrentProgram());
        assertEquals(mockProgram2, service2.getCurrentProgram());
        
        // Verify each tool was called
        verify(mockTool).getService(ProgramManager.class);
        verify(mockTool2).getService(ProgramManager.class);
    }
    
    @Test
    @DisplayName("TestProgramService works with real PluginTool constructor")
    void testProgramService_RealPluginToolConstructor() {
        // This tests that the TestProgramService(PluginTool) constructor works
        // We can't mock PluginTool, but we can pass null
        TestProgramService service = new TestProgramService((PluginTool) null);
        
        Program result = service.getCurrentProgram();
        assertNull(result);
    }
}
