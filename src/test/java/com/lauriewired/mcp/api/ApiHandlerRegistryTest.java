package com.lauriewired.mcp.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lauriewired.mcp.McpServerManager;
import com.lauriewired.mcp.services.AnalysisService;
import com.lauriewired.mcp.services.CommentService;
import com.lauriewired.mcp.services.DataTypeService;
import com.lauriewired.mcp.services.FunctionService;
import com.lauriewired.mcp.services.MemoryService;
import com.lauriewired.mcp.services.NamespaceService;
import com.lauriewired.mcp.services.ProgramService;
import com.lauriewired.mcp.services.SearchService;
import com.lauriewired.mcp.services.VariableService;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

@ExtendWith(MockitoExtension.class)
class ApiHandlerRegistryTest {

    @Mock
    private McpServerManager mockServerManager;
    
    @Mock
    private HttpServer mockHttpServer;
    
    @Mock
    private FunctionService mockFunctionService;
    
    @Mock
    private NamespaceService mockNamespaceService;
    
    @Mock
    private DataTypeService mockDataTypeService;
    
    @Mock
    private AnalysisService mockAnalysisService;
    
    @Mock
    private MemoryService mockMemoryService;
    
    @Mock
    private CommentService mockCommentService;
    
    @Mock
    private ProgramService mockProgramService;
    
    @Mock
    private SearchService mockSearchService;
    
    @Mock
    private VariableService mockVariableService;
    
    @Mock
    private HttpContext mockHttpContext;

    private ApiHandlerRegistry registry;

    @BeforeEach
    @SuppressWarnings("unused")
    void setUp() {
        registry = new ApiHandlerRegistry(
            mockServerManager,
            mockFunctionService,
            mockNamespaceService,
            mockDataTypeService,
            mockAnalysisService,
            mockCommentService,
            mockMemoryService,
            mockProgramService,
            mockSearchService,
            mockVariableService
        );
    }

    @Test
    void testConstructor_AcceptsParameters() {
        // Test that constructor accepts all required parameters
        assertNotNull(registry);
        
        // Verify the registry was created successfully
        ApiHandlerRegistry testRegistry = new ApiHandlerRegistry(
            mockServerManager,
            mockFunctionService,
            mockNamespaceService,
            mockDataTypeService,
            mockAnalysisService,
            mockCommentService,
            mockMemoryService,
            mockProgramService,
            mockSearchService,
            mockVariableService
        );
        assertNotNull(testRegistry);
    }

    @Test
    void testRegisterAllEndpoints() {
        // Setup mock to return the HTTP server
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        // Call the method
        registry.registerAllEndpoints();

        // Verify that all expected endpoints were registered
        // Function endpoints - using new standardized names
        verify(mockHttpServer).createContext(eq("/list_methods"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/decompile_function"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/rename_function"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_function_by_address"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_current_address"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_current_function"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_functions"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/decompile_function_by_address"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/disassemble_function"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/rename_function_by_address"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/search_functions_by_name"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_function_prototype"), any(HttpHandler.class));

        // Namespace endpoints
        verify(mockHttpServer).createContext(eq("/list_classes"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_namespaces"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_symbols"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_imports"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_exports"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/get_symbol_address"), any(HttpHandler.class));

        // DataType endpoints
        verify(mockHttpServer).createContext(eq("/list_structures"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/rename_structure"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/rename_struct_field"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/create_structure"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/add_structure_field"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/create_enum"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/add_enum_value"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_enums"), any(HttpHandler.class));

        // Analysis endpoints
        verify(mockHttpServer).createContext(eq("/list_references"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/analyze_control_flow"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/analyze_data_flow"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/analyze_call_graph"), any(HttpHandler.class));

        // Memory endpoints
        verify(mockHttpServer).createContext(eq("/list_segments"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/list_data_items"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/rename_data"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_memory_data_type"), any(HttpHandler.class));

        // Comment endpoints
        verify(mockHttpServer).createContext(eq("/set_decompiler_comment"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_disassembly_comment"), any(HttpHandler.class));
        
        // Search endpoints
        verify(mockHttpServer).createContext(eq("/search_memory"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/search_disassembly"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/search_decompiled"), any(HttpHandler.class));
        
        // Variable endpoints
        verify(mockHttpServer).createContext(eq("/rename_variable"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/split_variable"), any(HttpHandler.class));
        verify(mockHttpServer).createContext(eq("/set_local_variable_type"), any(HttpHandler.class));
    }

    @Test
    void testRegisterAllEndpoints_HandlesNullServer() {
        // Setup mock to return false for isServerRunning
        when(mockServerManager.isServerRunning()).thenReturn(false);

        // Should not throw, but handle gracefully
        assertDoesNotThrow(() -> registry.registerAllEndpoints());
        
        // Verify isServerRunning was called but getServer was not
        verify(mockServerManager).isServerRunning();
        verify(mockServerManager, never()).getServer();
    }

    @Test
    void testEndpointCount() {
        // Setup mock to return the HTTP server
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockHttpServer);
        when(mockHttpServer.createContext(anyString(), any(HttpHandler.class)))
            .thenReturn(mockHttpContext);

        registry.registerAllEndpoints();

        // Verify the expected number of endpoints were registered
        // Updated to 55 after adding rename_structure endpoint
        verify(mockHttpServer, times(55)).createContext(anyString(), any(HttpHandler.class));
    }
}