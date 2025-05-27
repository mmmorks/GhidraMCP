package com.lauriewired.mcp.api;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mock;
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
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Integration tests for API endpoints
 * Tests actual endpoint behavior with mocked services
 */
@ExtendWith(MockitoExtension.class)
public class ApiEndpointIntegrationTest {

    @Mock
    private McpServerManager mockServerManager;
    
    @Mock
    private FunctionService mockFunctionService;
    
    @Mock
    private NamespaceService mockNamespaceService;
    
    @Mock
    private DataTypeService mockDataTypeService;
    
    @Mock
    private AnalysisService mockAnalysisService;
    
    @Mock
    private CommentService mockCommentService;
    
    @Mock
    private MemoryService mockMemoryService;
    
    @Mock
    private ProgramService mockProgramService;
    
    @Mock
    private SearchService mockSearchService;
    
    @Mock
    private VariableService mockVariableService;
    
    @Mock
    private HttpServer mockServer;
    
    @Mock
    private HttpExchange mockExchange;
    
    @Mock
    private HttpContext mockContext;
    
    @Mock
    private Headers mockHeaders;
    
    private ApiHandlerRegistry apiHandlerRegistry;
    
    @BeforeEach
    @SuppressWarnings("unused")
    void setUp() {
        // Create registry with all services
        apiHandlerRegistry = new ApiHandlerRegistry(
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
        
        when(mockServerManager.isServerRunning()).thenReturn(true);
        when(mockServerManager.getServer()).thenReturn(mockServer);
        when(mockServer.createContext(any(String.class), any(HttpHandler.class))).thenReturn(mockContext);
    }
    
    // Memory Service Endpoints
    
    @Test
    @DisplayName("set_memory_data_type endpoint parses parameters correctly")
    void testSetMemoryDataTypeEndpoint_ParsesParameters() throws Exception {
        // Setup to capture the handler
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);
        
        // Register endpoints
        apiHandlerRegistry.registerAllEndpoints();
        
        // Capture the handler for set_memory_data_type
        verify(mockServer).createContext(eq("/set_memory_data_type"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();
        
        // Setup request body
        String requestBody = "address=0x1000&data_type=int&clear_existing=true";
        ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBody.getBytes());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        // Setup mock exchange
        when(mockExchange.getRequestURI()).thenReturn(URI.create("/set_memory_data_type"));
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        when(mockExchange.getRequestBody()).thenReturn(inputStream);
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestHeaders()).thenReturn(mockHeaders);
        when(mockHeaders.getFirst("Content-Type")).thenReturn("application/x-www-form-urlencoded");
        
        // Setup mock service response
        when(mockMemoryService.setMemoryDataType("0x1000", "int", true))
            .thenReturn("Data type 'int' (4 bytes) set at address 0x1000");
        
        // Invoke the handler
        handler.handle(mockExchange);
        
        // Verify the service was called with correct parameters
        verify(mockMemoryService).setMemoryDataType("0x1000", "int", true);
    }
    
    @Test
    @DisplayName("set_memory_data_type endpoint handles clear_existing=false")
    void testSetMemoryDataTypeEndpoint_ClearExistingFalse() throws Exception {
        // Setup to capture the handler
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);
        
        // Register endpoints
        apiHandlerRegistry.registerAllEndpoints();
        
        // Capture the handler
        verify(mockServer).createContext(eq("/set_memory_data_type"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();
        
        // Setup request body
        String requestBody = "address=0x2000&data_type=char[20]&clear_existing=false";
        ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBody.getBytes());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        // Setup mock exchange
        when(mockExchange.getRequestURI()).thenReturn(URI.create("/set_memory_data_type"));
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        when(mockExchange.getRequestBody()).thenReturn(inputStream);
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestHeaders()).thenReturn(mockHeaders);
        when(mockHeaders.getFirst("Content-Type")).thenReturn("application/x-www-form-urlencoded");
        
        // Setup mock service response
        when(mockMemoryService.setMemoryDataType("0x2000", "char[20]", false))
            .thenReturn("Data type 'char[20]' (20 bytes) set at address 0x2000");
        
        // Invoke the handler
        handler.handle(mockExchange);
        
        // Verify the service was called with correct parameters
        verify(mockMemoryService).setMemoryDataType("0x2000", "char[20]", false);
    }
    
    @Test
    @DisplayName("set_memory_data_type endpoint handles missing clear_existing parameter")
    void testSetMemoryDataTypeEndpoint_MissingClearExisting() throws Exception {
        // Setup to capture the handler
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);
        
        // Register endpoints
        apiHandlerRegistry.registerAllEndpoints();
        
        // Capture the handler
        verify(mockServer).createContext(eq("/set_memory_data_type"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();
        
        // Setup request body without clear_existing
        String requestBody = "address=0x3000&data_type=POINT";
        ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBody.getBytes());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        // Setup mock exchange
        when(mockExchange.getRequestURI()).thenReturn(URI.create("/set_memory_data_type"));
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        when(mockExchange.getRequestBody()).thenReturn(inputStream);
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestHeaders()).thenReturn(mockHeaders);
        when(mockHeaders.getFirst("Content-Type")).thenReturn("application/x-www-form-urlencoded");
        
        // Setup mock service response
        when(mockMemoryService.setMemoryDataType("0x3000", "POINT", false))
            .thenReturn("Data type 'POINT' (8 bytes) set at address 0x3000");
        
        // Invoke the handler
        handler.handle(mockExchange);
        
        // Verify the service was called with false as default
        verify(mockMemoryService).setMemoryDataType("0x3000", "POINT", false);
    }
}