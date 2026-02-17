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
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.ListOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.response.FunctionCodeResult;
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
    @DisplayName("set_address_data_type endpoint parses parameters correctly")
    void testSetMemoryDataTypeEndpoint_ParsesParameters() throws Exception {
        // Setup to capture the handler
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);
        
        // Register endpoints
        apiHandlerRegistry.registerAllEndpoints();
        
        // Capture the handler for set_address_data_type
        verify(mockServer).createContext(eq("/set_address_data_type"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();
        
        // Setup request body
        String requestBody = "address=0x1000&data_type=int&clear_existing=true";
        ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBody.getBytes());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        // Setup mock exchange
        when(mockExchange.getRequestURI()).thenReturn(URI.create("/set_address_data_type"));
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        when(mockExchange.getRequestBody()).thenReturn(inputStream);
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestHeaders()).thenReturn(mockHeaders);
        when(mockHeaders.getFirst("Content-Type")).thenReturn("application/x-www-form-urlencoded");
        
        // Setup mock service response
        when(mockMemoryService.setAddressDataType("0x1000", "int", true))
            .thenReturn(StatusOutput.ok("Data type 'int' (4 bytes) set at address 0x1000"));
        
        // Invoke the handler
        handler.handle(mockExchange);
        
        // Verify the service was called with correct parameters
        verify(mockMemoryService).setAddressDataType("0x1000", "int", true);
    }
    
    @Test
    @DisplayName("set_address_data_type endpoint handles clear_existing=false")
    void testSetMemoryDataTypeEndpoint_ClearExistingFalse() throws Exception {
        // Setup to capture the handler
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);
        
        // Register endpoints
        apiHandlerRegistry.registerAllEndpoints();
        
        // Capture the handler
        verify(mockServer).createContext(eq("/set_address_data_type"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();
        
        // Setup request body
        String requestBody = "address=0x2000&data_type=char[20]&clear_existing=false";
        ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBody.getBytes());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        // Setup mock exchange
        when(mockExchange.getRequestURI()).thenReturn(URI.create("/set_address_data_type"));
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        when(mockExchange.getRequestBody()).thenReturn(inputStream);
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestHeaders()).thenReturn(mockHeaders);
        when(mockHeaders.getFirst("Content-Type")).thenReturn("application/x-www-form-urlencoded");
        
        // Setup mock service response
        when(mockMemoryService.setAddressDataType("0x2000", "char[20]", false))
            .thenReturn(StatusOutput.ok("Data type 'char[20]' (20 bytes) set at address 0x2000"));
        
        // Invoke the handler
        handler.handle(mockExchange);
        
        // Verify the service was called with correct parameters
        verify(mockMemoryService).setAddressDataType("0x2000", "char[20]", false);
    }
    
    @Test
    @DisplayName("set_address_data_type endpoint handles missing clear_existing parameter")
    void testSetMemoryDataTypeEndpoint_MissingClearExisting() throws Exception {
        // Setup to capture the handler
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);
        
        // Register endpoints
        apiHandlerRegistry.registerAllEndpoints();
        
        // Capture the handler
        verify(mockServer).createContext(eq("/set_address_data_type"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();
        
        // Setup request body without clear_existing
        String requestBody = "address=0x3000&data_type=POINT";
        ByteArrayInputStream inputStream = new ByteArrayInputStream(requestBody.getBytes());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        // Setup mock exchange
        when(mockExchange.getRequestURI()).thenReturn(URI.create("/set_address_data_type"));
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        when(mockExchange.getRequestBody()).thenReturn(inputStream);
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestHeaders()).thenReturn(mockHeaders);
        when(mockHeaders.getFirst("Content-Type")).thenReturn("application/x-www-form-urlencoded");
        
        // Setup mock service response — default is false (backward compatible)
        when(mockMemoryService.setAddressDataType("0x3000", "POINT", false))
            .thenReturn(StatusOutput.ok("Data type 'POINT' (8 bytes) set at address 0x3000"));

        // Invoke the handler
        handler.handle(mockExchange);

        // Verify the service was called with false as default
        verify(mockMemoryService).setAddressDataType("0x3000", "POINT", false);
    }

    // GET Endpoint Tests

    @Test
    @DisplayName("GET endpoint parses query parameters correctly")
    void testGetEndpoint_QueryParams() throws Exception {
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);

        apiHandlerRegistry.registerAllEndpoints();

        verify(mockServer).createContext(eq("/get_function_code"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockExchange.getRequestURI()).thenReturn(
            URI.create("/get_function_code?function_identifier=main&mode=C"));
        when(mockExchange.getRequestMethod()).thenReturn("GET");
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);

        when(mockFunctionService.getFunctionCode("main", "C"))
            .thenReturn(new JsonOutput(new FunctionCodeResult("main", "C",
                java.util.List.of(new FunctionCodeResult.CodeLine(null, "int main(int argc, char **argv) { ... }", null)))));

        handler.handle(mockExchange);

        verify(mockFunctionService).getFunctionCode("main", "C");
    }

    @Test
    @DisplayName("GET endpoint uses default values for optional parameters")
    void testGetEndpoint_DefaultParams() throws Exception {
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);

        apiHandlerRegistry.registerAllEndpoints();

        verify(mockServer).createContext(eq("/get_function_code"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        // Only provide function_identifier, mode should default to "C"
        when(mockExchange.getRequestURI()).thenReturn(
            URI.create("/get_function_code?function_identifier=main"));
        when(mockExchange.getRequestMethod()).thenReturn("GET");
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);

        when(mockFunctionService.getFunctionCode("main", "C"))
            .thenReturn(new JsonOutput(new FunctionCodeResult("main", "C",
                java.util.List.of(new FunctionCodeResult.CodeLine(null, "int main() { ... }", null)))));

        handler.handle(mockExchange);

        verify(mockFunctionService).getFunctionCode("main", "C");
    }

    @Test
    @DisplayName("GET paginated endpoint respects offset and limit")
    void testGetEndpoint_Pagination() throws Exception {
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);

        apiHandlerRegistry.registerAllEndpoints();

        verify(mockServer).createContext(eq("/list_functions"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockExchange.getRequestURI()).thenReturn(
            URI.create("/list_functions?offset=10&limit=5"));
        when(mockExchange.getRequestMethod()).thenReturn("GET");
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);

        when(mockFunctionService.listFunctions(10, 5))
            .thenReturn(new ListOutput(java.util.List.of("func1", "func2", "func3"), 3, 10, 5));

        handler.handle(mockExchange);

        verify(mockFunctionService).listFunctions(10, 5);
    }

    // POST with JSON body tests

    @Test
    @DisplayName("POST endpoint with JSON body parses complex types")
    void testPostEndpoint_JsonBody() throws Exception {
        ArgumentCaptor<HttpHandler> handlerCaptor = ArgumentCaptor.forClass(HttpHandler.class);

        apiHandlerRegistry.registerAllEndpoints();

        verify(mockServer).createContext(eq("/rename_variables"), handlerCaptor.capture());
        HttpHandler handler = handlerCaptor.getValue();

        String jsonBody = "{\"function_identifier\":\"main\", \"renames\":{\"local_10\":\"buffer\", \"local_14\":\"size\"}}";
        ByteArrayInputStream inputStream = new ByteArrayInputStream(jsonBody.getBytes());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockExchange.getRequestURI()).thenReturn(URI.create("/rename_variables"));
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        when(mockExchange.getRequestBody()).thenReturn(inputStream);
        when(mockExchange.getResponseBody()).thenReturn(outputStream);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestHeaders()).thenReturn(mockHeaders);
        when(mockHeaders.getFirst("Content-Type")).thenReturn("application/json");

        java.util.Map<String, String> expectedRenames = new java.util.LinkedHashMap<>();
        expectedRenames.put("local_10", "buffer");
        expectedRenames.put("local_14", "size");

        when(mockVariableService.renameVariables("main", expectedRenames))
            .thenReturn(new JsonOutput(new com.lauriewired.mcp.model.response.RenameVariablesResult(
                "Variables renamed successfully", "main", expectedRenames, 2)));

        handler.handle(mockExchange);

        verify(mockVariableService).renameVariables("main", expectedRenames);
    }
}