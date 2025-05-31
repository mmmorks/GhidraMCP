package com.lauriewired.mcp.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.MockitoAnnotations;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

/**
 * Test class for TimeoutHandler
 */
public class TimeoutHandlerTest {
    
    @Mock
    private HttpExchange mockExchange;
    
    @Mock
    private Headers mockHeaders;
    
    private ByteArrayOutputStream responseBody;
    private TimeoutHandler timeoutHandler;
    
    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        
        // Setup mock exchange
        responseBody = new ByteArrayOutputStream();
        when(mockExchange.getResponseBody()).thenReturn(responseBody);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestURI()).thenReturn(new URI("/test"));
    }
    
    @AfterEach
    void tearDown() {
        // Shutdown the timeout handler if created
        if (timeoutHandler != null) {
            timeoutHandler.shutdown();
            timeoutHandler = null;
        }
    }
    
    @Test
    @DisplayName("Normal GET request completes within timeout")
    void testNormalGetRequestCompletesWithinTimeout() throws Exception {
        // Create a handler that completes quickly
        HttpHandler quickHandler = exchange -> {
            HttpUtils.sendResponse(exchange, "Quick response");
        };
        
        timeoutHandler = new TimeoutHandler(5); // 5 second timeout
        timeoutHandler.start(); // Start the monitor thread
        HttpHandler wrappedHandler = timeoutHandler.wrap(quickHandler);
        when(mockExchange.getRequestMethod()).thenReturn("GET");
        
        // Execute
        wrappedHandler.handle(mockExchange);
        
        // Verify normal response was sent
        verify(mockExchange).sendResponseHeaders(eq(200), eq(14L)); // "Quick response".length()
        assertEquals("Quick response", responseBody.toString("UTF-8"));
    }
    
    @Test
    @DisplayName("GET request times out when handler takes too long")
    void testGetRequestTimesOut() throws Exception {
        // Create a handler that takes too long
        AtomicBoolean handlerStarted = new AtomicBoolean(false);
        AtomicBoolean handlerCompleted = new AtomicBoolean(false);
        AtomicBoolean handlerInterrupted = new AtomicBoolean(false);
        
        HttpHandler slowHandler = exchange -> {
            handlerStarted.set(true);
            try {
                Thread.sleep(3000); // Sleep for 3 seconds
                handlerCompleted.set(true);
                HttpUtils.sendResponse(exchange, "Should not see this");
            } catch (InterruptedException e) {
                // This is expected when the timeout occurs
                handlerInterrupted.set(true);
            } catch (IOException e) {
                // This might happen if the exchange is closed
            }
        };
        
        timeoutHandler = new TimeoutHandler(1); // 1 second timeout
        timeoutHandler.start(); // Start the monitor thread
        HttpHandler wrappedHandler = timeoutHandler.wrap(slowHandler);
        when(mockExchange.getRequestMethod()).thenReturn("GET");
        
        // Execute in a separate thread since it will block
        Thread handlerThread = new Thread(() -> {
            try {
                wrappedHandler.handle(mockExchange);
            } catch (IOException e) {
                // Expected
            }
        });
        
        handlerThread.start();
        
        // Wait a bit to ensure the handler starts
        Thread.sleep(100);
        assertTrue(handlerStarted.get(), "Handler should have started");
        
        // Wait for timeout to occur and handler to be interrupted
        Thread.sleep(1500);
        
        // The handler thread should have been interrupted and completed
        handlerThread.join(1000);
        assertFalse(handlerThread.isAlive(), "Handler thread should have completed after being interrupted");
        
        // Verify the handler was interrupted but didn't complete normally
        assertTrue(handlerInterrupted.get(), "Handler should have been interrupted");
        assertFalse(handlerCompleted.get(), "Handler should not have completed normally");
    }
    
    @Test
    @DisplayName("POST request is not subject to timeout")
    void testPostRequestNotSubjectToTimeout() throws Exception {
        // Create a handler that takes a while
        HttpHandler slowHandler = exchange -> {
            try {
                Thread.sleep(2000); // Sleep for 2 seconds
                HttpUtils.sendResponse(exchange, "POST completed");
            } catch (InterruptedException e) {
                fail("POST request should not be interrupted");
            }
        };
        
        timeoutHandler = new TimeoutHandler(1); // 1 second timeout
        timeoutHandler.start(); // Start the monitor thread
        HttpHandler wrappedHandler = timeoutHandler.wrap(slowHandler);
        when(mockExchange.getRequestMethod()).thenReturn("POST");
        
        // Execute
        wrappedHandler.handle(mockExchange);
        
        // Verify normal response was sent (not timeout)
        verify(mockExchange).sendResponseHeaders(eq(200), eq(14L)); // "POST completed".length()
        assertEquals("POST completed", responseBody.toString("UTF-8"));
    }
    
    @Test
    @DisplayName("Handler IOException is propagated correctly")
    void testHandlerThrowsIOException() throws Exception {
        // Create a handler that throws IOException
        HttpHandler errorHandler = exchange -> {
            throw new IOException("Test IO error");
        };
        
        timeoutHandler = new TimeoutHandler(5);
        timeoutHandler.start(); // Start the monitor thread
        HttpHandler wrappedHandler = timeoutHandler.wrap(errorHandler);
        when(mockExchange.getRequestMethod()).thenReturn("GET");
        
        // Execute and expect IOException to be propagated
        assertThrows(IOException.class, () -> wrappedHandler.handle(mockExchange));
    }
    
    @Test
    @DisplayName("Handler RuntimeException results in 500 error")
    void testHandlerThrowsRuntimeException() throws Exception {
        // Create a handler that throws RuntimeException
        HttpHandler errorHandler = exchange -> {
            throw new RuntimeException("Test runtime error");
        };
        
        timeoutHandler = new TimeoutHandler(5);
        timeoutHandler.start(); // Start the monitor thread
        HttpHandler wrappedHandler = timeoutHandler.wrap(errorHandler);
        when(mockExchange.getRequestMethod()).thenReturn("GET");
        
        // Execute
        wrappedHandler.handle(mockExchange);
        
        // Verify error response was sent
        verify(mockExchange).sendResponseHeaders(eq(500), anyLong()); // 500 Internal Server Error
        assertEquals("Internal server error", responseBody.toString("UTF-8"));
    }
    
    @Test
    @DisplayName("Multiple concurrent requests are handled correctly")
    void testMultipleConcurrentRequests() throws Exception {
        // Create handlers with different execution times
        CountDownLatch startLatch = new CountDownLatch(3);
        AtomicInteger completedCount = new AtomicInteger(0);
        
        HttpHandler handler = exchange -> {
            startLatch.countDown();
            String path = exchange.getRequestURI().getPath();
            try {
                if (path.contains("quick")) {
                    Thread.sleep(100);
                    HttpUtils.sendResponse(exchange, "Quick");
                    completedCount.incrementAndGet();
                } else if (path.contains("medium")) {
                    Thread.sleep(500);
                    HttpUtils.sendResponse(exchange, "Medium");
                    completedCount.incrementAndGet();
                } else {
                    Thread.sleep(2000); // This one will timeout
                    HttpUtils.sendResponse(exchange, "Slow");
                    completedCount.incrementAndGet();
                }
            } catch (InterruptedException | IOException e) {
                // Expected for timeout or closed exchange
            }
        };
        
        timeoutHandler = new TimeoutHandler(1); // 1 second timeout
        timeoutHandler.start(); // Start the monitor thread
        HttpHandler wrappedQuick = timeoutHandler.wrap(handler);
        HttpHandler wrappedMedium = timeoutHandler.wrap(handler);
        HttpHandler wrappedSlow = timeoutHandler.wrap(handler);
        
        // Create mock exchanges for each request
        HttpExchange quickExchange = createMockExchange("/quick");
        HttpExchange mediumExchange = createMockExchange("/medium");
        HttpExchange slowExchange = createMockExchange("/slow");
        
        // Execute requests concurrently
        Thread t1 = new Thread(() -> {
            try {
                wrappedQuick.handle(quickExchange);
            } catch (IOException e) {
                // Ignore
            }
        });
        
        Thread t2 = new Thread(() -> {
            try {
                wrappedMedium.handle(mediumExchange);
            } catch (IOException e) {
                // Ignore
            }
        });
        
        Thread t3 = new Thread(() -> {
            try {
                wrappedSlow.handle(slowExchange);
            } catch (IOException e) {
                // Ignore
            }
        });
        
        t1.start();
        t2.start();
        t3.start();
        
        // Wait for all to start
        assertTrue(startLatch.await(2, TimeUnit.SECONDS), "All requests should start");
        
        // Wait for completion with some buffer
        t1.join(3000);
        t2.join(3000);
        
        // The slow request thread might still be running
        t3.interrupt();
        t3.join(1000);
        
        // Verify only 2 completed normally
        assertEquals(2, completedCount.get(), "Only quick and medium should complete");
    }
    
    private HttpExchange createMockExchange(String path) throws Exception {
        HttpExchange exchange = mock(HttpExchange.class);
        Headers headers = mock(Headers.class);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        
        when(exchange.getResponseBody()).thenReturn(body);
        when(exchange.getResponseHeaders()).thenReturn(headers);
        when(exchange.getRequestURI()).thenReturn(new URI(path));
        when(exchange.getRequestMethod()).thenReturn("GET");
        
        return exchange;
    }
}