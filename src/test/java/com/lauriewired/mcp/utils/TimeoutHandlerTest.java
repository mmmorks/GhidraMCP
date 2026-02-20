package com.lauriewired.mcp.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
 * Test class for TimeoutHandler.
 * Uses a fake {@link InstantSource} so that all timeout behavior is driven
 * by logical clock advances and {@link TimeoutHandler#wakeMonitor()} instead
 * of {@code Thread.sleep()}.
 */
public class TimeoutHandlerTest {

    /** Controllable clock for deterministic timeout testing. */
    private static class FakeClock implements InstantSource {
        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.EPOCH);

        @Override
        public Instant instant() {
            return now.get();
        }

        void advance(Duration duration) {
            now.updateAndGet(i -> i.plus(duration));
        }
    }

    @Mock
    private HttpExchange mockExchange;

    @Mock
    private Headers mockHeaders;

    private ByteArrayOutputStream responseBody;
    private TimeoutHandler timeoutHandler;
    private FakeClock fakeClock;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        responseBody = new ByteArrayOutputStream();
        when(mockExchange.getResponseBody()).thenReturn(responseBody);
        when(mockExchange.getResponseHeaders()).thenReturn(mockHeaders);
        when(mockExchange.getRequestURI()).thenReturn(new URI("/test"));

        fakeClock = new FakeClock();
    }

    @AfterEach
    void tearDown() {
        if (timeoutHandler != null) {
            timeoutHandler.shutdown();
            timeoutHandler = null;
        }
    }

    @Test
    @DisplayName("Normal GET request completes within timeout")
    void testNormalGetRequestCompletesWithinTimeout() throws Exception {
        HttpHandler quickHandler = exchange -> HttpUtils.sendResponse(exchange, "Quick response");

        timeoutHandler = new TimeoutHandler(5, fakeClock);
        timeoutHandler.start();
        HttpHandler wrappedHandler = timeoutHandler.wrap(quickHandler);
        when(mockExchange.getRequestMethod()).thenReturn("GET");

        wrappedHandler.handle(mockExchange);

        String expectedJson = "{\"status\":\"success\",\"data\":\"Quick response\"}";
        verify(mockExchange).sendResponseHeaders(eq(200), eq((long) expectedJson.getBytes("UTF-8").length));
        assertEquals(expectedJson, responseBody.toString("UTF-8"));
    }

    @Test
    @DisplayName("GET request times out when handler takes too long")
    void testGetRequestTimesOut() throws Exception {
        AtomicBoolean handlerStarted = new AtomicBoolean(false);
        AtomicBoolean handlerCompleted = new AtomicBoolean(false);
        AtomicBoolean handlerInterrupted = new AtomicBoolean(false);
        CountDownLatch handlerRunning = new CountDownLatch(1);

        HttpHandler slowHandler = exchange -> {
            handlerStarted.set(true);
            handlerRunning.countDown();
            try {
                // Block until interrupted by the timeout — not actually waited
                Thread.sleep(60_000);
                handlerCompleted.set(true);
                HttpUtils.sendResponse(exchange, "Should not see this");
            } catch (InterruptedException e) {
                handlerInterrupted.set(true);
            } catch (IOException e) {
                // Exchange may be closed by timeout
            }
        };

        timeoutHandler = new TimeoutHandler(1, fakeClock);
        timeoutHandler.start();
        HttpHandler wrappedHandler = timeoutHandler.wrap(slowHandler);
        when(mockExchange.getRequestMethod()).thenReturn("GET");

        Thread handlerThread = new Thread(() -> {
            try {
                wrappedHandler.handle(mockExchange);
            } catch (IOException e) {
                // Expected
            }
        });
        handlerThread.start();

        // Wait for the handler to be blocking inside the delegate
        assertTrue(handlerRunning.await(1, TimeUnit.SECONDS), "Handler should have started");

        // Advance the fake clock past the 1-second timeout and wake the monitor
        fakeClock.advance(Duration.ofSeconds(2));
        timeoutHandler.wakeMonitor();

        handlerThread.join(1000);
        assertFalse(handlerThread.isAlive(), "Handler thread should have completed after being interrupted");
        assertTrue(handlerStarted.get(), "Handler should have started");
        assertTrue(handlerInterrupted.get(), "Handler should have been interrupted");
        assertFalse(handlerCompleted.get(), "Handler should not have completed normally");
    }

    @Test
    @DisplayName("POST request is not subject to timeout")
    void testPostRequestNotSubjectToTimeout() throws Exception {
        HttpHandler handler = exchange -> HttpUtils.sendResponse(exchange, "POST completed");

        timeoutHandler = new TimeoutHandler(1, fakeClock);
        timeoutHandler.start();
        HttpHandler wrappedHandler = timeoutHandler.wrap(handler);
        when(mockExchange.getRequestMethod()).thenReturn("POST");

        // Even with the clock advanced past the deadline, POST completes normally
        fakeClock.advance(Duration.ofSeconds(5));
        wrappedHandler.handle(mockExchange);

        String expectedJson = "{\"status\":\"success\",\"data\":\"POST completed\"}";
        verify(mockExchange).sendResponseHeaders(eq(200), eq((long) expectedJson.getBytes("UTF-8").length));
        assertEquals(expectedJson, responseBody.toString("UTF-8"));
    }

    @Test
    @DisplayName("Handler IOException is propagated correctly")
    void testHandlerThrowsIOException() throws Exception {
        HttpHandler errorHandler = exchange -> {
            throw new IOException("Test IO error");
        };

        timeoutHandler = new TimeoutHandler(5, fakeClock);
        timeoutHandler.start();
        HttpHandler wrappedHandler = timeoutHandler.wrap(errorHandler);
        when(mockExchange.getRequestMethod()).thenReturn("GET");

        assertThrows(IOException.class, () -> wrappedHandler.handle(mockExchange));
    }

    @Test
    @DisplayName("Handler RuntimeException results in 500 error")
    void testHandlerThrowsRuntimeException() throws Exception {
        HttpHandler errorHandler = exchange -> {
            throw new RuntimeException("Test runtime error");
        };

        timeoutHandler = new TimeoutHandler(5, fakeClock);
        timeoutHandler.start();
        HttpHandler wrappedHandler = timeoutHandler.wrap(errorHandler);
        when(mockExchange.getRequestMethod()).thenReturn("GET");

        wrappedHandler.handle(mockExchange);

        verify(mockExchange).sendResponseHeaders(eq(500), anyLong());
        String responseStr = responseBody.toString("UTF-8");
        assertTrue(responseStr.contains("\"status\":\"error\""), "Response should be JSON error envelope");
        assertTrue(responseStr.contains("Internal server error"), "Response should contain error message");
    }

    @Test
    @DisplayName("Multiple concurrent requests are handled correctly")
    void testMultipleConcurrentRequests() throws Exception {
        CountDownLatch allStarted = new CountDownLatch(3);
        CountDownLatch quickGo = new CountDownLatch(1);
        CountDownLatch mediumGo = new CountDownLatch(1);
        AtomicInteger completedCount = new AtomicInteger(0);

        HttpHandler handler = exchange -> {
            allStarted.countDown();
            String path = exchange.getRequestURI().getPath();
            try {
                if (path.contains("quick")) {
                    quickGo.await();
                    HttpUtils.sendResponse(exchange, "Quick");
                    completedCount.incrementAndGet();
                } else if (path.contains("medium")) {
                    mediumGo.await();
                    HttpUtils.sendResponse(exchange, "Medium");
                    completedCount.incrementAndGet();
                } else {
                    // Block until interrupted by the timeout
                    Thread.sleep(60_000);
                    HttpUtils.sendResponse(exchange, "Slow");
                    completedCount.incrementAndGet();
                }
            } catch (InterruptedException | IOException e) {
                // Expected for timeout or closed exchange
            }
        };

        timeoutHandler = new TimeoutHandler(1, fakeClock);
        timeoutHandler.start();
        HttpHandler wrappedHandler = timeoutHandler.wrap(handler);

        HttpExchange quickExchange = createMockExchange("/quick");
        HttpExchange mediumExchange = createMockExchange("/medium");
        HttpExchange slowExchange = createMockExchange("/slow");

        Thread t1 = new Thread(() -> {
            try { wrappedHandler.handle(quickExchange); } catch (IOException e) { /* ignored */ }
        });
        Thread t2 = new Thread(() -> {
            try { wrappedHandler.handle(mediumExchange); } catch (IOException e) { /* ignored */ }
        });
        Thread t3 = new Thread(() -> {
            try { wrappedHandler.handle(slowExchange); } catch (IOException e) { /* ignored */ }
        });

        t1.start();
        t2.start();
        t3.start();

        // Wait for all handlers to start
        assertTrue(allStarted.await(1, TimeUnit.SECONDS), "All requests should start");

        // Release quick and medium so they complete successfully
        quickGo.countDown();
        mediumGo.countDown();
        t1.join(1000);
        t2.join(1000);

        // Advance clock past timeout and wake monitor to interrupt the slow request
        fakeClock.advance(Duration.ofSeconds(2));
        timeoutHandler.wakeMonitor();

        t3.join(1000);
        assertFalse(t3.isAlive(), "Slow thread should have been interrupted");
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
