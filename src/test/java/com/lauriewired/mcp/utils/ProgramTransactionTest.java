package com.lauriewired.mcp.utils;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import ghidra.program.model.listing.Program;

/**
 * Unit tests for ProgramTransaction
 */
@ExtendWith(MockitoExtension.class)
public class ProgramTransactionTest {

    @Mock
    private Program mockProgram;

    private static final int TX_ID = 42;

    @BeforeEach
    void setUp() {
        when(mockProgram.startTransaction(anyString())).thenReturn(TX_ID);
    }

    @Test
    @DisplayName("commit() causes endTransaction with true, then flushEvents")
    void testCommitCallsEndTransactionTrueThenFlush() {
        try (var tx = ProgramTransaction.start(mockProgram, "test")) {
            tx.commit();
        }

        InOrder inOrder = inOrder(mockProgram);
        inOrder.verify(mockProgram).endTransaction(TX_ID, true);
        inOrder.verify(mockProgram).flushEvents();
    }

    @Test
    @DisplayName("No commit() causes endTransaction with false (rollback), then flushEvents")
    void testRollbackWhenNoCommit() {
        try (var tx = ProgramTransaction.start(mockProgram, "test")) {
            // no commit
        }

        InOrder inOrder = inOrder(mockProgram);
        inOrder.verify(mockProgram).endTransaction(TX_ID, false);
        inOrder.verify(mockProgram).flushEvents();
    }

    @Test
    @DisplayName("Exception before commit() causes rollback")
    void testExceptionCausesRollback() {
        assertThrows(RuntimeException.class, () -> {
            try (var tx = ProgramTransaction.start(mockProgram, "test")) {
                throw new RuntimeException("oops");
            }
        });

        verify(mockProgram).endTransaction(TX_ID, false);
        verify(mockProgram).flushEvents();
    }

    @Test
    @DisplayName("close() is idempotent - second call is a no-op")
    void testIdempotentClose() {
        var tx = ProgramTransaction.start(mockProgram, "test");
        tx.commit();
        tx.close();
        tx.close(); // second close should be a no-op

        verify(mockProgram, times(1)).endTransaction(anyInt(), anyBoolean());
        verify(mockProgram, times(1)).flushEvents();
    }

    @Test
    @DisplayName("flushEvents is called even if endTransaction throws")
    void testFlushEventsCalledEvenIfEndTransactionThrows() {
        doThrow(new RuntimeException("endTransaction failed"))
            .when(mockProgram).endTransaction(anyInt(), anyBoolean());

        assertThrows(RuntimeException.class, () -> {
            try (var tx = ProgramTransaction.start(mockProgram, "test")) {
                tx.commit();
            }
        });

        verify(mockProgram).flushEvents();
    }

    @Test
    @DisplayName("start() passes the transaction name to program.startTransaction()")
    void testTransactionNamePassed() {
        try (var tx = ProgramTransaction.start(mockProgram, "My Custom Name")) {
            // no-op
        }

        verify(mockProgram).startTransaction("My Custom Name");
    }

    @Test
    @DisplayName("commit can be called multiple times without issue")
    void testMultipleCommitCalls() {
        try (var tx = ProgramTransaction.start(mockProgram, "test")) {
            tx.commit();
            tx.commit(); // should not cause problems
        }

        verify(mockProgram).endTransaction(TX_ID, true);
    }
}
