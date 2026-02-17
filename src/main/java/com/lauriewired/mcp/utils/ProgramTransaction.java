package com.lauriewired.mcp.utils;

import ghidra.program.model.listing.Program;

/**
 * AutoCloseable wrapper for Ghidra program transactions.
 * Ensures that {@code endTransaction()} and {@code flushEvents()} are always
 * called together, preventing Ghidra's "Open Transactions" dialog on exit.
 *
 * <p>Usage:
 * <pre>{@code
 * try (var tx = ProgramTransaction.start(program, "Rename function")) {
 *     // ... do work ...
 *     tx.commit();
 * }
 * }</pre>
 *
 * <p>If {@link #commit()} is not called before close, the transaction is rolled back.
 */
public class ProgramTransaction implements AutoCloseable {

    private final Program program;
    private final int transactionId;
    private boolean commitRequested;
    private boolean closed;

    private ProgramTransaction(final Program program, final int transactionId) {
        this.program = program;
        this.transactionId = transactionId;
    }

    /**
     * Start a new transaction on the given program.
     *
     * @param program the Ghidra program (must not be null)
     * @param name    human-readable transaction name for undo history
     * @return a new {@code ProgramTransaction} that must be closed
     */
    public static ProgramTransaction start(final Program program, final String name) {
        final int id = program.startTransaction(name);
        return new ProgramTransaction(program, id);
    }

    /**
     * Mark this transaction for commit. If this method is never called,
     * the transaction will be rolled back when closed.
     */
    public void commit() {
        commitRequested = true;
    }

    /**
     * End the transaction and flush domain object events.
     * This method is idempotent — subsequent calls are no-ops.
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            program.endTransaction(transactionId, commitRequested);
        } finally {
            program.flushEvents();
        }
    }
}
