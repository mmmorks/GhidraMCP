package com.lauriewired.test;

import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;

import ghidra.util.ErrorLogger;
import ghidra.util.Msg;

/**
 * Installs a no-op ErrorLogger on Ghidra's Msg class before any test runs.
 *
 * Before Application.initializeApplication() is called, Msg uses DefaultErrorLogger
 * which writes directly to System.err. This listener replaces it with a silent
 * implementation so pre-init Msg.warn/error calls don't pollute test output.
 *
 * Once a ProgramBuilder test calls Application.initializeApplication(), Ghidra
 * replaces this logger with Log4jErrorLogger — which is then silenced by
 * log4j2-test.xml (Root level OFF).
 */
public class QuietGhidraLoggingListener implements LauncherSessionListener {

    @Override
    public void launcherSessionOpened(LauncherSession session) {
        Msg.setErrorLogger(new NoOpErrorLogger());
    }

    private static final class NoOpErrorLogger implements ErrorLogger {
        @Override public void trace(Object o, Object msg) {}
        @Override public void trace(Object o, Object msg, Throwable t) {}
        @Override public void debug(Object o, Object msg) {}
        @Override public void debug(Object o, Object msg, Throwable t) {}
        @Override public void info(Object o, Object msg) {}
        @Override public void info(Object o, Object msg, Throwable t) {}
        @Override public void warn(Object o, Object msg) {}
        @Override public void warn(Object o, Object msg, Throwable t) {}
        @Override public void error(Object o, Object msg) {}
        @Override public void error(Object o, Object msg, Throwable t) {}
    }
}
