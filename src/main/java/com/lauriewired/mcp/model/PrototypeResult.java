package com.lauriewired.mcp.model;

/**
 * Represents the result of a function prototype setting operation.
 */
public class PrototypeResult {
    private final boolean success;
    private final String errorMessage;
    
    /**
     * Creates a new PrototypeResult.
     *
     * @param success true if the prototype was set successfully, false otherwise
     * @param errorMessage detailed error message or warning information
     */
    public PrototypeResult(boolean success, String errorMessage) {
        this.success = success;
        this.errorMessage = errorMessage;
    }
    
    /**
     * Checks if the operation was successful.
     *
     * @return true if successful, false otherwise
     */
    public boolean isSuccess() {
        return success;
    }
    
    /**
     * Gets the error message or warning information.
     * May contain debug information even on success.
     *
     * @return the error message or empty string if none
     */
    public String getErrorMessage() {
        return errorMessage;
    }
}
