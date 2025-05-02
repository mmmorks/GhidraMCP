package com.lauriewired.mcp.model;

/**
 * Represents the result of a function prototype setting operation.
 * 
 * @param success true if the prototype was set successfully, false otherwise
 * @param errorMessage detailed error message or warning information
 */
public record PrototypeResult(boolean success, String errorMessage) {
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
