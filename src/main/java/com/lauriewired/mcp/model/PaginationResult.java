package com.lauriewired.mcp.model;

/**
 * Represents a paginated result with metadata to help LLM agents understand pagination status
 */
public class PaginationResult {
    private final String content;
    private final int totalItems;
    private final int currentOffset;
    private final int currentLimit;
    private final boolean hasMoreResults;
    private final int nextOffset;
    private final String paginationHint;

    public PaginationResult(String content, int totalItems, int currentOffset, int currentLimit) {
        this.content = content;
        this.totalItems = totalItems;
        this.currentOffset = currentOffset;
        this.currentLimit = currentLimit;
        this.hasMoreResults = (currentOffset + currentLimit) < totalItems;
        this.nextOffset = hasMoreResults ? currentOffset + currentLimit : -1;
        this.paginationHint = buildPaginationHint();
    }

    private String buildPaginationHint() {
        StringBuilder hint = new StringBuilder();
        
        // Add pagination status information
        int itemsShown = Math.min(currentLimit, Math.max(0, totalItems - currentOffset));
        int startItem = currentOffset + 1;
        int endItem = currentOffset + itemsShown;
        
        hint.append(String.format("\n--- PAGINATION INFO ---\n"));
        hint.append(String.format("Showing items %d-%d of %d total items\n", 
            startItem, endItem, totalItems));
        
        if (hasMoreResults) {
            hint.append(String.format("⚠️  MORE RESULTS AVAILABLE! ⚠️\n"));
            hint.append(String.format("To see more results, call this API again with offset=%d&limit=%d\n", 
                nextOffset, currentLimit));
            hint.append(String.format("Remaining items: %d\n", totalItems - endItem));
            hint.append(String.format("IMPORTANT: You are only seeing a subset of results. Continue fetching to get complete data!\n"));
        } else {
            hint.append("✓ All results shown (no more pages)\n");
        }
        
        hint.append("--- END PAGINATION INFO ---");
        
        return hint.toString();
    }

    /**
     * Get the formatted result with pagination hints
     */
    public String getFormattedResult() {
        if (content == null || content.isEmpty()) {
            return hasMoreResults ? 
                "No results in this page, but more results may be available. Try different offset values." :
                "No results found.";
        }
        
        return content + paginationHint;
    }

    // Getters
    public String getContent() { return content; }
    public int getTotalItems() { return totalItems; }
    public int getCurrentOffset() { return currentOffset; }
    public int getCurrentLimit() { return currentLimit; }
    public boolean hasMoreResults() { return hasMoreResults; }
    public int getNextOffset() { return nextOffset; }
    public String getPaginationHint() { return paginationHint; }
}