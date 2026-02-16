package com.lauriewired.mcp.model;

import java.util.List;

import com.lauriewired.mcp.utils.HttpUtils;

/**
 * Output for tools that return paginated lists of items.
 */
public record ListOutput(List<String> items, int totalItems, int offset, int limit) implements ToolOutput {

    /** Whether more results are available beyond the current page. */
    public boolean hasMore() {
        return (offset + limit) < totalItems;
    }

    /**
     * Factory method that slices a full list into a paginated ListOutput.
     * Replaces the HttpUtils.paginateListWithHints() + PaginationResult.getFormattedResult() pattern.
     */
    public static ListOutput paginate(List<String> allItems, int offset, int limit) {
        if (allItems == null || allItems.isEmpty()) {
            return new ListOutput(List.of(), 0, offset, limit);
        }
        int start = Math.max(0, offset);
        if (start >= allItems.size()) {
            return new ListOutput(List.of(), allItems.size(), offset, limit);
        }
        int end = Math.min(start + limit, allItems.size());
        List<String> page = allItems.subList(start, end);
        return new ListOutput(List.copyOf(page), allItems.size(), offset, limit);
    }

    @Override
    public String toStructuredJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"items\": [");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(HttpUtils.escapeJson(items.get(i))).append("\"");
        }
        sb.append("], ");
        sb.append("\"totalItems\": ").append(totalItems).append(", ");
        sb.append("\"offset\": ").append(offset).append(", ");
        sb.append("\"limit\": ").append(limit).append(", ");
        sb.append("\"hasMore\": ").append(hasMore());
        sb.append("}");
        return sb.toString();
    }

    @Override
    public String toDisplayText() {
        if (items.isEmpty()) {
            return hasMore()
                ? "No results in this page, but more results may be available. Try different offset values."
                : "No results found.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.join("\n", items));

        // Reproduce the existing PaginationResult hint format
        int itemsShown = items.size();
        int startItem = offset + 1;
        int endItem = offset + itemsShown;

        sb.append("\n--- PAGINATION INFO ---\n");
        sb.append(String.format("Showing items %d-%d of %d total items\n", startItem, endItem, totalItems));

        if (hasMore()) {
            int nextOffset = offset + limit;
            sb.append("⚠️  MORE RESULTS AVAILABLE! ⚠️\n");
            sb.append(String.format("To see more results, call this API again with offset=%d&limit=%d\n",
                nextOffset, limit));
            sb.append(String.format("Remaining items: %d\n", totalItems - endItem));
            sb.append("IMPORTANT: You are only seeing a subset of results. Continue fetching to get complete data!\n");
        } else {
            sb.append("✓ All results shown (no more pages)\n");
        }

        sb.append("--- END PAGINATION INFO ---");
        return sb.toString();
    }
}
