package com.lauriewired.mcp.model;

import java.util.List;

import com.lauriewired.mcp.utils.Json;

/**
 * Output for tools that return paginated lists of items.
 * Items can be any type — record objects are serialized via Jackson.
 */
public record ListOutput(List<?> items, int totalItems, int offset, int limit) implements ToolOutput {

    /** Defensive copy: ensure the list is unmodifiable. */
    public ListOutput {
        items = List.copyOf(items);
    }

    /** Whether more results are available beyond the current page. */
    public boolean hasMore() {
        return (offset + limit) < totalItems;
    }

    /**
     * Factory method that slices a full list into a paginated ListOutput.
     */
    public static ListOutput paginate(final List<?> allItems, final int offset, final int limit) {
        if (allItems == null || allItems.isEmpty()) {
            return new ListOutput(List.of(), 0, offset, limit);
        }
        final int start = Math.max(0, offset);
        if (start >= allItems.size()) {
            return new ListOutput(List.of(), allItems.size(), offset, limit);
        }
        final int end = Math.min(start + limit, allItems.size());
        final List<?> page = allItems.subList(start, end);
        return new ListOutput(List.copyOf(page), allItems.size(), offset, limit);
    }

    @Override
    public String toStructuredJson() {
        return Json.serialize(this);
    }

    @Override
    public String toDisplayText() {
        if (items.isEmpty()) {
            return hasMore()
                ? "No results in this page, but more results may be available. Try different offset values."
                : "No results found.";
        }

        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append("\n");
            sb.append(String.valueOf(items.get(i)));
        }

        final int startItem = offset + 1;
        final int endItem = offset + items.size();

        sb.append("\n--- PAGINATION INFO ---\n");
        sb.append(String.format("Showing items %d-%d of %d total items\n", startItem, endItem, totalItems));

        if (hasMore()) {
            final int nextOffset = offset + limit;
            sb.append(String.format("To see more results, call this API again with offset=%d&limit=%d\n",
                nextOffset, limit));
            sb.append(String.format("Remaining items: %d\n", totalItems - endItem));
        } else {
            sb.append("All results shown (no more pages)\n");
        }

        sb.append("--- END PAGINATION INFO ---");
        return sb.toString();
    }
}
