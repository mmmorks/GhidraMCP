package com.lauriewired.mcp.model;

import java.util.List;

/**
 * Output for tools that return paginated lists of items.
 */
public record ListOutput(List<String> items, int totalItems, int offset, int limit) implements ToolOutput {

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
            // Items are already raw JSON values (objects or strings)
            sb.append(items.get(i));
        }
        sb.append("], ");
        sb.append("\"totalItems\": ").append(totalItems).append(", ");
        sb.append("\"offset\": ").append(offset).append(", ");
        sb.append("\"limit\": ").append(limit).append(", ");
        sb.append("\"hasMore\": ").append(hasMore());
        sb.append("}");
        return sb.toString();
    }

}
