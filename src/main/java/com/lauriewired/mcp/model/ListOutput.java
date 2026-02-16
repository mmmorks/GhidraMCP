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
    public static ListOutput paginate(List<?> allItems, int offset, int limit) {
        if (allItems == null || allItems.isEmpty()) {
            return new ListOutput(List.of(), 0, offset, limit);
        }
        int start = Math.max(0, offset);
        if (start >= allItems.size()) {
            return new ListOutput(List.of(), allItems.size(), offset, limit);
        }
        int end = Math.min(start + limit, allItems.size());
        List<?> page = allItems.subList(start, end);
        return new ListOutput(List.copyOf(page), allItems.size(), offset, limit);
    }

    @Override
    public String toStructuredJson() {
        return Json.serialize(this);
    }

}
