package com.lauriewired.mcp.model.response;

import java.util.Map;

public record RenameVariablesResult(String status, String function, Map<String, String> renamed, int count) {}
