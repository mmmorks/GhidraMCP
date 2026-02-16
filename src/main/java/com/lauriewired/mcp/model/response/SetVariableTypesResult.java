package com.lauriewired.mcp.model.response;

import java.util.Map;

public record SetVariableTypesResult(String status, String function, Map<String, String> applied, int count) {}
