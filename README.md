[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is a Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes 40 tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods, variables, and data
- List methods, classes, imports, exports, namespaces, and symbols
- Create and modify structures and enums
- Analyze control flow, data flow, and call graphs
- Search memory, disassembly, and decompiled code
- Read raw memory and inspect data types
- Set comments in both decompiler and disassembly views
- Paginated results with LLM-friendly navigation hints

# Available Tools

## Program (1 tool)

| Tool | Description |
|------|-------------|
| `get_program_info` | Get metadata about the currently loaded binary |

## Functions (8 tools)

| Tool | Description |
|------|-------------|
| `list_functions` | List function names with pagination |
| `get_function_code` | Get a function's decompiled or disassembled code |
| `rename_function` | Rename a function by name or address |
| `set_function_prototype` | Set or modify a function's signature/prototype |
| `get_current_address` | Get the address currently selected in the Ghidra GUI |
| `get_current_function` | Get the function currently selected in the Ghidra GUI |
| `search_functions_by_name` | Search for functions by partial name match |

## Data Types (9 tools)

| Tool | Description |
|------|-------------|
| `list_data_types` | List data types (structures and/or enums) with pagination |
| `get_data_type` | Get detailed information about a named data type |
| `create_structure` | Create a new structure data type |
| `update_structure` | Bulk update a structure: rename fields, change types, resize |
| `add_structure_field` | Add a field to an existing structure |
| `create_enum` | Create a new enum data type |
| `update_enum` | Bulk update an enum: rename values, change numeric values, resize |
| `add_enum_value` | Add a value to an existing enum |
| `find_data_type_usage` | Find all locations where a data type is used |

## Analysis (4 tools)

| Tool | Description |
|------|-------------|
| `analyze_control_flow` | Analyze the control flow of a function |
| `analyze_data_flow` | Track variable data flow in a function |
| `get_call_graph` | Get the call graph for a function with configurable depth |
| `list_references` | List cross-references (xrefs) to an address |

## Memory (7 tools)

| Tool | Description |
|------|-------------|
| `get_memory_layout` | Get the memory layout of the program (segments/sections) |
| `list_data_items` | List defined data labels and their values with pagination |
| `rename_data` | Rename a data label at an address |
| `set_address_data_type` | Set the data type at a specific memory address |
| `read_memory` | Read raw memory contents (hex, decimal, or binary) |
| `get_memory_permissions` | Get memory permissions and block information at an address |
| `get_address_data_type` | Get the data type currently defined at a memory address |

## Symbols (2 tools)

| Tool | Description |
|------|-------------|
| `list_symbols` | List all symbols with pagination |
| `get_symbol_address` | Get the memory address of a named symbol |

## Comments (2 tools)

| Tool | Description |
|------|-------------|
| `set_comment` | Set a comment at an address |
| `get_comment` | Get all comments at a specific address |

## Search (3 tools)

| Tool | Description |
|------|-------------|
| `search_memory` | Search program memory for byte patterns or strings |
| `search_disassembly` | Search for patterns in disassembled code using regex |
| `search_decompiled` | Search for patterns in decompiled code using regex |

## Variables (3 tools)

| Tool | Description |
|------|-------------|
| `rename_variables` | Batch rename local variables within a function |
| `split_variable` | Split or rename a variable at a specific usage address |
| `set_variable_types` | Batch set data types for local variables in a function |

# Installation

## Prerequisites
- [Ghidra](https://ghidra-sre.org) (12.0.3+)
- Python 3.10+
- Python dependencies: `pip install -r requirements.txt`

## Ghidra Plugin
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and the Python MCP bridge. Then, import the plugin into Ghidra:

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-1.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure server settings in `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## Configuration

The following options can be configured in Ghidra via `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`. All changes require a Ghidra restart or plugin reload to take effect.

| Option | Default | Description |
|--------|---------|-------------|
| Server Port | `8080` | The network port the HTTP server listens on |
| Thread Pool Size | `10` | Number of threads for handling concurrent requests |
| Request Timeout (seconds) | `30` | Timeout for HTTP requests; requests exceeding this are cancelled |

## MCP Clients

Any MCP client should work with ghidraMCP. Two examples are given below.

### Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server URL argument is optional. If omitted, the bridge defaults to `http://127.0.0.1:8080`. Set it to match the port configured in Ghidra if you changed it from the default.

### Example 2: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source

## Prerequisites
- Java 24
- Maven

## Build
```
mvn clean package
```

The generated zip file (`target/GhidraMCP-1.0-SNAPSHOT.zip`) includes the built Ghidra plugin and its resources:

- `lib/GhidraMCP.jar`
- `extension.properties`
- `Module.manifest`

## Running Tests
```
mvn test
```

Tests use JUnit 5 and Mockito. Code coverage reports are generated via JaCoCo and can be found in `target/site/jacoco/`.

# Architecture

```
MCP Client (Claude, 5ire, etc.)
    |
    | MCP Protocol (stdio)
    v
bridge_mcp_ghidra.py (Python MCP Server)
    |
    | HTTP requests
    v
GhidraMCPPlugin (Java, runs inside Ghidra)
    |
    +-- McpServerManager (HTTP server on port 8080)
    +-- ApiHandlerRegistry (40 endpoint handlers)
    +-- Service Layer
        +-- FunctionService
        +-- DataTypeService
        +-- AnalysisService
        +-- MemoryService
        +-- NamespaceService
        +-- CommentService
        +-- SearchService
        +-- VariableService
        +-- ProgramService
```

# Troubleshooting

**Plugin not appearing in Ghidra**
- Ensure you installed the extension via `File` -> `Install Extensions` and restarted Ghidra
- Check that the plugin is enabled in `File` -> `Configure` -> `Developer`

**Connection refused / bridge can't reach Ghidra**
- Verify the Ghidra plugin is loaded and the HTTP server started (check the Ghidra console for "GhidraMCP server started" messages)
- Ensure the port in the bridge URL matches the port configured in Ghidra (default: 8080)
- Check for port conflicts with other applications

**Python bridge fails to start**
- Ensure Python 3.10+ is installed
- Install dependencies: `pip install -r requirements.txt`
- Verify the path to `bridge_mcp_ghidra.py` in your MCP client config is an absolute path

**Timeouts on large binaries**
- Increase the request timeout in `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`
- Use paginated tools (`list_functions`, `list_data_items`, etc.) with smaller `limit` values
