[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is a Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes 54 tools from core Ghidra functionality to MCP clients.

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

## Functions (12 tools)

| Tool | Description |
|------|-------------|
| `list_methods` | List function names with pagination |
| `list_functions` | List all functions (name + address) |
| `decompile_function` | Decompile a function by name |
| `decompile_function_by_address` | Decompile a function by address |
| `disassemble_function` | Get assembly listing for a function |
| `rename_function` | Rename a function by name |
| `rename_function_by_address` | Rename a function by address |
| `set_function_prototype` | Set a function's signature/prototype |
| `get_function_by_address` | Get function details at an address |
| `get_current_address` | Get the current cursor address in Ghidra |
| `get_current_function` | Get the function at the current cursor |
| `search_functions_by_name` | Search for functions by partial name |

## Data Types (11 tools)

| Tool | Description |
|------|-------------|
| `list_structures` | List all defined structures |
| `get_structure_details` | Get detailed structure information |
| `list_structure_fields` | List fields of a structure |
| `rename_struct_field` | Rename a structure field |
| `create_structure` | Create a new structure |
| `add_structure_field` | Add a field to a structure |
| `list_enums` | List all defined enums |
| `get_enum_details` | Get detailed enum information |
| `create_enum` | Create a new enum |
| `add_enum_value` | Add a value to an enum |
| `find_data_type_usage` | Find where a data type is used |

## Analysis (7 tools)

| Tool | Description |
|------|-------------|
| `list_references` | List references to an address |
| `list_references_from` | List references from an address |
| `analyze_control_flow` | Build a control flow graph |
| `analyze_data_flow` | Track variable data flow |
| `analyze_call_graph` | Build a call graph with configurable depth |
| `get_function_callers` | Get functions that call a given function |
| `get_call_hierarchy` | Get full call hierarchy with depth |

## Memory (7 tools)

| Tool | Description |
|------|-------------|
| `list_segments` | List memory segments |
| `list_data_items` | List defined data items with pagination |
| `rename_data` | Rename a data label at an address |
| `set_memory_data_type` | Set data type at an address |
| `read_memory` | Read raw memory contents (hex, decimal, or binary) |
| `get_memory_permissions` | Get memory block permissions |
| `get_data_type_at` | Get the current data type at an address |

## Namespaces & Symbols (6 tools)

| Tool | Description |
|------|-------------|
| `list_classes` | List namespaces/classes |
| `list_namespaces` | List non-global namespaces |
| `list_symbols` | List all symbols |
| `list_imports` | List imported symbols |
| `list_exports` | List exported symbols |
| `get_symbol_address` | Get address of a named symbol |

## Comments (5 tools)

| Tool | Description |
|------|-------------|
| `set_decompiler_comment` | Set a pre-comment in the decompiler view |
| `set_disassembly_comment` | Set an EOL comment in the disassembly view |
| `get_comments` | Get all comments at an address |
| `get_decompiler_comment` | Get the decompiler comment at an address |
| `get_disassembly_comment` | Get the disassembly comment at an address |

## Search (3 tools)

| Tool | Description |
|------|-------------|
| `search_memory` | Search for byte patterns or strings in memory |
| `search_disassembly` | Search assembly code with regex |
| `search_decompiled` | Search decompiled code with regex |

## Variables (3 tools)

| Tool | Description |
|------|-------------|
| `rename_variable` | Rename a local variable in a function |
| `split_variable` | Split/rename a variable at a specific usage point |
| `set_local_variable_type` | Set data type for a local variable |

# Installation

## Prerequisites
- [Ghidra](https://ghidra-sre.org) (11.3.1+)
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
- Java 21
- Maven

## Build
```
mvn clean package assembly:single
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
    +-- ApiHandlerRegistry (54 endpoint handlers)
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
- Use paginated tools (`list_methods`, `list_data_items`, etc.) with smaller `limit` values
