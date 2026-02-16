# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import json
import requests

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080"
ghidra_server_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GHIDRA_SERVER

mcp = FastMCP("ghidra-mcp")

def safe_get(endpoint: str, params: dict | None = None) -> list:
    """Execute a GET request with optional parameters."""
    if params is None:
        params = {}

    url = f"{ghidra_server_url}/{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        if isinstance(data, dict):
            response = requests.post(f"{ghidra_server_url}/{endpoint}", data=data, timeout=5)
        else:
            response = requests.post(f"{ghidra_server_url}/{endpoint}", data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post_json(endpoint: str, payload: dict) -> str:
    """Execute a POST request with a JSON body."""
    try:
        response = requests.post(
            f"{ghidra_server_url}/{endpoint}",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_functions(offset: int = 0, limit: int = 100) -> list:
    """
    List function names in the loaded Ghidra program with pagination.

    Functions are defined subroutines in the binary (both user-defined and auto-discovered).

    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum function names to return

    Returns: List of function names with pagination info. If more results are available,
             the response includes clear indicators and instructions for fetching additional pages.

    Example: list_functions(0, 10) -> ['main', 'printf', 'malloc', ..., '--- PAGINATION INFO ---', ...]
    """
    return safe_get("list_functions", {"offset": offset, "limit": limit})

@mcp.tool()
def update_structure(name: str, new_name: str | None = None, size: int | None = None,
                     field_renames: dict[str, str] | None = None,
                     type_changes: dict[str, str] | None = None) -> str:
    """
    Bulk update a structure: rename fields, change field types, resize, and/or rename.

    All changes are applied in a single transaction with per-field error reporting.

    Parameters:
        name: Current structure name (required)
        new_name: New name for the structure (optional)
        size: New size in bytes (optional, only grows)
        field_renames: Map of old field name to new field name (optional),
                       e.g., {"field0_0x0": "width", "old_field": "new_field"}
        type_changes: Map of field name to new data type (optional). Keys can be
                      old OR new names — the server resolves ambiguity automatically.
                      e.g., {"width": "int", "old_field": "char *"}

    Returns: Per-field results with success/failure status and summary

    Note: For auto-generated field names like "field1_0x10", the number after "field"
    is the component index. type_changes keys are resolved against both existing field
    names and rename targets; ambiguous keys produce an error for that entry.

    Example: update_structure("MyStruct", field_renames={"field0_0x0": "width"},
                              type_changes={"width": "int"})
    """
    payload = {"name": name}
    if new_name is not None:
        payload["new_name"] = new_name
    if size is not None:
        payload["size"] = size
    if field_renames is not None:
        payload["field_renames"] = field_renames
    if type_changes is not None:
        payload["type_changes"] = type_changes
    return safe_post_json("update_structure", payload)

@mcp.tool()
def update_enum(name: str, new_name: str | None = None, size: int | None = None,
                value_renames: dict[str, str] | None = None,
                value_changes: dict[str, int] | None = None) -> str:
    """
    Bulk update an enum: rename values, change numeric values, resize, and/or rename.

    All changes are applied in a single transaction with per-entry error reporting.

    Parameters:
        name: Current enum name (required)
        new_name: New name for the enum (optional)
        size: New size in bytes — must be 1, 2, 4, or 8 (optional)
        value_renames: Map of old value name to new value name (optional),
                       e.g., {"OLD_VAL": "NEW_VAL"}
        value_changes: Map of value name to new numeric value (optional). Keys can be
                       old OR new names — the server resolves ambiguity automatically.
                       e.g., {"NEW_VAL": 42, "EXISTING": 100}

    Returns: Per-entry results with success/failure status and summary

    Note: value_changes keys are resolved against both existing value names and
    rename targets; ambiguous keys produce an error for that entry.

    Example: update_enum("MyFlags", new_name="FilePermissions",
                         value_renames={"OLD_VAL": "NEW_VAL"},
                         value_changes={"NEW_VAL": 42})
    """
    payload = {"name": name}
    if new_name is not None:
        payload["new_name"] = new_name
    if size is not None:
        payload["size"] = size
    if value_renames is not None:
        payload["value_renames"] = value_renames
    if value_changes is not None:
        payload["value_changes"] = value_changes
    return safe_post_json("update_enum", payload)

@mcp.tool()
def get_function_code(function_identifier: str, mode: str = "C") -> str:
    """
    Get a function's code in the specified representation.

    Resolves the function by name or address, then returns the requested output.

    Parameters:
        function_identifier: Function name (e.g., "main") or address (e.g., "00401000", "ram:00401000")
        mode: Output format - "C" for decompiled pseudocode (default), "assembly"/"asm" for
              disassembly listing, or "pcode" for Ghidra's intermediate representation

    Returns: Function code in the requested format, or error message

    Examples:
        get_function_code("main") -> C pseudocode for main
        get_function_code("00401000", "assembly") -> assembly listing
        get_function_code("FUN_00401000", "pcode") -> PCode output
    """
    return "\n".join(safe_get("get_function_code", {
        "function_identifier": function_identifier,
        "mode": mode
    }))

@mcp.tool()
def list_references(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    List cross-references (xrefs) to the specified address.

    Shows locations where an address is referenced from, helping track usage.

    Parameters:
        address: Target address (e.g., "00401000" or "ram:00401000")
        offset: Starting index for pagination (0-based)
        limit: Maximum references to return

    Returns: References with source address, type, and containing function

    Example: list_references("00401000") -> ['00400f50 -> 00401000 (from CALL in main)', ...]
    """
    return safe_get("list_references", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def rename_function(function_identifier: str, new_name: str) -> str:
    """
    Rename a function identified by name or address.

    Resolves the target function flexibly: pass a current function name
    (e.g., "FUN_00401000") or an address (e.g., "00401000", "ram:00401000").

    Parameters:
        function_identifier: Current function name or address
        new_name: New function name to assign

    Returns: Success or failure message

    Note: Function names must be unique within the program.

    Examples:
        rename_function("FUN_00401000", "initialize_system")
        rename_function("00401000", "initialize_system")
        rename_function("main", "entry_point")
    """
    return safe_post("rename_function", {
        "function_identifier": function_identifier,
        "new_name": new_name
    })

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.

    Labels identify data elements (strings, arrays, structures) to improve code readability.

    Parameters:
        address: Data address (e.g., "00401000" or "ram:00401000")
        new_name: New name to assign

    Returns: Message indicating operation was attempted

    Note: Creates a new label if none exists at the address. Address must point to data, not code.

    Example: rename_data("00402000", "config_table")
    """
    return safe_post("rename_data", {"address": address, "new_name": new_name})

@mcp.tool()
def list_data_types(kind: str = "all", offset: int = 0, limit: int = 100) -> list:
    """
    List data types (structures and/or enums) in the program with pagination.

    Parameters:
        kind: Filter by type — "all" (default), "struct", or "enum"
        offset: Starting index for pagination (0-based)
        limit: Maximum data types to return

    Returns: Data types with summary info, prefixed with [struct] or [enum]

    Example: list_data_types("struct", 0, 5) -> ['[struct] POINT: {int x, int y}', ...]
    """
    return safe_get("list_data_types", {"kind": kind, "offset": offset, "limit": limit})

@mcp.tool()
def create_structure(name: str, size: int = 0, category_path: str = "",
                     fields: list[list[str]] | None = None) -> str:
    """
    Create a new structure data type in Ghidra, optionally with inline fields.

    Creates a structure with the specified name, and when fields are provided,
    adds all fields in a single transaction — avoiding the multi-step
    create → add_field → add_field dance.

    Parameters:
        name: Name of the structure to create (required)
        size: Size in bytes (0 for auto-size based on fields)
        category_path: Category path like "/MyStructures" (empty for root)
        fields: Optional list of [field_name, data_type] pairs to add immediately,
                e.g., [["x", "int"], ["y", "int"], ["name", "char[32]"]]

    Returns: Success message with path or error message

    Note: Structure names must be unique. Use add_structure_field to add fields to existing structs.

    Example: create_structure("POINT", 0, "", [["x", "int"], ["y", "int"]])
    """
    payload = {"name": name, "size": str(size), "category_path": category_path}
    if fields is not None:
        payload["fields"] = fields
    return safe_post_json("create_structure", payload)

@mcp.tool()
def add_structure_field(struct_name: str, field_name: str, field_type: str,
                       field_size: int = -1, offset: int = -1, comment: str = "") -> str:
    """
    Add a field to an existing structure.

    Adds a new field with specified type at given offset or appends to end.

    Parameters:
        struct_name: Name of the structure to modify (required)
        field_name: Name for the new field (optional, can be empty)
        field_type: Data type like "int", "char", "DWORD", or another struct name (required)
        field_size: Size in bytes for fixed-size types (-1 for default)
        offset: Offset in structure to insert at (-1 to append)
        comment: Optional comment for the field

    Returns: Success or error message

    Note: Field types can be built-in types, typedefs, or other structures/enums.

    Example: add_structure_field("MY_STRUCT", "count", "int") -> "Field 'count' added to structure 'MY_STRUCT'"
    """
    return safe_post("add_structure_field", {
        "struct_name": struct_name,
        "field_name": field_name,
        "field_type": field_type,
        "field_size": field_size,
        "offset": offset,
        "comment": comment
    })

@mcp.tool()
def create_enum(name: str, size: int = 4, category_path: str = "",
                values: dict[str, int] | None = None) -> str:
    """
    Create a new enum data type in Ghidra, optionally with inline values.

    Creates an enumeration with the specified name, and when values are provided,
    adds all values in a single transaction — avoiding the multi-step
    create → add_value → add_value dance.

    Parameters:
        name: Name of the enum to create (required)
        size: Size in bytes - must be 1, 2, 4, or 8 (default: 4)
        category_path: Category path like "/MyEnums" (empty for root)
        values: Optional dictionary mapping value names to numeric values,
                e.g., {"FLAG_READ": 1, "FLAG_WRITE": 2, "FLAG_EXEC": 4}

    Returns: Success message with path or error message

    Note: Enum names must be unique. Use add_enum_value to add values to existing enums.

    Example: create_enum("FILE_FLAGS", 4, "", {"FLAG_READ": 1, "FLAG_WRITE": 2})
    """
    payload = {"name": name, "size": str(size), "category_path": category_path}
    if values is not None:
        payload["values"] = values
    return safe_post_json("create_enum", payload)

@mcp.tool()
def add_enum_value(enum_name: str, value_name: str, value: int) -> str:
    """
    Add a value to an existing enum.

    Adds a named constant with numeric value to the enumeration.

    Parameters:
        enum_name: Name of the enum to modify (required)
        value_name: Name for the enum constant (required)
        value: Numeric value for the constant (required)

    Returns: Success or error message

    Note: Value names must be unique within the enum. Values can be negative.

    Example: add_enum_value("MY_FLAGS", "FLAG_ENABLED", 0x01) -> "Value 'FLAG_ENABLED' (1) added to enum 'MY_FLAGS'"
    """
    return safe_post("add_enum_value", {
        "enum_name": enum_name,
        "value_name": value_name,
        "value": value
    })

@mcp.tool()
def get_memory_layout(offset: int = 0, limit: int = 100) -> list:
    """
    Get the memory layout of the program (segments/sections).

    Shows distinct regions in the binary's address space (.text, .data, .rodata, etc.)
    with their address ranges.

    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum segments to return

    Returns: Memory segments with name and address range

    Example: get_memory_layout() -> ['.text: 00401000 - 00410000', '.data: 00411000 - 00412000', ...]
    """
    return safe_get("get_memory_layout", {"offset": offset, "limit": limit})

@mcp.tool()
def list_symbols(offset: int = 0, limit: int = 100) -> list:
    """
    List all symbols (functions, variables, labels, etc.) with pagination.

    Comprehensive listing of all named entities in the program.

    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum symbols to return

    Returns: Symbols with addresses in format "symbol_name -> address"

    Example: list_symbols(0, 5) -> ['main -> 00401000', 'gVar1 -> 00410010', ...]
    """
    return safe_get("list_symbols", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.

    Shows memory locations containing data (strings, arrays, structures, primitives).

    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum data items to return

    Returns: Data items with address, label and value

    Note: Unlabeled items shown as "(unnamed)"

    Example: list_data_items(0, 3) -> ['00410000: hello_msg = "Hello, World!"', ...]
    """
    return safe_get("list_data_items", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions by partial name match (case-insensitive).

    Helps explore large binaries or find related functionality.

    Parameters:
        query: Substring to search for in function names (required)
        offset: Starting index for pagination (0-based)
        limit: Maximum matches to return

    Returns: Matching functions formatted as "function_name @ address"

    Example: search_functions_by_name("init") -> ['initialize @ 00401000', ...]
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("search_functions_by_name", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get detailed information about a function at the specified address.

    Retrieves name, signature, entry point and body range for the function.

    Parameters:
        address: Address to look up (e.g., "00401000" or "ram:00401000")

    Returns: Detailed function information or error message

    Example: get_function_by_address("00401000") -> "Function: main at 00401000..."
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user in the Ghidra GUI.

    Retrieves cursor location in Code Browser or Decompiler view.

    Parameters: None

    Returns: Currently selected address or error message

    Note: Requires Ghidra GUI running with a selected location.

    Example: get_current_address() -> "00401234"
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get information about the function currently selected in the Ghidra GUI.

    Returns details about function containing the selected address.

    Parameters: None

    Returns: Current function information (name, entry point, signature) or error

    Note: Requires Ghidra GUI with location selected within a function.

    Example: get_current_function() -> "Function: main at 00401000..."
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for an address in the decompiled pseudocode view.

    Adds a pre-comment to document code purpose or behavior in decompiled output.

    Parameters:
        address: Target address (e.g., "00401000" or "ram:00401000")
        comment: Comment text to add

    Returns: Success or failure message with details

    Note: Comments persist in Ghidra database between sessions. Appears before the line.

    Example: set_decompiler_comment("00401010", "Initialize the configuration")
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for an address in the assembly listing view.

    Adds an end-of-line (EOL) comment to document the instruction's purpose.

    Parameters:
        address: Target address (e.g., "00401000" or "ram:00401000")
        comment: Comment text to add

    Returns: Success or failure message with details

    Note: Comments persist in Ghidra database. Appears at the end of the line.

    Example: set_disassembly_comment("00401010", "Initialize EAX register")
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set or modify a function's signature/prototype.

    Changes return type, parameter types and names to improve decompiler output.

    Parameters:
        function_address: Function address (e.g., "00401000")
        prototype: C-style function signature (e.g., "int main(int argc, char **argv)")

    Returns: Success or failure message with details

    Note: Function name in prototype is ignored; only types matter. Parameter names are applied.

    Example: set_function_prototype("00401000", "int process_data(char *buffer, size_t length)")
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_variable_types(function_address: str, types: dict[str, str]) -> str:
    """
    Batch set data types for local variables in a function.

    All type changes are applied in a single transaction — if any fails,
    none are applied (all-or-nothing). The function is decompiled once and
    all type changes are executed together for efficiency.

    Parameters:
        function_address: Function address (e.g., "00401000")
        types: Dictionary mapping variable names to new data types,
               e.g., {"local_10": "int", "local_14": "char *", "local_18": "POINT"}

    Returns: JSON with status, applied type changes, and count

    Note: Supports built-in types, pointers, and structures. Windows-style types also supported.

    Example: set_variable_types("00401000", {"local_10": "int", "local_14": "char *"})
    """
    return safe_post_json("set_variable_types", {
        "function_address": function_address,
        "types": types
    })

@mcp.tool()
def rename_variables(function_name: str, renames: dict[str, str]) -> str:
    """
    Batch rename local variables within a single function.

    All renames are applied in a single transaction — if any rename fails,
    none are applied (all-or-nothing). The function is decompiled once and
    all renames are executed together for efficiency.

    Parameters:
        function_name: Name of the function containing the variables
        renames: Dictionary mapping current variable names to new names,
                 e.g., {"local_10": "buffer_size", "local_14": "file_handle"}

    Returns: JSON with status, renamed pairs, and count

    Note: Variable names must be unique within the function scope.
          Only one function at a time is supported.

    Tip: If the decompiler reuses a single variable name across unrelated usages
         (e.g., the same local is used for a loop counter and later a buffer pointer),
         use split_variable first to give that specific use of memory a distinct identity
         from that point in the function onward, then rename it here.

    Example: rename_variables("main", {"local_10": "buffer_size", "param_1": "argc"})
    """
    return safe_post_json("rename_variables", {
        "function_name": function_name,
        "renames": renames
    })

@mcp.tool()
def split_variable(function_name: str, variable_name: str, usage_address: str, new_name: str = "") -> str:
    """
    Split or rename a variable at a specific usage address within a function.

    Useful when the decompiler reuses a single variable name across unrelated usages.
    Splitting assigns a distinct name at one usage site without affecting others.

    Parameters:
        function_name: Name of function containing the variable
        variable_name: Current variable name to split
        usage_address: Address where this specific usage occurs (bare hex, no 0x prefix)
        new_name: New name for the variable at this usage (optional; Ghidra auto-generates if empty)

    Returns: Status of the split operation

    Example: split_variable("main", "local_10", "00401050", "loop_counter")
    """
    data = {
        "function_name": function_name,
        "variable_name": variable_name,
        "usage_address": usage_address,
    }
    if new_name:
        data["new_name"] = new_name
    return safe_post("split_variable", data)

@mcp.tool()
def analyze_control_flow(address: str) -> str:
    """
    Analyze the control flow of a function at the given address.

    Creates a textual control flow graph (CFG) showing how basic blocks connect.

    Parameters:
        address: Function address (e.g., "00401000") - entry point or any address within

    Returns: Detailed CFG with blocks, jumps, and instructions

    Note: Basic blocks are instruction sequences with single entry/exit points.
    Essential for understanding branching and loops.

    Example: analyze_control_flow("00401000") -> "Control Flow Analysis for function:..."
    """
    return "\n".join(safe_get("analyze_control_flow", {"address": address}))

@mcp.tool()
def analyze_data_flow(address: str, variable: str) -> str:
    """
    Analyze the data flow for a variable in a function.

    Tracks where a variable is defined (written) and used (read) throughout execution paths.

    Parameters:
        address: Function address (e.g., "00401000")
        variable: Variable name to track

    Returns: Detailed analysis with variable info, definitions and uses

    Note: Helps understand value propagation and useful for analyzing algorithms.

    Example: analyze_data_flow("00401000", "local_10") -> "Data Flow Analysis..."
    """
    return "\n".join(safe_get("analyze_data_flow", {"address": address, "variable": variable}))

@mcp.tool()
def analyze_call_graph(address: str, depth: int = 2) -> str:
    """
    Analyze the call graph starting from a function.

    Creates hierarchical representation of function calls to specified depth.

    Parameters:
        address: Starting function address (e.g., "00401000")
        depth: Maximum call depth to traverse (default: 2, max: 5)

    Returns: Hierarchical call graph with function names and addresses

    Note: Only considers static function calls. Helps understand program structure.

    Example: analyze_call_graph("00401000", 3) -> "Call Graph Analysis..."
    """
    return "\n".join(safe_get("analyze_call_graph", {"address": address, "depth": depth}))

@mcp.tool()
def search_memory(query: str, as_string: bool = True, block_name: str = "", limit: int = 10) -> str:
    """
    Search program memory for byte patterns or strings.

    Searches initialized memory blocks for specified patterns and shows context around matches.

    Parameters:
        query: The pattern to search for (string or hex bytes like "00 FF 32")
        as_string: True to search for UTF-8 string, False to search for hex bytes
        block_name: Optional memory block name to restrict search
        limit: Maximum number of results to return

    Returns: Memory matches with address, label, and context bytes

    Example: search_memory("Password", True) -> matches of "Password" string in memory
    """
    params = {
        "query": query,
        "as_string": "true" if as_string else "false",
        "limit": limit
    }
    if block_name:
        params["block_name"] = block_name

    return "\n".join(safe_get("search_memory", params))

@mcp.tool()
def search_disassembly(query: str, offset: int = 0, limit: int = 10) -> list:
    """
    Search for patterns in disassembled code using regex.

    Searches instruction mnemonics, operands, and comments in functions.

    Parameters:
        query: Regex pattern to search for in assembly instructions
        offset: Starting index for pagination
        limit: Maximum number of results to return

    Returns: Matching instructions with function context and nearby instructions

    Example: search_disassembly("mov.*eax") -> finds MOV instructions using EAX register
    """
    return safe_get("search_disassembly", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def search_decompiled(query: str, offset: int = 0, limit: int = 5) -> str:
    """
    Search for patterns in decompiled C-like code using regex.

    Searches variables, expressions, and comments in decompiled functions.

    Parameters:
        query: Regex pattern to search for in decompiled code
        offset: Starting index for pagination
        limit: Maximum number of functions to search/return

    Returns: Matching code fragments with function context and surrounding lines

    Note: This is resource-intensive as each function must be decompiled.

    Example: search_decompiled("malloc\\(.*\\)") -> finds malloc calls in decompiled code
    """
    return "\n".join(safe_get("search_decompiled", {"query": query, "offset": offset, "limit": limit}))

@mcp.tool()
def get_symbol_address(symbol_name: str) -> str:
    """
    Get the memory address of a named symbol in the program.

    Looks up symbols (functions, variables, labels) by name in the symbol table.

    Parameters:
        symbol_name: Symbol name (case-sensitive, exact match required)

    Returns: Memory address in Ghidra's format or error message

    Note: For functions, returns entry point; for data, returns storage location.

    Example: get_symbol_address("main") -> "00401000"
    """
    return "\n".join(safe_get("get_symbol_address", {"symbol_name": symbol_name}))

@mcp.tool()
def set_address_data_type(address: str, data_type: str, clear_existing: bool = True) -> str:
    """
    Set the data type at a specific memory address.

    Creates or modifies data at the specified address with the given type.
    Symmetric counterpart to get_address_data_type.

    Parameters:
        address: Memory address (e.g., "00401000" or "ram:00401000")
        data_type: Data type name ("int", "char[20]", "POINT", etc.)
        clear_existing: Whether to clear existing data at the address first (default: True)

    Returns: Success message with details or error message

    Note: The data type can be a built-in type, structure, enum, or array.
    Array syntax: "type[size]" e.g., "char[256]" for a string buffer.

    Example: set_memory_data_type("00402000", "POINT") -> "Data type 'POINT' set at address 00402000"
    """
    return safe_post("set_address_data_type", {
        "address": address,
        "data_type": data_type,
        "clear_existing": "true" if clear_existing else "false"
    })

@mcp.tool()
def read_memory(address: str, size: int = 16, format: str = "hex") -> str:
    """
    Read raw memory contents at a specific address.

    Reads bytes from memory and formats them for analysis.

    Parameters:
        address: Memory address to read from (e.g., "00401000")
        size: Number of bytes to read (1-1024, default: 16)
        format: Output format - "hex", "decimal", "binary", or "ascii" (default: "hex")

    Returns: Formatted memory contents with context

    Note: Shows memory in rows with address, hex bytes, and ASCII representation.

    Example: read_memory("00401000", 32, "hex") -> Memory dump with hex values
    """
    return "\n".join(safe_get("read_memory", {"address": address, "size": size, "format": format}))

@mcp.tool()
def get_memory_permissions(address: str) -> str:
    """
    Get memory permissions and block information at an address.

    Shows memory block properties including read/write/execute permissions.

    Parameters:
        address: Memory address to check (e.g., "00401000")

    Returns: Memory block info with permissions and properties

    Note: Helps identify code vs data regions and memory protection.

    Example: get_memory_permissions("00401000") -> "Block: .text, Permissions: R-X"
    """
    return "\n".join(safe_get("get_memory_permissions", {"address": address}))

@mcp.tool()
def get_memory_data_type(address: str) -> str:
    """
    Get the data type currently defined at a memory address.

    Shows whether address contains instruction, defined data, or is undefined.
    Symmetric counterpart to set_memory_data_type.

    Parameters:
        address: Memory address to check (e.g., "00401000")

    Returns: Data type information including type name, size, and value

    Note: Useful for checking if memory has been analyzed/typed.

    Example: get_memory_data_type("00402000") -> "Type: DWORD, Value: 0x12345678"
    """
    return "\n".join(safe_get("get_memory_data_type", {"address": address}))

@mcp.tool()
def list_references_from(address: str, offset: int = 0, limit: int = 100) -> str:
    """
    List all references FROM a specific address.

    Shows what addresses/symbols this address references (calls, jumps, data access).

    Parameters:
        address: Source address or symbol name (e.g., "00401000" or "main")
        offset: Starting index for pagination (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns: List of references with destination addresses and types

    Note: Complements list_references which shows references TO an address.

    Example: list_references_from("main") -> "00401000 -> 00401234 (strlen) [CALL]"
    """
    return "\n".join(safe_get("list_references_from", {"address": address, "offset": offset, "limit": limit}))

@mcp.tool()
def get_function_callers(function_name: str) -> str:
    """
    Get all functions that call a specific function.

    Finds all callers of the specified function by name.

    Parameters:
        function_name: Name of the function to find callers for

    Returns: List of calling functions with their addresses

    Note: Helps understand function usage and dependencies.

    Example: get_function_callers("process_data") -> "Called by: main at 00401000"
    """
    return "\n".join(safe_get("get_function_callers", {"function_name": function_name}))

@mcp.tool()
def get_call_hierarchy(function_name: str, depth: int = 2) -> str:
    """
    Get complete call hierarchy for a function (callers and callees).

    Shows both functions that call this function and functions it calls.

    Parameters:
        function_name: Name of the function to analyze
        depth: Maximum depth to traverse (1-5, default: 2)

    Returns: Hierarchical view of function relationships

    Note: Provides complete context of function's role in program.

    Example: get_call_hierarchy("main", 3) -> Full call tree
    """
    return "\n".join(safe_get("get_call_hierarchy", {"function_name": function_name, "depth": depth}))

@mcp.tool()
def get_data_type(name: str) -> str:
    """
    Get detailed information about a named data type (auto-detects struct vs enum).

    For structures: returns full field layout with offsets, types, sizes, and comments.
    For enums: returns all values sorted numerically with hex and decimal representation.

    Parameters:
        name: Name of the data type to examine (e.g., "POINT", "FILE_FLAGS")

    Returns: Detailed data type information

    Example: get_data_type("POINT") -> "Structure: POINT\nSize: 8 bytes\nFields:\n  [0000] x: int..."
    """
    return "\n".join(safe_get("get_data_type", {"name": name}))

@mcp.tool()
def find_data_type_usage(type_name: str, field_name: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    Find all locations where a data type is used in the program.

    Searches defined data items and function signatures (return types, parameters,
    local variables) for usages of the specified type, including through pointers,
    arrays, and typedefs.

    When field_name is provided and the type is a struct/union, restricts the search
    to locations where that specific field is referenced (similar to Ghidra's
    "Find References to Field" feature).

    Parameters:
        type_name: Name of the data type to search for (e.g., "POINT", "MyStruct")
        field_name: Optional field name to restrict search to (e.g., "x" to find only uses of MyStruct.x)
        offset: Starting index for pagination (0-based)
        limit: Maximum results to return

    Returns: List of usage locations with context (data labels, function signatures)

    Example: find_data_type_usage("POINT") -> ['Data: origin @ 00402000 (type: POINT)', 'Param variable: p1 in draw_line @ 00401000 (type: POINT *)']
    Example: find_data_type_usage("POINT", field_name="x") -> ['Data: origin.x @ 00402000 (type: int)']
    """
    params = {"type_name": type_name, "offset": offset, "limit": limit}
    if field_name is not None:
        params["field_name"] = field_name
    return safe_get("find_data_type_usage", params)

@mcp.tool()
def get_comments(address: str) -> str:
    """
    Get all comments at a specific address.

    Retrieves all comment types (pre, post, EOL, plate, repeatable).

    Parameters:
        address: Address to get comments from (e.g., "00401000")

    Returns: All comments found at the address by type

    Note: Shows which comment types are present and their content.

    Example: get_comments("00401000") -> "Pre Comment: Initialize system..."
    """
    return "\n".join(safe_get("get_comments", {"address": address}))

@mcp.tool()
def get_decompiler_comment(address: str) -> str:
    """
    Get the decompiler comment at a specific address.

    Retrieves the pre-comment shown in decompiled view.

    Parameters:
        address: Address to get comment from (e.g., "00401000")

    Returns: Decompiler comment or message if none found

    Note: These comments appear above lines in decompiled code.

    Example: get_decompiler_comment("00401000") -> "Initialize hardware registers"
    """
    return "\n".join(safe_get("get_decompiler_comment", {"address": address}))

@mcp.tool()
def get_disassembly_comment(address: str) -> str:
    """
    Get the disassembly comment at a specific address.

    Retrieves the end-of-line comment shown in disassembly view.

    Parameters:
        address: Address to get comment from (e.g., "00401000")

    Returns: Disassembly comment or message if none found

    Note: These comments appear at the end of assembly lines.

    Example: get_disassembly_comment("00401000") -> "Save return address"
    """
    return "\n".join(safe_get("get_disassembly_comment", {"address": address}))

if __name__ == "__main__":
    mcp.run()
