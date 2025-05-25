# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
ghidra_server_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GHIDRA_SERVER

mcp = FastMCP("ghidra-mcp")

def safe_get(endpoint: str, params: dict = None) -> list:
    """Execute a GET request with optional parameters."""
    if params is None:
        params = {}

    url = f"{ghidra_server_url}/{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=5)
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

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List function names in the loaded Ghidra program with pagination.
    
    Functions are defined subroutines in the binary (both user-defined and auto-discovered).
    
    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum function names to return
    
    Returns: List of function names or error message if no program loaded
    
    Example: list_methods(0, 10) -> ['main', 'printf', 'malloc', ...]
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List namespace/class names in the loaded Ghidra program with pagination.
    
    Namespaces organize symbols hierarchically, often corresponding to classes in source code.
    
    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum namespace/class names to return
    
    Returns: List of namespace/class names or error message if no program loaded
    
    Example: list_classes(0, 10) -> ['String', 'ArrayList', 'HashMap', ...]
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def rename_struct_field(struct_name: str, old_field_name: str, new_field_name: str) -> str:
    """
    Rename a field within a structure data type.
    
    Improves readability of decompiled code. Structure must exist in data type manager.
    
    Parameters:
        struct_name: Structure name (without path)
        old_field_name: Current name (user-defined or auto-generated like "field1_0x10")
        new_field_name: New name to assign
    
    Returns: Success or failure message
    
    Note: For auto-names like "field1_0x10", the number after "field" is the component index.
    
    Example: rename_struct_field("HWND", "field0_0x0", "handle")
    """
    return safe_post("renameStructField", {
        "structName": struct_name,
        "oldFieldName": old_field_name, 
        "newFieldName": new_field_name
    })

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a function by name to C-like pseudocode.
    
    Converts assembly to readable code with high-level constructs (loops, conditionals).
    
    Parameters:
        name: Function name (must match exactly)
    
    Returns: Decompiled C code or error message
    
    Note: Variable names may be auto-generated (e.g., "local_10") unless renamed.
    
    Example: decompile_function("main") -> "int main(int argc, char **argv) {...}"
    """
    return safe_post("decompile", name)

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
    return safe_get("references", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    
    Documents code purpose and improves decompiled output readability.
    
    Parameters:
        old_name: Current function name
        new_name: New function name
    
    Returns: Success or failure message
    
    Note: Function names must be unique within the program.
    
    Example: rename_function("FUN_00401000", "initialize_system")
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

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
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_structures(offset: int = 0, limit: int = 100) -> list:
    """
    List structure/type definitions in the program with pagination.
    
    Structures represent complex data types similar to C structs.
    
    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum structures to return
    
    Returns: Structures with fields in format "StructName: {type1 field1, type2 field2, ...}"
    
    Example: list_structures(0, 5) -> ['POINT: {int x, int y}', 'RECT: {int left...}', ...]
    """
    return safe_get("structures", {"offset": offset, "limit": limit})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List memory segments in the program with pagination.
    
    Shows distinct regions in binary's address space (.text, .data, .rodata, etc.)
    
    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum segments to return
    
    Returns: Memory segments with name and address range
    
    Example: list_segments() -> ['.text: 00401000 - 00410000', '.data: 00411000 - 00412000', ...]
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    
    Shows functions/data used from external libraries, resolved at load time.
    
    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum imports to return
    
    Returns: Imported symbols with their addresses
    
    Example: list_imports(0, 5) -> ['printf -> EXTERNAL:00000000', 'malloc -> EXTERNAL:00000000', ...]
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    
    Shows functions/data made available to other modules (public API in libraries).
    
    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum exports to return
    
    Returns: Exported symbols with their addresses
    
    Example: list_exports(0, 5) -> ['initialize_library -> 00401000', 'get_version -> 00401050', ...]
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List non-global namespaces in the program with pagination.
    
    Namespaces organize symbols hierarchically (like classes, modules, or packages).
    
    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum namespaces to return
    
    Returns: List of namespace names excluding global namespace
    
    Note: Similar to list_classes() but focuses on namespace concept.
    
    Example: list_namespaces(0, 5) -> ['com', 'com.example', 'com.example.app', ...]
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_symbols(offset: int = 0, limit: int = 100) -> list:
    """
    List all symbols (functions, variables, labels, etc.) with pagination.
    
    Comprehensive listing of all named entities in the program.
    
    Parameters:
        offset: Starting index for pagination (0-based)
        limit: Maximum symbols to return
    
    Returns: Symbols with addresses in format "symbol_name -> address"
    
    Note: More comprehensive than list_methods() or list_imports().
    
    Example: list_symbols(0, 5) -> ['main -> 00401000', 'gVar1 -> 00410010', ...]
    """
    return safe_get("symbols", {"offset": offset, "limit": limit})

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
    return safe_get("data", {"offset": offset, "limit": limit})

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
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

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
def list_functions() -> list:
    """
    List all functions in the database with their addresses.
    
    Complete listing without pagination (unlike list_methods()).
    
    Parameters: None
    
    Returns: Functions as "function_name at address"
    
    Note: For large programs, use list_methods() with pagination instead.
    
    Example: list_functions() -> ['main at 00401000', 'initialize at 00401050', ...]
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address to C-like pseudocode.
    
    Converts assembly code to readable high-level code for the specified function.
    
    Parameters:
        address: Function address (e.g., "00401000") - can be entry point or any address within function
    
    Returns: Decompiled C code or error message
    
    Note: Variable names may be auto-generated unless renamed. Tries exact address match first.
    
    Example: decompile_function_by_address("00401000") -> "int main(int argc, char **argv) {...}"
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code for a function with address and comments.
    
    Retrieves assembly instructions for function at or containing the specified address.
    
    Parameters:
        address: Function address (e.g., "00401000") - can be entry point or any address within
    
    Returns: List of assembly instructions with format "address: instruction [; comment]"
    
    Note: Assembly syntax depends on processor architecture. Shows EOL comments if present.
    
    Example: disassemble_function("00401000") -> ['00401000: PUSH EBP', '00401001: MOV EBP,ESP', ...]
    """
    return safe_get("disassemble_function", {"address": address})

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
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function identified by its address.
    
    Alternative to rename_function() that uses address instead of current name.
    
    Parameters:
        function_address: Address of function (e.g., "00401000")
        new_name: New name to assign
    
    Returns: Success or failure message
    
    Note: Function names must be unique. Will find function at or containing the address.
    
    Example: rename_function_by_address("00401000", "initialize_system")
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

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
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set data type for a local variable in a function.
    
    Improves decompiler output and clarifies variable purpose.
    
    Parameters:
        function_address: Function address (e.g., "00401000")
        variable_name: Variable name to change
        new_type: New data type as string ("int", "char *", "POINT", etc.)
    
    Returns: Detailed operation info (variable, type resolution, success/failure)
    
    Note: Supports built-in types, pointers, and structures. Windows-style types also supported.
    
    Example: set_local_variable_type("00401000", "local_10", "POINT")
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> dict:
    """
    Rename a local variable within a function identified by name.
    
    Improves readability of decompiled code by using meaningful variable names.
    
    Parameters:
        function_name: Name of function containing the variable
        old_name: Current variable name
        new_name: New variable name to assign
        usage_address: Address where variable is used (optional, for context)
    
    Returns: Dictionary with status and list of variables in the function
    
    Note: Uses function name rather than address. Variable names must be unique within scope.
    
    Example: rename_variable("main", "local_10", "configValue")
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

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
def search_memory(query: str, as_string: bool = True, block_name: str = None, limit: int = 10) -> str:
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
        "asString": "true" if as_string else "false",
        "limit": limit
    }
    if block_name:
        params["blockName"] = block_name
    
    return "\n".join(safe_get("searchMemory", params))

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
    return safe_get("searchDisassembly", {"query": query, "offset": offset, "limit": limit})

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
    return "\n".join(safe_get("searchDecompiled", {"query": query, "offset": offset, "limit": limit}))

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

if __name__ == "__main__":
    mcp.run()
