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
    """
    Perform a GET request with optional query parameters.
    """
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
    List all function names in the currently loaded Ghidra program with pagination.
    
    In Ghidra, functions represent defined subroutines in the binary that have been
    identified during analysis. This includes both user-defined functions and
    automatically discovered ones.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of function names to return
    
    Returns:
        A list of strings containing function names. If no program is loaded,
        returns a single-item list with an error message.
    
    Example:
        >>> list_methods(0, 10)  # Get first 10 function names
        ['main', 'printf', 'malloc', ...]
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the currently loaded Ghidra program with pagination.
    
    In Ghidra, namespaces organize symbols hierarchically, similar to how classes
    organize code in object-oriented programming. This function returns all non-global
    namespaces, which often correspond to classes in the original source code.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of namespace/class names to return
    
    Returns:
        A list of strings containing namespace/class names. If no program is loaded,
        returns a single-item list with an error message.
    
    Example:
        >>> list_classes(0, 10)  # Get first 10 namespace/class names
        ['String', 'ArrayList', 'HashMap', ...]
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def rename_struct_field(struct_name: str, old_field_name: str, new_field_name: str) -> str:
    """
    Rename a field within a structure data type in the Ghidra program.
    
    This function allows you to change the name of a field in a structure, which
    improves readability and understanding of the decompiled code. The structure
    must already exist in the Ghidra program's data type manager.
    
    Parameters:
        struct_name: The name of the structure (without path)
        old_field_name: The current name of the field to rename. Can be either a user-defined
                        name or an auto-generated name like "field1_0x10"
        new_field_name: The new name to assign to the field
    
    Returns:
        A string indicating success or failure, with an error message if applicable.
    
    Notes:
        - For auto-generated field names like "field1_0x10", the number after "field"
          represents the index of the component in the structure.
        - This operation modifies the Ghidra program and cannot be undone except by
          renaming the field again.
    
    Example:
        >>> rename_struct_field("HWND", "field0_0x0", "handle")
        "Field renamed successfully"
    """
    return safe_post("renameStructField", {
        "structName": struct_name,
        "oldFieldName": old_field_name, 
        "newFieldName": new_field_name
    })

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    
    This function uses Ghidra's decompiler to convert assembly code into readable
    C-like pseudocode. The decompiler attempts to reconstruct high-level constructs
    like loops, conditionals, and function calls.
    
    Parameters:
        name: The name of the function to decompile. This should match exactly
              with a function name in the program.
    
    Returns:
        A string containing the decompiled C code if successful, or an error message
        if the function cannot be found or decompilation fails.
    
    Notes:
        - The quality of decompilation depends on how well Ghidra has analyzed the binary
        - Variable names may be auto-generated (e.g., "local_10") unless they've been renamed
        - Data types may be approximated based on usage patterns
    
    Example:
        >>> decompile_function("main")
        "int main(int argc, char **argv) {\\n  printf(\\"Hello, World!\\");\\n  return 0;\\n}"
    """
    return safe_post("decompile", name)

@mcp.tool()
def list_references(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    List all references (cross-references or xrefs) to the specified address with pagination.
    
    In reverse engineering, cross-references show where a particular address is referenced
    from in the code. This helps track how functions, variables, or data are used throughout
    the program.
    
    Parameters:
        address: The address to find references to, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000")
        offset: The starting index for pagination (0-based)
        limit: Maximum number of references to return
    
    Returns:
        A list of strings describing each reference, including the source address,
        reference type (call, data, etc.), and containing function if applicable.
        If no references are found or an error occurs, returns an appropriate message.
    
    Example:
        >>> list_references("00401000")
        ['00400f50 -> 00401000 (from CALL in main)', '00400f80 -> 00401000 (from CALL in init)']
    """
    return safe_get("references", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    
    Renaming functions is a key part of the reverse engineering process, as it helps
    document the purpose of code and improves readability of the decompiled output.
    
    Parameters:
        old_name: The current name of the function to rename
        new_name: The new name to assign to the function
    
    Returns:
        A string indicating success ("Renamed successfully") or failure ("Rename failed").
    
    Notes:
        - Function names must be unique within the program
        - Some names may be reserved or invalid in certain contexts
        - This operation modifies the Ghidra program and cannot be undone except by
          renaming the function again
    
    Example:
        >>> rename_function("FUN_00401000", "initialize_system")
        "Renamed successfully"
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    
    Data labels identify and name data elements in the binary, such as strings,
    arrays, structures, or other variables. Renaming these improves the readability
    of decompiled code that references this data.
    
    Parameters:
        address: The address of the data to rename, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000")
        new_name: The new name to assign to the data
    
    Returns:
        A string indicating that the rename operation was attempted. Success or failure
        is not directly reported in the return value.
    
    Notes:
        - This function will create a new label if one doesn't exist at the address
        - The address must point to defined data, not code
        - This operation modifies the Ghidra program and cannot be undone except by
          renaming the data again
    
    Example:
        >>> rename_data("00402000", "config_table")
        "Rename data attempted"
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_structures(offset: int = 0, limit: int = 100) -> list:
    """
    List all structure/type definitions in the program with pagination.
    
    Structures in Ghidra represent complex data types composed of multiple fields,
    similar to C structs. This function returns a list of all structures defined
    in the program's data type manager, along with their field information.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of structures to return
    
    Returns:
        A list of strings, each describing a structure and its fields in the format:
        "StructName: {type1 field1, type2 field2, ...}"
        If no program is loaded, returns a single-item list with an error message.
    
    Example:
        >>> list_structures(0, 5)
        ['POINT: {int x, int y}', 'RECT: {int left, int top, int right, int bottom}', ...]
    """
    return safe_get("structures", {"offset": offset, "limit": limit})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    
    Memory segments represent distinct regions in the binary's address space, such as
    code (.text), data (.data), read-only data (.rodata), etc. Understanding the
    memory layout is important for reverse engineering.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of segments to return
    
    Returns:
        A list of strings describing each memory segment, including name and address range.
        If no program is loaded, returns a single-item list with an error message.
    
    Example:
        >>> list_segments()
        ['.text: 00401000 - 00410000', '.data: 00411000 - 00412000', ...]
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    
    Imported symbols represent functions or data that the program uses from external
    libraries or modules. These are typically resolved at load time by the dynamic
    linker. Analyzing imports helps understand the program's dependencies and
    functionality.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of imported symbols to return
    
    Returns:
        A list of strings describing each imported symbol and its address.
        If no program is loaded, returns a single-item list with an error message.
    
    Example:
        >>> list_imports(0, 5)
        ['printf -> EXTERNAL:00000000', 'malloc -> EXTERNAL:00000000', ...]
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    
    Exported symbols represent functions or data that the program makes available
    for use by other modules. In libraries, these are the public API. In executables,
    exports are less common but may exist for plugins or dynamic interaction.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of exported symbols to return
    
    Returns:
        A list of strings describing each exported symbol and its address.
        If no program is loaded, returns a single-item list with an error message.
    
    Example:
        >>> list_exports(0, 5)
        ['initialize_library -> 00401000', 'get_version -> 00401050', ...]
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    
    Namespaces in Ghidra organize symbols hierarchically, similar to namespaces in
    programming languages. They often correspond to classes, modules, or packages
    in the original source code.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of namespaces to return
    
    Returns:
        A list of strings containing namespace names, excluding the global namespace.
        If no program is loaded, returns a single-item list with an error message.
    
    Notes:
        - This function is similar to list_classes() but focuses specifically on
          the namespace concept rather than implying class semantics
    
    Example:
        >>> list_namespaces(0, 5)
        ['com', 'com.example', 'com.example.app', ...]
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_symbols(offset: int = 0, limit: int = 100) -> list:
    """
    List all symbols (functions, variables, etc.) in the program with pagination.
    
    Symbols in Ghidra represent named entities in the program, including functions,
    variables, labels, and other named elements. This comprehensive listing includes
    all symbol types.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of symbols to return
    
    Returns:
        A list of strings describing each symbol and its address in the format:
        "symbol_name -> address"
        If no program is loaded, returns a single-item list with an error message.
    
    Notes:
        - This is a more comprehensive listing compared to specialized functions like
          list_methods() or list_imports()
        - The list may be very large for complex programs
    
    Example:
        >>> list_symbols(0, 5)
        ['main -> 00401000', 'gVar1 -> 00410010', 'init -> 00401100', ...]
    """
    return safe_get("symbols", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    
    Data items in Ghidra represent memory locations that contain data rather than code.
    These can include strings, arrays, structures, and primitive values that have been
    identified and typed during analysis.
    
    Parameters:
        offset: The starting index for pagination (0-based)
        limit: Maximum number of data items to return
    
    Returns:
        A list of strings describing each data item, including its address, label (if any),
        and value representation. If no program is loaded, returns a single-item list
        with an error message.
    
    Notes:
        - Data items without explicit labels will be shown as "(unnamed)"
        - Non-ASCII characters in values are escaped for display
    
    Example:
        >>> list_data_items(0, 3)
        ['00410000: hello_msg = "Hello, World!"', 
         '00410010: error_code = 0x1', 
         '00410014: (unnamed) = 0x0']
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    
    This function allows you to find functions by partial name matches, which is
    useful when exploring a large binary or looking for related functionality.
    The search is case-insensitive.
    
    Parameters:
        query: The substring to search for in function names (required)
        offset: The starting index for pagination (0-based)
        limit: Maximum number of matching functions to return
    
    Returns:
        A list of strings describing matching functions in the format:
        "function_name @ address"
        If no matches are found, returns a message indicating no matches.
        If query is empty, returns an error message.
    
    Example:
        >>> search_functions_by_name("init")
        ['initialize @ 00401000', 'init_display @ 00401050', 'reinitialize @ 00401100']
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get detailed information about a function at the specified address.
    
    This function retrieves information about the function located at or containing
    the specified address, including its name, signature, entry point, and body range.
    
    Parameters:
        address: The address to look up, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000")
    
    Returns:
        A string containing detailed information about the function, including:
        - Function name
        - Address
        - Function signature (parameter and return types)
        - Entry point address
        - Body address range (min to max)
        
        If no function is found at the address or an error occurs, returns an
        appropriate error message.
    
    Example:
        >>> get_function_by_address("00401000")
        "Function: main at 00401000
        Signature: int main(int argc, char ** argv)
        Entry: 00401000
        Body: 00401000 - 00401050"
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user in the Ghidra GUI.
    
    This function retrieves the address that is currently selected or under the
    cursor in Ghidra's Code Browser or Decompiler view. This is useful for
    context-aware operations that need to work with the user's current focus.
    
    Parameters:
        None
    
    Returns:
        A string containing the currently selected address in Ghidra's address format.
        If no address is selected or the Code Viewer service is not available,
        returns an appropriate error message.
    
    Notes:
        - This function requires that the Ghidra GUI is running and a program is loaded
        - The user must have selected a location in the Code Browser or Decompiler
    
    Example:
        >>> get_current_address()
        "00401234"
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get information about the function currently selected by the user in the Ghidra GUI.
    
    This function retrieves details about the function containing the address that
    is currently selected in Ghidra's Code Browser or Decompiler view. This is useful
    for context-aware operations that need to work with the user's current focus.
    
    Parameters:
        None
    
    Returns:
        A string containing information about the current function, including:
        - Function name
        - Entry point address
        - Function signature
        
        If no function contains the current selection, or if the Code Viewer service
        is not available, returns an appropriate error message.
    
    Notes:
        - This function requires that the Ghidra GUI is running and a program is loaded
        - The user must have selected a location within a defined function
    
    Example:
        >>> get_current_function()
        "Function: main at 00401000
        Signature: int main(int argc, char ** argv)"
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database with their addresses.
    
    This function provides a complete listing of all functions defined in the
    currently loaded program, along with their entry point addresses. Unlike
    list_methods(), this function returns address information for each function.
    
    Parameters:
        None
    
    Returns:
        A list of strings describing each function in the format:
        "function_name at address"
        If no program is loaded, returns a single-item list with an error message.
    
    Notes:
        - This function returns all functions at once without pagination
        - For large programs with many functions, consider using list_methods()
          with pagination instead
    
    Example:
        >>> list_functions()
        ['main at 00401000', 'initialize at 00401050', 'cleanup at 00401100', ...]
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address and return the decompiled C code.
    
    This function uses Ghidra's decompiler to convert assembly code into readable
    C-like pseudocode for the function at or containing the specified address.
    
    Parameters:
        address: The address of the function to decompile, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000"). This can be either the entry point
                of the function or any address within the function body.
    
    Returns:
        A string containing the decompiled C code if successful, or an error message
        if the function cannot be found or decompilation fails.
    
    Notes:
        - The quality of decompilation depends on how well Ghidra has analyzed the binary
        - Variable names may be auto-generated (e.g., "local_10") unless they've been renamed
        - Data types may be approximated based on usage patterns
        - This function will first try to find a function exactly at the given address,
          and if not found, will look for a function containing the address
    
    Example:
        >>> decompile_function_by_address("00401000")
        "int main(int argc, char **argv) {\\n  printf(\\"Hello, World!\\");\\n  return 0;\\n}"
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    
    This function retrieves the assembly instructions for the function at or containing
    the specified address. Each instruction is returned with its address and any
    associated end-of-line comments.
    
    Parameters:
        address: The address of the function to disassemble, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000"). This can be either the entry point
                of the function or any address within the function body.
    
    Returns:
        A list of strings, each representing one assembly instruction in the format:
        "address: instruction [; comment]"
        If no function is found at the address or an error occurs, returns an
        appropriate error message.
    
    Notes:
        - The assembly syntax depends on the processor architecture of the binary
        - Comments shown are end-of-line (EOL) comments from the Ghidra database
        - This function will first try to find a function exactly at the given address,
          and if not found, will look for a function containing the address
    
    Example:
        >>> disassemble_function("00401000")
        ['00401000: PUSH EBP', '00401001: MOV EBP,ESP', '00401003: CALL printf ; Print greeting']
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    
    This function adds a pre-comment to the specified address in the decompiled
    C-like pseudocode view. Comments help document the code and explain its purpose
    or behavior, which is especially valuable in reverse engineering.
    
    Parameters:
        address: The address where the comment should be placed, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000")
        comment: The text of the comment to add
    
    Returns:
        A string indicating success ("Comment set successfully") or failure
        ("Failed to set comment") with any error details.
    
    Notes:
        - Comments are stored in the Ghidra program database and will persist
          between sessions
        - This adds a PRE_COMMENT, which appears before the line in the decompiler view
        - This operation modifies the Ghidra program and cannot be undone except by
          removing or changing the comment
    
    Example:
        >>> set_decompiler_comment("00401010", "Initialize the configuration")
        "Comment set successfully"
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly view.
    
    This function adds an end-of-line (EOL) comment to the specified address in the
    assembly listing view. Comments help document the code and explain its purpose
    or behavior, which is especially valuable in reverse engineering.
    
    Parameters:
        address: The address where the comment should be placed, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000")
        comment: The text of the comment to add
    
    Returns:
        A string indicating success ("Comment set successfully") or failure
        ("Failed to set comment") with any error details.
    
    Notes:
        - Comments are stored in the Ghidra program database and will persist
          between sessions
        - This adds an EOL_COMMENT, which appears at the end of the line in the
          disassembly view
        - This operation modifies the Ghidra program and cannot be undone except by
          removing or changing the comment
    
    Example:
        >>> set_disassembly_comment("00401010", "Initialize EAX register")
        "Comment set successfully"
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function identified by its address.
    
    This function changes the name of a function at the specified address, which
    improves readability and understanding of the program. Unlike rename_function(),
    which requires the current function name, this function identifies the target
    function by its address.
    
    Parameters:
        function_address: The address of the function to rename, in Ghidra's address format
                          (e.g., "00401000" or "ram:00401000")
        new_name: The new name to assign to the function
    
    Returns:
        A string indicating success ("Function renamed successfully") or failure
        ("Failed to rename function") with any error details.
    
    Notes:
        - Function names must be unique within the program
        - Some names may be reserved or invalid in certain contexts
        - This operation modifies the Ghidra program and cannot be undone except by
          renaming the function again
        - This function will look for a function exactly at the given address, or
          containing the address if no exact match is found
    
    Example:
        >>> rename_function_by_address("00401000", "initialize_system")
        "Function renamed successfully"
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set or modify a function's signature/prototype.
    
    This function changes the signature of a function at the specified address,
    including its return type, parameter types, and parameter names. This is
    particularly useful for improving the decompiler output by providing more
    accurate type information.
    
    Parameters:
        function_address: The address of the function to modify, in Ghidra's address format
                          (e.g., "00401000" or "ram:00401000")
        prototype: The new function prototype in C-style syntax, including return type,
                   function name, and parameters. For example:
                   "int main(int argc, char **argv)"
    
    Returns:
        A string indicating success or failure, with additional details or error messages.
        Successful operations may include warnings or debug information.
    
    Notes:
        - The prototype must follow C syntax rules
        - The function name in the prototype is ignored; only the types matter
        - Parameter names will be applied to the function's variables
        - This operation modifies the Ghidra program and cannot be undone except by
          setting the prototype again
        - This function may affect the decompiler output significantly
    
    Example:
        >>> set_function_prototype("00401000", "int process_data(char *buffer, size_t length)")
        "Function prototype set successfully"
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set or change the data type of a local variable in a function.
    
    This function modifies the data type of a local variable within a function,
    which can improve the accuracy of the decompiler output and help in understanding
    the variable's purpose and usage.
    
    Parameters:
        function_address: The address of the function containing the variable,
                          in Ghidra's address format (e.g., "00401000")
        variable_name: The name of the variable whose type should be changed
        new_type: The new data type to assign, as a string. This can be:
                  - A built-in type (e.g., "int", "char", "float")
                  - A pointer type (e.g., "char *" or "PCHAR" for Windows-style pointers)
                  - A structure name (e.g., "POINT" or "FILE")
    
    Returns:
        A string containing detailed information about the operation, including:
        - The variable and type being set
        - Whether the type was found in the data type manager
        - Success or failure status
    
    Notes:
        - If the exact type is not found, the function will try to resolve it using
          common naming conventions or fall back to a default type
        - Windows-style pointer types (e.g., "PVOID" for "void*") are supported
        - This operation modifies the Ghidra program and cannot be undone except by
          changing the type again
        - This function uses Ghidra's high-level variable system (HighVariable)
    
    Example:
        >>> set_local_variable_type("00401000", "local_10", "POINT")
        "Setting variable type: local_10 to POINT in function at 00401000
        
        Found type: /POINT
        
        Result: Variable type set successfully"
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> dict:
    """
    Rename a local variable within a function identified by name.

    This function changes the name of a local variable within a function's scope
    which improves readability of the decompiled code. Unlike rename_local_variable()
    which identifies the function by address, this function uses the function's name.

    Parameters:
        function_name: The name of the function containing the variable
        old_name: The current name of the variable to rename
        new_name: The new name to assign to the variable

    Returns:
        A dictionary containing:
        - 'status': A string indicating success ("Variable renamed") or failure with an error message
        - 'variables': A list of dictionaries, each containing information about a variable in the function:
            - 'name': The variable name
            - 'dataType': The variable's data type

    Notes:
        - This operation affects how the variable appears in the decompiler view
        - Variable names must be unique within the function's scope
        - This operation modifies the Ghidra program and cannot be undone except by
          renaming the variable again
        - If multiple functions have the same name, the first one found will be used

    Example:
        >>> result = rename_variable("main", "local_10", "configValue")
        >>> print(result['status'])
        "Variable renamed"
        >>> print(len(result['variables']))
        5
        >>> print(result['variables'][0]['name'])
        "configValue"
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
    
    This function performs control flow analysis on the specified function and
    returns a detailed textual representation of its control flow graph (CFG).
    The CFG shows how basic blocks are connected through different types of
    control flow transfers (jumps, calls, returns).
    
    Parameters:
        address: The address of the function to analyze, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000"). This can be either the entry point
                of the function or any address within the function body.
    
    Returns:
        A multi-line string containing a detailed description of the function's
        control flow graph, including:
        - Basic blocks with their address ranges
        - Flow types between blocks (conditional/unconditional jumps, calls, returns)
        - Instructions within each block
        
        If no function is found at the address or an error occurs, returns an
        appropriate error message.
    
    Notes:
        - Basic blocks are sequences of instructions with a single entry point and
          a single exit point (no branches in or out except at the beginning and end)
        - This analysis uses Ghidra's BasicBlockModel to identify blocks and their
          relationships
        - Understanding control flow is essential for comprehending program logic,
          especially for complex functions with multiple branches and loops
    
    Example:
        >>> analyze_control_flow("00401000")
        "Control Flow Analysis for function: main at 00401000
        
        Block at 00401000 (00401000 - 00401010)
          - Conditional Jump to 00401020
          - Fallthrough to 00401011
          Instructions:
            00401000: PUSH EBP
            00401001: MOV EBP,ESP
            00401003: CMP EAX,0
            00401006: JZ 00401020
            ...
        "
    """
    return "\n".join(safe_get("analyze_control_flow", {"address": address}))

@mcp.tool()
def analyze_data_flow(address: str, variable: str) -> str:
    """
    Analyze the data flow for a variable in a function.
    
    This function performs data flow analysis on a specific variable within the
    specified function. It tracks where the variable is defined (written to) and
    where it is used (read from) throughout the function's execution paths.
    
    Parameters:
        address: The address of the function to analyze, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000")
        variable: The name of the variable to track within the function
    
    Returns:
        A multi-line string containing a detailed analysis of the variable's data flow,
        including:
        - Variable information (name, type, storage locations)
        - All definitions (where the variable is assigned values)
        - All uses (where the variable's value is read)
        - The instructions associated with each definition and use
        
        If the function or variable is not found, or an error occurs, returns an
        appropriate error message.
    
    Notes:
        - This analysis uses Ghidra's decompiler and PCode operations to track
          variable usage at a low level
        - Data flow analysis helps understand how values propagate through a program
        - This is particularly useful for understanding complex algorithms or
          identifying potential vulnerabilities
        - The analysis works with Ghidra's high-level variables (HighVariable)
    
    Example:
        >>> analyze_data_flow("00401000", "local_10")
        "Data Flow Analysis for variable 'local_10' in function main at 00401000
        
        Variable information:
          Name: local_10
          Type: int
          Storage: EBP-0x10
        
        Variable definitions and uses:
          00401010: DEFINE: COPY - MOV EAX,0x5
          00401015: USE: INT_ADD - ADD EAX,EBX
          ...
        "
    """
    return "\n".join(safe_get("analyze_data_flow", {"address": address, "variable": variable}))

@mcp.tool()
def analyze_call_graph(address: str, depth: int = 2) -> str:
    """
    Analyze the call graph starting from a function.
    
    This function generates a hierarchical representation of function calls starting
    from the specified function. It shows which functions are called by the starting
    function, which functions those functions call, and so on up to the specified depth.
    
    Parameters:
        address: The address of the function to start from, in Ghidra's address format
                (e.g., "00401000" or "ram:00401000")
        depth: The maximum depth to traverse in the call hierarchy (default: 2, max: 5).
               Higher values provide more comprehensive analysis but may produce
               very large outputs.
    
    Returns:
        A multi-line string containing a hierarchical representation of the call graph,
        showing:
        - The hierarchy of function calls with proper indentation
        - Function names and addresses at each level
        - Cycle detection to avoid infinite recursion (marked as "already visited")
        
        If the function is not found or an error occurs, returns an appropriate
        error message.
    
    Notes:
        - This analysis only considers static function calls that can be determined
          from the code (not dynamic calls through function pointers)
        - The depth is limited to 5 to prevent excessive output
        - Understanding call graphs is essential for comprehending program structure
          and data/control flow between functions
        - This can help identify important functions and understand program architecture
    
    Example:
        >>> analyze_call_graph("00401000", 3)
        "Call Graph Analysis for function: main at 00401000 (depth: 3)
        
        - main at 00401000
          - initialize at 00401050
            - allocate_memory at 00401100
            - setup_defaults at 00401200
          - process_input at 00401300
            - validate_data at 00401400
          - cleanup at 00401500 (already visited)
        "
    """
    return "\n".join(safe_get("analyze_call_graph", {"address": address, "depth": depth}))

@mcp.tool()
def get_symbol_address(symbol_name: str) -> str:
    """
    Get the memory address of a named symbol in the program.
    
    This function looks up a symbol by name in the current program's symbol table
    and returns its memory address. Symbols can be functions, variables, labels,
    or any other named entity in the binary.
    
    Parameters:
        symbol_name: The name of the symbol to look up. Must match exactly with
                     a symbol name in the program.
    
    Returns:
        A string containing the memory address of the symbol in Ghidra's address format
        (e.g., "00401000"). If the symbol is not found or multiple symbols with the
        same name exist, returns an appropriate error message.
    
    Notes:
        - This function is case-sensitive and requires an exact match with the symbol name
        - For functions, this returns the entry point address
        - For data, this returns the address where the data is stored
        - This is useful for cross-referencing symbols or finding the location of
          specific functions or variables in the binary
    
    Example:
        >>> get_symbol_address("main")
        "00401000"
        >>> get_symbol_address("gConfigData")
        "00403A20"
    """
    return "\n".join(safe_get("get_symbol_address", {"symbol_name": symbol_name}))

if __name__ == "__main__":
    mcp.run()
