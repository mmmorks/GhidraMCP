package com.lauriewired.mcp.services;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.features.base.memsearch.bytesequence.ExtendedByteSequence;
import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.TextOutput;
import com.lauriewired.mcp.model.ToolOutput;

/**
 * Service for search-related operations in Ghidra
 */
public class SearchService {
    private final ProgramService programService;

    /**
     * Creates a new SearchService
     *
     * @param programService the program service for accessing the current program
     */
    public SearchService(ProgramService programService) {
        this.programService = programService;
    }

    @McpTool(description = """
        Search program memory for byte patterns or strings.

        Searches initialized memory blocks for specified patterns and shows context around matches.

        Returns: Memory matches with address, label, and context bytes

        Example: search_memory("Password", True) -> matches of "Password" string in memory """)
    public ToolOutput searchMemory(
            @Param("The pattern to search for (string or hex bytes like \"00 FF 32\")") String query,
            @Param(value = "True to search for UTF-8 string, False to search for hex bytes", defaultValue = "true") boolean asString,
            @Param(value = "Optional memory block name to restrict search", defaultValue = "") String blockName,
            @Param(value = "Maximum number of results to return", defaultValue = "10") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (query == null || query.isEmpty()) return StatusOutput.error("Search query is required");

        List<String> results = new ArrayList<>();
        Memory memory = program.getMemory();

        try {
            // Create a byte matcher based on the input type
            ByteMatcher matcher;
            int patternLength;
            
            if (asString) {
                final byte[] searchPattern = query.getBytes(StandardCharsets.UTF_8);
                SearchSettings settings = new SearchSettings();
                settings.withSearchFormat(SearchFormat.STRING);
                matcher = new ByteMatcher(query, settings) {
                    @Override
                    public Iterable<ByteMatcher.ByteMatch> match(ExtendedByteSequence ebs) {
                        List<ByteMatch> matches = new ArrayList<>();
                        
                        // Skip if sequence is shorter than the pattern
                        if (ebs.getLength() < searchPattern.length) {
                            return matches;
                        }
                        
                        // Search for pattern in the sequence
                        for (int i = 0; i <= ebs.getLength() - searchPattern.length; i++) {
                            boolean found = true;
                            for (int j = 0; j < searchPattern.length; j++) {
                                if (ebs.getByte(i + j) != searchPattern[j]) {
                                    found = false;
                                    break;
                                }
                            }
                            
                            if (found) {
                                final int offset = i;
                                matches.add(new ByteMatcher.ByteMatch(offset, searchPattern.length));
                            }
                        }
                        
                        return matches;
                    }

                    @Override
                    public String getDescription() {
                        return "String: " + query;
                    }

                    @Override
                    public String getToolTip() {
                        return "Searching for string";
                    }
                };
                patternLength = query.getBytes(StandardCharsets.UTF_8).length;
            } else {
                // Parse hex strings for byte pattern searches
                String[] byteStrings = query.split("\\s+");
                byte[] bytePattern = new byte[byteStrings.length];
                boolean[] wildcardMask = new boolean[byteStrings.length];
                
                for (int i = 0; i < byteStrings.length; i++) {
                    if (byteStrings[i].equals("??")) {
                        wildcardMask[i] = true;
                        bytePattern[i] = 0; // Value doesn't matter for wildcards
                    } else {
                        wildcardMask[i] = false;
                        bytePattern[i] = (byte) Integer.parseInt(byteStrings[i], 16);
                    }
                }
                
                // Create a byte matcher for hex pattern
                final byte[] pattern = bytePattern;
                final boolean[] mask = wildcardMask;
                SearchSettings settings = new SearchSettings();
                settings.withSearchFormat(SearchFormat.HEX);
                
                matcher = new ByteMatcher(query, settings) {
                    @Override
                    public Iterable<ByteMatcher.ByteMatch> match(ExtendedByteSequence ebs) {
                        List<ByteMatch> matches = new ArrayList<>();
                        
                        // Skip if sequence is shorter than the pattern
                        if (ebs.getLength() < pattern.length) {
                            return matches;
                        }
                        
                        // Search for pattern in the sequence
                        for (int i = 0; i <= ebs.getLength() - pattern.length; i++) {
                            boolean found = true;
                            for (int j = 0; j < pattern.length; j++) {
                                // Skip wildcards
                                if (mask[j]) {
                                    continue;
                                }
                                
                                if (ebs.getByte(i + j) != pattern[j]) {
                                    found = false;
                                    break;
                                }
                            }
                            
                            if (found) {
                                final int offset = i;
                                matches.add(new ByteMatcher.ByteMatch(offset, pattern.length));
                            }
                        }
                        
                        return matches;
                    }

                    @Override
                    public String getDescription() {
                        return "Hex Pattern";
                    }

                    @Override
                    public String getToolTip() {
                        return "Searching for hex byte pattern with wildcards";
                    }
                };
                patternLength = bytePattern.length;
            }
            
            // Define the search area
            AddressSet searchSet = new AddressSet();
            if (blockName != null && !blockName.isEmpty()) {
                MemoryBlock block = memory.getBlock(blockName);
                if (block == null) {
                    return StatusOutput.error("Memory block not found: " + blockName);
                }
                searchSet.add(block.getStart(), block.getEnd());
            } else {
                // Search all initialized memory if no block specified
                for (MemoryBlock block : memory.getBlocks()) {
                    if (block.isInitialized()) {
                        searchSet.add(block.getStart(), block.getEnd());
                    }
                }
            }
            
            // Create a program byte source for the memory search
            ProgramByteSource byteSource = new ProgramByteSource(program);
            
            // Create a memory searcher with the proper parameters
            MemorySearcher searcher = new MemorySearcher(byteSource, matcher, searchSet, limit);
            
            // Perform the search
            List<Address> matches = new ArrayList<>();
            int count = 0;
            MemoryMatch memMatch;
            
            Address startAddr = searchSet.getMinAddress();
            while ((memMatch = searcher.findNext(startAddr, TaskMonitor.DUMMY)) != null && count < limit) {
                Address matchAddress = memMatch.getAddress();
                matches.add(matchAddress);
                startAddr = matchAddress.next();
                count++;
            }
            
            // Format results
            for (Address matchAddr : matches) {
                results.add(formatMemoryMatch(program, memory, matchAddr, patternLength));
            }
            
        } catch (NumberFormatException e) {
            return StatusOutput.error("Error searching memory: " + e.getMessage());
        }

        if (results.isEmpty()) {
            return new TextOutput("No matches found for query: " + query);
        }

        return new TextOutput(String.join("\n\n", results));
    }
    
    /**
     * Format a memory match with context
     */
    private String formatMemoryMatch(Program program, Memory memory, Address matchAddr, int matchLength) {
        StringBuilder result = new StringBuilder();
        result.append("Match at: ").append(matchAddr);
        
        // Get memory block info
        MemoryBlock block = memory.getBlock(matchAddr);
        if (block != null) {
            result.append(" (").append(block.getName()).append(")");
        }
        result.append("\n");
        
        // Check if there's a label at this address
        if (program.getSymbolTable().getPrimarySymbol(matchAddr) != null) {
            String label = program.getSymbolTable().getPrimarySymbol(matchAddr).getName();
            result.append("Label: ").append(label).append("\n");
        }
        
        // Get memory context (16 bytes before and after)
        int contextSize = 16;
        Address startContextAddr = matchAddr.subtract(contextSize);
        Address endContextAddr = matchAddr.add(matchLength + contextSize - 1);
        
        // Ensure context addresses are in valid memory
        if (block != null) {
            if (startContextAddr.compareTo(block.getStart()) < 0) {
                startContextAddr = block.getStart();
            }
            if (endContextAddr.compareTo(block.getEnd()) > 0) {
                endContextAddr = block.getEnd();
            }
        }
        
        int totalBytes = (int)endContextAddr.subtract(startContextAddr) + 1;
        if (totalBytes > 0) {
            byte[] context = new byte[totalBytes];
            try {
                memory.getBytes(startContextAddr, context, 0, context.length);
                
                // Format bytes in rows of 16
                result.append("Context:\n");
                for (int i = 0; i < context.length; i += 16) {
                    Address rowAddr = startContextAddr.add(i);
                    result.append(String.format("%s: ", rowAddr));
                    
                    // Print hex bytes
                    for (int j = 0; j < 16 && (i + j) < context.length; j++) {
                        // Highlight the matching bytes
                        boolean isMatch = rowAddr.add(j).compareTo(matchAddr) >= 0 && 
                                        rowAddr.add(j).compareTo(matchAddr.add(matchLength - 1)) <= 0;
                        
                        if (isMatch) {
                            result.append(String.format("[%02X] ", context[i + j] & 0xFF));
                        } else {
                            result.append(String.format("%02X ", context[i + j] & 0xFF));
                        }
                    }
                    
                    // ASCII representation
                    result.append(" | ");
                    for (int j = 0; j < 16 && (i + j) < context.length; j++) {
                        char c = (char)(context[i + j] & 0xFF);
                        if (c >= 32 && c < 127) {
                            result.append(c);
                        } else {
                            result.append('.');
                        }
                    }
                    result.append("\n");
                }
            } catch (MemoryAccessException e) {
                result.append("Could not read memory context: ").append(e.getMessage());
            }
        }
        
        return result.toString();
    }

    @McpTool(description = """
        Search for patterns in disassembled code using regex.

        Searches instruction mnemonics, operands, and comments in functions.

        Returns: Matching instructions with function context and nearby instructions

        Example: search_disassembly("mov.*eax") -> finds MOV instructions using EAX register """)
    public ToolOutput searchDisassembly(
            @Param("Regex pattern to search for in assembly instructions") String query,
            @Param(value = "Starting index for pagination", defaultValue = "0") int offset,
            @Param(value = "Maximum number of results to return", defaultValue = "10") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (query == null || query.isEmpty()) return StatusOutput.error("Search query is required");

        Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return StatusOutput.error("Invalid regex pattern: " + e.getMessage());
        }

        // Get the memory blocks to search through
        Memory memory = program.getMemory();
        List<MemoryBlock> codeBlocks = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute()) {
                codeBlocks.add(block);
            }
        }

        if (codeBlocks.isEmpty()) {
            return StatusOutput.error("No executable code blocks found in program");
        }
        
        List<String> results = new ArrayList<>();
        int resultCount = 0;
        
        // Search through all executable memory blocks
        for (MemoryBlock block : codeBlocks) {
            if (resultCount >= limit) break;
            
            Address start = block.getStart();
            Address end = block.getEnd();
            
            // Create a list to hold matched addresses (to group nearby matches)
            List<List<Instruction>> matchGroups = new ArrayList<>();
            List<Instruction> currentGroup = null;
            Address lastMatchEnd = null;
            int groupDistance = 10; // Max address distance to consider part of the same group
            
            // Get instructions from this memory block
            InstructionIterator instructions = program.getListing().getInstructions(start, true);
            
            // Search through all instructions in this block
            while (instructions.hasNext() && resultCount < limit) {
                Instruction instr = instructions.next();
                
                // Stop if we've gone past the end of the block
                if (instr.getAddress().compareTo(end) > 0) break;
                
                // Format the instruction with any comments
                String comment = program.getListing().getComment(
                    ghidra.program.model.listing.CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";
                
                String instrText = String.format("%s: %s %s", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment);
                
                // Check if this instruction matches the pattern
                Matcher matcher = pattern.matcher(instrText);
                if (matcher.find()) {
                    // Check if this match should be part of the current group
                    if (currentGroup == null || lastMatchEnd == null || 
                        instr.getAddress().subtract(lastMatchEnd) > groupDistance) {
                        // Start a new group
                        currentGroup = new ArrayList<>();
                        matchGroups.add(currentGroup);
                    }
                    
                    // Add this instruction to the current group
                    currentGroup.add(instr);
                    lastMatchEnd = instr.getAddress();
                    resultCount++;
                }
            }
            
            // Process the match groups and create formatted results
            for (List<Instruction> group : matchGroups) {
                if (group.isEmpty()) continue;
                
                StringBuilder groupResult = new StringBuilder();
                Address firstAddr = group.get(0).getAddress();
                
                // Add location header - see if this address is in a function
                Function function = program.getFunctionManager().getFunctionContaining(firstAddr);
                if (function != null) {
                    groupResult.append(String.format("Location: %s (in function %s)\n", 
                        firstAddr, function.getName()));
                } else {
                    groupResult.append(String.format("Location: %s\n", firstAddr));
                }
                groupResult.append("----------------------------------------\n");
                
                // Add context for instruction group
                int contextLines = 3;
                
                // Get instructions before the first match for context
                List<Instruction> beforeContext = new ArrayList<>();
                Address contextStart = firstAddr;
                for (int i = 0; i < contextLines; i++) {
                    contextStart = contextStart.previous();
                    if (contextStart == null) break;
                    
                    Instruction prevInstr = program.getListing().getInstructionAt(contextStart);
                    if (prevInstr == null) break;
                    
                    beforeContext.add(0, prevInstr); // Add at beginning to maintain order
                }
                
                // Add instructions before the matches
                for (Instruction instr : beforeContext) {
                    String comment = program.getListing().getComment(
                        ghidra.program.model.listing.CodeUnit.EOL_COMMENT, instr.getAddress());
                    comment = (comment != null) ? "; " + comment : "";
                    
                    groupResult.append(String.format("  %s: %s %s\n", 
                        instr.getAddress(), 
                        instr.toString(),
                        comment));
                }
                
                // Add the matching instructions with highlighting
                for (Instruction instr : group) {
                    String comment = program.getListing().getComment(
                        ghidra.program.model.listing.CodeUnit.EOL_COMMENT, instr.getAddress());
                    comment = (comment != null) ? "; " + comment : "";
                    
                    groupResult.append(String.format("→ %s: %s %s\n", 
                        instr.getAddress(), 
                        instr.toString(),
                        comment));
                }
                
                // Get instructions after the last match for context
                Instruction lastInstr = group.get(group.size() - 1);
                Address afterAddr = lastInstr.getAddress();
                
                for (int i = 0; i < contextLines; i++) {
                    afterAddr = afterAddr.next();
                    if (afterAddr == null) break;
                    
                    Instruction afterInstr = program.getListing().getInstructionAt(afterAddr);
                    if (afterInstr == null) break;
                    
                    String comment = program.getListing().getComment(
                        ghidra.program.model.listing.CodeUnit.EOL_COMMENT, afterInstr.getAddress());
                    comment = (comment != null) ? "; " + comment : "";
                    
                    groupResult.append(String.format("  %s: %s %s\n", 
                        afterInstr.getAddress(), 
                        afterInstr.toString(),
                        comment));
                }
                
                groupResult.append("\n");
                results.add(groupResult.toString());
            }
        }
        
        if (results.isEmpty()) {
            return new TextOutput("No matches found for pattern: " + query);
        }

        // Apply pagination
        int fromIndex = Math.min(offset, results.size());
        int toIndex = Math.min(offset + limit, results.size());
        List<String> paginatedResults = results.subList(fromIndex, toIndex);

        return new TextOutput(String.join("\n", paginatedResults));
    }

    @McpTool(description = """
        Search for patterns in decompiled C-like code using regex.

        Searches variables, expressions, and comments in decompiled functions.

        Returns: Matching code fragments with function context and surrounding lines

        Note: This is resource-intensive as each function must be decompiled.

        Example: search_decompiled("malloc\\\\(.*\\\\)") -> finds malloc calls in decompiled code """)
    public ToolOutput searchDecompiled(
            @Param("Regex pattern to search for in decompiled code") String query,
            @Param(value = "Starting index for pagination", defaultValue = "0") int offset,
            @Param(value = "Maximum number of functions to search/return", defaultValue = "5") int limit) {
        Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (query == null || query.isEmpty()) return StatusOutput.error("Search query is required");

        Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return StatusOutput.error("Invalid regex pattern: " + e.getMessage());
        }

        List<String> results = new ArrayList<>();
        FunctionManager functionManager = program.getFunctionManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        
        int resultCount = 0;
        int processedCount = 0;
        
        // For each function in the program
        for (Function function : functionManager.getFunctions(true)) {
            processedCount++;
            if (resultCount >= limit) break;
            
            // Decompile the function
            DecompileResults decompileResults = decomp.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (decompileResults == null || !decompileResults.decompileCompleted()) {
                continue;
            }
            
            String decompiled = decompileResults.getDecompiledFunction().getC();
            Matcher matcher = pattern.matcher(decompiled);
            
            // If found a match in this function
            if (matcher.find()) {
                // Build a nice result with context
                StringBuilder result = new StringBuilder();
                result.append(String.format("Function: %s at %s\n", function.getName(), function.getEntryPoint()));
                result.append("----------------------------------------\n");
                
                // Split the decompiled code into lines
                String[] lines = decompiled.split("\n");
                
                // Find the matching line numbers
                List<Integer> matchingLines = new ArrayList<>();
                for (int i = 0; i < lines.length; i++) {
                    if (pattern.matcher(lines[i]).find()) {
                        matchingLines.add(i);
                    }
                }
                
                // Add each match with context
                for (int lineNum : matchingLines) {
                    // Add context before match (up to 3 lines)
                    int startContext = Math.max(0, lineNum - 3);
                    for (int i = startContext; i < lineNum; i++) {
                        result.append("  ").append(lines[i]).append("\n");
                    }
                    
                    // Add matching line with highlighting
                    result.append("→ ").append(lines[lineNum]).append("\n");
                    
                    // Add context after match (up to 3 lines)
                    int endContext = Math.min(lines.length - 1, lineNum + 3);
                    for (int i = lineNum + 1; i <= endContext; i++) {
                        result.append("  ").append(lines[i]).append("\n");
                    }
                    
                    result.append("\n");
                }
                
                results.add(result.toString());
                resultCount++;
            }
            
            // Provide progress update periodically
            if (processedCount % 100 == 0) {
                Msg.info(this, "Processed " + processedCount + " functions for decompiled search");
            }
        }
        
        if (results.isEmpty()) {
            return new TextOutput("No matches found for pattern: " + query);
        }

        // Apply pagination
        int fromIndex = Math.min(offset, results.size());
        int toIndex = Math.min(offset + limit, results.size());
        List<String> paginatedResults = results.subList(fromIndex, toIndex);

        return new TextOutput(String.join("\n\n", paginatedResults));
    }
}
