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
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.TextOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.utils.JsonBuilder;

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
            return StatusOutput.error("No matches found for query: " + query);
        }

        JsonBuilder.JsonArrayBuilder matchesArray = JsonBuilder.array();
        for (String r : results) {
            matchesArray.addRaw(r);
        }

        String json = JsonBuilder.object()
                .put("query", query)
                .put("matchCount", results.size())
                .putArray("matches", matchesArray)
                .build();
        return new JsonOutput(json);
    }

    /**
     * Format a memory match as a JSON object string
     */
    private String formatMemoryMatch(Program program, Memory memory, Address matchAddr, int matchLength) {
        MemoryBlock block = memory.getBlock(matchAddr);
        String blockName = block != null ? block.getName() : null;

        ghidra.program.model.symbol.Symbol sym = program.getSymbolTable().getPrimarySymbol(matchAddr);
        String label = sym != null ? sym.getName() : null;

        // Build hex context
        StringBuilder context = new StringBuilder();
        int contextSize = 16;
        Address startContextAddr = matchAddr.subtract(contextSize);
        Address endContextAddr = matchAddr.add(matchLength + contextSize - 1);
        if (block != null) {
            if (startContextAddr.compareTo(block.getStart()) < 0) startContextAddr = block.getStart();
            if (endContextAddr.compareTo(block.getEnd()) > 0) endContextAddr = block.getEnd();
        }
        int totalBytes = (int) endContextAddr.subtract(startContextAddr) + 1;
        if (totalBytes > 0) {
            byte[] bytes = new byte[totalBytes];
            try {
                memory.getBytes(startContextAddr, bytes, 0, bytes.length);
                for (int i = 0; i < bytes.length; i++) {
                    if (i > 0) context.append(' ');
                    context.append(String.format("%02X", bytes[i] & 0xFF));
                }
            } catch (MemoryAccessException e) {
                context.append("unreadable");
            }
        }

        JsonBuilder b = JsonBuilder.object()
                .put("address", matchAddr.toString());
        if (blockName != null) b.put("block", blockName);
        if (label != null) b.put("label", label);
        b.put("context", context.toString());
        return b.build();
    }

    @McpTool(outputType = JsonOutput.class, description = """
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

        Memory memory = program.getMemory();
        List<MemoryBlock> codeBlocks = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute()) codeBlocks.add(block);
        }

        if (codeBlocks.isEmpty()) {
            return StatusOutput.error("No executable code blocks found in program");
        }

        JsonBuilder.JsonArrayBuilder matchesArray = JsonBuilder.array();
        int resultCount = 0;

        for (MemoryBlock block : codeBlocks) {
            if (resultCount >= limit) break;

            Address start = block.getStart();
            Address end = block.getEnd();
            InstructionIterator instructions = program.getListing().getInstructions(start, true);

            while (instructions.hasNext() && resultCount < limit) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) break;

                String instrText = instr.getAddress() + ": " + instr.toString();
                Matcher matcher = pattern.matcher(instrText);
                if (matcher.find()) {
                    Function function = program.getFunctionManager().getFunctionContaining(instr.getAddress());

                    // Build context lines
                    JsonBuilder.JsonArrayBuilder contextArray = JsonBuilder.array();

                    // Before context
                    int contextLines = 3;
                    Address contextStart = instr.getAddress();
                    List<Instruction> beforeCtx = new ArrayList<>();
                    for (int i = 0; i < contextLines; i++) {
                        contextStart = contextStart.previous();
                        if (contextStart == null) break;
                        Instruction prevInstr = program.getListing().getInstructionAt(contextStart);
                        if (prevInstr == null) break;
                        beforeCtx.add(0, prevInstr);
                    }
                    for (Instruction ctx : beforeCtx) {
                        contextArray.addRaw(JsonBuilder.object()
                                .put("address", ctx.getAddress().toString())
                                .put("text", ctx.toString())
                                .put("isMatch", false)
                                .build());
                    }

                    // The match itself
                    contextArray.addRaw(JsonBuilder.object()
                            .put("address", instr.getAddress().toString())
                            .put("text", instr.toString())
                            .put("isMatch", true)
                            .build());

                    // After context
                    Address afterAddr = instr.getAddress();
                    for (int i = 0; i < contextLines; i++) {
                        afterAddr = afterAddr.next();
                        if (afterAddr == null) break;
                        Instruction afterInstr = program.getListing().getInstructionAt(afterAddr);
                        if (afterInstr == null) break;
                        contextArray.addRaw(JsonBuilder.object()
                                .put("address", afterInstr.getAddress().toString())
                                .put("text", afterInstr.toString())
                                .put("isMatch", false)
                                .build());
                    }

                    JsonBuilder matchObj = JsonBuilder.object()
                            .put("address", instr.getAddress().toString())
                            .putIfNotNull("function", function != null ? function.getName() : null)
                            .put("matchedInstruction", instr.toString())
                            .putArray("context", contextArray);
                    matchesArray.addRaw(matchObj.build());
                    resultCount++;
                }
            }
        }

        if (resultCount == 0) {
            return StatusOutput.error("No matches found for pattern: " + query);
        }

        String json = JsonBuilder.object()
                .put("query", query)
                .put("matchCount", resultCount)
                .putArray("matches", matchesArray)
                .build();
        return new JsonOutput(json);
    }

    @McpTool(outputType = JsonOutput.class, description = """
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

        JsonBuilder.JsonArrayBuilder matchesArray = JsonBuilder.array();
        FunctionManager functionManager = program.getFunctionManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        int resultCount = 0;
        int processedCount = 0;

        for (Function function : functionManager.getFunctions(true)) {
            processedCount++;
            if (resultCount >= limit) break;

            DecompileResults decompileResults = decomp.decompileFunction(function, 30, TaskMonitor.DUMMY);
            if (decompileResults == null || !decompileResults.decompileCompleted()) continue;

            String decompiled = decompileResults.getDecompiledFunction().getC();
            Matcher matcher = pattern.matcher(decompiled);

            if (matcher.find()) {
                String[] lines = decompiled.split("\n");

                // Find matching lines and build context
                for (int i = 0; i < lines.length; i++) {
                    if (pattern.matcher(lines[i]).find()) {
                        JsonBuilder.JsonArrayBuilder contextArray = JsonBuilder.array();
                        int startCtx = Math.max(0, i - 3);
                        int endCtx = Math.min(lines.length - 1, i + 3);
                        for (int j = startCtx; j <= endCtx; j++) {
                            contextArray.addString(lines[j]);
                        }

                        matchesArray.addRaw(JsonBuilder.object()
                                .put("function", function.getName())
                                .put("address", function.getEntryPoint().toString())
                                .put("matchLine", lines[i].trim())
                                .putArray("context", contextArray)
                                .build());
                    }
                }
                resultCount++;
            }

            if (processedCount % 100 == 0) {
                Msg.info(this, "Processed " + processedCount + " functions for decompiled search");
            }
        }

        if (resultCount == 0) {
            return StatusOutput.error("No matches found for pattern: " + query);
        }

        String json = JsonBuilder.object()
                .put("query", query)
                .put("matchCount", resultCount)
                .putArray("matches", matchesArray)
                .build();
        return new JsonOutput(json);
    }
}
