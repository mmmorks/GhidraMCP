package com.lauriewired.mcp.services;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
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
import ghidra.util.task.TaskMonitorAdapter;

import com.lauriewired.mcp.api.McpTool;
import com.lauriewired.mcp.api.Param;
import com.lauriewired.mcp.model.JsonOutput;
import com.lauriewired.mcp.model.StatusOutput;
import com.lauriewired.mcp.model.ToolOutput;
import com.lauriewired.mcp.model.response.SearchDecompiledResult;
import com.lauriewired.mcp.model.response.SearchDisassemblyResult;
import com.lauriewired.mcp.model.response.SearchMemoryResult;

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
    public SearchService(final ProgramService programService) {
        this.programService = programService;
    }

    @McpTool(outputType = JsonOutput.class, responseType = SearchMemoryResult.class, description = """
        Search program memory for byte patterns or strings.

        Searches initialized memory blocks for specified patterns and shows context around matches.

        Returns: Memory matches with address, label, and context bytes

        Example: search_memory("Password", True) -> matches of "Password" string in memory """)
    public ToolOutput searchMemory(
            @Param("The pattern to search for (string or hex bytes like \"00 FF 32\")") final String query,
            @Param(value = "True to search for UTF-8 string, False to search for hex bytes", defaultValue = "true") final boolean asString,
            @Param(value = "Optional memory block name to restrict search", defaultValue = "") final String blockName,
            @Param(value = "Maximum number of results to return", defaultValue = "10") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (query == null || query.isEmpty()) return StatusOutput.error("Search query is required");

        final List<SearchMemoryResult.MemoryMatch> results = new ArrayList<>();
        final Memory memory = program.getMemory();

        try {
            // Create a byte matcher based on the input type
            final ByteMatcher matcher;
            final int patternLength;

            if (asString) {
                final byte[] searchPattern = query.getBytes(StandardCharsets.UTF_8);
                final SearchSettings settings = new SearchSettings()
                    .withSearchFormat(SearchFormat.STRING);
                matcher = new ByteMatcher("String Search", query, settings) {
                    @Override
                    public Iterable<ByteMatcher.ByteMatch> match(final ExtendedByteSequence ebs) {
                        final List<ByteMatch> matches = new ArrayList<>();

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
                                matches.add(new ByteMatcher.ByteMatch(offset, searchPattern.length, this));
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
                final String[] byteStrings = query.split("\\s+");
                final byte[] bytePattern = new byte[byteStrings.length];
                final boolean[] wildcardMask = new boolean[byteStrings.length];

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
                final SearchSettings settings = new SearchSettings()
                    .withSearchFormat(SearchFormat.HEX);
                matcher = new ByteMatcher("Hex Search", query, settings) {
                    @Override
                    public Iterable<ByteMatcher.ByteMatch> match(final ExtendedByteSequence ebs) {
                        final List<ByteMatch> matches = new ArrayList<>();

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
                                matches.add(new ByteMatcher.ByteMatch(offset, pattern.length, this));
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
            final AddressSet searchSet = new AddressSet();
            if (blockName != null && !blockName.isEmpty()) {
                final MemoryBlock block = memory.getBlock(blockName);
                if (block == null) {
                    return StatusOutput.error("Memory block not found: " + blockName);
                }
                searchSet.add(block.getStart(), block.getEnd());
            } else {
                // Search all initialized memory if no block specified
                for (final MemoryBlock block : memory.getBlocks()) {
                    if (block.isInitialized()) {
                        searchSet.add(block.getStart(), block.getEnd());
                    }
                }
            }

            // Create a program byte source for the memory search
            final ProgramByteSource byteSource = new ProgramByteSource(program);

            // Create a memory searcher with the proper parameters
            final MemorySearcher searcher = new MemorySearcher(byteSource, matcher, searchSet, limit);

            // Perform the search
            final List<Address> matches = new ArrayList<>();
            int count = 0;
            MemoryMatch memMatch;

            Address startAddr = searchSet.getMinAddress();
            while ((memMatch = searcher.findNext(startAddr, TaskMonitor.DUMMY)) != null && count < limit) {
                final Address matchAddress = memMatch.getAddress();
                matches.add(matchAddress);
                startAddr = matchAddress.next();
                count++;
            }

            // Format results
            for (final Address matchAddr : matches) {
                results.add(formatMemoryMatch(program, memory, matchAddr, patternLength));
            }

        } catch (NumberFormatException e) {
            return StatusOutput.error("Error searching memory: " + e.getMessage());
        }

        if (results.isEmpty()) {
            return StatusOutput.ok("No matches found for query: " + query);
        }

        return new JsonOutput(new SearchMemoryResult(query, results.size(), results));
    }

    /**
     * Format a memory match as a record
     */
    private SearchMemoryResult.MemoryMatch formatMemoryMatch(final Program program, final Memory memory, final Address matchAddr, final int matchLength) {
        final MemoryBlock block = memory.getBlock(matchAddr);
        final String blockNameStr = block != null ? block.getName() : null;

        final ghidra.program.model.symbol.Symbol sym = program.getSymbolTable().getPrimarySymbol(matchAddr);
        final String label = sym != null ? sym.getName() : null;

        // Build hex context
        final StringBuilder context = new StringBuilder();
        final int contextSize = 16;
        Address startContextAddr = matchAddr.subtract(contextSize);
        Address endContextAddr = matchAddr.add(matchLength + contextSize - 1);
        if (block != null) {
            if (startContextAddr.compareTo(block.getStart()) < 0) startContextAddr = block.getStart();
            if (endContextAddr.compareTo(block.getEnd()) > 0) endContextAddr = block.getEnd();
        }
        final int totalBytes = (int) endContextAddr.subtract(startContextAddr) + 1;
        if (totalBytes > 0) {
            final byte[] bytes = new byte[totalBytes];
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

        return new SearchMemoryResult.MemoryMatch(
                matchAddr.toString(), blockNameStr, label, context.toString());
    }

    @McpTool(outputType = JsonOutput.class, responseType = SearchDisassemblyResult.class, description = """
        Search for patterns in disassembled code using regex.

        Searches instruction mnemonics, operands, and comments in functions.

        Returns: Matching instructions with function context and nearby instructions

        Example: search_disassembly("mov.*eax") -> finds MOV instructions using EAX register """)
    public ToolOutput searchDisassembly(
            @Param("Regex pattern to search for in assembly instructions") final String query,
            @Param(value = "Starting index for pagination", defaultValue = "0") int offset,
            @Param(value = "Maximum number of results to return", defaultValue = "10") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (query == null || query.isEmpty()) return StatusOutput.error("Search query is required");

        final Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return StatusOutput.error("Invalid regex pattern: " + e.getMessage());
        }

        final Memory memory = program.getMemory();
        final List<MemoryBlock> codeBlocks = new ArrayList<>();
        for (final MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute()) codeBlocks.add(block);
        }

        if (codeBlocks.isEmpty()) {
            return StatusOutput.ok("No executable code blocks found in program");
        }

        final List<SearchDisassemblyResult.DisasmMatch> matches = new ArrayList<>();
        int resultCount = 0;

        for (final MemoryBlock block : codeBlocks) {
            if (resultCount >= limit) break;

            final Address start = block.getStart();
            final Address end = block.getEnd();
            final InstructionIterator instructions = program.getListing().getInstructions(start, true);

            while (instructions.hasNext() && resultCount < limit) {
                final Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) break;

                final String instrText = instr.getAddress() + ": " + instr.toString();
                final Matcher matcher = pattern.matcher(instrText);
                if (matcher.find()) {
                    final Function function = program.getFunctionManager().getFunctionContaining(instr.getAddress());

                    // Build context lines
                    final List<SearchDisassemblyResult.ContextLine> contextLines = new ArrayList<>();

                    // Before context
                    final int contextLineCount = 3;
                    Address contextStart = instr.getAddress();
                    final List<Instruction> beforeCtx = new ArrayList<>();
                    for (int i = 0; i < contextLineCount; i++) {
                        contextStart = contextStart.previous();
                        if (contextStart == null) break;
                        final Instruction prevInstr = program.getListing().getInstructionAt(contextStart);
                        if (prevInstr == null) break;
                        beforeCtx.add(0, prevInstr);
                    }
                    for (final Instruction ctx : beforeCtx) {
                        contextLines.add(new SearchDisassemblyResult.ContextLine(
                                ctx.getAddress().toString(), ctx.toString(), false));
                    }

                    // The match itself
                    contextLines.add(new SearchDisassemblyResult.ContextLine(
                            instr.getAddress().toString(), instr.toString(), true));

                    // After context
                    Address afterAddr = instr.getAddress();
                    for (int i = 0; i < contextLineCount; i++) {
                        afterAddr = afterAddr.next();
                        if (afterAddr == null) break;
                        final Instruction afterInstr = program.getListing().getInstructionAt(afterAddr);
                        if (afterInstr == null) break;
                        contextLines.add(new SearchDisassemblyResult.ContextLine(
                                afterInstr.getAddress().toString(), afterInstr.toString(), false));
                    }

                    matches.add(new SearchDisassemblyResult.DisasmMatch(
                            instr.getAddress().toString(),
                            function != null ? function.getName() : null,
                            instr.toString(),
                            contextLines));
                    resultCount++;
                }
            }
        }

        if (resultCount == 0) {
            return StatusOutput.ok("No matches found for pattern: " + query);
        }

        return new JsonOutput(new SearchDisassemblyResult(query, resultCount, matches));
    }

    @McpTool(outputType = JsonOutput.class, responseType = SearchDecompiledResult.class, description = """
        Search for patterns in decompiled C-like code using regex.

        Searches variables, expressions, and comments in decompiled functions.

        Returns: Matching code fragments with function context and surrounding lines

        Note: This is resource-intensive as each function must be decompiled.

        Example: search_decompiled("malloc\\\\(.*\\\\)") -> finds malloc calls in decompiled code """)
    public ToolOutput searchDecompiled(
            @Param("Regex pattern to search for in decompiled code") final String query,
            @Param(value = "Starting index for pagination", defaultValue = "0") int offset,
            @Param(value = "Maximum number of functions to search/return", defaultValue = "5") final int limit) {
        final Program program = programService.getCurrentProgram();
        if (program == null) return StatusOutput.error("No program loaded");
        if (query == null || query.isEmpty()) return StatusOutput.error("Search query is required");

        final Pattern pattern;
        try {
            pattern = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return StatusOutput.error("Invalid regex pattern: " + e.getMessage());
        }

        final List<SearchDecompiledResult.DecompiledMatch> matches =
                Collections.synchronizedList(new ArrayList<>());
        final FunctionManager functionManager = program.getFunctionManager();
        final AtomicInteger matchedFunctionCount = new AtomicInteger(0);
        final AtomicBoolean limitReached = new AtomicBoolean(false);

        // Cancellable monitor — true enables cancellation (cancel() is a no-op when false)
        final TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);

        // Callback that decompiles each function in parallel and applies regex matching
        final DecompilerCallback<List<SearchDecompiledResult.DecompiledMatch>> callback =
                new DecompilerCallback<>(program, decompiler -> {
                    // Do NOT call openProgram() — DecompilerCallback does this after configure()
                }) {
                    @Override
                    public List<SearchDecompiledResult.DecompiledMatch> process(
                            final DecompileResults decompileResults, final TaskMonitor taskMonitor) {
                        if (limitReached.get()) {
                            return List.of();
                        }
                        if (decompileResults == null || !decompileResults.decompileCompleted()) {
                            return List.of();
                        }
                        if (decompileResults.getDecompiledFunction() == null) {
                            return List.of();
                        }

                        final String decompiled = decompileResults.getDecompiledFunction().getC();
                        if (decompiled == null) {
                            return List.of();
                        }

                        // Pattern is immutable/thread-safe — each thread creates its own Matcher
                        final Matcher matcher = pattern.matcher(decompiled);
                        if (!matcher.find()) {
                            return List.of();
                        }

                        final Function function = decompileResults.getFunction();
                        final String[] lines = decompiled.split("\n");
                        final List<SearchDecompiledResult.DecompiledMatch> functionMatches = new ArrayList<>();

                        for (int i = 0; i < lines.length; i++) {
                            if (pattern.matcher(lines[i]).find()) {
                                final List<String> contextLines = new ArrayList<>();
                                final int startCtx = Math.max(0, i - 3);
                                final int endCtx = Math.min(lines.length - 1, i + 3);
                                for (int j = startCtx; j <= endCtx; j++) {
                                    contextLines.add(lines[j]);
                                }

                                functionMatches.add(new SearchDecompiledResult.DecompiledMatch(
                                        function.getName(),
                                        function.getEntryPoint().toString(),
                                        lines[i].trim(),
                                        contextLines));
                            }
                        }

                        return functionMatches;
                    }
                };

        try {
            ParallelDecompiler.decompileFunctions(callback, program,
                    functionManager.getFunctions(true).iterator(),
                    functionMatches -> {
                        if (functionMatches != null && !functionMatches.isEmpty()) {
                            matches.addAll(functionMatches);
                            if (matchedFunctionCount.incrementAndGet() >= limit) {
                                limitReached.set(true);
                                monitor.cancel();
                            }
                        }
                    },
                    monitor);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            // HTTP timeout fired — return whatever we have so far
        } catch (final Exception e) {
            if (!limitReached.get()) {
                Msg.error(this, "Error during parallel decompilation search", e);
            }
            // Limit-reached cancellation is expected — fall through
        } finally {
            callback.dispose();
        }

        if (matches.isEmpty()) {
            return StatusOutput.ok("No matches found for pattern: " + query);
        }

        return new JsonOutput(new SearchDecompiledResult(query,
                matchedFunctionCount.get(), matches));
    }
}
