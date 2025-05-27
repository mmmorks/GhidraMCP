#!/usr/bin/env python3
"""
Telemetry Analyzer for Ghidra MCP Server
Analyzes JSON telemetry logs to provide insights on tool usage, performance, and errors.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
import statistics

# Complete list of all MCP tools available in the system
ALL_MCP_TOOLS = [
    'add_enum_value',
    'add_structure_field',
    'analyze_call_graph',
    'analyze_control_flow',
    'analyze_data_flow',
    'create_enum',
    'create_structure',
    'decompile_function',
    'decompile_function_by_address',
    'disassemble_function',
    'get_current_address',
    'get_current_function',
    'get_function_by_address',
    'get_symbol_address',
    'list_classes',
    'list_data_items',
    'list_enums',
    'list_exports',
    'list_functions',
    'list_imports',
    'list_methods',
    'list_namespaces',
    'list_references',
    'list_segments',
    'list_structures',
    'list_symbols',
    'rename_data',
    'rename_function',
    'rename_function_by_address',
    'rename_struct_field',
    'rename_variable',
    'search_decompiled',
    'search_disassembly',
    'search_functions_by_name',
    'search_memory',
    'set_decompiler_comment',
    'set_disassembly_comment',
    'set_function_prototype',
    'set_local_variable_type',
    'set_memory_data_type'
]

def parse_jsonl_file(file_path):
    """Parse a JSONL file and return list of events."""
    events = []
    with open(file_path, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Error parsing line: {e}")
    return events

def analyze_telemetry(telemetry_dir):
    """Analyze all telemetry files in the directory."""
    telemetry_path = Path(telemetry_dir)
    if not telemetry_path.exists():
        print(f"Telemetry directory not found: {telemetry_dir}")
        return
    
    # Collect all events
    all_events = []
    for jsonl_file in telemetry_path.glob("mcp_telemetry_*.jsonl"):
        events = parse_jsonl_file(jsonl_file)
        all_events.extend(events)
        print(f"Loaded {len(events)} events from {jsonl_file.name}")
    
    if not all_events:
        print("No telemetry events found.")
        return
    
    # Sort events by timestamp
    all_events.sort(key=lambda x: x['timestamp'])
    
    # Analysis
    print("\n" + "="*80)
    print("TELEMETRY ANALYSIS REPORT")
    print("="*80)
    
    # 1. Overall Statistics
    print("\n1. OVERALL STATISTICS")
    print("-" * 40)
    total_events = len(all_events)
    tool_events = [e for e in all_events if e['eventType'] in ['TOOL_START', 'TOOL_SUCCESS', 'TOOL_FAILURE']]
    session_events = [e for e in all_events if e['eventType'] in ['SESSION_START', 'SESSION_END']]
    
    print(f"Total events: {total_events}")
    print(f"Tool invocations: {len([e for e in all_events if e['eventType'] == 'TOOL_START'])}")
    print(f"Successful completions: {len([e for e in all_events if e['eventType'] == 'TOOL_SUCCESS'])}")
    print(f"Failures: {len([e for e in all_events if e['eventType'] == 'TOOL_FAILURE'])}")
    print(f"Sessions: {len([e for e in all_events if e['eventType'] == 'SESSION_START'])}")
    
    # 2. Tool Usage Statistics
    print("\n2. TOOL USAGE STATISTICS")
    print("-" * 40)
    tool_usage = Counter()
    tool_success = Counter()
    tool_failure = Counter()
    tool_durations = defaultdict(list)
    
    for event in all_events:
        if event.get('toolName'):  # Use .get() to handle missing toolName
            if event['eventType'] == 'TOOL_START':
                tool_usage[event['toolName']] += 1
            elif event['eventType'] == 'TOOL_SUCCESS':
                tool_success[event['toolName']] += 1
                if event.get('durationMs', 0) > 0:
                    tool_durations[event['toolName']].append(event['durationMs'])
            elif event['eventType'] == 'TOOL_FAILURE':
                tool_failure[event['toolName']] += 1
    
    # Add unused tools with 0 counts
    for tool in ALL_MCP_TOOLS:
        if tool not in tool_usage:
            tool_usage[tool] = 0
            tool_success[tool] = 0
            tool_failure[tool] = 0
    
    # Sort by usage
    sorted_tools = sorted(tool_usage.items(), key=lambda x: x[1], reverse=True)
    
    print(f"{'Tool Name':<30} {'Uses':<10} {'Success':<10} {'Fail':<10} {'Success%':<10} {'Avg Time(ms)':<12}")
    print("-" * 82)
    
    for tool_name, usage_count in sorted_tools:
        success_count = tool_success.get(tool_name, 0)
        failure_count = tool_failure.get(tool_name, 0)
        success_rate = (success_count / usage_count * 100) if usage_count > 0 else 0
        avg_duration = statistics.mean(tool_durations[tool_name]) if tool_durations[tool_name] else 0
        
        print(f"{tool_name:<30} {usage_count:<10} {success_count:<10} {failure_count:<10} "
              f"{success_rate:<10.1f} {avg_duration:<12.1f}")
    
    # 3. Error Analysis
    print("\n3. ERROR ANALYSIS")
    print("-" * 40)
    error_types = Counter()
    error_by_tool = defaultdict(Counter)
    
    for event in all_events:
        if event['eventType'] == 'TOOL_FAILURE' and event.get('errorType'):
            error_types[event['errorType']] += 1
            if event.get('toolName'):
                error_by_tool[event['toolName']][event['errorType']] += 1
    
    if error_types:
        print(f"{'Error Type':<30} {'Count':<10}")
        print("-" * 40)
        for error_type, count in error_types.most_common(10):
            print(f"{error_type:<30} {count:<10}")
        
        print("\nTop errors by tool:")
        for tool_name, errors in error_by_tool.items():
            if errors:
                print(f"\n  {tool_name}:")
                for error_type, count in errors.most_common(3):
                    print(f"    - {error_type}: {count}")
    else:
        print("No errors recorded!")
    
    # 4. Performance Analysis
    print("\n4. PERFORMANCE ANALYSIS")
    print("-" * 40)
    
    for tool_name, durations in tool_durations.items():
        if len(durations) >= 2:
            print(f"\n{tool_name}:")
            print(f"  - Min: {min(durations):.1f}ms")
            print(f"  - Max: {max(durations):.1f}ms")
            print(f"  - Mean: {statistics.mean(durations):.1f}ms")
            print(f"  - Median: {statistics.median(durations):.1f}ms")
            if len(durations) >= 10:
                print(f"  - 95th percentile: {statistics.quantiles(durations, n=20)[18]:.1f}ms")
    
    # 5. Unused or Rarely Used Tools
    print("\n5. TOOL OPTIMIZATION CANDIDATES")
    print("-" * 40)
    
    # Completely unused tools
    unused_tools = [(tool, count) for tool, count in tool_usage.items() if count == 0]
    if unused_tools:
        print(f"Completely unused tools ({len(unused_tools)} total):")
        # Show first 10 unused tools
        for tool, count in unused_tools[:10]:
            print(f"  - {tool}")
        if len(unused_tools) > 10:
            print(f"  ... and {len(unused_tools) - 10} more")
        print()
    
    # Tools used less than 5 times (but more than 0)
    rarely_used = [(tool, count) for tool, count in tool_usage.items() if 0 < count < 5]
    if rarely_used:
        print("Rarely used tools (1-4 invocations):")
        for tool, count in rarely_used:
            print(f"  - {tool}: {count} uses")
    
    # Tools with high failure rates
    print("\nTools with high failure rates (> 20%):")
    high_failure_tools = []
    for tool_name, usage_count in tool_usage.items():
        failure_count = tool_failure.get(tool_name, 0)
        if usage_count >= 5:  # Only consider tools used at least 5 times
            failure_rate = (failure_count / usage_count * 100)
            if failure_rate > 20:
                high_failure_tools.append((tool_name, failure_rate, failure_count, usage_count))
    
    if high_failure_tools:
        for tool_name, failure_rate, failure_count, usage_count in high_failure_tools:
            print(f"  - {tool_name}: {failure_rate:.1f}% failure rate ({failure_count}/{usage_count})")
    else:
        print("  No tools with high failure rates found.")
    
    # 6. Session Analysis
    print("\n6. SESSION ANALYSIS")
    print("-" * 40)
    
    sessions = defaultdict(dict)
    for event in all_events:
        session_id = event['sessionId']
        if event['eventType'] == 'SESSION_START':
            sessions[session_id]['start'] = event['timestamp']
        elif event['eventType'] == 'SESSION_END':
            sessions[session_id]['end'] = event['timestamp']
            if event.get('metadata'):
                sessions[session_id]['duration'] = event['metadata'].get('sessionDuration', 0)
                sessions[session_id]['requests'] = event['metadata'].get('totalRequests', 0)
    
    if sessions:
        total_sessions = len(sessions)
        durations = [s.get('duration', 0) for s in sessions.values() if s.get('duration', 0) > 0]
        requests = [s.get('requests', 0) for s in sessions.values() if s.get('requests', 0) > 0]
        
        avg_duration = statistics.mean(durations) if durations else 0
        avg_requests = statistics.mean(requests) if requests else 0
        
        print(f"Total sessions: {total_sessions}")
        if avg_duration > 0:
            print(f"Average session duration: {avg_duration/1000:.1f} seconds")
        if avg_requests > 0:
            print(f"Average requests per session: {avg_requests:.1f}")
    
    # 7. Recommendations
    print("\n7. RECOMMENDATIONS")
    print("-" * 40)
    
    recommendations = []
    
    # Check for completely unused tools first
    unused_count = len([t for t, c in tool_usage.items() if c == 0])
    if unused_count > 0:
        recommendations.append(f"Remove {unused_count} completely unused tools to save significant token space")
    
    # Check for rarely used tools
    for tool, count in tool_usage.items():
        if 0 < count < 3:
            recommendations.append(f"Consider removing '{tool}' - only used {count} times")
    
    # Check for tools with consistent errors
    for tool_name, errors in error_by_tool.items():
        if tool_name in tool_usage and tool_usage[tool_name] > 5:
            failure_count = tool_failure.get(tool_name, 0)
            if failure_count > 0:
                failure_rate = failure_count / tool_usage[tool_name] * 100
                if failure_rate > 30:
                    top_error = errors.most_common(1)[0] if errors else ("Unknown", 0)
                    recommendations.append(f"Fix '{tool_name}' - {failure_rate:.0f}% failure rate, mainly: {top_error[0]}")
    
    # Check for slow tools
    for tool_name, durations in tool_durations.items():
        if durations and statistics.mean(durations) > 5000:  # > 5 seconds
            recommendations.append(f"Optimize '{tool_name}' - average response time {statistics.mean(durations)/1000:.1f}s")
    
    if recommendations:
        for rec in recommendations[:10]:  # Show top 10 recommendations
            print(f"• {rec}")
    else:
        print("No specific recommendations at this time.")
    
    # 8. Token Efficiency Summary
    print("\n8. TOKEN EFFICIENCY SUMMARY")
    print("-" * 40)
    
    total_tools = len(ALL_MCP_TOOLS)
    used_tools = len([t for t, c in tool_usage.items() if c > 0])
    unused_tools_count = total_tools - used_tools
    
    print(f"Total MCP tools available: {total_tools}")
    print(f"Tools actually used: {used_tools} ({used_tools/total_tools*100:.1f}%)")
    print(f"Tools never used: {unused_tools_count} ({unused_tools_count/total_tools*100:.1f}%)")
    
    if unused_tools_count > 0:
        # Estimate token savings (rough estimate: ~50-100 tokens per tool definition)
        min_tokens_saved = unused_tools_count * 50
        max_tokens_saved = unused_tools_count * 100
        print(f"\nEstimated token savings by removing unused tools: {min_tokens_saved:,} - {max_tokens_saved:,} tokens")
        print(f"This represents approximately {min_tokens_saved/100000*100:.1f}% - {max_tokens_saved/100000*100:.1f}% of a typical 100k context window")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    telemetry_dir = sys.argv[1] if len(sys.argv) > 1 else "~/.ghidra_mcp/telemetry"
    telemetry_dir = Path(telemetry_dir).expanduser()
    analyze_telemetry(telemetry_dir)