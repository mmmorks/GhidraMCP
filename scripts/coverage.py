#!/usr/bin/env python3
"""Agent-friendly code coverage reporter.

Parses JaCoCo output to produce concise, text-based coverage summaries
that are useful for LLM agents writing tests or improving coverage.

Usage:
    # Summary table of all classes sorted by line coverage %
    python scripts/coverage.py

    # Only show classes below 60% line coverage
    python scripts/coverage.py --below 60

    # Show uncovered line numbers for a specific source file
    python scripts/coverage.py --file FunctionService.java

    # Show uncovered lines for all files in a package
    python scripts/coverage.py --package services

    # Combine: uncovered lines only for low-coverage files
    python scripts/coverage.py --file AnalysisService.java --source
"""

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
JACOCO_CSV = PROJECT_ROOT / "target" / "site" / "jacoco" / "jacoco.csv"
JACOCO_XML = PROJECT_ROOT / "target" / "site" / "jacoco" / "jacoco.xml"


def load_csv_summary():
    """Parse JaCoCo CSV into a list of class coverage dicts."""
    if not JACOCO_CSV.exists():
        print(f"Error: {JACOCO_CSV} not found. Run 'mvn test' first.", file=sys.stderr)
        sys.exit(1)

    rows = []
    with open(JACOCO_CSV) as f:
        reader = csv.DictReader(f)
        for row in reader:
            missed = int(row["LINE_MISSED"])
            covered = int(row["LINE_COVERED"])
            total = missed + covered
            pct = (covered / total * 100) if total > 0 else 0.0

            branch_missed = int(row["BRANCH_MISSED"])
            branch_covered = int(row["BRANCH_COVERED"])
            branch_total = branch_missed + branch_covered
            branch_pct = (branch_covered / branch_total * 100) if branch_total > 0 else 0.0

            rows.append({
                "package": row["PACKAGE"].replace("/", "."),
                "class": row["CLASS"],
                "line_covered": covered,
                "line_missed": missed,
                "line_total": total,
                "line_pct": pct,
                "branch_pct": branch_pct,
            })
    return rows


def print_summary(rows, below=None):
    """Print a coverage summary table."""
    if below is not None:
        rows = [r for r in rows if r["line_pct"] < below]

    rows.sort(key=lambda r: r["line_pct"])

    if not rows:
        print("All classes meet the coverage threshold.")
        return

    # Compute column widths
    max_class = max(len(r["class"]) for r in rows)
    max_class = max(max_class, 5)  # minimum "CLASS" header width

    header = f"{'CLASS':<{max_class}}  {'LINES':>9}  {'LINE %':>6}  {'BRANCH %':>8}  MISSED"
    print(header)
    print("-" * len(header))

    total_covered = 0
    total_lines = 0

    for r in rows:
        total_covered += r["line_covered"]
        total_lines += r["line_total"]

        lines_str = f"{r['line_covered']}/{r['line_total']}"
        pct_str = f"{r['line_pct']:.0f}%"
        branch_str = f"{r['branch_pct']:.0f}%"
        missed_str = f"{r['line_missed']}" if r["line_missed"] > 0 else ""

        print(f"{r['class']:<{max_class}}  {lines_str:>9}  {pct_str:>6}  {branch_str:>8}  {missed_str}")

    print("-" * len(header))
    overall_pct = (total_covered / total_lines * 100) if total_lines > 0 else 0
    print(f"{'TOTAL':<{max_class}}  {total_covered}/{total_lines}  {overall_pct:.0f}%")


def load_xml_uncovered(file_filter=None, package_filter=None):
    """Parse JaCoCo XML to find uncovered and partially covered lines."""
    if not JACOCO_XML.exists():
        print(f"Error: {JACOCO_XML} not found. Run 'mvn test' first.", file=sys.stderr)
        sys.exit(1)

    tree = ET.parse(JACOCO_XML)
    root = tree.getroot()
    results = {}

    for pkg in root.findall(".//package"):
        pkg_name = pkg.get("name", "").replace("/", ".")

        if package_filter and package_filter not in pkg_name:
            continue

        for sf in pkg.findall("sourcefile"):
            sf_name = sf.get("name", "")

            if file_filter and file_filter != sf_name:
                continue

            uncovered = []
            partial = []

            for line in sf.findall("line"):
                nr = int(line.get("nr"))
                mi = int(line.get("mi", 0))
                ci = int(line.get("ci", 0))
                mb = int(line.get("mb", 0))
                cb = int(line.get("cb", 0))

                if mi > 0 and ci == 0:
                    uncovered.append(nr)
                elif mb > 0 and cb > 0:
                    partial.append(nr)

            if uncovered or partial:
                key = f"{pkg_name}.{sf_name}"
                results[key] = {"uncovered": uncovered, "partial": partial}

    return results


def collapse_ranges(numbers):
    """Collapse consecutive numbers into range strings: [1,2,3,5,7,8] -> '1-3, 5, 7-8'"""
    if not numbers:
        return ""
    ranges = []
    start = prev = numbers[0]
    for n in numbers[1:]:
        if n == prev + 1:
            prev = n
        else:
            ranges.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = n
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ", ".join(ranges)


def print_uncovered(results, show_source=False):
    """Print uncovered line details."""
    if not results:
        print("No uncovered lines found for the given filter.")
        return

    for key in sorted(results):
        data = results[key]
        print(f"\n{key}")

        if data["uncovered"]:
            print(f"  Uncovered lines ({len(data['uncovered'])}): {collapse_ranges(data['uncovered'])}")

        if data["partial"]:
            print(f"  Partial branches ({len(data['partial'])}): {collapse_ranges(data['partial'])}")

        if show_source:
            # Try to find and display the source with coverage markers
            # key is e.g. "com.lauriewired.mcp.services.MemoryService.java"
            sf_name = key.split(".")[-2] + ".java"  # e.g., "MemoryService.java"
            source_files = list(PROJECT_ROOT.glob(f"src/main/java/**/{sf_name}"))
            if source_files:
                uncov_set = set(data["uncovered"])
                partial_set = set(data["partial"])
                print()
                with open(source_files[0]) as f:
                    for i, line in enumerate(f, 1):
                        if i in uncov_set:
                            marker = ">"
                        elif i in partial_set:
                            marker = "~"
                        else:
                            continue
                        print(f"  {marker} {i:4d}: {line.rstrip()}")


def main():
    parser = argparse.ArgumentParser(
        description="Agent-friendly JaCoCo coverage reporter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s                         Summary table of all classes
  %(prog)s --below 60              Classes below 60%% line coverage
  %(prog)s --file FunctionService.java    Uncovered lines in a file
  %(prog)s --file FunctionService.java --source  With source context
  %(prog)s --package services      Uncovered lines in a package""",
    )
    parser.add_argument(
        "--below",
        type=float,
        metavar="PCT",
        help="Only show classes below this line coverage %%",
    )
    parser.add_argument(
        "--file",
        metavar="FILE.java",
        help="Show uncovered lines for a specific source file",
    )
    parser.add_argument(
        "--package",
        metavar="NAME",
        help="Filter to source files whose package contains NAME",
    )
    parser.add_argument(
        "--source",
        action="store_true",
        help="Show the actual uncovered source lines (use with --file)",
    )

    args = parser.parse_args()

    if args.file or args.package:
        results = load_xml_uncovered(
            file_filter=args.file, package_filter=args.package
        )
        print_uncovered(results, show_source=args.source)
    else:
        rows = load_csv_summary()
        print_summary(rows, below=args.below)


if __name__ == "__main__":
    main()
