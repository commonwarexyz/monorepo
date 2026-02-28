#!/usr/bin/env python3
"""Parse JUnit XML from nextest to extract message counts per test.

Outputs message counts to stdout (for message_counts.json).
If --lengths-file is provided, writes lengths data to that file separately.
"""
import sys, re, json
import xml.etree.ElementTree as ET

def main():
    lengths_file = None
    junit_path = None

    # Parse args
    args = sys.argv[1:]
    while args:
        if args[0] == "--lengths-file" and len(args) > 1:
            lengths_file = args[1]
            args = args[2:]
        elif junit_path is None:
            junit_path = args[0]
            args = args[1:]
        else:
            print(f"Unknown argument: {args[0]}", file=sys.stderr)
            sys.exit(1)

    if not junit_path:
        print("Usage: parse_junit.py <junit.xml> [--lengths-file <path>]", file=sys.stderr)
        sys.exit(1)

    lengths_out = open(lengths_file, 'w') if lengths_file else None

    try:
        tree = ET.parse(junit_path)
        for testsuite in tree.getroot().findall('testsuite'):
            suite_name = testsuite.get('name', '')
            for testcase in testsuite.findall('testcase'):
                system_err = testcase.find('system-err')
                if system_err is None or not system_err.text:
                    continue

                count = re.search(r'MSG_COUNT:(\d+)', system_err.text)
                if not count:
                    continue

                test_name = f"{suite_name}::{testcase.get('name', '')}"

                # Output counts to stdout
                result = {
                    "test": test_name,
                    "messages": int(count.group(1)),
                    "duration_secs": float(testcase.get('time', 0))
                }
                print(json.dumps(result))

                # Output lengths to separate file if requested
                if lengths_out:
                    lengths = re.search(r'MSG_LENGTHS:(\[.*\])', system_err.text)
                    if lengths:
                        lengths_out.write(json.dumps({
                            "test": test_name,
                            "lengths": json.loads(lengths.group(1))
                        }) + "\n")
    finally:
        if lengths_out:
            lengths_out.close()

if __name__ == "__main__":
    main()
