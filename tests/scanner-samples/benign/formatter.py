#!/usr/bin/env python3
"""Benign sample: a simple file formatter utility."""
import sys
from pathlib import Path


def format_file(file_path: str, indent: int = 4) -> str:
    """Read a file and reformat with consistent indentation."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()
    formatted = []
    for line in lines:
        stripped = line.lstrip()
        if stripped:
            level = (len(line) - len(stripped)) // indent
            formatted.append(" " * (level * indent) + stripped)
        else:
            formatted.append("")

    return "\n".join(formatted)


def main():
    if len(sys.argv) < 2:
        print("Usage: formatter.py <file>")
        sys.exit(1)

    result = format_file(sys.argv[1])
    print(result)


if __name__ == "__main__":
    main()
