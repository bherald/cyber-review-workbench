#!/usr/bin/env python3
"""Check tracked release content without printing potential confidential matches."""

from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
patterns = [
    ("retired internal identity", re.compile("d" + "tc", re.I)),
    ("private LAN address", re.compile(r"192\.168\.[0-9]+\.[0-9]+")),
    ("private user directory", re.compile(r"/home/" + "bill" + r"\b|/Users/" + "bill" + r"\b")),
    ("provider credential", re.compile(r"\b(?:sk" + r"-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b")),
    ("private key block", re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
failures = []
for path in filter(None, paths):
    file = root / path
    if file.is_symlink() or path.endswith((".sqlite", ".db", ".pem", ".key")) or Path(path).name.startswith(".env"):
        failures.append((path, "runtime, binding or credential file"))
        continue
    try:
        text = file.read_text(encoding="utf-8")
    except (UnicodeError, OSError):
        failures.append((path, "unexpected nontext release payload"))
        continue
    for label, pattern in patterns:
        if pattern.search(text) or pattern.search(path):
            failures.append((path, label))
if failures:
    for path, label in failures:
        print(path + ": " + label)
    sys.exit(1)
print(f"Release-content check passed for {len(list(filter(None, paths)))} tracked files.")
