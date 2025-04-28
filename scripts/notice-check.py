# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import os
import subprocess
import sys
from fnmatch import fnmatch

# Notice line that must be present at the top of every source file.
NOTICE_LINES = [
    "Copyright (c) Microsoft Corporation.",
    "Licensed under the MIT License.",
]

# Literal file prefix, derived from NOTICE_LINES.
# This adds language-specific comment characters to the start of each line.
# Also includes variants with a shebang as the first line
PREFIXES = [
    os.linesep.join([prefix + " " + line for line in NOTICE_LINES])
    for prefix in ["//", "#"]
]
PREFIXES.extend(
    os.linesep.join([f"#!{interpreter}"] + ["# " + line for line in NOTICE_LINES])
    for interpreter in ["/bin/bash", "/usr/bin/env python3.12"]
)

# Only files which match these patterns will be scanned.
PATTERNS = ["*.c", "*.cpp", "*.h", "*.hpp", "*.py", "*.sh", "*.cmake", "CMakeLists.txt"]


def is_src(path):
    name = os.path.basename(path)
    return any(map(lambda p: fnmatch(name, p), PATTERNS))


def list_files():
    r = subprocess.run(["git", "ls-files"], capture_output=True, check=True)
    return r.stdout.decode().splitlines()


def check_notice(path):
    if not is_src(path):
        return True

    with open(path, "rb") as f:
        text = f.read()
        for prefix in PREFIXES:
            if text.startswith(prefix.encode("ascii")):
                return True

    return False


if __name__ == "__main__":
    missing = [p for p in list_files() if not check_notice(p)]
    for path in missing:
        print(f"Copyright notice missing from {path}")
    if missing:
        sys.exit(1)
