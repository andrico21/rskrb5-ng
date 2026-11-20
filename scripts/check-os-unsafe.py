#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/check-os-unsafe.py [--self-test]
"""Audit the unsafe code of the companion crate `rskrb5-ng-os` (plan 2 todo 14).

Every `unsafe` block, `unsafe extern` block, `unsafe fn` and `unsafe impl` in
`rskrb5-ng-os/src` must carry an `#[expect(unsafe_code, reason = "...")]` in the
attributes right above its statement or item, and every `unsafe` block (and
`unsafe extern` block) a comment right above it: `// SAFETY:` for a block, any
comment for an extern block. Comment lines, attribute lines and the statement
line itself count as "right above". The main crate stays free of unsafe code:
`src` may not contain an unsafe block, function or impl.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
UNSAFE: Final = re.compile(r'\bunsafe\s*(\{|extern(?=\s*(?:""\s*)?\{)|fn(?=\s+\w)|impl\b)')
EXPECT: Final = re.compile(
    r'#\[expect\(\s*unsafe_code\s*,\s*reason\s*=\s*"[^"]+"\s*\)\]'
)


def code_part(line: str) -> str:
    """The line without a trailing `//` comment or string contents (a sketch, enough here)."""
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    return text.split("//", 1)[0]


def header(lines: list[str], index: int) -> list[str]:
    """The comment and attribute lines right above line `index`, and the line itself."""
    above = []
    cursor = index - 1
    while cursor >= 0:
        stripped = lines[cursor].strip()
        if (
            stripped.startswith(("//", "#[", "#![", ")]", "reason"))
            or stripped.endswith("(")
            and stripped.startswith("#")
        ):
            above.append(stripped)
            cursor -= 1
            continue
        break
    statement = cursor
    while (
        statement >= 0
        and not lines[statement].rstrip().endswith((";", "{", "}", ","))
        and lines[statement].strip()
    ):
        above.append(lines[statement].strip())
        statement -= 1
    return above + [lines[index].strip()]


def audit(name: str, text: str) -> list[str]:
    """The problems of one source file."""
    problems = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = UNSAFE.search(code_part(line))
        if match is None:
            continue
        context = header(lines, index)
        joined = "\n".join(context)
        if not EXPECT.search(joined.replace("\n", " ")):
            problems.append(
                f"{name}:{index + 1}: unsafe without #[expect(unsafe_code, reason)]"
            )
        kind = match[1]
        comments = [entry for entry in context if entry.startswith("//")]
        if kind == "{" and not any(
            entry.startswith("// SAFETY:") for entry in comments
        ):
            problems.append(
                f"{name}:{index + 1}: unsafe block without a // SAFETY: comment"
            )
        if kind == "extern" and not comments:
            problems.append(
                f"{name}:{index + 1}: unsafe extern block without a comment"
            )
    return problems


def check(root: Path) -> list[str]:
    """The problems of the tree under `root`."""
    problems = []
    for path in sorted((root / "rskrb5-ng-os" / "src").rglob("*.rs")):
        problems += audit(str(path.relative_to(root)), path.read_text(encoding="utf-8"))
    for path in sorted((root / "src").rglob("*.rs")):
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if re.search(r"unsafe\s*(\{|fn |impl )", code_part(line)):
                problems.append(
                    f"{path.relative_to(root)}:{index + 1}: unsafe in the main crate"
                )
    return problems


def self_test() -> int:
    good = (
        "// SAFETY: the pointer is live.\n"
        '#[expect(unsafe_code, reason = "FFI call")]\n'
        "let code = unsafe { call() };\n"
        "// The declarations.\n"
        '#[expect(unsafe_code, reason = "FFI declarations")]\n'
        'unsafe extern "C" {\n'
        "    fn call() -> i32;\n"
        "}\n"
    )
    assert audit("good.rs", good) == [], audit("good.rs", good)
    no_safety = '#[expect(unsafe_code, reason = "x")]\nlet code = unsafe { call() };\n'
    assert len(audit("a.rs", no_safety)) == 1
    no_expect = "// SAFETY: fine.\nlet code = unsafe { call() };\n"
    assert len(audit("b.rs", no_expect)) == 1
    bare_extern = 'unsafe extern "C" {\n}\n'
    assert len(audit("c.rs", bare_extern)) == 2
    assert audit("d.rs", '// unsafe { in a comment }\nlet text = "unsafe {";\n') == []
    pointer = 'struct T {\n    call: Option<unsafe extern "C" fn(i32) -> i32>,\n    other: unsafe fn(),\n}\n'
    assert audit("e.rs", pointer) == [], audit("e.rs", pointer)
    print("check-os-unsafe: self-test ok")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    problems = check(ROOT)
    for problem in problems:
        print(problem)
    print(f"check-os-unsafe: {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
