#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/leaf_features.py --enforce
"""Additive leaf-feature gate (owner decision D10; docs/dependency-admission.md).

A leaf flag enables optional dependencies and the code that uses them, and
nothing else. `[package.metadata.rskrb5-ng.leaf-features.<leaf>]` of `Cargo.toml`
declares, per leaf, its `minimal` core features, its `modules` and `tests`
(files, or directories written with a trailing `/`) and its `seams`
(`file`, `item`, `call`). The gate reads that table and rejects:

* a leaf that is not a `[features]` entry, is in the `default` closure, is
  enabled by a core feature, or enables another leaf (directly or through core
  features), and `minimal` features that are not core features;
* two leaves declaring the same path, and declared paths that do not exist;
* a `cfg(... feature = "<leaf>" ...)` (also `cfg_attr` and `cfg!`) in `src/`,
  `tests/`, `examples/` or `fuzz/` outside the leaf's own modules and tests,
  unless it sits in one declared seam or is the single `mod` line of that leaf
  in `src/lib.rs`; a `cfg` naming two leaves;
* a seam whose item is missing, whose item holds the `call` other than exactly
  once, whose gated unit is longer than SEAM_LINES code lines, or that no `cfg`
  uses.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from rust_lex import match_bracket, strip_comments_and_strings

SEAM_LINES: Final = 5
SCANNED: Final = ("src", "tests", "examples", "fuzz")
KEYS: Final = frozenset({"minimal", "modules", "tests", "seams"})
CFG: Final = re.compile(r"(?<![\w$])(?:r#)?(cfg|cfg_attr)(\s*!)?\s*\(")
FEATURE: Final = re.compile(r"(?<![\w])feature\s*=")
ATTR_BEFORE: Final = re.compile(r"#\s*(!)?\s*\[\s*$")
MOD_LINE: Final = re.compile(
    r"\s*(?:#\s*\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
)


@dataclass(frozen=True, slots=True)
class Seam:
    file: str
    item: str
    call: str


@dataclass(frozen=True, slots=True)
class Leaf:
    name: str
    minimal: tuple[str, ...]
    modules: tuple[str, ...]
    tests: tuple[str, ...]
    seams: tuple[Seam, ...]


def read_leaves(manifest: dict) -> tuple[dict[str, Leaf], list[str]]:
    table = (
        manifest.get("package", {})
        .get("metadata", {})
        .get("rskrb5-ng", {})
        .get("leaf-features", {})
    )
    leaves, problems = {}, []
    for name, body in table.items():
        unknown = sorted(set(body) - KEYS)
        if unknown:
            problems.append(f"leaf `{name}`: unknown key(s) {unknown}")
        leaves[name] = Leaf(
            name,
            tuple(body.get("minimal", ())),
            tuple(body.get("modules", ())),
            tuple(body.get("tests", ())),
            tuple(Seam(s["file"], s["item"], s["call"]) for s in body.get("seams", ())),
        )
    return leaves, problems


def resolve(features: dict[str, list[str]], seed: str) -> set[str]:
    """Features reached from `seed` through plain feature entries."""
    seen, pending = {seed}, [seed]
    while pending:
        for entry in features.get(pending.pop(), ()):
            if entry in features and entry not in seen:
                seen.add(entry)
                pending.append(entry)
    return seen


def feature_problems(manifest: dict, leaves: dict[str, Leaf]) -> list[str]:
    features = manifest.get("features", {})
    problems = []
    for name, leaf in sorted(leaves.items()):
        if name not in features:
            problems.append(f"leaf `{name}` is not a `[features]` entry")
            continue
        others = (resolve(features, name) & set(leaves)) - {name}
        problems += [f"leaf `{name}` depends on leaf `{other}`" for other in sorted(others)]
        problems += [
            f"leaf `{name}`: minimal feature `{feature}` is not a core feature"
            for feature in leaf.minimal
            if feature not in features or feature in leaves
        ]
    for leaf in sorted(resolve(features, "default") & set(leaves)) if "default" in features else []:
        problems.append(f"leaf `{leaf}` is in the `default` closure")
    for feature, entries in sorted(features.items()):
        if feature in leaves:
            continue
        for entry in entries:
            target = entry.split("/", 1)[0].rstrip("?")
            if target in leaves and not entry.startswith("dep:"):
                problems.append(f"core feature `{feature}` enables leaf `{target}`")
    return problems


def covers(declared: str, relative: str) -> bool:
    return relative.startswith(declared) if declared.endswith("/") else relative == declared


def path_problems(root: Path, leaves: dict[str, Leaf]) -> list[str]:
    problems = []
    declared = [(leaf.name, path) for leaf in leaves.values() for path in (*leaf.modules, *leaf.tests)]
    for name, path in declared:
        if not (root / path).exists():
            problems.append(f"leaf `{name}`: declared path `{path}` does not exist")
    for index, (first, a) in enumerate(declared):
        for second, b in declared[index + 1 :]:
            if first != second and (covers(a, b) or covers(b, a) or a == b):
                problems.append(f"leaves `{first}` and `{second}` both declare `{a}` / `{b}`")
    return problems


def cfg_spans(stripped: str, original: str) -> list[tuple[int, int, int | None, bool, set[str]]]:
    """Outermost cfg expressions: (open, close, end of the attribute or macro, is_outer_attr, leaf names)."""
    spans, floor = [], 0
    for match in CFG.finditer(stripped):
        if match.start() < floor:
            continue
        open_at = match.end() - 1
        close = match_bracket(stripped, open_at)
        if close is None:
            continue
        floor = close
        names = {
            literal[1]
            for hit in FEATURE.finditer(stripped, open_at, close)
            if (literal := re.match(r'\s*"([^"\\]*)"', original[hit.end() :]))
        }
        attribute = ATTR_BEFORE.search(stripped[: match.start()])
        if match.group(2):
            spans.append((open_at, close, close + 1, False, names))
        elif attribute and not attribute[1]:
            rest = re.match(r"\s*\]", stripped[close + 1 :])
            spans.append((open_at, close, close + 1 + (rest.end() if rest else 0), True, names))
        else:
            spans.append((open_at, close, None, False, names))
    return spans


def unit_end(text: str, start: int) -> int:
    """End of the statement, match arm or item that a cfg gates."""
    index = start
    while attribute := re.compile(r"\s*#\s*\[").match(text, index):
        close = match_bracket(text, attribute.end() - 1)
        if close is None:
            return len(text)
        index = close + 1
    depth = 0
    for at in range(index, len(text)):
        char = text[at]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return at
            depth -= 1
            if depth == 0 and char == "}":
                tail = re.compile(r"\s*,").match(text, at + 1)
                return tail.end() if tail else at + 1
        elif depth == 0 and char in ",;":
            return at + 1
    return len(text)


def item_spans(stripped: str, item: str) -> list[tuple[int, int]]:
    pattern = r"(?<![\w])" + r"\s+".join(map(re.escape, item.split())) + r"(?![\w])"
    found = []
    for match in re.finditer(pattern, stripped):
        depth = 0
        for at in range(match.end(), len(stripped)):
            char = stripped[at]
            depth += char in "([" 
            depth -= char in ")]"
            if char == ";" and depth == 0:
                break
            if char == "{" and depth == 0:
                close = match_bracket(stripped, at)
                if close is not None:
                    found.append((match.start(), close + 1))
                break
    return found


def check_occurrence(
    relative: str,
    stripped: str,
    span: tuple[int, int, int | None, bool, set[str]],
    leaf: Leaf,
    state: tuple[set[tuple[str, int]], dict[str, int]],
) -> str | None:
    """None when the cfg of `leaf` is in a permitted place, else the problem."""
    used, mod_lines = state
    _, close, unit_start, outer, _ = span
    line = stripped.count("\n", 0, close) + 1
    where = f"{relative}:{line}"
    if any(covers(path, relative) for path in (*leaf.modules, *leaf.tests)):
        return None
    if unit_start is not None:
        for number, seam in enumerate(leaf.seams):
            if seam.file != relative:
                continue
            for start, end in item_spans(stripped, seam.item):
                if not start <= close < end:
                    continue
                used.add((leaf.name, number))
                calls = len(re.findall(re.escape(seam.call), stripped[start:end]))
                code = [x for x in stripped[unit_start : unit_end(stripped, unit_start)].splitlines() if x.strip()]
                if calls != 1:
                    return f"{where}: seam `{seam.item}` of leaf `{leaf.name}` holds `{seam.call}` {calls} times, not exactly once"
                if len(code) > SEAM_LINES:
                    return f"{where}: seam `{seam.item}` gates {len(code)} lines, more than {SEAM_LINES}"
                return None
    module = MOD_LINE.match(stripped, unit_start) if outer and unit_start is not None else None
    if relative == "src/lib.rs" and module:
        name = module[1]
        if any(covers(path, f"src/{name}.rs") or covers(path, f"src/{name}/mod.rs") for path in leaf.modules):
            mod_lines[leaf.name] = mod_lines.get(leaf.name, 0) + 1
            return None if mod_lines[leaf.name] == 1 else f"{where}: second `mod` line of leaf `{leaf.name}` in src/lib.rs"
    return f"{where}: cfg for leaf `{leaf.name}` is outside its declared modules, tests, seams and `mod` line"


def source_problems(root: Path, leaves: dict[str, Leaf]) -> list[str]:
    problems: list[str] = []
    state: tuple[set[tuple[str, int]], dict[str, int]] = (set(), {})
    for directory in SCANNED:
        for path in sorted((root / directory).rglob("*.rs")):
            relative = path.relative_to(root).as_posix()
            if "target" in path.relative_to(root).parts:
                continue
            original = path.read_text(encoding="utf-8")
            stripped = strip_comments_and_strings(original)
            for span in cfg_spans(stripped, original):
                named = sorted(span[4] & set(leaves))
                if len(named) > 1:
                    problems.append(f"{relative}: a cfg names two leaves: {named}")
                elif named:
                    problem = check_occurrence(relative, stripped, span, leaves[named[0]], state)
                    problems += [problem] if problem else []
    for leaf in leaves.values():
        for number, seam in enumerate(leaf.seams):
            file = root / seam.file
            if not file.exists() or not item_spans(strip_comments_and_strings(file.read_text(encoding="utf-8")), seam.item):
                problems.append(f"leaf `{leaf.name}`: seam item `{seam.item}` not found in {seam.file}")
            elif (leaf.name, number) not in state[0]:
                problems.append(f"leaf `{leaf.name}`: seam `{seam.item}` in {seam.file} is unused (no cfg of the leaf in it)")
    return problems


def check(root: Path) -> list[str]:
    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    leaves, problems = read_leaves(manifest)
    return problems + feature_problems(manifest, leaves) + path_problems(root, leaves) + source_problems(root, leaves)


def self_test() -> int:
    from tempfile import TemporaryDirectory

    manifest = """\
[package]
name = "fixture"
[package.metadata.rskrb5-ng.leaf-features.alpha]
minimal = ["messages"]
modules = ["src/alpha.rs", "src/alpha/"]
tests = ["tests/alpha.rs"]
seams = [{ file = "src/crypto.rs", item = "fn dispatch", call = "alpha::run" }]
[package.metadata.rskrb5-ng.leaf-features.beta]
minimal = []
modules = ["src/beta.rs"]
[features]
default = ["messages"]
messages = []
alpha = ["messages", "dep:alpha"]
beta = ["dep:beta"]
"""
    files = {
        "src/lib.rs": '#[cfg(feature = "alpha")]\nmod alpha;\n#[cfg(feature = "beta")]\nmod beta;\nmod crypto;\n',
        "src/alpha.rs": '#[cfg(feature = "alpha")]\npub fn run(x: u8) -> u8 { x }\n',
        "src/alpha/inner.rs": '#![cfg(feature = "alpha")]\n',
        "src/beta.rs": '#[cfg(feature = "beta")]\npub fn run() {}\n',
        "tests/alpha.rs": '#![cfg(feature = "alpha")]\n',
        "src/other.rs": '// #[cfg(feature = "alpha")]\nconst S: &str = "feature = \\"alpha\\"";\n#[cfg(feature = "messages")]\nfn core() {}\n',
        "src/crypto.rs": (
            "pub fn dispatch(x: u8) -> u8 {\n    match x {\n        1 => 1,\n"
            '        #[cfg(feature = "alpha")]\n        2 => alpha::run(x),\n        _ => 0,\n    }\n}\n'
        ),
    }

    def run(changes: dict[str, str | None] | None = None, toml: str = manifest) -> list[str]:
        tree = files | (changes or {})
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(toml)
            for name, text in tree.items():
                if text is not None:
                    (root / name).parent.mkdir(parents=True, exist_ok=True)
                    (root / name).write_text(text)
            return check(root)

    def rejects(needle: str, label: str, changes: dict[str, str | None] | None = None, toml: str = manifest) -> None:
        found = run(changes, toml)
        assert any(needle in line for line in found), f"{label}: {needle!r} not in {found}"

    cfg_alpha = '#[cfg(feature = "alpha")]\nfn f() {}\n'
    assert run() == [], run()
    rejects("outside", "a leaf cfg outside its paths", {"src/other.rs": cfg_alpha})
    rejects("outside", "cfg! outside its paths", {"src/other.rs": 'fn f() -> bool { cfg!(feature = "beta") }\n'})
    rejects("outside", "a negated leaf cfg", {"src/other.rs": '#[cfg(not(feature = "alpha"))]\nfn f() {}\n'})
    rejects("outside", "a leaf cfg_attr", {"src/other.rs": '#[cfg_attr(feature = "alpha", derive(Debug))]\nstruct S;\n'})
    rejects("outside", "a leaf cfg in an example", {"examples/e.rs": cfg_alpha})
    rejects("outside", "a leaf cfg in the fuzz crate", {"fuzz/fuzz_targets/t.rs": cfg_alpha})
    rejects("outside", "another leaf's cfg in a leaf module", {"src/beta.rs": cfg_alpha})
    rejects("two leaves", "a cfg naming two leaves", {"src/alpha.rs": '#[cfg(all(feature = "alpha", feature = "beta"))]\nfn f() {}\n'})
    rejects("two leaves", "an any() naming two leaves", {"src/lib.rs": '#[cfg(any(feature = "alpha", feature = "beta"))]\nmod crypto;\n'})
    rejects("two leaves", "a nested cfg_attr naming two leaves", {"src/alpha.rs": '#[cfg_attr(feature = "alpha", cfg(feature = "beta"))]\nfn f() {}\n'})
    # Feature-graph rules.
    rejects("depends on leaf", "a leaf depending on a leaf", toml=manifest.replace('alpha = ["messages", "dep:alpha"]', 'alpha = ["messages", "beta", "dep:alpha"]'))
    rejects("depends on leaf", "a leaf depending on a leaf through a core feature", toml=manifest.replace("messages = []", 'messages = ["beta"]'))
    rejects("default", "a leaf in the default closure", toml=manifest.replace('default = ["messages"]', 'default = ["alpha"]'))
    rejects("core feature", "a core feature enabling a leaf", toml=manifest.replace("messages = []", 'messages = ["alpha"]').replace('default = ["messages"]', "default = []"))
    rejects("is not a `[features]` entry", "a leaf without a feature", toml=manifest.replace('beta = ["dep:beta"]\n', ""))
    rejects("minimal", "a minimal set naming a leaf", toml=manifest.replace('minimal = ["messages"]', 'minimal = ["beta"]'))
    rejects("both declare", "two leaves declaring one path", toml=manifest.replace('modules = ["src/beta.rs"]', 'modules = ["src/beta.rs", "src/alpha.rs"]'))
    rejects("does not exist", "a declared path that does not exist", {"src/beta.rs": None})
    # Seams and the lib.rs mod line.
    two_calls = files["src/crypto.rs"].replace("_ => 0,", "_ => alpha::run(0),")
    rejects("exactly once", "a seam with two delegating calls", {"src/crypto.rs": two_calls})
    rejects("exactly once", "a seam without its call", {"src/crypto.rs": files["src/crypto.rs"].replace("alpha::run(x)", "x")})
    rejects("not found", "a seam whose item is missing", {"src/crypto.rs": files["src/crypto.rs"].replace("fn dispatch", "fn route")})
    rejects("unused", "a seam no cfg uses", {"src/crypto.rs": files["src/crypto.rs"].replace('        #[cfg(feature = "alpha")]\n', "")})
    long_arm = files["src/crypto.rs"].replace("2 => alpha::run(x),", "2 => {\n let a = 1;\n let b = 2;\n let c = 3;\n let d = 4;\n alpha::run(x + a + b + c + d)\n }")
    rejects("lines", "a seam unit longer than the cap", {"src/crypto.rs": long_arm})
    rejects("second", "two mod lines of one leaf", {"src/lib.rs": files["src/lib.rs"] + '#[cfg(feature = "alpha")]\nmod alpha;\n'})
    rejects("outside", "a mod line outside src/lib.rs", {"src/other.rs": '#[cfg(feature = "beta")]\nmod beta;\n'})
    rejects("outside", "a leaf cfg on a non-mod item of lib.rs", {"src/lib.rs": files["src/lib.rs"] + '#[cfg(feature = "alpha")]\nfn f() {}\n'})
    print(f"leaf_features self-test: ok ({len(files)} fixture files, leaf cfg, seam, mod line and feature-graph cases)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    problems = check(args.root)
    print("\n".join(problems + [f"leaf_features: {len(problems)} problem(s)"]))
    return int(args.enforce and bool(problems))


if __name__ == "__main__":
    sys.exit(main())
