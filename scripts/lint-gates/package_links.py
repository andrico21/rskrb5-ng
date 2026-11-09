#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/package_links.py --enforce
"""Hold every relative Markdown link of the published package inside it.

`cargo package --list --allow-dirty` names the files of the archive. Each
packaged Markdown file is read (CRLF-safe; fenced code blocks and code spans
are skipped) for inline and image links, reference definitions, autolinks
and HTML `href`/`src` attributes. A relative target must name a packaged
file (or a directory holding one) and a fragment must name a heading or an
`id`/`name` anchor of a packaged Markdown target. Targets the archive
excludes are linked as `https://github.com/andrico21/rskrb5-ng/blob/main/...`
(or `tree/main/...`), which must name an existing file (directory) of the
checkout. `http(s)`, `mailto` and anchor-only links are not resolved; any
other scheme, a root-absolute path and a path leaving the package fail.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import subprocess
import sys
from contextlib import redirect_stdout
from io import StringIO
from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final
from urllib.parse import unquote

ROOT: Final = Path(__file__).resolve().parents[2]
REPO_URL: Final = re.compile(
    r"https://github\.com/andrico21/rskrb5-ng/(blob|tree)/main/([^#?]+)"
)
SCHEME: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
FENCE: Final = re.compile(r" {0,3}(`{3,}|~{3,})")
REFERENCE: Final = re.compile(
    r"^ {0,3}\[(?!\^)(?:\\[^\n]|[^\]\\])+\]:[ \t]*(?:\n[ \t]*)?",
    re.MULTILINE,
)
AUTOLINK: Final = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]*:[^\s<>]*)>")
ANCHOR: Final = re.compile(r"""<a\s[^>]*\b(?:id|name)\s*=\s*["']([^"']+)["']""")
HEADING: Final = re.compile(r" {0,3}#{1,6}\s+(.*?)\s*#*\s*$")


def package_files(root: Path) -> frozenset[str]:
    listing = subprocess.run(
        ["cargo", "package", "--list", "--allow-dirty"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if listing.returncode != 0:
        raise SystemExit(
            f"package_links: cargo package --list failed:\n{listing.stderr}"
        )
    return frozenset(
        line.strip() for line in listing.stdout.splitlines() if line.strip()
    )


def prose_lines(text: str) -> list[tuple[int, str]]:
    """Numbered lines outside fenced code blocks."""
    lines = []
    fence = ""
    for number, line in enumerate(
        text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1
    ):
        opening = FENCE.match(line)
        if fence:
            if (
                opening
                and opening.group(1)[0] == fence[0]
                and len(opening.group(1)) >= len(fence)
            ):
                fence = ""
            continue
        if opening:
            fence = opening.group(1)
            continue
        lines.append((number, line))
    return lines


def destination(line: str, start: int) -> str:
    if line.startswith("<", start):
        end = line.find(">", start)
        return line[start + 1 : end if end >= 0 else len(line)]
    depth, index = 0, start
    while index < len(line):
        char = line[index]
        if char == "\\":
            index += 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            if depth == 0:
                break
            depth -= 1
        elif char.isspace():
            break
        index += 1
    return line[start:index]


def link_targets(text: str) -> list[tuple[int, str]]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [""] * len(normalized.split("\n"))
    for number, raw in prose_lines(normalized):
        lines[number - 1] = raw
    prose = "\n".join(lines)
    visible = code_spans(prose)
    found: list[tuple[int, str]] = []
    index = 0
    while index < len(visible):
        if visible[index] == "\\":
            index += 2
            continue
        if visible.startswith("](", index):
            start = index + 2
            while start < len(visible) and visible[start].isspace():
                start += 1
            found.append(
                (visible.count("\n", 0, index) + 1, destination(visible, start))
            )
        index += 1
    for reference in REFERENCE.finditer(visible):
        found.append(
            (
                visible.count("\n", 0, reference.start()) + 1,
                destination(visible, reference.end()),
            )
        )
    for number, line in enumerate(visible.splitlines(), 1):
        found.extend((number, m.group(1)) for m in AUTOLINK.finditer(line))
    parser = LinkAttributes()
    parser.feed(visible)
    parser.close()
    found.extend(parser.targets)
    return found


def code_spans(prose: str) -> str:
    """Blank exact-run spans within blocks; escapes apply only outside spans."""
    boundaries = {0, len(prose)}
    offset = 0
    for line in prose.splitlines(keepends=True):
        content = line.rstrip("\n")
        if not content.strip() or re.match(
            r" {0,3}(?:#{1,6}(?:\s|$)|>|[-+*]\s|\d+[.)]\s|<[/!A-Za-z])",
            content,
        ):
            boundaries.add(offset)
        if (
            not content.strip()
            or re.match(r" {0,3}#{1,6}(?:\s|$)", content)
            or re.fullmatch(
                r" {0,3}(?:=+|-+|(?:-[ \t]*){3,}|(?:\*[ \t]*){3,}|(?:_[ \t]*){3,})[ \t]*",
                content,
            )
        ):
            boundaries.add(offset + len(line))
        offset += len(line)
    chars = list(prose)
    ordered = sorted(boundaries)
    for start, stop in zip(ordered, ordered[1:]):
        index = start
        while index < stop:
            if prose[index] == "\\":
                index += 2
                continue
            opening = re.match(r"`+", prose[index:stop])
            if opening is None:
                index += 1
                continue
            end = index + len(opening[0])
            closing = next(
                (
                    run
                    for run in re.finditer(r"`+", prose[end:stop])
                    if len(run[0]) == len(opening[0])
                ),
                None,
            )
            if closing is None:
                index = end
                continue
            close = end + closing.end()
            for position in range(index, close):
                if chars[position] != "\n":
                    chars[position] = " "
            index = close
    return "".join(chars)


class LinkAttributes(HTMLParser):
    """Accumulate real HTML link attributes with parser source positions."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.targets: list[tuple[int, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in {"href", "src"} and value is not None:
                self.targets.append((self.getpos()[0], value))


def anchors(text: str) -> frozenset[str]:
    """GitHub heading slugs (duplicates numbered) plus explicit HTML anchors."""
    seen: dict[str, int] = {}
    found = set(ANCHOR.findall(text))
    for _, line in prose_lines(text):
        heading = HEADING.match(line.replace("`", ""))
        if heading is None:
            continue
        title = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading.group(1))
        slug = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        found.add(slug if count == 0 else f"{slug}-{count}")
    return frozenset(found)


def target_problem(
    root: Path, files: frozenset[str], source: str, target: str
) -> str | None:
    if not target or target.startswith("#"):
        return None
    if SCHEME.match(target):
        repo = REPO_URL.match(target)
        if repo is None:
            scheme = target.split(":", 1)[0].lower()
            return (
                None
                if scheme in {"http", "https", "mailto"}
                else f"unsupported scheme `{scheme}:`"
            )
        path = root / unquote(repo.group(2)).rstrip("/")
        exists = path.is_file() if repo.group(1) == "blob" else path.is_dir()
        return (
            None
            if exists
            else f"no {repo.group(1)} `{repo.group(2)}` in the repository"
        )
    if target.startswith("/"):
        return "root-absolute path"
    path_part, _, fragment = target.partition("#")
    path = posixpath.normpath(
        posixpath.join(posixpath.dirname(source), unquote(path_part.split("?")[0]))
    )
    if path == ".." or path.startswith("../"):
        return "resolves outside the package"
    if path not in files:
        if any(name.startswith(path.rstrip("/") + "/") for name in files):
            return None
        where = "excluded from the package" if (root / path).exists() else "missing"
        kind = "tree" if (root / path).is_dir() else "blob"
        return f"`{path}` is {where}; use https://github.com/andrico21/rskrb5-ng/{kind}/main/{path}"
    if fragment and path.endswith(".md"):
        text = (root / path).read_bytes().decode("utf-8")
        if unquote(fragment) not in anchors(text):
            return f"`{path}` has no anchor `#{fragment}`"
    return None


def check(root: Path, files: frozenset[str]) -> list[str]:
    problems = []
    for source in sorted(name for name in files if name.endswith(".md")):
        text = (root / source).read_bytes().decode("utf-8")
        for number, target in link_targets(text):
            problem = target_problem(root, files, source, target)
            if problem is not None:
                problems.append(f"{source}:{number}: ({target}) {problem}")
    return problems


def self_test() -> int:
    payload = package_files(ROOT)
    for checkout_audit in (
        "tests/mit_parity_manifest.rs",
        "tests/gokrb5_parity_manifest.rs",
    ):
        assert checkout_audit not in payload, (
            f"checkout-only audit packaged: {checkout_audit}"
        )
    with TemporaryDirectory() as directory:
        root = Path(directory)
        for name in (
            "README.md",
            "docs/a.md",
            "docs/review/README.md",
            "scripts/x.py",
            "src/lib.rs",
        ):
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(
                "# Title\n\n## Two words `code`\n\n## Two words code\n"
            )
        files = frozenset({"README.md", "docs/a.md", "src/lib.rs"})

        def problems(readme: bytes) -> list[str]:
            (root / "README.md").write_bytes(readme)
            return check(root, files)

        clean = (
            b"[a](docs/a.md#two-words-code-1) ![i](docs/a.md) [s](#local) [w](https://x.org/a)\n"
            b"[m](mailto:a@b.c) <https://x.org> [ref]: <docs/a.md#title>\n"
            b"[r](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/README.md)\n"
            b"[t](https://github.com/andrico21/rskrb5-ng/tree/main/scripts/) [d](docs/)\n"
            b"`[c](docs/review/README.md)` and ``[c](x)``\n```md\n[f](docs/review/README.md)\n```\n"
        )
        assert problems(clean) == [], problems(clean)
        assert problems(clean.replace(b"\n", b"\r\n")) == [], "CRLF clean"
        for link in (
            "[bad]:\n  missing.md\n[x][bad]",
            "[long\n label]:\n  missing.md\n[x][long label]",
            "[bad]:\n  <missing.md>\n[x][bad]",
            '[bad]:\r\n\tmissing.md "title"\r\n[x][bad]',
            "[escaped\\]label]:\n missing.md\n[x][escaped\\]label]",
            "[bad](\nmissing.md)",
            "<a href=missing.md>x</a>",
            "<img src=missing.png>",
        ):
            (root / "docs/a.md").write_text(
                "# Title\n\n## Two words `code`\n\n## Two words code\n" + link
            )
            assert len(problems(clean)) == 1, (link, problems(clean))
        (root / "docs/a.md").write_text(
            "# Title\n\n## Two words `code`\n\n## Two words code\n[good](\n../README.md)"
        )
        assert problems(clean) == [], "valid multiline destination"
        (root / "docs/a.md").write_text(
            "# Title\n\n## Two words `code`\n\n## Two words code\n"
            '[good]:\n  <../README.md>\n  "title"\n[x][good]\n'
            "```md\n[bad]:\n missing.md\n```\n"
        )
        assert problems(clean) == [], "valid multiline reference or fenced exclusion"
        (root / "docs/a.md").write_text(
            "# Title\n\n## Two words `code`\n\n## Two words code\n"
        )
        for bad, count in (
            (b"` unmatched\n[bad](missing.md)\n``code``", 1),
            (b"`` unmatched\n[bad](missing.md)\n`code`", 1),
            (b"` unmatched [bad](missing.md)", 1),
            (b"\\` [bad](missing.md) `", 1),
            (b"`code\\` [bad](missing.md) `", 1),
            (b"`` [bad](missing.md) ` literal ``", 0),
            (b"` [bad](missing.md) `", 0),
            (b"` code\n[bad](missing.md) `", 0),
            (b"` code\n\n[bad](missing.md) `", 1),
            (b"` code\n# [bad](missing.md) `", 1),
            (b"# ` code\n[bad](missing.md) `", 1),
            (b"- ` code\n- [bad](missing.md) `", 1),
            (b"` code\n---\n[bad](missing.md) `", 1),
            (b"` code\n> [bad](missing.md) `", 1),
            (b"` code\n<div>\n[bad](missing.md) `\n</div>", 1),
            (b"see [review](docs/review/README.md)\n", 1),
            (b"see [review](docs/review/README.md)\r\nmore\r\n", 1),
            (b"[ref]: docs/review/README.md\n", 1),
            (b'<a href="scripts/x.py">x</a>\n', 1),
            (b"[m](docs/missing.md)\n", 1),
            (b"[f](docs/a.md#absent)\n", 1),
            (b"[o](../outside.md) [p](/README.md) <file:///etc/hosts>\n", 3),
            (
                b"[u](https://github.com/andrico21/rskrb5-ng/blob/main/docs/nope.md)\n",
                1,
            ),
            (b"[d](scripts/) ~~~\n", 1),
        ):
            assert len(problems(bad)) == count, (bad, problems(bad))
        headings = (root / "docs/a.md").read_text()
        (root / "docs/a.md").write_text(
            headings + "[r](review/README.md) [s](../scripts/x.py)\n"
        )
        assert len(problems(clean)) == 2, problems(clean)
        (root / "Cargo.toml").write_text(
            '[package]\nname = "t"\nversion = "0.0.0"\nedition = "2021"\n'
            'license = "MIT"\ndescription = "t"\nexclude = ["docs/review/", "scripts/"]\n'
        )
        (root / "docs/a.md").write_text(headings)
        (root / "README.md").write_text("[r](docs/review/README.md)\n")
        report = StringIO()
        with redirect_stdout(report):
            failed = main(["--enforce", "--root", str(root)])
            (root / "README.md").write_text(clean.decode())
            passed = main(["--enforce", "--root", str(root)])
        assert (failed, passed) == (1, 0), report.getvalue()
        assert "README.md:1: (docs/review/README.md)" in report.getvalue(), (
            report.getvalue()
        )
    print(
        "package_links self-test: ok (inline, reference, autolink, HTML, CRLF, fragments, cargo list)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    files = package_files(args.root)
    problems = check(args.root, files)
    markdown = sum(name.endswith(".md") for name in files)
    print(
        "\n".join(
            problems
            + [
                f"package_links: {len(problems)} problem(s) in {markdown} packaged Markdown file(s)"
            ]
        )
    )
    return int(args.enforce and bool(problems))


if __name__ == "__main__":
    sys.exit(main())
