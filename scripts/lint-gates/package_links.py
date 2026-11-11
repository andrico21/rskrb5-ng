#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["markdown-it-py==3.0.0", "mdurl==0.1.2"]
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
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final
from urllib.parse import unquote

from package_markdown import UnclassifiableDestination, link_targets, markdown_parser

ROOT: Final = Path(__file__).resolve().parents[2]
REPO_URL: Final = re.compile(
    r"https://github\.com/andrico21/rskrb5-ng/(blob|tree)/main/([^#?]+)"
)
SCHEME: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
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
    """Numbered lines outside parser-recognized code and HTML blocks."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    excluded = set()
    for token in markdown_parser().parse(text):
        if token.type in {"fence", "code_block", "html_block"} and token.map:
            excluded.update(range(token.map[0] + 1, token.map[1] + 1))
    return [
        (number, line)
        for number, line in enumerate(text.split("\n"), 1)
        if number not in excluded
    ]


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
        try:
            targets = link_targets(text)
        except UnclassifiableDestination as error:
            problems.append(f"{source}: {error}")
            continue
        for number, target in targets:
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
        failures = []
        # U6-01..03: complete rendered targets must defeat packaged decoys.
        (root / "missing").write_text("decoy")
        for label, markdown, expected in (
            ("inline_backtick", "[real](missing`file`.md)", "missing`file`.md"),
            ("angle_backtick", "[real](<missing`file`.md>)", "missing`file`.md"),
            (
                "title_backtick",
                '[ok](README.md "`title") [real](missing.md) `',
                "missing.md",
            ),
            (
                "image_backtick",
                '![ok](README.md "`title") ![real](missing.md) `',
                "missing.md",
            ),
            ("unicode_nbsp", "[real](missing\u00a0file.md)", "missing\u00a0file.md"),
            ("unicode_emspace", "[real](missing\u2003file.md)", "missing\u2003file.md"),
            (
                "unicode_narrow_nbsp",
                "[real](missing\u202ffile.md)",
                "missing\u202ffile.md",
            ),
            (
                "html_div_backtick",
                '<div>\n`<a href="missing.md">real</a>`\n</div>',
                "missing.md",
            ),
            (
                "html_pre_backtick",
                '<pre>\n`<a href="missing.md">real</a>`\n</pre>',
                "missing.md",
            ),
            (
                "html_custom_backtick",
                '<custom>\n`<img src="missing.md">`\n</custom>',
                "missing.md",
            ),
        ):
            (root / "README.md").write_text(markdown)
            found = check(root, files | {"missing"})
            if len(found) != 1 or f"({expected})" not in found[0]:
                failures.append((label, found, expected))
        (root / "missing&").write_text("decoy")
        entity_files = files | {"missing&"}
        for label, markdown, expected in (
            (
                "entity_fragment",
                "[real](docs/a.md&#35;absent)",
                [(1, "docs/a.md#absent")],
            ),
            (
                "entity_query",
                "[real](missing&#46;md?x=1&amp;y=2)",
                [(1, "missing.md?x=1&y=2")],
            ),
            ("escaped_entity", r"[real](missing\&#46;md)", [(1, "missing&#46;md")]),
            ("single_decode", "[real](missing&amp;#46;md)", [(1, "missing&#46;md")]),
            (
                "unmatched_code_comment",
                "`<!--\n\n```\n<!--\n```\n\n[real](missing2.md)\n-->\n`",
                [(7, "missing2.md")],
            ),
            (
                "escaped_comment",
                "\\<!--\n\n```\n<!--\n```\n\n[real](missing2.md)\n-->\n`",
                [(7, "missing2.md")],
            ),
            (
                "code_comment_before_fence",
                "`<!--`\n\n```\n-->\n[code](README.md)\n```\n[real](missing2.md)",
                [(7, "missing2.md")],
            ),
            ("inline_entity", "[real](missing&#46;md)", [(1, "missing.md")]),
            ("reference_entity", "[x][r]\n\n[r]: missing&#46;md", [(3, "missing.md")]),
            ("angle_entity", "[real](<missing&#x2e;md>)", [(1, "missing.md")]),
            ("named_entity", "[real](missing&period;md)", [(1, "missing.md")]),
            (
                "existing_entity",
                "[real](docs/a&#46;md#title)",
                [(1, "docs/a.md#title")],
            ),
            ("escaped_destination", r"[real](missing\&.md)", [(1, "missing&.md")]),
            ("entity_zero", "[real](missing&#0;.md)", [(1, "missing\ufffd.md")]),
            ("entity_c1", "[real](missing&#128;.md)", [(1, "missing\x80.md")]),
            (
                "entity_unknown",
                "[real](missing&notanentity;.md)",
                [(1, "missing&notanentity;.md")],
            ),
        ):
            (root / "README.md").write_text(markdown)
            targets = link_targets(markdown)
            if targets != expected:
                failures.append((label, targets, expected))
            found = check(root, entity_files)
            wanted = (
                0
                if label in {"existing_entity", "escaped_entity", "single_decode"}
                else 1
            )
            if len(found) != wanted or (
                wanted
                and f"README.md:{expected[0][0]}: ({expected[0][1]})" not in found[0]
            ):
                failures.append((label, found, expected))
        for bad, count in (
            (b'<a title="`">x</a> [bad](missing.md) <a title="`">y</a>', 1),
            (b'see <a title="`">x</a> [bad](missing.md) <a title="`">y</a>', 1),
            (b"see <a title='``'>x</a> [bad](missing.md) <a title='``'>y</a>", 1),
            (b"see <!-- ` --> [bad](missing.md) <!-- ` -->", 1),
            (b'[bad]: missing`file.md "`title`"\n[x][bad]', 1),
            (b'[bad]: <missing`file.md> "`title`"\n[x][bad]', 1),
            (b"<!--\n```\n-->\n[bad](missing.md)\n", 1),
            (b'<div title="x\n```\n">\n</div>\n\n[bad](missing.md)\n', 1),
            (b'`<a title="x"> [bad](missing.md) </a>`', 0),
            (b"`<!-- [bad](missing.md) -->`", 0),
            (b'```html\n<a title="`"> [bad](missing.md)\n```\n', 0),
            (
                b'see <a title="`" href="docs/a.md">ok</a> [ok](docs/a.md) <a title="`">ok</a>',
                0,
            ),
            (b"see <!-- ` --> [ok](docs/a.md) <!-- ` -->", 0),
            (b"<https://example.org/`x> [bad](missing.md) `", 1),
            (b"[bad]: missing`file`.md\n[x][bad]", 1),
            (b'[ok]: docs/a.md "`title"\n[x][ok]\n[bad](missing.md) `', 1),
            (
                b'see <a title="`" href=https://example.org>x</a> [bad](missing.md) <a title="`">y</a>',
                1,
            ),
            (b"<script>`</script>\n\n[bad](missing.md) `", 1),
            (b"<style>\n```\n</style>\n\n[bad](missing.md)\n", 1),
            (b"<div>\n```\n</div>\n\n[bad](missing.md)\n", 1),
            (b"<![CDATA[\n```\n]]>\n\n[bad](missing.md)\n", 1),
            (
                "```text\ninside\n```\u00a0\ninside\n```\n[bad](missing.md)\n".encode(),
                1,
            ),
            (
                "~~~text\r\ninside\r\n~~~\u2003\r\ninside\r\n~~~\r\n[bad](missing.md)\r\n".encode(),
                1,
            ),
            (b"``` invalid ` info\n\n[bad](missing.md)\n", 1),
            (b"```md\n``` trailing\n[bad](missing.md)\n```\n", 0),
            (b"~~~md\n~~~ trailing\n[bad](missing.md)\n~~~\n", 0),
            (b"~~~ invalid ` info\n[bad](missing.md)\n~~~\n", 0),
            (b"```md\n[bad](missing.md)\n``` \t\n[bad](missing.md)\n", 1),
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
            # CommonMark and lychee render no link here (todo 61 evidence).
            (b"` code\n<div>\n[bad](missing.md) `\n</div>", 0),
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
            found = problems(bad)
            if len(found) != count:
                failures.append((bad, found, count))
        assert not failures, failures
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
