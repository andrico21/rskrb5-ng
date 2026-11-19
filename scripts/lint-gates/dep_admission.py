#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/dep_admission.py --enforce
"""Dependency admission gate (owner decisions D3, D6, D10; docs/dependency-admission.md).

Two stages. The manifest stage reads every first-party `Cargo.toml` and applies
the admission rules to each direct dependency added after the baseline: it
must be optional, enabled only by leaf features, and have an admission record;
no forbidden crate may be declared at all. The only non-optional exception is
`rustix` under the non-Linux Unix target table with exactly the features its
record lists. The graph stage walks the feature-resolved graph of every
first-party package on four targets (`cargo tree --all-features -e
normal,build,dev --target <t>`; raw `cargo metadata` over-approximates, it
reaches `ring` through an unused hickory-proto feature) and rejects forbidden
crates, `links` packages and `cc`/`cmake`/`pkg-config` build scripts outside the
OS-wrapper allow list, and the fuzz runtime's `libfuzzer-sys` anywhere but in
the standalone fuzz crate. A failure in the manifest stage stops before cargo.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import source_set

BASELINE: Final = "c790b57a21e0a681f1bbf8db41462bdf69f5c27f"
TARGETS: Final = (
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-apple-darwin",
    "i686-unknown-linux-gnu",
)
FORBIDDEN: Final = (
    "openssl*",
    "native-tls",
    "ring",
    "aws-lc*",
    "cryptoki*",
    "libloading",
    "bindgen",
)
OS_WRAPPERS: Final = frozenset(
    {
        "libc",
        "linux-raw-sys",
        "rustix",
        "windows-sys",
        "windows-targets",
        "windows-link",
    }
)
BUILD_TOOLS: Final = frozenset({"cc", "cmake", "pkg-config"})
FIRST_PARTY: Final = frozenset({"rskrb5-ng", "rskrb5-ng-os", "rskrb5-ng-fuzz"})
FUZZ_RUNTIME: Final = "libfuzzer-sys"
FUZZ_PACKAGE: Final = "rskrb5-ng-fuzz"
RUSTIX_TABLE: Final = (
    'cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))'
)
DOC: Final = "docs/dependency-admission.md"
FIELDS: Final = (
    "Version",
    "Leaf flags",
    "Licence",
    "Source review",
    "Constant-time and zeroization",
    "Cargo vet",
    "Maintenance",
)
KINDS: Final = (
    ("normal", "dependencies"),
    ("dev", "dev-dependencies"),
    ("build", "build-dependencies"),
)
TREE_LINE: Final = re.compile(r"^(\S+) v(\S+)")
DEPTH_LINE: Final = re.compile(r"^(\d+)(\S+) v\S+")
FIELD_LINE: Final = re.compile(r"^[-*]\s+([A-Za-z][A-Za-z -]*?):\s*(.*?)\s*$")


@dataclass(frozen=True, slots=True)
class Dep:
    package: str
    kind: str
    target: str | None
    optional: bool
    features: frozenset[str]
    default_features: bool


def forbidden(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in FORBIDDEN)


def direct_dependencies(manifest: dict) -> list[Dep]:
    """Every direct dependency of every kind, in the plain and the target tables."""
    scopes: list[tuple[str | None, dict]] = [(None, manifest)]
    scopes += [(cfg, table) for cfg, table in manifest.get("target", {}).items()]
    found = []
    for target, scope in scopes:
        for kind, key in KINDS:
            for name, spec in scope.get(key, {}).items():
                detail = spec if isinstance(spec, dict) else {}
                found.append(
                    Dep(
                        package=str(detail.get("package", name)),
                        kind=kind,
                        target=target,
                        optional=bool(detail.get("optional", False)),
                        features=frozenset(detail.get("features", ())),
                        default_features=bool(detail.get("default-features", True)),
                    )
                )
    return found


def enabling_features(manifest: dict, package: str) -> set[str]:
    """Features that enable the optional `package`; the implicit one counts as `package`."""
    users: set[str] = set()
    explicit = False
    for feature, entries in manifest.get("features", {}).items():
        for entry in entries:
            name = entry.removeprefix("dep:")
            if entry.startswith("dep:") and name.split("/")[0] == package:
                explicit = True
                users.add(feature)
            elif "/" in name and name.split("/")[0].rstrip("?") == package:
                users.add(feature)
    return users if explicit else users | {package}


def rustix_problems(declared: list[Dep], record: dict[str, str] | None) -> list[str]:
    """Only the recorded non-Linux-Unix target exception may be non-optional."""
    problems = []
    for dep in declared:
        where = "[dependencies]" if dep.target is None else f"[target.'{dep.target}']"
        if dep.kind != "normal" or dep.target != RUSTIX_TABLE:
            problems.append(
                f"non-optional rustix in {dep.kind} {where}: the only exception is "
                f"[target.'{RUSTIX_TABLE}'.dependencies] (owner 2026-11-18)"
            )
            continue
        listed = {
            f.strip()
            for f in (record or {}).get("Features", "").split(",")
            if f.strip()
        }
        if dep.default_features:
            problems.append("rustix must set default-features = false")
        if dep.features != listed:
            extra = sorted(dep.features - listed)
            problems.append(
                f"rustix features {sorted(dep.features)} differ from its admission record {sorted(listed)}"
                + (f" (unlisted: {extra})" if extra else "")
            )
    return problems


def manifest_problems(
    manifest: dict,
    baseline: frozenset[tuple[str, str]],
    records: dict[str, dict[str, str]],
) -> list[str]:
    owner = manifest.get("package", {}).get("name", "?")
    leaves = set(
        manifest.get("package", {})
        .get("metadata", {})
        .get("rskrb5-ng", {})
        .get("leaf-features", {})
    )
    problems = []
    deps = direct_dependencies(manifest)
    for dep in deps:
        if forbidden(dep.package):
            problems.append(
                f"{owner}: forbidden crate `{dep.package}` as a {dep.kind} dependency"
            )
    new = [
        dep
        for dep in deps
        if (dep.kind, dep.package) not in baseline
        and dep.package not in FIRST_PARTY
        and not forbidden(dep.package)
    ]
    rustix = [
        d for d in new if d.package == "rustix" and not d.optional and d.kind != "dev"
    ]
    problems += [
        f"{owner}: {line}" for line in rustix_problems(rustix, records.get("rustix"))
    ]
    for dep in new:
        if dep.package not in records:
            problems.append(
                f"{owner}: `{dep.package}` lacks an admission record in {DOC}"
            )
        if dep.kind == "dev" or dep in rustix:
            continue
        if not dep.optional:
            problems.append(
                f"{owner}: non-optional new dependency `{dep.package}` "
                "(D10: optional, enabled only by leaf features)"
            )
            continue
        for feature in sorted(enabling_features(manifest, dep.package) - leaves):
            problems.append(
                f"{owner}: `{dep.package}` is enabled by `{feature}`, which is not a leaf "
                "feature of [package.metadata.rskrb5-ng.leaf-features]"
            )
    return problems


def version_problems(
    manifest: dict,
    baseline: frozenset[tuple[str, str]],
    records: dict[str, dict[str, str]],
    locked: dict[str, set[str]],
) -> list[str]:
    owner = manifest.get("package", {}).get("name", "?")
    problems = []
    for dep in direct_dependencies(manifest):
        if (dep.kind, dep.package) in baseline or dep.package in FIRST_PARTY:
            continue
        record = records.get(dep.package)
        if record is None:
            continue
        missing = [field for field in FIELDS if not record.get(field)]
        if missing:
            problems.append(f"{owner}: record of `{dep.package}` lacks {missing}")
        version = record.get("Version", "").lstrip("=")
        if version not in locked.get(dep.package, set()):
            problems.append(
                f"{owner}: record of `{dep.package}` names version {version!r}, "
                f"the lock has {sorted(locked.get(dep.package, set()))}"
            )
    return problems


def tree_packages(text: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for line in text.splitlines():
        match = TREE_LINE.match(line)
        if match:
            found.setdefault(match[1], set()).add(match[2])
    return found


def graph_problems(
    label: str,
    trees: dict[str, str],
    metadata: dict,
    exempt: frozenset[str],
    role: str,
) -> list[str]:
    """`role` is `fuzz` for the standalone fuzz crate, else `main`."""
    problems = []
    runtime = exempt | {FUZZ_RUNTIME}
    seen: dict[str, set[str]] = {}
    for target, text in sorted(trees.items()):
        for name, versions in tree_packages(text).items():
            seen.setdefault(name, set()).update(versions)
            if forbidden(name):
                problems.append(
                    f"{label}: forbidden crate `{name}` in the resolved graph for {target}"
                )
            if role != "fuzz" and name in runtime:
                problems.append(
                    f"{label}: `{name}` (the fuzz runtime {FUZZ_RUNTIME}, or a package "
                    f"reachable only through it) is reachable from {label} for {target}"
                )
    for package in metadata.get("packages", []):
        name = package["name"]
        if package["version"] not in seen.get(name, set()):
            continue
        tools = {
            d["name"]
            for d in package.get("dependencies", [])
            if d.get("kind") == "build"
        } & BUILD_TOOLS
        if not (package.get("links") or tools) or name in OS_WRAPPERS:
            continue
        if role == "fuzz" and name in runtime:
            continue
        what = (
            f"links `{package['links']}`"
            if package.get("links")
            else f"builds with {sorted(tools)}"
        )
        problems.append(
            f"{label}: `{name}` {package['version']} {what}, outside the OS-wrapper allow list"
        )
    return problems


def subtree_names(depth_tree: str, root: str) -> set[str]:
    """Names under the depth-1 node `root` of a `--prefix depth --no-dedupe` tree."""
    names: set[str] = set()
    inside = False
    for line in depth_tree.splitlines():
        match = DEPTH_LINE.match(line)
        if not match:
            continue
        depth, name = int(match[1]), match[2]
        if depth == 1:
            inside = name == root
        if inside:
            names.add(name)
    return names


def exempt_names(depth_tree: str) -> frozenset[str]:
    """Packages of the fuzz graph reachable from `libfuzzer-sys` but not from `rskrb5-ng`."""
    return frozenset(
        subtree_names(depth_tree, FUZZ_RUNTIME) - subtree_names(depth_tree, "rskrb5-ng")
    )


def parse_records(markdown: str) -> dict[str, dict[str, str]]:
    """`### <crate>` headings with `- Field: value` lines; fenced blocks are skipped."""
    records: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    fenced = False
    for line in markdown.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif fenced:
            continue
        elif line.startswith("### "):
            name = line[4:].strip().strip("`").split()[0] if line[4:].strip() else ""
            current = records.setdefault(name.strip("`"), {}) if name else None
        elif line.startswith("#"):
            current = None
        elif current is not None and (field := FIELD_LINE.match(line)):
            current[field[1]] = field[2]
    return records


def parse_baseline(markdown: str) -> dict[str, frozenset[tuple[str, str]]]:
    """The fenced `baseline` block: one `<package> <kind> <dependency>` per line."""
    found: dict[str, set[tuple[str, str]]] = {}
    inside = False
    for line in markdown.splitlines():
        if line.startswith("```"):
            inside = line.strip() == "```baseline"
        elif inside and line.strip():
            package, kind, name = line.split()
            found.setdefault(package, set()).add((kind, name))
    return {package: frozenset(deps) for package, deps in found.items()}


def baseline_manifest_sets(
    texts: dict[str, str],
) -> dict[str, frozenset[tuple[str, str]]]:
    """The direct dependencies of manifests (from `git show <BASELINE>:<path>`)."""
    sets = {}
    for text in texts.values():
        manifest = tomllib.loads(text)
        sets[manifest["package"]["name"]] = frozenset(
            (dep.kind, dep.package) for dep in direct_dependencies(manifest)
        )
    return sets


def git_baseline(root: Path, paths: list[str]) -> dict[str, str] | None:
    texts = {}
    for path in paths:
        shown = subprocess.run(
            ["git", "-C", str(root), "show", f"{BASELINE}:{path}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if shown.returncode != 0:
            return None
        texts[path] = shown.stdout
    return texts


def cargo(root: Path, *arguments: str) -> str:
    done = subprocess.run(
        ["flock", "-w", "900", "/tmp/rskrb5-cargo.lock", "cargo", *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(f"cargo {' '.join(arguments)}: {done.stderr.strip()[-400:]}")
    return done.stdout


def resolved_tree(root: Path, manifest: Path, target: str, offline: bool, shape: tuple[str, ...] = ("--prefix", "none")) -> str:
    arguments = ["tree", "--manifest-path", str(manifest), "--all-features", "-e", "normal,build,dev",
                 "--target", target, "--format", "{p}", *shape]
    if (manifest.parent / "Cargo.lock").exists():
        arguments.append("--locked")
    return cargo(root, *arguments, *(["--offline"] if offline else []))


def enforce(root: Path, offline: bool) -> list[str]:
    docs = (root / DOC).read_text(encoding="utf-8")
    records = parse_records(docs)
    declared = parse_baseline(docs)
    problems = []
    paths = ["Cargo.toml", "fuzz/Cargo.toml"]
    texts = git_baseline(root, paths)
    if texts is not None and baseline_manifest_sets(texts) != declared:
        problems.append(
            f"{DOC}: the baseline block differs from `git show {BASELINE}:<manifests>`"
        )
    manifests = {}
    for path in source_set.manifests(root):
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        if "package" in manifest:
            manifests[path] = manifest
    for path, manifest in manifests.items():
        old = declared.get(manifest["package"]["name"], frozenset())
        problems += [
            f"{path.relative_to(root)}: {line}"
            for line in manifest_problems(manifest, old, records)
        ]
    if problems:
        return problems
    fuzz = next(
        (p for p, m in manifests.items() if m["package"]["name"] == FUZZ_PACKAGE), None
    )
    exempt: frozenset[str] = frozenset()
    if fuzz is not None:
        host = TARGETS[0]
        exempt = exempt_names(
            resolved_tree(root, fuzz, host, offline, ("--prefix", "depth", "--no-dedupe"))
        )
    locked: dict[str, set[str]] = {}
    for path, manifest in manifests.items():
        name = manifest["package"]["name"]
        trees = {t: resolved_tree(root, path, t, offline) for t in TARGETS}
        metadata_arguments = [
            "metadata",
            "--manifest-path",
            str(path),
            "--all-features",
            "--format-version",
            "1",
        ]
        if (path.parent / "Cargo.lock").exists():
            metadata_arguments.append("--locked")
        metadata = json.loads(
            cargo(root, *metadata_arguments, *(["--offline"] if offline else []))
        )
        for package in metadata["packages"]:
            locked.setdefault(package["name"], set()).add(package["version"])
        role = "fuzz" if name == FUZZ_PACKAGE else "main"
        problems += graph_problems(name, trees, metadata, exempt, role)
    for manifest in manifests.values():
        old = declared.get(manifest["package"]["name"], frozenset())
        problems += version_problems(manifest, old, records, locked)
    return problems


def self_test() -> int:
    import copy

    full = {field: "recorded" for field in FIELDS}
    records = {
        "camellia": full | {"Version": "0.2.0"},
        "rustix": full | {"Version": "1.0.0", "Features": "process"},
        "newcrate": full | {"Version": "1.0.0"},
    }
    baseline = frozenset({("normal", "aes")})
    base = {
        "package": {
            "name": "rskrb5-ng",
            "metadata": {"rskrb5-ng": {"leaf-features": {"camellia": {}}}},
        },
        "features": {"default": [], "camellia": ["dep:camellia"]},
        "dependencies": {"aes": "0.9", "camellia": {"version": "0.2", "optional": True}},
    }
    exception = {
        "version": "1",
        "default-features": False,
        "features": ["process"],
    }
    # The accepted fixture is the production declaration (Y2-01): a feature set
    # the manifest does not declare must not be what the self-test accepts.
    production = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "Cargo.toml").read_text(encoding="utf-8")
    )["target"][RUSTIX_TABLE]["dependencies"]["rustix"]
    assert exception["features"] == production["features"], (
        f"self-test accepts rustix features {exception['features']}, "
        f"Cargo.toml declares {production['features']}"
    )

    def variant(path: tuple[str, ...], name: str, spec: object, source: dict = base) -> dict:
        manifest = copy.deepcopy(source)
        table = manifest
        for key in path:
            table = table.setdefault(key, {})
        table[name] = spec
        return manifest

    def expect(manifest: dict, needle: str | None, label: str) -> None:
        found = manifest_problems(manifest, baseline, records)
        if needle is None:
            assert not found, f"{label}: unexpected {found}"
        else:
            assert any(needle in line for line in found), f"{label}: {needle!r} not in {found}"

    expect(base, None, "an optional leaf dependency with a record")
    expect(variant(("dependencies",), "ring", "*"), "`ring`", "forbidden crate, normal")
    expect(variant(("dev-dependencies",), "openssl-sys", "0.9"), "`openssl-sys`", "forbidden crate, dev")
    expect(variant(("build-dependencies",), "bindgen", "0.7"), "`bindgen`", "forbidden crate, build")
    expect(variant(("dependencies",), "tls", {"package": "native-tls", "version": "1"}), "`native-tls`", "forbidden crate, renamed")
    expect(variant(("target", "cfg(unix)", "dependencies"), "aws-lc-rs", "1"), "`aws-lc-rs`", "forbidden crate, target table")
    fuzz = {"package": {"name": FUZZ_PACKAGE}, "dependencies": {"cryptoki": "0.9"}}
    expect(fuzz, "`cryptoki`", "forbidden crate in the fuzz crate")
    expect(variant(("dependencies",), "newcrate", "1"), "non-optional new dependency `newcrate`", "non-optional new dependency")
    expect(variant(("dependencies",), "other", {"version": "1", "optional": True}), "lacks an admission record", "no record")
    expect(variant(("features",), "extra", ["dep:camellia"]), "enabled by `extra`", "non-leaf feature")
    expect(variant(("dependencies",), "newcrate", {"version": "1", "optional": True}), "enabled by `newcrate`", "implicit feature")
    # The grandfathered libfuzzer-sys is the fuzz crate's; the main crate may not add it.
    fuzz_base = frozenset({("normal", "libfuzzer-sys"), ("normal", "rskrb5-ng")})
    legacy = {
        "package": {"name": FUZZ_PACKAGE},
        "dependencies": {"libfuzzer-sys": "0.4", "rskrb5-ng": {"path": ".."}},
    }
    assert manifest_problems(legacy, fuzz_base, records) == []
    expect(variant(("dependencies",), "libfuzzer-sys", "0.4"), "`libfuzzer-sys`", "libfuzzer-sys in the main crate")
    # The recorded rustix exception, and its rejected variants.
    table = ("target", RUSTIX_TABLE, "dependencies")
    expect(variant(table, "rustix", exception), None, "the rustix exception")
    expect(variant(("dependencies",), "rustix", dict(exception)), "non-optional rustix", "rustix in [dependencies]")
    expect(variant(("target", "cfg(unix)", "dependencies"), "rustix", dict(exception)), "non-optional rustix", "rustix in another target table")
    expect(variant(("target", 'cfg(target_os = "linux")', "dependencies"), "rustix", dict(exception)), "non-optional rustix", "rustix in the Linux table")
    expect(variant(table, "rustix", exception | {"features": ["process", "fs"]}), "unlisted: ['fs']", "rustix with the obsolete fs feature")
    expect(variant(table, "rustix", exception | {"features": ["process", "net"]}), "unlisted: ['net']", "rustix with an unlisted feature")
    expect(variant(table, "rustix", exception | {"default-features": True}), "default-features = false", "rustix with default features")
    expect(variant(table, "newcrate", "1", variant(table, "rustix", exception)), "non-optional new dependency `newcrate`", "a second non-optional dependency")
    expect(variant(("dev-dependencies",), "rustix", "1"), None, "a dev rustix needs only its record")

    main_tree = "rskrb5-ng v0.3.0 (/work)\naes v0.9.3\nlibc v0.2.191\nrasn v0.29.0 (*)\n"
    fuzz_tree = main_tree + "libfuzzer-sys v0.4.13\ncc v1.11.2\narbitrary v1.4.0\n"
    package = lambda name, version, links=None, build=(): {  # noqa: E731
        "name": name, "version": version, "links": links,
        "dependencies": [{"name": tool, "kind": "build"} for tool in build],
    }
    clean_meta = {"packages": [package("aes", "0.9.3"), package("libc", "0.2.191")]}
    trees = {target: main_tree for target in TARGETS}
    assert graph_problems("rskrb5-ng", trees, clean_meta, frozenset(), "main") == []
    windows_ring = dict(trees) | {TARGETS[1]: main_tree + "ring v0.17.14\n"}
    found = graph_problems("rskrb5-ng", windows_ring, clean_meta, frozenset(), "main")
    assert found and "`ring`" in found[0] and TARGETS[1] in found[0], found
    assert graph_problems(FUZZ_PACKAGE, {TARGETS[0]: main_tree + "aws-lc-sys v0.1.0\n"}, clean_meta, frozenset(), "fuzz")
    links_meta = {"packages": [package("foo-sys", "1.0.0", links="foo")]}
    assert graph_problems("rskrb5-ng", {TARGETS[0]: main_tree + "foo-sys v1.0.0\n"}, links_meta, frozenset(), "main")
    cc_meta = {"packages": [package("tool", "1.0.0", build=("cc",))]}
    assert graph_problems("rskrb5-ng", {TARGETS[0]: main_tree + "tool v1.0.0\n"}, cc_meta, frozenset(), "main")
    wrapper_meta = {"packages": [package("windows-sys", "0.61.2", links="win")]}
    assert not graph_problems("rskrb5-ng", {TARGETS[0]: main_tree + "windows-sys v0.61.2\n"}, wrapper_meta, frozenset(), "main")
    depth_tree = (
        "0rskrb5-ng-fuzz v0.0.0 (/work/fuzz)\n1libfuzzer-sys v0.4.13\n2cc v1.11.2\n2arbitrary v1.4.0\n"
        "1rskrb5-ng v0.3.0 (/work)\n2aes v0.9.3\n2cc-shared v1.0.0\n"
    )
    exempt = exempt_names(depth_tree)
    assert exempt == {"libfuzzer-sys", "cc", "arbitrary"}, exempt
    runtime_meta = {"packages": [package("libfuzzer-sys", "0.4.13", build=("cc",)), package("cc", "1.11.2")]}
    fuzz_trees = {target: fuzz_tree for target in TARGETS}
    assert graph_problems(FUZZ_PACKAGE, fuzz_trees, runtime_meta, exempt, "fuzz") == []
    leaked = graph_problems("rskrb5-ng", fuzz_trees, runtime_meta, exempt, "main")
    assert any("`libfuzzer-sys`" in line for line in leaked), leaked
    only_cc = graph_problems("rskrb5-ng", {TARGETS[0]: main_tree + "cc v1.11.2\n"}, clean_meta, exempt, "main")
    assert any("`cc`" in line for line in only_cc), only_cc

    markdown = (
        "## Records\n\n```text\n### example\n- Version: 9\n```\n\n### `camellia` 0.2.0\n"
        "- Version: 0.2.0\n- Leaf flags: camellia\n\n## Next\n- Version: 1\n\n```baseline\n"
        "rskrb5-ng normal aes\nrskrb5-ng dev axum\n```\n"
    )
    assert parse_records(markdown) == {"camellia": {"Version": "0.2.0", "Leaf flags": "camellia"}}
    assert parse_baseline(markdown) == {"rskrb5-ng": frozenset({("normal", "aes"), ("dev", "axum")})}
    shown = {"Cargo.toml": '[package]\nname = "rskrb5-ng"\n[dependencies]\naes = "1"\n[dev-dependencies]\naxum = "1"\n'}
    assert baseline_manifest_sets(shown) == parse_baseline(markdown)
    assert baseline_manifest_sets(shown) != parse_baseline(markdown.replace("axum", "other"))
    locked = {"camellia": {"0.2.0"}}
    assert version_problems(base, baseline, records, locked) == []
    assert version_problems(base, baseline, records, {"camellia": {"0.3.0"}})
    thin = {"camellia": {"Version": "0.2.0"}}
    assert version_problems(base, baseline, thin, locked)
    print("dep_admission self-test: ok (manifest rules, rustix exception, graph rules, records)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument(
        "--offline", action="store_true", help="pass --offline to cargo"
    )
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        problems = enforce(args.root, args.offline)
    except (RuntimeError, OSError) as error:
        problems = [f"dep_admission: {error}"]
    print("\n".join(problems + [f"dep_admission: {len(problems)} problem(s)"]))
    return int(args.enforce and bool(problems))


if __name__ == "__main__":
    sys.exit(main())
