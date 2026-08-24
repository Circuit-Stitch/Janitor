#!/usr/bin/env python3
"""Writes THIRD-PARTY-LICENSES.txt for the crates that ship inside JanitorKit.

The macOS shell links one binary and compiles no Rust, so it cannot read
Cargo.lock and cannot discover what it is linking. This script runs where
Cargo.lock lives and produces the list the shell displays. The publish workflow
runs it beside build-xcframework.sh and uploads the result next to the zip, so
the list is frozen with the bytes it describes.

WHAT IS COUNTED

The closure starts at janitor-app with every feature on, resolved for both Apple
targets and unioned. Dev-dependencies and build-dependencies are dropped: test
doubles and build scripts do not reach the shipped binary, so no notice is owed
for them. Circuit Stitch's own crates are dropped too, because the application's
own license already covers them.

WHAT IS EMITTED

Packages are grouped by SPDX expression. Each license text is printed once, and
the packages under it are listed with the copyright line taken from the license
file the crate itself ships. MIT is the reason for that shape: it asks for the
copyright notice, and every MIT crate carries a different one.

A crate that ships no license file is listed with its SPDX expression and a note
saying so. That is a fact about the crate, not a failure of this script.

Usage:
    scripts/third-party-licenses.py [output-file]

Needs cargo and a populated registry cache. Stdlib only, so CI installs nothing.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Both halves of the universal slice. A dependency pulled in by only one of them
# still ships, so the closure is the union rather than either one alone.
TARGETS = ["aarch64-apple-darwin", "x86_64-apple-darwin"]

ROOT_CRATE = "janitor-app"

# Circuit Stitch's own crates. The application's license covers these, so they
# are not third-party notices.
FIRST_PARTY_PREFIX = "janitor-"

# Filenames crates use for license text, best first.
LICENSE_NAMES = re.compile(r"^(LICENSE|LICENCE|COPYING|NOTICE)", re.IGNORECASE)

# A real copyright notice, not the word "copyright" inside license prose. The
# year is what separates them: Apache-2.0's own body wraps lines onto "copyright
# license to reproduce" and "(c) You must retain", and neither carries one.
COPYRIGHT_LINE = re.compile(
    r"^\s*(Copyright|COPYRIGHT|©|\(c\)|\(C\))\b.*\b(19|20)\d{2}\b"
)


def metadata(manifest: Path, target: str) -> dict:
    """cargo metadata for one target, with every feature on."""
    out = subprocess.run(
        [
            "cargo", "metadata",
            "--format-version", "1",
            "--all-features",
            "--filter-platform", target,
            "--manifest-path", str(manifest),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout)


def closure(meta: dict) -> set:
    """Package ids reachable from the root crate through normal dependencies."""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    packages = {p["id"]: p for p in meta["packages"]}

    roots = [i for i, p in packages.items() if p["name"] == ROOT_CRATE]
    if not roots:
        raise SystemExit(f"{ROOT_CRATE} is not in this workspace")

    seen, stack = set(), list(roots)
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            kinds = {k.get("kind") for k in dep.get("dep_kinds", [])}
            # kind is null for a normal dependency. A dep that is only ever a
            # dev or build dependency never reaches the shipped binary.
            if kinds and None not in kinds:
                continue
            stack.append(dep["pkg"])
    return seen


def fingerprint(text: str) -> str:
    """A license text with its copyright lines and spacing removed.

    Two MIT texts differ only in whose copyright sits at the top. Stripping that
    makes them compare equal, so the shared body is printed once instead of a
    hundred and fifty times.
    """
    body = [ln for ln in text.splitlines() if not COPYRIGHT_LINE.match(ln)]
    return " ".join(" ".join(body).lower().split())


def license_texts(pkg: dict) -> tuple:
    """Every license text a crate ships, and the copyright lines inside them.

    A dual-licensed crate ships one file per option. All of them are returned,
    so a group offered under two licenses reproduces both.
    """
    src = Path(pkg["manifest_path"]).parent
    if not src.is_dir():
        return [], []

    files = sorted(
        (f for f in src.iterdir() if f.is_file() and LICENSE_NAMES.match(f.name)),
        key=lambda f: (f.name.upper() != "LICENSE", f.name),
    )

    texts, copyrights = [], []
    for f in files:
        body = f.read_text(encoding="utf-8", errors="replace")
        stripped = body.strip()
        if stripped:
            texts.append(stripped)
        for line in body.splitlines():
            # The Apache appendix ships an unfilled template. It names nobody.
            if COPYRIGHT_LINE.match(line) and "[yyyy]" not in line:
                line = line.strip()
                if line not in copyrights:
                    copyrights.append(line)
    return texts, copyrights


def main() -> None:
    manifest = Path(__file__).resolve().parent.parent / "Cargo.toml"
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("THIRD-PARTY-LICENSES.txt")

    packages, ids = {}, set()
    for target in TARGETS:
        meta = metadata(manifest, target)
        packages.update({p["id"]: p for p in meta["packages"]})
        ids |= closure(meta)

    third_party = [
        packages[i] for i in ids
        if not packages[i]["name"].startswith(FIRST_PARTY_PREFIX)
    ]
    third_party.sort(key=lambda p: (p["name"].lower(), p["version"]))

    groups = {}
    for pkg in third_party:
        spdx = pkg.get("license") or "see the crate's own license file"
        groups.setdefault(spdx, []).append(pkg)

    lines = [
        "THIRD-PARTY SOFTWARE NOTICES",
        "",
        "Janitor links the open-source packages listed below. Each package is",
        "listed with its version, the license it is offered under, and the",
        "copyright notice it ships. The full text of each license follows the",
        "packages offered under it.",
        "",
        f"{len(third_party)} packages, {len(groups)} distinct license expressions.",
        "",
        "Generated by scripts/third-party-licenses.py. Do not edit by hand.",
        "",
    ]

    for spdx in sorted(groups):
        pkgs = groups[spdx]
        lines += ["=" * 78, spdx, "=" * 78, ""]

        bodies = {}
        for pkg in pkgs:
            texts, copyrights = license_texts(pkg)
            for text in texts:
                bodies.setdefault(fingerprint(text), text)

            entry = f"  {pkg['name']} {pkg['version']}"
            if pkg.get("repository"):
                entry += f"\n      {pkg['repository']}"
            if copyrights:
                for c in copyrights:
                    entry += f"\n      {c}"
            elif texts:
                entry += "\n      (no copyright line; license text reproduced below)"
            else:
                entry += "\n      (the crate ships no license file)"
            lines.append(entry)

        lines.append("")
        for text in bodies.values():
            lines += ["-" * 78, "", text, ""]

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{out_path}: {len(third_party)} packages, {len(groups)} license expressions")


if __name__ == "__main__":
    main()
