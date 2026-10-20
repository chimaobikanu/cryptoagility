#!/usr/bin/env python3
"""Bump every place the version is declared, atomically.

Why this exists: the version lives in two files and `tests/test_version.py` asserts they agree, so
editing one without the other turns CI red. That is the drift guard doing its job — it caught exactly
that during the 0.1.3 release, when `pyproject.toml` was bumped in one commit and
`cryptoagility._FALLBACK_VERSION` in the next, and GitHub mailed a failed-workflow notice about a
release that ultimately published fine. Use this script and the two can never be edited separately.

    python3 scripts/bump_version.py 0.2.0            # rewrite every location
    python3 scripts/bump_version.py --check          # verify they agree; change nothing (exit 1 if not)
    python3 scripts/bump_version.py 0.2.0 --dry-run   # show what would change

Reminder: a release also needs a CHANGELOG entry for the new version. `--check` warns if it is missing.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# (path, regex with the version in the first capture group, human label)
TARGETS = [
    (ROOT / "pyproject.toml", r'^version\s*=\s*"([^"]+)"', "project version"),
    (ROOT / "cryptoagility.py", r'^_FALLBACK_VERSION\s*=\s*"([^"]+)"', "reported-version fallback"),
]
CHANGELOG = ROOT / "CHANGELOG.md"


def read_version(path: pathlib.Path, pattern: str) -> str | None:
    match = re.search(pattern, path.read_text(), re.MULTILINE)
    return match.group(1) if match else None


def set_version(path: pathlib.Path, pattern: str, version: str) -> bool:
    text = path.read_text()
    new, count = re.subn(pattern, lambda m: m.group(0).replace(m.group(1), version),
                         text, count=1, flags=re.MULTILINE)
    if count and new != text:
        path.write_text(new)
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Bump every declared version at once.")
    ap.add_argument("version", nargs="?", help="new version, e.g. 0.2.0")
    ap.add_argument("--check", action="store_true", help="verify the locations agree; change nothing")
    ap.add_argument("--dry-run", action="store_true", help="show changes without writing")
    args = ap.parse_args()

    found = [(p, pat, label, read_version(p, pat)) for p, pat, label in TARGETS]

    if args.check or not args.version:
        versions = {v for *_, v in found}
        for _, _, label, v in found:
            print(f"  {label:26s} {v}")
        if None in versions or len(versions) != 1:
            print("  MISMATCH — every location must declare the same version.")
            return 1
        only = versions.pop()
        if f"## [{only}]" not in CHANGELOG.read_text():
            print(f"  CHANGELOG has no '## [{only}]' section (required for a release).")
            return 1
        print(f"  consistent at {only}, changelog present.")
        return 0

    if not re.fullmatch(r"\d+\.\d+\.\d+([-.].+)?", args.version):
        print(f"'{args.version}' does not look like a release version.", file=sys.stderr)
        return 2

    changed = 0
    for path, pat, label, _ in found:
        if args.dry_run:
            print(f"  would set {label} in {path.name} -> {args.version}")
            continue
        if set_version(path, pat, args.version):
            print(f"  {label:26s} -> {args.version}  ({path.name})")
            changed += 1
    if args.dry_run:
        return 0
    if f"## [{args.version}]" not in CHANGELOG.read_text():
        print(f"  NOTE: add a '## [{args.version}]' section to CHANGELOG.md before tagging.")
    print(f"  {changed} location(s) updated. Commit them together, then tag v{args.version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())