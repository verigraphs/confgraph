"""ReDoS scan of the confgraph parser regexes (CCR-0126).

The parsers are regex-dense and run over config text supplied by whoever uploads
it, so a catastrophically-backtracking pattern is uninsured risk on an untrusted
path. A crude nested-quantifier heuristic (run by hand while filing CCR-0126)
found nothing — but that is exactly the naive check that misses the real ReDoS
families, so its clean result is weak evidence. This runs a *real* analyser
(regexploit) once and records the outcome either way, and baselines the clean
result so a NEWLY added pathological pattern fails the gate (the CCR-0054
principle) without the 0 findings today ever being a gate nobody can fail.

What it scans (CCR-0126 item 1 — "the composed alternation is the real input to
the engine"):
  * every regex string literal the parsers pass to an ``re.*`` call or to the
    repo's ``PatternSet`` helper (collected statically by walking the parser
    ASTs — this is the 726-literal set the CCR counted), AND
  * every ``PatternSet.union`` alternation, collected at runtime by importing the
    parser modules and reading each PatternSet instance (a union composes many
    literals into one expression, which is where ReDoS most often hides).

This is scope items 1-4 of CCR-0126. The platform-side parse timeout (item 5)
lives in confgraph_platform and is out of this repo.

Usage:
  uv run --with regexploit python tools/redos_scan.py            # report + artifact
  uv run --with regexploit python tools/redos_scan.py --check    # gate: exit 1 on a NEW finding
  uv run --with regexploit python tools/redos_scan.py --update-baseline
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
PARSER_DIR = REPO / "confgraph" / "parsers"
ARTIFACT = REPO / "tools" / "redos_scan.json"
BASELINE = REPO / "tools" / "redos_baseline.json"

_RE_METHODS = {"compile", "match", "search", "fullmatch", "findall", "finditer", "sub", "subn", "split"}
# ciscoconfparse methods that take a regex the engine compiles and runs over config lines.
_CCP_METHODS = {"find_objects", "find_lines", "find_children", "find_all_children",
                "find_objects_w_child", "find_objects_wo_child", "re_search_children"}


def _static_literals() -> list[tuple[str, str]]:
    """(source-location, pattern) for every regex literal passed to re.* or PatternSet."""
    out: list[tuple[str, str]] = []
    for pyfile in sorted(PARSER_DIR.glob("*.py")):
        rel = f"confgraph/parsers/{pyfile.name}"
        tree = ast.parse(pyfile.read_text(), filename=str(pyfile))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # re.<method>(pattern, ...) — pattern is the first positional arg
            if isinstance(func, ast.Attribute) and func.attr in _RE_METHODS:
                if isinstance(func.value, ast.Name) and func.value.id == "re" and node.args:
                    a0 = node.args[0]
                    if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                        out.append((f"{rel}:{node.lineno}", a0.value))
            # ciscoconfparse .find_objects(regex, ...) etc. — regex is the first positional arg
            if isinstance(func, ast.Attribute) and func.attr in _CCP_METHODS and node.args:
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    out.append((f"{rel}:{node.lineno}", a0.value))
            # PatternSet(...) / <ps>.extended(...) — every string-literal arg is a dialect
            name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
            if name in ("PatternSet", "extended"):
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        out.append((f"{rel}:{node.lineno}", a.value))
    return out


def _runtime_unions() -> list[tuple[str, str]]:
    """(location, union-string) for every PatternSet instance reachable from the parsers."""
    import importlib
    import inspect
    import pkgutil

    import confgraph.parsers as parsers_pkg
    from confgraph.parsers.base import PatternSet

    seen: dict[int, tuple[str, str]] = {}

    def consider(where: str, obj) -> None:
        if isinstance(obj, PatternSet) and id(obj) not in seen:
            try:
                seen[id(obj)] = (where, obj.union)
            except Exception:
                pass

    for mod_info in pkgutil.iter_modules(parsers_pkg.__path__):
        mod = importlib.import_module(f"confgraph.parsers.{mod_info.name}")
        for gname, gobj in vars(mod).items():
            consider(f"{mod_info.name}.{gname}", gobj)
            if inspect.isclass(gobj):
                for cname, cobj in vars(gobj).items():
                    consider(f"{mod_info.name}.{gobj.__name__}.{cname}", cobj)
    return [v for v in seen.values()]


def _analyse(pattern: str) -> int | None:
    """Worst regexploit starriness for `pattern` (0 = clean), or None if unparseable."""
    from regexploit.ast.sre import SreOpParser
    from regexploit.redos import find

    try:
        parsed = SreOpParser().parse_sre(pattern)
    except Exception:
        return None
    try:
        return max((r.starriness for r in find(parsed)), default=0)
    except Exception:
        return None


def scan() -> dict:
    patterns: dict[str, str] = {}   # pattern -> first location seen
    for where, pat in _static_literals():
        patterns.setdefault(pat, where)
    unions = 0
    for where, pat in _runtime_unions():
        if pat not in patterns:
            unions += 1
        patterns.setdefault(pat, where)

    findings, unparseable = [], 0
    for pat, where in patterns.items():
        score = _analyse(pat)
        if score is None:
            unparseable += 1
        elif score > 0:
            findings.append({"location": where, "starriness": score, "pattern": pat})
    findings.sort(key=lambda f: (-f["starriness"], f["location"]))
    return {
        "tool": "regexploit",
        "patterns_scanned": len(patterns),
        "union_compositions": unions,
        "unparseable": unparseable,
        "finding_count": len(findings),
        "findings": findings,
    }


def _keys(result: dict) -> list[str]:
    return sorted(f"{f['location']}::{f['pattern']}" for f in result["findings"])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ReDoS scan of confgraph parser regexes (CCR-0126)")
    ap.add_argument("--check", action="store_true", help="gate: exit 1 if findings differ from baseline")
    ap.add_argument("--update-baseline", action="store_true", help="rewrite the baseline")
    args = ap.parse_args(argv)

    result = scan()
    ARTIFACT.write_text(json.dumps(result, indent=2) + "\n")
    keys = _keys(result)

    if args.update_baseline:
        BASELINE.write_text(json.dumps({"redos_findings": keys}, indent=2) + "\n")
        print(f"baseline rewritten: {len(keys)} ReDoS finding(s) -> {BASELINE.name}")
        return 0

    if args.check:
        if not BASELINE.exists():
            print("FAIL: no baseline; run --update-baseline first.", file=sys.stderr)
            return 1
        base = set(json.loads(BASELINE.read_text())["redos_findings"])
        now = set(keys)
        new = sorted(now - base)
        gone = sorted(base - now)
        if not new and not gone:
            print(f"OK: ReDoS findings match baseline ({len(now)}). Scanned {result['patterns_scanned']} patterns.")
            return 0
        if new:
            print(f"FAIL: {len(new)} NEW ReDoS-suspect pattern(s):", file=sys.stderr)
            for k in new:
                print(f"  + {k}", file=sys.stderr)
        if gone:
            print(f"FAIL: {len(gone)} baseline finding(s) gone (pattern fixed/removed?) — refresh with --update-baseline:", file=sys.stderr)
            for k in gone:
                print(f"  - {k}", file=sys.stderr)
        return 1

    print(f"scanned {result['patterns_scanned']} patterns "
          f"({result['union_compositions']} PatternSet.union compositions, "
          f"{result['unparseable']} unparseable) with regexploit")
    print(f"ReDoS-suspect findings: {result['finding_count']}")
    for f in result["findings"]:
        print(f"  starriness={f['starriness']:>3}  {f['location']}  {f['pattern']!r}")
    print(f"\nartifact -> tools/{ARTIFACT.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
