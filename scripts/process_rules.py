"""Pipeline step: check rules in rules/, then convert each to JSON + a plain query.

Usage:
  python scripts/process_rules.py                      # check ALL rules in rules/
  python scripts/process_rules.py rules/a.yml rules/b.yml   # check ONLY these files

Fails (exit 1) with a clear message if a checked rule is invalid.
"""
import json, os, pathlib, re, sys, yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "converted"
REQUIRED = ["title", "id", "status", "author", "date", "tags",
            "logsource", "detection", "level", "falsepositives"]


def error(path, msg):
    # "::error" makes GitHub show the message on the run page
    print(f"::error file={path.relative_to(ROOT)}::{msg}")


def rule_files(args):
    """Which files to check.
    - No arguments: every rules/*.yml (local run / full scan).
    - With arguments: only those files. Paths that no longer exist
      (deleted in the push) are skipped instead of crashing.
    """
    if not args:
        return sorted((ROOT / "rules").glob("*.yml"))
    files = []
    for a in args:
        p = pathlib.Path(a)
        p = (p if p.is_absolute() else pathlib.Path.cwd() / p).resolve()
        if not p.exists():
            print(f"::notice::Skipping {a} (deleted or not found)")
            continue
        files.append(p)
    return sorted(files)


def check(path, rule):
    problems = []
    if not isinstance(rule, dict):
        return ["file is not a valid Sigma rule (not a YAML mapping)"]
    for field in REQUIRED:
        if field not in rule:
            problems.append(f"missing required field '{field}'")
    tags = rule.get("tags") or []
    if not any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(t).lower()) for t in tags):
        problems.append("no valid ATT&CK technique tag (example: attack.t1059.003)")
    det = rule.get("detection") or {}
    if "condition" not in det:
        problems.append("detection has no 'condition'")
    return problems


def to_query(detection):
    parts = []
    for name, sel in detection.items():
        if name == "condition" or not isinstance(sel, dict):
            continue
        clauses = []
        for key, val in sel.items():
            field, _, mod = key.partition("|")
            vals = val if isinstance(val, list) else [val]
            op = {"endswith": "ENDS WITH", "startswith": "STARTS WITH",
                  "contains": "CONTAINS"}.get(mod, "=")
            clauses.append("(" + " OR ".join(f'{field} {op} "{v}"' for v in vals) + ")")
        parts.append(f"{name}: " + " AND ".join(clauses))
    return parts


def main():
    args = sys.argv[1:]
    OUT.mkdir(parents=True, exist_ok=True)
    rows, failed = [], False

    for path in rule_files(args):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            error(path, f"invalid YAML: {e}")
            rows.append((path.name, "FAIL", "invalid YAML"))
            failed = True
            continue

        problems = check(path, rule)
        if problems:
            for p in problems:
                error(path, p)
            rows.append((path.name, "FAIL", "; ".join(problems)))
            failed = True
            continue

        converted = {
            "rule_id": rule["id"],
            "title": rule["title"],
            "level": rule["level"],
            "techniques": [t for t in rule["tags"] if str(t).lower().startswith("attack.t")],
            "query": to_query(rule["detection"]),
            "condition": rule["detection"]["condition"],
            "note": "Demo conversion. The real coversion is in the next part of the pipeline(convert_wazuh.py).",
        }
        (OUT / f"{path.stem}.json").write_text(json.dumps(converted, indent=2), encoding="utf-8")
        rows.append((path.name, "PASS", f"converted to out/converted/{path.stem}.json"))

    print("\nResult:")
    for name, status, note in rows:
        print(f"  {status}  {name}  {note}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and rows:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("| Rule | Result | Detail |\n|---|---|---|\n")
            for name, status, note in rows:
                f.write(f"| {name} | {status} | {note} |\n")

    # Only complain about "no rules" on a full scan. When specific files were
    # passed in (e.g. a push that only deleted rules), an empty list is fine.
    if not rows and not args:
        print("::error::No rules found in rules/")
        failed = True

    sys.exit(1 if failed else 0)


main()
