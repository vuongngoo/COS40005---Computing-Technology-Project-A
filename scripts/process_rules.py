"""Pipeline step 1: check the Sigma rules in rules/ (syntax + metadata), then write a demo JSON for each.

Usage:
  python scripts/process_rules.py                           # check ALL rules in rules/
  python scripts/process_rules.py rules/a.yml rules/b.yml   # check ONLY these files

Fails (exit 1) with a clear message if a checked rule is invalid.
Needs: pip install pyyaml pysigma
"""
import datetime, json, os, pathlib, re, sys, uuid, yaml

from sigma.collection import SigmaCollection

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "converted"
REQUIRED = ["title", "id", "status", "author", "date", "tags",
            "logsource", "detection", "level", "falsepositives"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}


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


def find_duplicates_by_id(path, rule_id):
    """Names of OTHER files in rules/ that have the same 'id' as the rule being checked.
    No YAML parsing: a cheap substring filter first, then a regex that confirms
    a top-level (non-indented) 'id:' line."""
    wanted = str(rule_id).strip().lower()
    pattern = re.compile(
        r"^id:\s*['\"]?" + re.escape(wanted) + r"['\"]?\s*(#.*)?$",
        re.IGNORECASE | re.MULTILINE,
    )
    me = path.resolve()
    dups = []
    for p in (ROOT / "rules").glob("*.yml"):
        if p.resolve() == me:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        if wanted in text.lower() and pattern.search(text):
            dups.append(p.name)
    return sorted(dups)


def check(path, rule):
    problems = []
    if not isinstance(rule, dict):
        return ["file is not a valid Sigma rule (not a YAML mapping)"]
    for field in REQUIRED:
        if field not in rule:
            problems.append(f"missing required field '{field}'")

    # --- values, not just presence ---
    if "level" in rule and str(rule["level"]).lower() not in LEVELS:
        problems.append(f"level '{rule['level']}' is not one of {sorted(LEVELS)}")
    if "status" in rule and str(rule["status"]).lower() not in STATUSES:
        problems.append(f"status '{rule['status']}' is not one of {sorted(STATUSES)}")
    if "id" in rule:
        try:
            uuid.UUID(str(rule["id"]))
        except ValueError:
            problems.append(f"id '{rule['id']}' is not a valid UUID")
        else:
            others = find_duplicates_by_id(path, rule["id"])
            if others:
                problems.append(f"duplicate id, also used by {', '.join(others)}")
    if "date" in rule and not isinstance(rule["date"], datetime.date):
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(rule["date"])):
            problems.append(f"date '{rule['date']}' is not YYYY-MM-DD")
    if "falsepositives" in rule and not rule["falsepositives"]:
        problems.append("falsepositives is empty")

    tags = rule.get("tags") or []
    if not isinstance(tags, list):
        problems.append("tags must be a list")
        tags = []
    if not any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(t).lower()) for t in tags):
        problems.append("no valid ATT&CK technique tag (example: attack.t1059.003)")
    det = rule.get("detection") or {}
    if "condition" not in det:
        problems.append("detection has no 'condition'")
    return problems


def check_with_pysigma(path):
    """Let pySigma read the rule. parse() is what catches a condition that names a
    selection which does not exist (from_yaml alone does not)."""
    try:
        for rule in SigmaCollection.from_yaml(path.read_text(encoding="utf-8")).rules:
            for cond in rule.detection.parsed_condition:
                cond.parse()
    except Exception as e:
        return [f"pySigma: {e}"]
    return []


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
        if not problems:                       # only ask pySigma once the basics are right
            problems = check_with_pysigma(path)
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
            "note": "Demo conversion. The real conversion is in the next part of the pipeline (convert_wazuh.py).",
        }
        (OUT / f"{path.stem}.json").write_text(json.dumps(converted, indent=2), encoding="utf-8")
        rows.append((path.name, "PASS", f"converted to out/converted/{path.stem}.json"))

    print("\nResult:")
    for name, status, note in rows:
        print(f"  {status}  {name}  {note}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and rows:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n### Step 1: Syntax and metadata check\n")
            f.write("| Rule | Result | Detail |\n|---|---|---|\n")
            for name, status, note in sorted(rows, key=lambda r: r[1] != "FAIL"):  # FAIL first
                f.write(f"| {name} | {status} | {note.replace('|', '/')} |\n")

    # Only complain about "no rules" on a full scan. When specific files were
    # passed in (e.g. a push that only deleted rules), an empty list is fine.
    if not rows and not args:
        print("::error::No rules found in rules/")
        failed = True

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
