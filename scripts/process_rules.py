"""Pipeline step 1: check the Sigma rules in rules/ (syntax + metadata), then write a demo JSON for each.

Usage:
  python scripts/process_rules.py                           # check ALL rules in rules/
  python scripts/process_rules.py rules/a.yml rules/b.yml   # check ONLY these files

Fails (exit 1) with a clear message if a checked rule is invalid.
Needs: pip install pyyaml pysigma
"""
import datetime, json, os, pathlib, re, sys, uuid, yaml, requests, os, shutil, subprocess

from sigma.collection import SigmaCollection

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"    
OUT = ROOT / "out" / "converted"
REQUIRED = ["title", "id", "status", "author", "date", "tags",
            "logsource", "detection", "level", "falsepositives"]
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}



ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)
def is_new_file(path):
    """True only if we can PROVE the file did not exist before this push (BASE_SHA)."""
    base = os.environ.get("BASE_SHA", "")
    if not base or set(base) == {"0"}:
        return False
    git = lambda *a: subprocess.run(["git", *a], cwd=ROOT, capture_output=True)
    if git("cat-file", "-e", f"{base}^{{commit}}").returncode != 0:
        return False                                   # unknown base: never guess
    rel = path.resolve().relative_to(ROOT).as_posix()
    return git("cat-file", "-e", f"{base}:{rel}").returncode != 0
  
def load_attack_ids():
    try:
        response = requests.get(ATTACK_URL, timeout=30)
        response.raise_for_status()
        dataset = response.json()

    except requests.RequestException as e:
        raise RuntimeError(f"Cannot download MITRE ATT&CK dataset: {e}")

    valid_ids = set()

    for obj in dataset["objects"]:
        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")

                if external_id:
                    valid_ids.add(external_id.lower())

    return valid_ids


def check_attack_tags(tags, valid_attack_ids):
    problems = []

    if not isinstance(tags, list):
        return ["tags must be a list"]

    for tag in tags:
        tag = str(tag).lower()

        if not tag.startswith("attack."):
            continue

        attack_id = tag.removeprefix("attack.")

        # Only validate technique/sub-technique IDs
        if not re.fullmatch(r"t\d{4}(\.\d{3})?", attack_id):
            continue

        if attack_id not in valid_attack_ids:
            problems.append(
                f"ATT&CK ID '{attack_id}' does not exist "
                "or is deprecated/revoked"
            )

    # Require at least one valid technique tag
    has_technique = any(
        re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(tag), re.IGNORECASE)
        and str(tag).lower().removeprefix("attack.") in valid_attack_ids
        for tag in tags
    )

    if not has_technique:
        problems.append("no valid ATT&CK technique tag found")

    return problems

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


def check(path, rule,  valid_attack_ids):
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
    problems.extend(check_attack_tags(tags, valid_attack_ids))
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


def remove_rejected_rules(invalid, changed_files_mode, enabled):
    """invalid = [(path, problems)]. Returns {file name: what happened}.
    A rule is deleted ONLY if all of these are true (otherwise it is kept and just reported):
      1. --remove-failed was given
      2. running in GitHub Actions on a push event
      3. specific files were passed in (changed-files mode; a full scan never deletes)
      4. the file is NEW in this push (an existing rule that was edited is never deleted)
    A copy goes to out/rejected/ first, so the author can recover it from the artifact."""
    actions = {}
    in_push = (os.environ.get("GITHUB_ACTIONS") == "true"
               and os.environ.get("GITHUB_EVENT_NAME") == "push")
    for path, _problems in invalid:
        if not enabled:
            actions[path.name] = "kept"
        elif not in_push:
            actions[path.name] = "kept (not a push in CI)"
        elif not changed_files_mode:
            actions[path.name] = "kept (a full scan never deletes)"
        elif path.resolve().parent != RULES_DIR.resolve() or path.suffix.lower() != ".yml":
            actions[path.name] = "kept (not a rule file)"
        elif not is_new_file(path):
            actions[path.name] = "kept (existing rule: fix it, do not delete)"
        else:
            try:
                REJECTED_DIR.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, REJECTED_DIR / path.name)
                path.unlink()
                actions[path.name] = "removed from rules/ (copy in artifact out/rejected/)"
            except OSError as e:
                actions[path.name] = f"kept (delete failed: {e})"
    return actions
          
def main():
    argv = sys.argv[1:]
    remove = "--remove-failed" in argv
    args = [a for a in argv if not a.startswith("--")]

    # Download MITRE ATT&CK dataset.
    try:
        valid_attack_ids = load_attack_ids()

    except RuntimeError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    OUT.mkdir(parents=True, exist_ok=True)

    rows = []
    invalid_files = []   # (path, problems) for every rule that failed
    failed = False

    files = rule_files(args)

    # Validate each rule.
    for path in files:
        try:
            content = path.read_text(encoding="utf-8")
            rule = yaml.safe_load(content)

        except (yaml.YAMLError, UnicodeDecodeError) as e:
            problems = [f"invalid YAML: {e}"]

        except OSError as e:
            problems = [f"cannot read file: {e}"]

        else:
            problems = check(path, rule, valid_attack_ids)

            # Run pySigma only if basic validation passes.
            if not problems:
                problems = check_with_pysigma(path)

        # Invalid rule: print the errors now, while the file still exists.
        if problems:
            for problem in problems:
                error(path, problem)

            rows.append(
                (path.name, "FAIL", "; ".join(problems))
            )

            invalid_files.append((path, problems))
            failed = True
            continue

        # Valid rule: convert to demo JSON.
        converted = {
            "rule_id": rule["id"],
            "title": rule["title"],
            "level": rule["level"],
            "techniques": [
                tag for tag in rule["tags"]
                if str(tag).lower().startswith("attack.t")
            ],
            "query": to_query(rule["detection"]),
            "condition": rule["detection"]["condition"],
            "note": (
                "Demo conversion. The real conversion is in the "
                "next part of the pipeline (convert_wazuh.py)."
            ),
        }

        output_file = OUT / f"{path.stem}.json"

        output_file.write_text(
            json.dumps(converted, indent=2),
            encoding="utf-8"
        )

        rows.append(
            (
                path.name,
                "PASS",
                f"converted to out/converted/{path.stem}.json"
            )
        )

    # --------------------------------------------------
    # Decide what happens to the rejected rules.
    # All error details are already collected and printed
    # above, so removing a file here loses no information.
    # --------------------------------------------------

    actions = remove_rejected_rules(invalid_files, bool(args), remove)

    # --------------------------------------------------
    # Print validation summary.
    # --------------------------------------------------

    print("\nResult:")

    for name, status, note in rows:
        action = actions.get(name, "")
        suffix = f"  [{action}]" if action else ""
        print(f"  {status}  {name}  {note}{suffix}")

    removed = sum(1 for a in actions.values() if a.startswith("removed"))

    print("\nSummary:")
    print(f"  Total:   {len(rows)}")
    print(f"  Passed:  {sum(1 for r in rows if r[1] == 'PASS')}")
    print(f"  Failed:  {sum(1 for r in rows if r[1] == 'FAIL')}")
    print(f"  Removed: {removed}")

    # GitHub Actions summary.
    summary = os.environ.get("GITHUB_STEP_SUMMARY")

    if summary and rows:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n### Step 1: Syntax and metadata check\n")
            f.write("| Rule | Result | Detail | Action |\n")
            f.write("|---|---|---|---|\n")

            for name, status, note in sorted(
                rows,
                key=lambda r: r[1] != "FAIL"
            ):
                safe_note = note.replace("|", "/")
                action = actions.get(name, "")
                f.write(
                    f"| {name} | {status} | {safe_note} | {action} |\n"
                )

    # Only complain about no rules on a full scan.
    if not rows and not args:
        print("::error::No rules found in rules/")
        failed = True

    # Exit code tells GitHub Actions whether validation failed.
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
