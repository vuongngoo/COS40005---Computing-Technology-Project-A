"""Pipeline Step 3: replay the converted Wazuh regexes on the labelled corpus.

For every Sigma rule in rules/ this script
  1. converts it with the SAME code CI uses to build the Wazuh XML (scripts/convert_wazuh.py),
  2. runs each resulting Wazuh branch (a set of <field type="pcre2"> checks) over every
     event of tests/corpus/corpus.jsonl,
  3. reports true positives, false negatives, false positives per rule.

No Wazuh server is needed. The corpus events are real Wazuh-decoded Sysmon events, so the
Wazuh quirks (doubled backslashes, escaped quotes) are already in the data.

Exit code 1 (CI fails) when
  * a rule misses an attack event of its own technique (false negative / lost detection), or
  * a rule fires on an ORDINARY benign event (false positive).
Lookalike events (legitimate use of the same tool) and accepted known misses are reported
but never fail the build.

Usage:
  python scripts/fp_check.py                         # all rules in rules/
  python scripts/fp_check.py rules/T1003.002.yml     # only these rules
"""
import argparse
import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import convert_wazuh as cw  # noqa: E402  (same converter as the deploy job)
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.rule import SigmaRule  # noqa: E402

PARENT_EVENT_ID = {"sysmon_event1": "1", "sysmon_event3": "3",
                   "sysmon_event_10": "10", "sysmon_event_11": "11"}


def technique_of(rule):
    for tag in (str(t).lower() for t in rule.tags):
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag)
        if m:
            return m.group(1).upper()
    return None


def field_value(event, wazuh_field):
    """'win.eventdata.commandLine' -> event['eventdata']['commandLine'] (None if absent)."""
    parts = wazuh_field.split(".")
    if parts[0] == "win":
        parts = parts[1:]
    if parts == ["system", "eventID"]:
        return event.get("eventID")
    if len(parts) == 2 and parts[0] == "eventdata":
        return event.get("eventdata", {}).get(parts[1])
    return None


_cache = {}


def _re(pattern):
    if pattern not in _cache:
        _cache[pattern] = re.compile(pattern)
    return _cache[pattern]


def branch_matches(branch, event):
    for field, pattern, negated in branch:
        if field is None:  # keyword search: look in every field value
            value = " ".join(str(v) for v in event.get("eventdata", {}).values())
        else:
            value = field_value(event, field)
            if value is None:
                return False
        hit = _re(pattern).search(str(value)) is not None
        if hit == negated:
            return False
    return True


def load_rules(paths):
    rules = []
    for path in paths:
        coll = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        for rule in coll.rules:
            if not isinstance(rule, SigmaRule):
                continue
            ls = rule.logsource
            key = (str(ls.product).lower() if ls.product else None,
                   str(ls.category).lower() if ls.category else None)
            parent = cw.LOGSOURCE_PARENT_GROUP.get(key)
            branches = [b for q in cw.convert_rule(rule) for b in q]
            base = cw.ID_BASE + (rule.id.int % cw.ID_SLOTS) * cw.MAX_BRANCHES
            rules.append({"file": path.name, "title": rule.title, "technique": technique_of(rule),
                          "base": base, "branches": branches,
                          "event_id": PARENT_EVENT_ID.get(parent)})
    return rules


def rule_fires(rule, event):
    if rule["event_id"] and str(event.get("eventID")) != rule["event_id"]:
        return False
    return any(branch_matches(b, event) for b in rule["branches"])


def short(event, n=110):
    return (event["eventdata"].get("commandLine") or event["eventdata"].get("image") or "")[:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rules", nargs="*")
    ap.add_argument("--corpus", default=str(ROOT / "tests" / "corpus" / "corpus.jsonl"))
    args = ap.parse_args()

    paths = [pathlib.Path(r) for r in args.rules] if args.rules else sorted((ROOT / "rules").glob("*.yml"))
    events = [json.loads(l) for l in open(args.corpus, encoding="utf-8") if l.strip()]
    rules = load_rules(paths)

    n_att = sum(1 for e in events if e["label"] == "attack")
    n_ord = sum(1 for e in events if e["label"] == "benign" and e["cls"] == "ordinary")
    n_look = sum(1 for e in events if e["label"] == "benign" and e["cls"] == "lookalike")
    print(f"Corpus: {len(events)} events  (attack {n_att}, benign ordinary {n_ord}, benign lookalike {n_look})\n")

    rows, details, failed = [], [], False
    for r in rules:
        tp = fn = fp = look = 0
        fn_cmds, fp_cmds, look_cmds, miss_note = [], {}, {}, ""
        miss_total = miss_hit = 0
        for e in events:
            fires = rule_fires(r, e)
            if e["label"] == "attack" and e["technique"] == r["technique"]:
                if e.get("expect_miss"):
                    miss_total += 1
                    miss_hit += fires
                elif fires:
                    tp += 1
                else:
                    fn += 1
                    fn_cmds.append(short(e))
            elif e["label"] == "benign" and fires:
                if e["cls"] == "ordinary":
                    fp += 1
                    fp_cmds[short(e)] = fp_cmds.get(short(e), 0) + 1
                else:
                    look += 1
                    look_cmds[e["name"]] = look_cmds.get(e["name"], 0) + 1
        positives = tp + fn
        status = "PASS"
        if fn or fp:
            status, failed = "FAIL", True
        elif positives == 0:
            status = "NO-DATA"
        if miss_total:
            miss_note = f"{miss_hit}/{miss_total} known-miss detected"
        rows.append((r["file"], r["technique"] or "-", r["base"], f"{tp}/{positives}", fn, fp, look, miss_note, status))
        for c in fn_cmds:
            details.append(f"  FN  {r['file']}: attack not detected: {c}")
        for c, n in fp_cmds.items():
            details.append(f"  FP  {r['file']}: fired on ordinary benign x{n}: {c}")

    head = ("Rule file", "Technique", "Wazuh id", "TP", "FN", "FP", "Lookalike", "Note", "Status")
    widths = [max(len(str(x)) for x in col) for col in zip(head, *rows)]
    fmt = "  ".join("{:<%d}" % w for w in widths)
    print(fmt.format(*head))
    for row in rows:
        print(fmt.format(*[str(x) for x in row]))
    print()
    for d in details:
        print(d)

    tot_fp = sum(r[5] for r in rows)
    tot_look = sum(r[6] for r in rows)
    print(f"\nFP on ordinary benign events: {tot_fp} (limit 0)  |  lookalike hits (info only): {tot_look}")
    print("RESULT:", "FAIL" if failed else "PASS")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n### Detection test on corpus\n\n")
            f.write(f"Corpus: {len(events)} events (attack {n_att}, ordinary benign {n_ord}, lookalike {n_look})\n\n")
            f.write("| Rule | Technique | TP | FN | FP | Lookalike | Status |\n|---|---|---|---|---|---|---|\n")
            for row in rows:
                f.write(f"| {row[0]} | {row[1]} | {row[3]} | {row[4]} | {row[5]} | {row[6]} | {row[8]} |\n")
            if details:
                f.write("\n" + "\n".join(f"- `{d.strip()}`" for d in details) + "\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
