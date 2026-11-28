"""Build the labelled test corpus from raw Wazuh archive logs.

Run this ONCE on the machine that has the raw logs (e.g. the Wazuh server); the output
(tests/corpus/corpus.jsonl) is committed to the repo and used by scripts/fp_check.py in CI.

Usage:
  python scripts/make_corpus.py \
      --archive corpus_raw/ossec-archive-27.json.gz \
      --archive corpus_raw/archives_28_full.json \
      --windows tests/corpus_windows.csv \
      --labels tests/corpus_labels.yml \
      --out tests/corpus/corpus.jsonl

How events are labelled
  * Only Sysmon process-create events (eventID 1) are kept.
  * Event time inside a *benign* window (windows csv, kind starting with "benign")
        -> label "benign"   (class "lookalike" if it matches a lookalike signature,
                              otherwise class "ordinary")
  * Event outside every benign window that matches an attack signature
        -> label "attack" + technique (+ expect_miss for accepted false negatives)
  * Anything else is dropped (background noise we cannot label with confidence).
"""
import argparse
import csv
import gzip
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

import yaml


def norm(text):
    """Undo Wazuh's JSON escaping (\\\\ -> \\ and \\" -> ") and lower-case."""
    return (text or "").replace("\\\\", "\\").replace('\\"', '"').lower()


def parse_ts(value):
    """'2026-11-27T16:24:48.527+0000' -> aware datetime (UTC)."""
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).astimezone(timezone.utc)
        except ValueError:
            pass
    raise ValueError(f"bad timestamp: {value!r}")


def parse_window_time(value):
    return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def load_windows(path):
    wins = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["kind"].strip().lower().startswith("benign"):
                wins.append((parse_window_time(row["start_utc"]), parse_window_time(row["end_utc"]), row["what"]))
    return wins


def in_windows(ts, wins):
    return any(a <= ts <= b for a, b, _ in wins)


def image_ok(image, names):
    img = norm(image).replace("\\", "/")
    return any(img == n or img.endswith("/" + n) for n in (x.lower() for x in names))


def sig_match(sig, image, cmd):
    if not image_ok(image, sig["image"]):
        return False
    if any(s not in cmd for s in sig.get("all", [])):
        return False
    anys = sig.get("any")
    if anys and not any(s in cmd for s in anys):
        return False
    return True


def open_any(path):
    p = str(path)
    if p.endswith(".gz"):
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return open(p, "r", encoding="utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", action="append", required=True, help="archives.json or .json.gz (repeatable)")
    ap.add_argument("--windows", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--agent", default=None, help="only keep events from this agent name")
    args = ap.parse_args()

    labels = yaml.safe_load(open(args.labels, encoding="utf-8"))
    attack_sigs = labels["attack_signatures"]
    look_sigs = labels["lookalike_signatures"]
    wins = load_windows(args.windows)
    if not wins:
        sys.exit("no benign windows found in " + args.windows)

    seen, out, stats = set(), [], {}
    for path in args.archive:
        with open_any(path) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                win = (d.get("data") or {}).get("win") or {}
                system, ed = win.get("system") or {}, win.get("eventdata") or {}
                if str(system.get("eventID")) != "1":
                    continue
                if args.agent and (d.get("agent") or {}).get("name") != args.agent:
                    continue
                try:
                    ts = parse_ts(d["timestamp"])
                except (KeyError, ValueError):
                    continue
                image, cmd_raw = ed.get("image", ""), ed.get("commandLine", "")
                key = (ts.isoformat(), image, cmd_raw)
                if key in seen:
                    continue
                seen.add(key)
                cmd = norm(cmd_raw)

                rec = {"ts": ts.strftime("%Y-%m-%dT%H:%M:%S"), "eventID": "1"}
                if in_windows(ts, wins):
                    cls, name = "ordinary", ""
                    for sig in look_sigs:
                        if sig_match(sig, image, cmd):
                            cls, name = "lookalike", sig["name"]
                            break
                    rec.update(label="benign", cls=cls, name=name)
                else:
                    hit = next((s for s in attack_sigs if sig_match(s, image, cmd)), None)
                    if hit is None:
                        continue
                    rec.update(label="attack", technique=hit["technique"],
                               expect_miss=bool(hit.get("expect_miss", False)))
                rec["eventdata"] = {k: ed[k] for k in
                                    ("image", "commandLine", "parentImage", "originalFileName") if k in ed}
                rec["id"] = hashlib.sha1("|".join(key).encode()).hexdigest()[:12]
                out.append(rec)
                k = (rec["label"], rec.get("cls") or rec.get("technique"))
                stats[k] = stats.get(k, 0) + 1

    out.sort(key=lambda r: (r["label"], r["ts"]))
    outp = pathlib.Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with open(outp, "w", encoding="utf-8", newline="\n") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    print(f"wrote {len(out)} events -> {outp}")
    for (label, what), n in sorted(stats.items(), key=lambda kv: (kv[0][0], str(kv[0][1]))):
        print(f"  {label:7} {str(what):12} {n}")


if __name__ == "__main__":
    main()
