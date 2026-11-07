"""Pipeline Step 2: Convert validated Sigma YAML rules to Wazuh XML rules via pySigma.

Usage:
  python scripts/convert_wazuh.py                       # convert ALL rules in rules/
  python scripts/convert_wazuh.py rules/a.yml rules/b.yml # convert ONLY these files
"""
import itertools
import math
import os
import pathlib
import re
import sys
from xml.sax.saxutils import escape
 
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError, SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaTimestampPart,
    SpecialChars,
)
 
ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "wazuh"
 
 
# Config against log sources
LOGSOURCE_PARENT_GROUP = {
    ("windows", "process_creation"): "sysmon_event1",
    ("windows", "network_connection"): "sysmon_event3",
    ("windows", "process_access"): "sysmon_event_10",
    ("windows", "file_event"): "sysmon_event_11",
}
 
# Sigma level, numbers can be changed
LEVELS = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 15}
 
# Sigma field -> Wazuh field. Fields not listed fall back to win.eventdata.<field with first letter lower-cased>
FIELD_MAP = {
    "EventID": "win.system.eventID",
    "Channel": "win.system.channel",
    "Provider_Name": "win.system.providerName",
    "Computer": "win.system.computer",
}
 
# For rule ID calc later
ID_BASE = 100000
MAX_BRANCHES = 10
ID_SLOTS = 1900  # 1900 * 10 IDs -> 100000..118999
 
 
def _merge_or(branches):
    """OR of single positive literals on the same field -> one alternation regex."""
    merged, by_field, out = [], {}, []
    for br in branches:
        if len(br) == 1 and not br[0][2]:
            by_field.setdefault(br[0][0], []).append(br[0][1])
        else:
            out.append(br)
    for field, pats in by_field.items():
        pats = list(dict.fromkeys(pats))
        if len(pats) == 1:
            merged.append([(field, pats[0], False)])
        elif all(p.startswith("(?i)") for p in pats):
            merged.append([(field, "(?i)(?:" + "|".join(p[4:] for p in pats) + ")", False)])
        else:
            merged.append([(field, "(?:" + "|".join(f"(?i:{p[4:]})" if p.startswith("(?i)") else p
                                                    for p in pats) + ")", False)])
    return merged + out
 
 
def _check_size(count):
    """Reject a condition that would need more than MAX_BRANCHES Wazuh rules."""
    if count > MAX_BRANCHES:
        raise SigmaFeatureNotSupportedByBackendError(
            f"condition expands to {count} Wazuh rules (limit {MAX_BRANCHES}); "
            "simplify the rule or split it"
        )


def _and(dnfs):
    _check_size(math.prod(len(dnf) for dnf in dnfs))
    return [sum(combo, []) for combo in itertools.product(*dnfs)]


def _not(dnf):
    # NOT(OR_i AND_j l_ij) = AND_i OR_j NOT l_ij. 
    factors = [[[(f, p, not n)] for (f, p, n) in branch] for branch in dnf]
    return _and(factors)
 
 
_PCRE_META = re.compile(r"([.^$*+?{}\[\]\\|()])")
 
 
def _glob_to_pcre(sigma_string, anchored=True):
    """
    anchored=True  : whole-value match (^...$), used for field values.
    anchored=False : substring match, used for keyword (field-less) searches.
    """
    parts = list(sigma_string.s)
    leading_wildcard = bool(parts) and parts[0] == SpecialChars.WILDCARD_MULTI
    if leading_wildcard:
        parts = parts[1:]
    trailing_wildcard = bool(parts) and parts[-1] == SpecialChars.WILDCARD_MULTI
    if trailing_wildcard:
        parts = parts[:-1]
 
    out = []
    for part in parts:
        if isinstance(part, str):
            out.append(_PCRE_META.sub(r"\\\1", part))
        elif part == SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        else:
            raise SigmaFeatureNotSupportedByBackendError(
                f"unsupported element in value: {part!r}"
            )
    pattern = "".join(out)
    
    if anchored:
        if not leading_wildcard:
            pattern = "^" + pattern
        if not trailing_wildcard:
            pattern = pattern + "$"
    return pattern
 
 
def wazuh_field(sigma_field):
    """Sigma field name -> Wazuh field path (None stays None: a keyword search)."""
    if sigma_field is None:
        return None
    if "." in sigma_field:  # already a Wazuh field path
        return sigma_field
    if sigma_field in FIELD_MAP:
        return FIELD_MAP[sigma_field]
    return "win.eventdata." + sigma_field[0].lower() + sigma_field[1:]


def _regex_pattern(value):
    """SigmaRegularExpression -> plain pcre2 string with inline flags.
    In pySigma 2.x `.regexp` is a SigmaString, so it must go through str()."""
    flags = ""
    for flag, letter in ((SigmaRegularExpressionFlag.IGNORECASE, "i"),
                         (SigmaRegularExpressionFlag.MULTILINE, "m"),
                         (SigmaRegularExpressionFlag.DOTALL, "s")):
        if flag in (value.flags or ()):
            flags += letter
    return (f"(?{flags})" if flags else "") + str(value.regexp)


# Value types that cannot be expressed as a Wazuh pcre2 match
_UNSUPPORTED_VALUES = (
    (SigmaBool, "boolean values"),
    (SigmaCIDRExpression, "cidr modifier"),
    (SigmaNull, "null values"),
    (SigmaTimestampPart, "timestamp parts"),
    (SigmaCompareExpression, "lt/lte/gt/gte modifiers"),
    (SigmaFieldReference, "fieldref modifier"),
    (SigmaQueryExpression, "query expressions"),
    (SigmaExists, "exists modifier"),
)


def _literal(field, value):
    """One field/value pair -> one literal (wazuh_field_or_None, pcre2_pattern, negated).
    `field` is None for a keyword search, which matches anywhere in the log."""
    keyword = field is None
    # Unsupported types are rejected FIRST: some are subclasses of supported ones
    # (SigmaTimestampPart is a SigmaNumber) and would otherwise be converted wrongly.
    for unsupported_type, feature in _UNSUPPORTED_VALUES:
        if isinstance(value, unsupported_type):
            raise SigmaFeatureNotSupportedByBackendError(
                f"{feature} is not supported for Wazuh")
    match value:
        case SigmaCasedString():  # must precede SigmaString (it is a subclass)
            pattern = _glob_to_pcre(value, anchored=not keyword)
        case SigmaString():
            pattern = "(?i)" + _glob_to_pcre(value, anchored=not keyword)
        case SigmaNumber():
            escaped = _PCRE_META.sub(r"\\\1", str(value))
            pattern = escaped if keyword else f"^{escaped}$"
        case SigmaRegularExpression():
            pattern = _regex_pattern(value)
        case _:
            raise SigmaFeatureNotSupportedByBackendError(
                f"unsupported element in value: {value!r}")
    return (wazuh_field(field), pattern, False)


def _or(dnfs):
    merged = _merge_or(sum(dnfs, []))
    _check_size(len(merged))
    return merged


def _leaf(field, value):
    """A single field=value test (field None = keyword) -> DNF."""
    if isinstance(value, SigmaExpansion):  # e.g. |windash: one value, several spellings
        return _or([[[_literal(field, v)]] for v in value.values])
    return [[_literal(field, value)]]


def _to_dnf(node):
    """pySigma condition tree node -> DNF (list of branches of literals)."""
    match node:
        case ConditionOR():
            return _or([_to_dnf(arg) for arg in node.args])
        case ConditionAND():
            return _and([_to_dnf(arg) for arg in node.args])
        case ConditionNOT():
            return _not(_to_dnf(node.args[0]))
        case ConditionFieldEqualsValueExpression():
            return _leaf(node.field, node.value)
        case ConditionValueExpression():  # keyword search, no field
            return _leaf(None, node.value)
        case _:  # pragma: no cover - the parser only produces the node types above
            raise TypeError(f"unexpected node in condition tree: {type(node).__name__}")


def convert_rule(rule):
    """Sigma rule -> list with one DNF per condition (a rule may list several conditions)."""
    return [_to_dnf(condition.parsed) for condition in rule.detection.parsed_condition]
 

# XML Generation -- 
 
def error(path, msg):
    print(f"::error file={path.relative_to(ROOT)}::{msg}")
 
 
def rule_files(args):
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
 
 
def literal_xml(field, pattern, negated):
    neg = ' negate="yes"' if negated else ""
    pattern = escape(pattern)
    if field is None:
        return f'    <regex type="pcre2"{neg}>{pattern}</regex>'
    return f'    <field name="{field}" type="pcre2"{neg}>{pattern}</field>'
 
 
def rule_to_xml(rule: SigmaRule, branches):
    ls = rule.logsource
    key = (str(ls.product).lower() if ls.product else None,
           str(ls.category).lower() if ls.category else None)
    parent = LOGSOURCE_PARENT_GROUP.get(key)
    if parent is None:
        supported = ", ".join(f"{p}/{c}" for p, c in LOGSOURCE_PARENT_GROUP)
        raise SigmaFeatureNotSupportedByBackendError(
            f"logsource {key[0]}/{key[1]} has no Wazuh parent group; "
            f"add it to LOGSOURCE_PARENT_GROUP (currently: {supported})"
        )

    if rule.id is None:
        raise SigmaFeatureNotSupportedByBackendError( "rule has no 'id'; the Wazuh rule ID is derived from it")
 
    level = LEVELS.get(str(rule.level.name).lower() if rule.level else "medium", 8)
    base = ID_BASE + (rule.id.int % ID_SLOTS) * MAX_BRANCHES
    mitre = sorted({str(t).split(".", 1)[1].upper()
                    for t in (str(x) for x in rule.tags)
                    if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t.lower())})
 
    xml = []
    for i, branch in enumerate(branches):
        suffix = f" [{i + 1}/{len(branches)}]" if len(branches) > 1 else ""
        xml.append(f'  <rule id="{base + i}" level="{level}">')
        xml.append(f"    <if_group>{parent}</if_group>")
        xml.extend(literal_xml(*lit) for lit in branch)
        xml.append(f"    <description>{escape(rule.title)}{suffix}</description>")
        if mitre:
            xml.append("    <mitre>" + "".join(f"<id>{m}</id>" for m in mitre) + "</mitre>")
        xml.append(f'    <info type="text">Sigma rule id: {rule.id}</info>')
        xml.append("  </rule>")
    return base, "\n".join(xml)
 
 
def convert_file(path):
    """Returns (xml_text, base_id, rule_count). Raises SigmaError on problems."""
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
    skipped = [getattr(r, "title", "?") for r in collection.rules if not isinstance(r, SigmaRule)]
    if skipped:  # never drop a detection silently
        raise SigmaFeatureNotSupportedByBackendError(
            "correlation rules are not supported for Wazuh (found: "
            + ", ".join(f"'{t}'" for t in skipped) + ")")
    if not rules:
        raise SigmaFeatureNotSupportedByBackendError("no Sigma rule found in file")
    chunks, first_id, count, seen_bases = [], None, 0, {}
    for rule in rules:
        queries = convert_rule(rule)
        if not queries:
            raise SigmaFeatureNotSupportedByBackendError("conversion produced no rule")
        # A Sigma rule may list several conditions; each is an alternative way to match,
        # so their branches are OR-ed together (never silently drop all but the first).
        branches = [branch for query in queries for branch in query]
        if len(branches) > MAX_BRANCHES:
            raise SigmaFeatureNotSupportedByBackendError(
                f"rule expands to {len(branches)} Wazuh rules (limit {MAX_BRANCHES}); "
                "simplify the rule or split it"
            )
        base, xml = rule_to_xml(rule, branches)
        if base in seen_bases:
            raise SigmaFeatureNotSupportedByBackendError(
                f"rules '{seen_bases[base]}' and '{rule.title}' in the same file map to "
                f"the same Wazuh rule ID block {base}"
            )
        seen_bases[base] = rule.title
        first_id = first_id or base
        count += len(branches)
        chunks.append(xml)
    body = "\n".join(chunks)
    # "--" is illegal inside an XML comment and would make Wazuh reject the whole file
    comment_name = path.name.replace("--", "- -")
    return (f'<!-- Generated from {comment_name} by convert_to_wazuh.py - do not edit -->\n'
            f'<group name="sigma,">\n{body}\n</group>\n'), first_id, count


def main():
    args = sys.argv[1:]
    OUT.mkdir(parents=True, exist_ok=True)
    rows, failed, used_ids = [], False, {}

    for path in rule_files(args):
        try:
            xml, base, count = convert_file(path)
        except SigmaError as e:
            error(path, f"{type(e).__name__}: {e}")
            rows.append((path.name, "FAIL", str(e)))
            failed = True
            continue
        except Exception as e:  # unexpected: report, keep going with other files
            error(path, f"unexpected error: {e!r}")
            rows.append((path.name, "FAIL", repr(e)))
            failed = True
            continue

        clash = used_ids.get(base)
        if clash:
            msg = f"Wazuh rule ID block {base} already used by {clash}; change one rule's UUID"
            error(path, msg)
            rows.append((path.name, "FAIL", msg))
            failed = True
            continue
        used_ids[base] = path.name

        (OUT / f"{path.stem}.xml").write_text(xml, encoding="utf-8")
        rows.append((path.name, "PASS",
                     f"{count} Wazuh rule(s), IDs from {base} -> out/wazuh/{path.stem}.xml"))

    print("\nResult:")
    for name, status, note in rows:
        print(f"  {status}  {name}  {note}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and rows:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n| Rule | Wazuh conversion | Detail |\n|---|---|---|\n")
            for name, status, note in rows:
                f.write(f"| {name} | {status} | {note} |\n")

    if not rows and not args:
        print("::error::No rules found in rules/")
        failed = True

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()