"""Pipeline Step 2: Convert validated Sigma YAML rules to Wazuh XML rules via pySigma.

Usage:
  python scripts/convert_wazuh.py                       # convert ALL rules in rules/
  python scripts/convert_wazuh.py rules/a.yml rules/b.yml # convert ONLY these files
"""
import itertools
import os
import pathlib
import re
import sys
from xml.sax.saxutils import escape
 
from sigma.collection import SigmaCollection
from sigma.conversion.base import Backend
from sigma.exceptions import SigmaError, SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpressionFlag, SpecialChars
 
ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "wazuh"
 
 
# Config against log sources
LOGSOURCE_PARENT_GROUP = {
    ("windows", "process_creation"): "sysmon_event1",
    ("windows", "network_connection"): "sysmon_event3",
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
 
 
def _and(dnfs):
    return [sum(combo, []) for combo in itertools.product(*dnfs)]
 
 
def _not(dnf):
    # NOT(OR_i AND_j l_ij) = AND_i OR_j NOT l_ij
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
 
 
class WazuhBackend(Backend):
    """Converts a Sigma condition into DNF literals for Wazuh <field> elements."""
 
    name = "Wazuh"
    formats = {"default": "Wazuh rule branches (DNF)"}
    requires_pipeline = False
 
    #helpers
    @staticmethod
    def wazuh_field(sigma_field):
        if sigma_field is None:
            return None
        if "." in sigma_field:  # already a Wazuh field path
            return sigma_field
        if sigma_field in FIELD_MAP:
            return FIELD_MAP[sigma_field]
        return "win.eventdata." + sigma_field[0].lower() + sigma_field[1:]
 
    def _guard(self, dnf):
        if len(dnf) > MAX_BRANCHES:
            raise SigmaFeatureNotSupportedByBackendError(
                f"condition expands to {len(dnf)} Wazuh rules (limit {MAX_BRANCHES}); "
                "simplify the rule or split it"
            )
        return dnf
 
    # boolean logic
    def convert_condition_or(self, cond, state):
        branches = sum((self.convert_condition(a, state) for a in cond.args), [])
        return self._guard(_merge_or(branches))
 
    def convert_condition_and(self, cond, state):
        return self._guard(_and([self.convert_condition(a, state) for a in cond.args]))
 
    def convert_condition_not(self, cond, state):
        return self._guard(_not(self.convert_condition(cond.args[0], state)))
 
    def convert_condition_as_in_expression(self, cond, state):  # not used (no 'in' expr)
        raise SigmaFeatureNotSupportedByBackendError("in-expressions")
 
    # values
    def convert_condition_field_eq_val_str(self, cond, state):
        pat = "(?i)" + _glob_to_pcre(cond.value)
        return [[(self.wazuh_field(cond.field), pat, False)]]
 
    def convert_condition_field_eq_val_str_case_sensitive(self, cond, state):
        return [[(self.wazuh_field(cond.field), _glob_to_pcre(cond.value), False)]]
 
    def convert_condition_field_eq_val_num(self, cond, state):
        escaped = _PCRE_META.sub(r"\\\1", str(cond.value))
        return [[(self.wazuh_field(cond.field), f"^{escaped}$", False)]]
 
    @staticmethod
    def _regex_pattern(value):
        flags = ""
        for flag, letter in ((SigmaRegularExpressionFlag.IGNORECASE, "i"),
                             (SigmaRegularExpressionFlag.MULTILINE, "m"),
                             (SigmaRegularExpressionFlag.DOTALL, "s")):
            if flag in (value.flags or ()):
                flags += letter
        return (f"(?{flags})" if flags else "") + str(value.regexp)
 
    def convert_condition_field_eq_val_re(self, cond, state):
        return [[(self.wazuh_field(cond.field), self._regex_pattern(cond.value), False)]]
 
    # keyword searches (no field): matched against the whole log
    def convert_condition_val_str(self, cond, state):
        return [[(None, "(?i)" + _glob_to_pcre(cond.value, anchored=False), False)]]
 
    def convert_condition_val_re(self, cond, state):
        return [[(None, self._regex_pattern(cond.value), False)]]
 
    def convert_condition_val_num(self, cond, state):
        return [[(None, _PCRE_META.sub(r"\\\1", str(cond.value)), False)]]
 
    # output 
    def finalize_query_default(self, rule, query, index, state):
        return query
 
    def finalize_output_default(self, queries):
        return queries
 
 
def _unsupported(feature):
    def method(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError(f"{feature} is not supported for Wazuh")
    return method
 
 
for _name, _feature in {
    "convert_condition_field_eq_val_bool": "boolean values",
    "convert_condition_field_eq_val_cidr": "cidr modifier",
    "convert_condition_field_eq_val_null": "null values",
    "convert_condition_field_eq_val_timestamp_part": "timestamp parts",
    "convert_condition_field_compare_op_val": "lt/lte/gt/gte modifiers",
    "convert_condition_field_eq_field": "fieldref modifier",
    "convert_condition_field_eq_query_expr": "query expressions",
    "convert_condition_field_exists": "exists modifier",
    "convert_condition_field_not_exists": "exists modifier",
    "convert_condition_query_expr": "query expressions",
    "convert_correlation_event_count_rule": "correlation rules",
    "convert_correlation_extended_temporal_ordered_rule": "correlation rules",
    "convert_correlation_extended_temporal_rule": "correlation rules",
    "convert_correlation_temporal_ordered_rule": "correlation rules",
    "convert_correlation_temporal_rule": "correlation rules",
    "convert_correlation_value_avg_rule": "correlation rules",
    "convert_correlation_value_count_rule": "correlation rules",
    "convert_correlation_value_median_rule": "correlation rules",
    "convert_correlation_value_percentile_rule": "correlation rules",
    "convert_correlation_value_sum_rule": "correlation rules",
}.items():
    setattr(WazuhBackend, _name, _unsupported(_feature))
WazuhBackend.__abstractmethods__ = frozenset()
 

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
 
 
def convert_file(path, backend):
    """Returns (xml_text, base_id, rule_count). Raises SigmaError on problems."""
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
    if not rules:
        raise SigmaFeatureNotSupportedByBackendError("no (non-correlation) Sigma rule found")
    chunks, first_id, count, seen_bases = [], None, 0, {}
    for rule in rules:
        queries = backend.convert_rule(rule)
        if not queries:
            raise SigmaFeatureNotSupportedByBackendError("conversion produced no rule")
    branches = [branch for query in queries for branch in query]
    if len(branches) > MAX_BRANCHES:
        raise SigmaFeatureNotSupportedByBackendError( f"rule expands to {len(branches)} Wazuh rules (limit {MAX_BRANCHES}); ""simplify the rule or split it" )
    base, xml = rule_to_xml(rule, branches)
    if base in seen_bases:
        raise SigmaFeatureNotSupportedByBackendError( f"rules '{seen_bases[base]}' and '{rule.title}' in the same file map to " f"the same Wazuh rule ID block {base}" )
    seen_bases[base] = rule.title
    first_id = first_id or base
    count += len(branches)
    chunks.append(xml)
    body = "\n".join(chunks)
    
    comment_name = path.name.replace("--", "- -") # "--" is illegal inside an XML comment and would make Wazuh reject the whole file
    return (f'<!-- Generated from {comment_name} by convert_to_wazuh.py - do not edit -->\n'
            f'<group name="sigma,">\n{body}\n</group>\n'), first_id, count
 
 
def main():
    args = sys.argv[1:]
    OUT.mkdir(parents=True, exist_ok=True)
    backend = WazuhBackend()
    rows, failed, used_ids = [], False, {}
 
    for path in rule_files(args):
        try:
            xml, base, count = convert_file(path, backend)
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