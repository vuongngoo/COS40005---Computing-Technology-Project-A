"""Pipeline Step 2: Convert validated Sigma YAML rules to Wazuh XML rules via pySigma.

Usage:
  python scripts/convert_wazuh.py                       # convert ALL rules in rules/
  python scripts/convert_wazuh.py rules/a.yml rules/b.yml # convert ONLY these files
"""
import hashlib
import os
import pathlib
import sys
import xml.etree.ElementTree as ET
from xml.dom import minidom

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.types import SigmaRegularExpression, SigmaString

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "out" / "converted"

# Map Sigma severity levels to Wazuh rule levels (0-15)
LEVEL_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 12,
    "critical": 15,
}

# Map generic Sigma fields to Wazuh decoded field names via pySigma ProcessingPipeline
WAZUH_FIELD_MAP = {
    "Image": "win.eventdata.image",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "ParentCommandLine": "win.eventdata.parentCommandLine",
    "User": "win.eventdata.user",
    "TargetFilename": "win.eventdata.targetFilename",
    "OriginalFileName": "win.eventdata.originalFileName",
    "EventID": "win.system.eventID",
    "DestinationIp": "data.dstip",
    "SourceIp": "data.srcip",
    "DestinationPort": "data.dstport",
}


def error(path: pathlib.Path, msg: str):
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


def build_wazuh_pipeline() -> ProcessingPipeline:
    """Create a pySigma ProcessingPipeline to map Sigma fields to Wazuh decoder fields."""
    return ProcessingPipeline(
        name="Wazuh Field Mapping Pipeline",
        priority=20,
        items=[
            ProcessingItem(
                identifier="wazuh_field_mapping",
                transformation=FieldMappingTransformation(WAZUH_FIELD_MAP),
            )
        ],
    )


def deterministic_rule_id(sigma_uuid: str) -> int:
    """Generate a consistent Wazuh rule ID in the custom range (100100 - 119999)."""
    digest = hashlib.sha256(str(sigma_uuid).encode("utf-8")).hexdigest()
    return 100100 + (int(digest[:8], 16) % 19899)


def sigma_val_to_pcre2(val) -> str:
    if isinstance(val, SigmaRegularExpression):
        return str(val.regexp)
    if isinstance(val, SigmaString):
        return str(val.to_regex())
    return str(val)


def extract_field_matchers(parsed_cond, negate=False):
    """Traverse pySigma's parsed AST to extract (field, pcre2_pattern, negate) tuples."""
    matchers = []
    if isinstance(parsed_cond, ConditionFieldEqualsValueExpression):
        pattern = sigma_val_to_pcre2(parsed_cond.value)
        matchers.append((parsed_cond.field, pattern, negate))
    elif isinstance(parsed_cond, ConditionNOT):
        for arg in parsed_cond.args:
            matchers.extend(extract_field_matchers(arg, negate=not negate))
    elif isinstance(parsed_cond, (ConditionAND, ConditionOR)):
        # Merge OR values on the same field into a single PCRE2 alternation: (val1|val2)
        if isinstance(parsed_cond, ConditionOR):
            sub = [extract_field_matchers(a, negate) for a in parsed_cond.args]
            flat = [item for sublist in sub for item in sublist]
            fields = {f for f, _, _ in flat}
            if len(fields) == 1 and len(flat) > 1:
                field = flat[0][0]
                combined = "(?i)(?:" + "|".join(p for _, p, _ in flat) + ")"
                return [(field, combined, negate)]
        for arg in parsed_cond.args:
            matchers.extend(extract_field_matchers(arg, negate))
    return matchers


def sigma_to_wazuh_xml(sigma_rule, pipeline: ProcessingPipeline) -> ET.Element:
    """Transform a pySigma SigmaRule object into a Wazuh <rule> XML element."""
    pipeline.apply(sigma_rule)

    rule_id = deterministic_rule_id(sigma_rule.id)
    level = LEVEL_MAP.get(str(sigma_rule.level).lower(), 5)

    rule_el = ET.Element("rule", id=str(rule_id), level=str(level))

    # Base group routing based on Sigma logsource
    if sigma_rule.logsource.product == "windows":
        if_group = ET.SubElement(rule_el, "if_group")
        if_group.text = "windows"

    # Extract conditions from pySigma's parsed detection AST
    for cond in sigma_rule.detection.parsed_condition:
        parsed_tree = cond.parse()
        for field_name, pattern, is_negated in extract_field_matchers(parsed_tree):
            field_el = ET.SubElement(rule_el, "field", name=field_name, type="pcre2")
            if is_negated:
                field_el.set("negate", "yes")
            field_el.text = pattern if pattern.startswith("(?i)") else f"(?i){pattern}"

    # Description
    desc_el = ET.SubElement(rule_el, "description")
    desc_el.text = f"[Sigma] {sigma_rule.title} (ID: {sigma_rule.id})"

    # MITRE ATT&CK tags
    mitre_ids = [
        str(t.name).upper()
        for t in (sigma_rule.tags or [])
        if t.namespace == "attack" and str(t.name).lower().startswith("t")
    ]
    if mitre_ids:
        mitre_el = ET.SubElement(rule_el, "mitre")
        for m_id in mitre_ids:
            id_el = ET.SubElement(mitre_el, "id")
            id_el.text = m_id

    return rule_el


def prettify_xml(elem: ET.Element) -> str:
    rough = ET.tostring(elem, encoding="utf-8")
    parsed = minidom.parseString(rough)
    return "\n".join(line for line in parsed.toprettyxml(indent="  ").splitlines() if line.strip())


def main():
    args = sys.argv[1:]
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pipeline = build_wazuh_pipeline()

    group_el = ET.Element("group", name="sigma,custom_sigma_rules,")
    rows, failed = [], False

    for path in rule_files(args):
        try:
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
            for sigma_rule in collection.rules:
                rule_xml = sigma_to_wazuh_xml(sigma_rule, pipeline)
                group_el.append(rule_xml)

                # Write individual rule XML
                single_group = ET.Element("group", name="sigma,custom_sigma_rules,")
                single_group.append(rule_xml)
                out_file = OUT_DIR / f"{path.stem}.xml"
                out_file.write_text(prettify_xml(single_group) + "\n", encoding="utf-8")

                wazuh_id = rule_xml.get("id")
                rows.append((path.name, "PASS", wazuh_id, f"out/wazuh/{path.stem}.xml"))
        except (SigmaError, Exception) as e:
            error(path, f"pySigma conversion failed: {e}")
            rows.append((path.name, "FAIL", "-", str(e)))
            failed = True

    # Write combined bundle for direct deployment to /var/ossec/etc/rules/sigma_rules.xml
    if len(group_el) > 0:
        bundle_path = OUT_DIR / "sigma_rules_bundle.xml"
        bundle_path.write_text(prettify_xml(group_el) + "\n", encoding="utf-8")

    print("\npySigma Wazuh Conversion Result:")
    for name, status, w_id, note in rows:
        print(f"  {status}  {name} (Wazuh ID: {w_id}) -> {note}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and rows:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n### Step 2: pySigma Wazuh XML Conversion\n")
            f.write("| Rule | Status | Wazuh Rule ID | Output / Error |\n|---|---|---|---|\n")
            for name, status, w_id, note in rows:
                f.write(f"| {name} | {status} | `{w_id}` | {note} |\n")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
