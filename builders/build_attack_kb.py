import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import urlopen

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_OUTPUT_DIR = PROJECT_ROOT / "data" / "raw" / "attack"
RAG_OUTPUT_DIR = PROJECT_ROOT / "data" / "rag" / "attack"
LEGACY_RAW_FALLBACKS = [
    PROJECT_ROOT / "data" / "legacy_snapshots" / "attack_knowledge_raw.json",
    PROJECT_ROOT.parent / "data" / "attack" / "attack_knowledge_raw.json",
]

RAW_OUTPUT = RAW_OUTPUT_DIR / "attack_knowledge_raw.json"
RAG_OUTPUT = RAG_OUTPUT_DIR / "attack_knowledge_for_rag.jsonl"


def load_json_from_url(url: str, timeout: int = 30) -> Dict[str, Any]:
    try:
        with urlopen(url, timeout=timeout) as resp:
            return json.load(resp)
    except URLError as exc:
        raise RuntimeError(f"Failed to download ATT&CK data from {url}: {exc}") from exc


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def save_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def find_local_fallback() -> Optional[Path]:
    if RAW_OUTPUT.exists():
        return RAW_OUTPUT
    for candidate in LEGACY_RAW_FALLBACKS:
        if candidate.exists():
            return candidate
    return None


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def unique_strs(items: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def clean_text(text: Optional[str]) -> str:
    if not text:
        return ""
    text = re.sub(r"\(Citation:[^)]+\)", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def get_attack_id(stix_obj: Dict[str, Any]) -> str:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") in {
            "mitre-attack",
            "mitre-mobile-attack",
            "mitre-ics-attack",
        }:
            return ref.get("external_id", "")
    return ""


def is_revoked_or_deprecated(stix_obj: Dict[str, Any]) -> bool:
    return bool(stix_obj.get("revoked", False) or stix_obj.get("x_mitre_deprecated", False))


def build_attack_knowledge(
    bundle: Dict[str, Any],
    platform_filter: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    objects = bundle.get("objects", [])
    allowed_platforms = set(platform_filter or [])

    attack_patterns: Dict[str, Dict[str, Any]] = {}
    tactics_by_shortname: Dict[str, Dict[str, Any]] = {}
    mitigations: Dict[str, Dict[str, Any]] = {}
    relationships: List[Dict[str, Any]] = []

    for obj in objects:
        obj_type = obj.get("type")
        if is_revoked_or_deprecated(obj):
            continue
        if obj_type == "attack-pattern":
            attack_patterns[obj["id"]] = obj
        elif obj_type == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname")
            if shortname:
                tactics_by_shortname[shortname] = obj
        elif obj_type == "course-of-action":
            mitigations[obj["id"]] = obj
        elif obj_type == "relationship":
            relationships.append(obj)

    mitigation_map: Dict[str, List[str]] = {}
    for rel in relationships:
        if rel.get("relationship_type") != "mitigates":
            continue
        src = rel.get("source_ref")
        tgt = rel.get("target_ref")
        if src in mitigations and tgt in attack_patterns:
            mitigation_map.setdefault(tgt, []).append(src)

    records: List[Dict[str, Any]] = []
    for stix_id, obj in attack_patterns.items():
        platforms = [str(x) for x in ensure_list(obj.get("x_mitre_platforms")) if x]
        if allowed_platforms and not any(platform in allowed_platforms for platform in platforms):
            continue

        kill_chain_phases = ensure_list(obj.get("kill_chain_phases"))
        tactic_names: List[str] = []
        tactic_ids: List[str] = []
        for phase in kill_chain_phases:
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            shortname = phase.get("phase_name")
            tactic = tactics_by_shortname.get(shortname)
            if tactic:
                tactic_names.append(tactic.get("name", shortname or ""))
                tactic_ids.append(get_attack_id(tactic))
            elif shortname:
                tactic_names.append(shortname)

        mitigation_items = []
        for mid in mitigation_map.get(stix_id, []):
            mit = mitigations.get(mid, {})
            mitigation_items.append(
                {
                    "mitigation_id": get_attack_id(mit),
                    "mitigation_name": mit.get("name", ""),
                    "mitigation_desc": clean_text(mit.get("description", "")),
                }
            )

        attack_id = get_attack_id(obj)
        name = obj.get("name", "")
        data_sources = [str(x) for x in ensure_list(obj.get("x_mitre_data_sources")) if x]
        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique", False))
        keywords = unique_strs(
            [attack_id, name]
            + tactic_names
            + platforms
            + data_sources
            + [mit["mitigation_name"] for mit in mitigation_items if mit.get("mitigation_name")]
        )

        records.append(
            {
                "stix_id": stix_id,
                "attack_id": attack_id,
                "name": name,
                "description": clean_text(obj.get("description", "")),
                "type": "sub-technique" if is_subtechnique else "technique",
                "platforms": platforms,
                "tactics": unique_strs(tactic_names),
                "tactic_ids": unique_strs([x for x in tactic_ids if x]),
                "data_sources": data_sources,
                "permissions_required": [str(x) for x in ensure_list(obj.get("x_mitre_permissions_required")) if x],
                "defense_bypassed": [str(x) for x in ensure_list(obj.get("x_mitre_defense_bypassed")) if x],
                "detection": clean_text(obj.get("x_mitre_detection", "")),
                "system_requirements": [str(x) for x in ensure_list(obj.get("x_mitre_system_requirements")) if x],
                "remote_support": bool(obj.get("x_mitre_remote_support", False)),
                "mitigations": mitigation_items,
                "url": next(
                    (
                        ref.get("url", "")
                        for ref in obj.get("external_references", [])
                        if ref.get("source_name") in {
                            "mitre-attack",
                            "mitre-mobile-attack",
                            "mitre-ics-attack",
                        }
                    ),
                    "",
                ),
                "keywords": keywords,
            }
        )

    records.sort(key=lambda item: item.get("attack_id", ""))
    return records


def build_rag_doc(record: Dict[str, Any]) -> Dict[str, Any]:
    attack_id = record["attack_id"]
    name = record["name"]
    description = record["description"] or "No ATT&CK description available."
    tactics_text = ", ".join(record["tactics"]) if record["tactics"] else "Unknown"
    platforms_text = ", ".join(record["platforms"]) if record["platforms"] else "Unknown"
    data_sources_text = ", ".join(record["data_sources"]) if record["data_sources"] else "Unknown"
    mitigation_text = ", ".join(
        mitigation["mitigation_name"]
        for mitigation in record.get("mitigations", [])
        if mitigation.get("mitigation_name")
    ) or "None"
    detection_text = record.get("detection") or "No detection guidance."

    summary = (
        f"{attack_id} {name}. Type: {record['type']}. "
        f"Tactics: {tactics_text}. Platforms: {platforms_text}."
    )
    content = (
        f"ATT&CK ID: {attack_id}\n"
        f"Name: {name}\n"
        f"Type: {record['type']}\n"
        f"Tactics: {tactics_text}\n"
        f"Platforms: {platforms_text}\n"
        f"Description: {description}\n"
        f"Data Sources: {data_sources_text}\n"
        f"Detection: {detection_text}\n"
        f"Mitigations: {mitigation_text}\n"
    )

    return {
        "doc_id": f"attack::{attack_id}",
        "source": "ATTACK",
        "doc_type": "attack-technique",
        "title": f"{attack_id} {name}",
        "summary": summary,
        "content": content,
        "tags": unique_strs(record["tactics"] + record["platforms"] + [record["type"]]),
        "keywords": record["keywords"],
        "platforms": record["platforms"],
        "attack_ids": [attack_id],
        "metadata": {
            "language": "en",
            "type": record["type"],
            "tactics": record["tactics"],
            "tactic_ids": record["tactic_ids"],
            "url": record["url"],
        },
    }


def main() -> None:
    RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RAG_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("[+] Downloading ATT&CK STIX data...")
    records: List[Dict[str, Any]]
    try:
        bundle = load_json_from_url(ATTACK_STIX_URL)
        print("[+] Building ATT&CK knowledge records...")
        records = build_attack_knowledge(bundle, platform_filter=["Windows"])
        save_json(RAW_OUTPUT, records)
    except RuntimeError as exc:
        fallback_path = find_local_fallback()
        if fallback_path is None:
            raise
        print(f"[!] {exc}")
        print(f"[!] Falling back to local records: {fallback_path}")
        records = load_json(fallback_path)
        if fallback_path != RAW_OUTPUT:
            save_json(RAW_OUTPUT, records)

    print("[+] Building RAG-ready documents...")
    rag_docs = [build_rag_doc(record) for record in records]
    save_jsonl(RAG_OUTPUT, rag_docs)

    print("[+] Done.")
    print(f"    Raw records   : {RAW_OUTPUT}")
    print(f"    RAG documents : {RAG_OUTPUT}")
    print(f"    Total records : {len(records)}")


if __name__ == "__main__":
    main()
