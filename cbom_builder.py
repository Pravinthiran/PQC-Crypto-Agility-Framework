# cbom_builder.py
import json
import os
import uuid
from datetime import datetime, timezone
from scanner_ast import scan_source_files
from scanner_certs import scan_certificates


def generate_cbom(repo_root: str, output_path: str = "cbom.json") -> dict:
    """Aggregates static and dynamic discovery data into a valid CycloneDX 1.6 CBOM."""
    print("=" * 65)
    print("   PQC DISCOVERY ENGINE: AGGREGATING CBOM INVENTORY")
    print("=" * 65)

    # 1. Run Static Source Scanner
    print("[*] Executing Static Code Discovery Engine...")
    static_findings = scan_source_files(repo_root)
    print(f"[+] Static Engine completed: {len(static_findings)} assets found.")

    # 2. Run Dynamic Certificate Scanner
    certs_dir = os.path.join(repo_root, "certs")
    print("\n[*] Executing Dynamic Certificate Discovery Engine...")
    cert_findings = scan_certificates(certs_dir)
    print(f"[+] Certificate Engine completed: {len(cert_findings)} assets found.")

    all_findings = static_findings + cert_findings

    # 3. Format findings into standard CycloneDX 1.6 components
    cyclonedx_components = []
    for idx, item in enumerate(all_findings, start=1):
        component_entry = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{idx}",
            "name": f"{item.get('algorithm', 'Unknown')}-{item.get('primitive_family', 'Crypto')}",
            "properties": [
                {"name": "asset_type", "value": str(item.get("asset_type"))},
                {"name": "location", "value": str(item.get("location"))},
                {"name": "primitive_family", "value": str(item.get("primitive_family"))},
                {"name": "algorithm", "value": str(item.get("algorithm"))},
                {"name": "key_size_or_curve", "value": str(item.get("key_size_or_curve"))},
                {"name": "quantum_safe", "value": str(item.get("quantum_safe")).lower()},
                {"name": "vulnerability_type", "value": str(item.get("vulnerability_type"))},
                {"name": "migration_urgency", "value": str(item.get("migration_urgency"))}
            ]
        }
        if "signature_algorithm" in item:
            component_entry["properties"].append(
                {"name": "signature_algorithm", "value": str(item["signature_algorithm"])}
            )
        if "common_name" in item:
            component_entry["properties"].append(
                {"name": "common_name", "value": str(item["common_name"])}
            )

        cyclonedx_components.append(component_entry)

    # 4. CycloneDX 1.6 Valid Schema Structure
    cbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Crypto-Agility Discovery Engine",
                        "version": "1.0.0"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": "Enterprise Testbed Target",
                "scope": "optional"  # Accepted values: "required", "optional", "excluded"
            },
            "properties": [
                {"name": "total_cryptographic_assets", "value": str(len(all_findings))},
                {"name": "quantum_vulnerable_count", "value": str(sum(1 for i in all_findings if not i.get("quantum_safe", False)))},
                {"name": "quantum_safe_count", "value": str(sum(1 for i in all_findings if i.get("quantum_safe", False)))},
                {"name": "critical_urgency_count", "value": str(sum(1 for i in all_findings if i.get("migration_urgency") == "Critical"))}
            ]
        },
        "components": cyclonedx_components
    }

    # 5. Export JSON
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2)

    print("\n" + "=" * 65)
    print(f"[+] SUCCESS: Validated CBOM generated at: {os.path.abspath(output_path)}")
    print(f"    - Total Identified Assets : {len(all_findings)}")
    print("=" * 65)

    return cbom


if __name__ == "__main__":
    target_repo = os.path.join(os.getcwd(), "testbed_repo")
    generate_cbom(target_repo, "cbom.json")