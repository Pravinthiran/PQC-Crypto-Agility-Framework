# verify_phase2.py
import json
import os
import sys

def run_phase2_verification():
    print("=" * 65)
    print("      PQC CRYPTO-AGILITY FRAMEWORK: PHASE 2 AUDIT & VERIFICATION")
    print("=" * 65)

    all_passed = True

    # 1. Check Module Existence
    print("\n[+] ENGINE MODULE INTEGRITY:")
    modules = ["scanner_ast.py", "scanner_certs.py", "cbom_builder.py", "cbom.json"]
    for mod in modules:
        exists = os.path.exists(mod)
        status = "FOUND" if exists else "MISSING"
        if not exists:
            all_passed = False
        print(f"    - {mod:<18} : {status}")

    # 2. Inspect Static AST Engine Findings
    print("\n[+] STATIC DISCOVERY AUDIT (scanner_ast.py):")
    try:
        from scanner_ast import scan_source_files
        testbed_dir = os.path.join(os.getcwd(), "testbed_repo")
        static_res = scan_source_files(testbed_dir)
        algs = [item.get("algorithm") for item in static_res]
        print(f"    - Assets Discovered  : {len(static_res)}")
        print(f"    - Algorithms Found   : {', '.join(set(algs))}")
        
        expected_algs = {"MD5", "SHA1", "RSA", "ECC"}
        if expected_algs.issubset(set(algs)):
            print(f"    - AST Rule Coverage  : PASSED (MD5, SHA1, RSA, ECC detected)")
        else:
            print(f"    - AST Rule Coverage  : WARNING (Missing {expected_algs - set(algs)})")
            all_passed = False
    except Exception as e:
        print(f"    - AST Scanner Error  : FAILED ({e})")
        all_passed = False

    # 3. Inspect Dynamic Certificate Engine Findings
    print("\n[+] DYNAMIC DISCOVERY AUDIT (scanner_certs.py):")
    try:
        from scanner_certs import scan_certificates
        certs_dir = os.path.join(os.getcwd(), "testbed_repo", "certs")
        cert_res = scan_certificates(certs_dir)
        print(f"    - Certificates Found : {len(cert_res)}")
        if len(cert_res) > 0:
            cert = cert_res[0]
            print(f"    - Target Cert CN     : {cert.get('common_name')}")
            print(f"    - Key Type / Size    : {cert.get('algorithm')} ({cert.get('key_size_or_curve')})")
            print(f"    - Signature Alg      : {cert.get('signature_algorithm')}")
            print(f"    - Dynamic Engine     : PASSED")
        else:
            print(f"    - Dynamic Engine     : FAILED (No certificates parsed)")
            all_passed = False
    except Exception as e:
        print(f"    - Cert Scanner Error : FAILED ({e})")
        all_passed = False

    # 4. CycloneDX 1.6 CBOM Schema Audit
    print("\n[+] CBOM VALIDATION AUDIT (cbom.json):")
    cbom_path = os.path.join(os.getcwd(), "cbom.json")
    if os.path.exists(cbom_path):
        try:
            with open(cbom_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            bom_format = data.get("bomFormat")
            spec_version = data.get("specVersion")
            scope = data.get("metadata", {}).get("component", {}).get("scope")
            components = data.get("components", [])
            props = {p["name"]: p["value"] for p in data.get("metadata", {}).get("properties", [])}

            print(f"    - BOM Standard       : {bom_format} v{spec_version}")
            print(f"    - Scope Specification: {scope} (Valid Enum)")
            print(f"    - Inventory Elements : {len(components)} components")
            print(f"    - Vulnerable Assets  : {props.get('quantum_vulnerable_count', 'N/A')}")
            print(f"    - Critical Urgency   : {props.get('critical_urgency_count', 'N/A')}")

            # Strict format assertions
            assert bom_format == "CycloneDX", "Invalid BOM format"
            assert spec_version == "1.6", "Invalid spec version"
            assert scope in ["required", "optional", "excluded"], "Invalid scope enum"
            assert len(components) >= 5, "Component count mismatch"
            print(f"    - CycloneDX Schema   : PASSED (Compliant)")
        except Exception as e:
            print(f"    - Schema Validation  : FAILED ({e})")
            all_passed = False
    else:
        print(f"    - File cbom.json     : MISSING")
        all_passed = False

    print("\n" + "=" * 65)
    if all_passed:
        print("      STATUS: ALL PHASE 2 REQUIREMENTS VERIFIED & CONFIRMED")
    else:
        print("      STATUS: PHASE 2 AUDIT DETECTED WARNINGS/FAILURES")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_phase2_verification()