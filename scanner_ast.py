# scanner_ast.py
import ast
import os
import re
from typing import Any, Dict, List


class CryptoASTVisitor(ast.NodeVisitor):
    """Parses Abstract Syntax Trees to identify cryptographic API calls."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call):
        # 1. Inspect hashlib invocations (hashlib.md5, hashlib.sha1, hashlib.new(...))
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

            # Case: hashlib.md5(...) or hashlib.sha1(...)
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if func_name.lower() in ["md5", "sha1"]:
                    self.findings.append({
                        "asset_type": "Source Code Function Call",
                        "location": f"{self.filepath}:{node.lineno}",
                        "primitive_family": "Hash Function",
                        "algorithm": func_name.upper(),
                        "key_size_or_curve": "N/A",
                        "quantum_safe": False,
                        "vulnerability_type": "Classical Deprecation",
                        "migration_urgency": "Medium"
                    })

            # Case: rsa.generate_private_key(...)
            elif func_name == "generate_private_key":
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "rsa":
                        key_size = 2048  # Default baseline
                        for kw in node.keywords:
                            if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                                key_size = kw.value.value

                        self.findings.append({
                            "asset_type": "Source Code Key Generation",
                            "location": f"{self.filepath}:{node.lineno}",
                            "primitive_family": "Asymmetric Cryptography",
                            "algorithm": "RSA",
                            "key_size_or_curve": str(key_size),
                            "quantum_safe": False,
                            "vulnerability_type": "Shor's Algorithm (Vulnerable to CRQC)",
                            "migration_urgency": "Critical"
                        })

                    # Case: ec.generate_private_key(ec.SECP256R1())
                    elif node.func.value.id == "ec":
                        curve_name = "ECC"
                        if node.args and isinstance(node.args[0], ast.Call):
                            if isinstance(node.args[0].func, ast.Attribute):
                                curve_name = node.args[0].func.attr

                        self.findings.append({
                            "asset_type": "Source Code Key Generation",
                            "location": f"{self.filepath}:{node.lineno}",
                            "primitive_family": "Asymmetric Cryptography",
                            "algorithm": "ECC",
                            "key_size_or_curve": curve_name,
                            "quantum_safe": False,
                            "vulnerability_type": "Shor's Algorithm (Vulnerable to CRQC)",
                            "migration_urgency": "Critical"
                        })

        self.generic_visit(node)


def scan_source_files(target_dir: str) -> List[Dict[str, Any]]:
    """Traverses Python files using AST parsing with Regex fallback."""
    findings = []
    
    # Regex fallback for non-standard or raw string imports
    legacy_patterns = [
        (re.compile(r"DES\.new\(|AES_128|Blowfish"), "Legacy Block Cipher", "DES/Blowfish", "Symmetric", "High"),
        (re.compile(r"hashlib\.new\(['\"](md5|sha1)['\"]"), "Hash Function", "MD5/SHA1", "Hash", "Medium")
    ]

    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        content = f.read()

                    # 1. AST Parsing
                    tree = ast.parse(content, filename=full_path)
                    visitor = CryptoASTVisitor(full_path)
                    visitor.visit(tree)
                    findings.extend(visitor.findings)

                    # 2. Regex Parsing for inline patterns
                    for line_idx, line in enumerate(content.splitlines(), start=1):
                        for pattern, prim_family, alg, vuln, urgency in legacy_patterns:
                            if pattern.search(line):
                                findings.append({
                                    "asset_type": "Regex Match",
                                    "location": f"{full_path}:{line_idx}",
                                    "primitive_family": prim_family,
                                    "algorithm": alg,
                                    "key_size_or_curve": "Unknown",
                                    "quantum_safe": False,
                                    "vulnerability_type": vuln,
                                    "migration_urgency": urgency
                                })

                except Exception as err:
                    print(f"[-] Error scanning {full_path}: {err}")

    return findings


if __name__ == "__main__":
    test_dir = os.path.join(os.getcwd(), "testbed_repo")
    results = scan_source_files(test_dir)
    print(f"[+] Static scan complete. Identified {len(results)} source items.")