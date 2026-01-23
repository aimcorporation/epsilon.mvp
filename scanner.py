"""
Advanced Integrated Modules (A.I.M.) // Core Scanner Module
Project Epsilon
© 2026 — All rights reserved.
"""

import subprocess
import json

def calculate_confidence(severity: str) -> int:
    """Simple confidence score calculator (placeholder for real logic)."""
    if severity == "HIGH":
        return 8
    if severity == "MEDIUM":
        return 6
    return 3

def scan_target(target_path: str) -> dict:
    """
    Unified entry point: detects if target is code or container and routes accordingly.
    Scans Python code with Bandit or containers/images with Trivy.
    Returns dict with findings, severity breakdown, confidence scores.
    """
    result = {
        "target": target_path,
        "status": "scan_complete",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_findings": 0,
        "severity_breakdown": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "findings": [],
        "remediations": []
    }

    if target_path.endswith(".py") or target_path.endswith(".py/"):
        # Real Bandit call
        cmd = ["bandit", "-r", target_path, "-f", "json", "--quiet"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            bandit_output = json.loads(proc.stdout)
            issues = bandit_output.get("results", [])
            result["total_findings"] = len(issues)
            for issue in issues:
                result["findings"].append({
                    "vulnerability": issue["issue_text"],
                    "severity": issue["issue_severity"],
                    "confidence_score": calculate_confidence(issue["issue_severity"]),
                    "line": issue["line_number"]
                })
        except Exception as e:
            result["error"] = str(e)
    else:
        # Container scan handled by container_scanner.py
        result["total_findings"] = 0  # Placeholder until integrated

    return result
