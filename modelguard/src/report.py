import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.scanner import ScanResult


def to_dict(result: "ScanResult") -> dict:
    return {
        "file_path": result.file_path,
        "file_name": result.file_name,
        "file_size": result.file_size,
        "sha256": result.sha256,
        "scan_duration_ms": result.scan_duration_ms,
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "scanned_at": result.scanned_at.isoformat(),
        "layers_completed": result.layers_completed,
        "findings": [
            {
                "layer": f.layer,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
    }


def to_json(result: "ScanResult", indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def findings_summary(result: "ScanResult") -> dict:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in result.findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    return summary
