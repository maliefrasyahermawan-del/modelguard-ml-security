import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List


@dataclass
class Finding:
    layer: str       # "format" | "pickle" | "yara" | "deep"
    severity: str    # "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    title: str
    description: str
    evidence: str


@dataclass
class ScanResult:
    file_path: str
    file_name: str
    file_size: int
    sha256: str
    scan_duration_ms: int
    verdict: str       # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
    risk_score: int    # 0-100
    findings: List[Finding]
    scanned_at: datetime
    layers_completed: List[str]


_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _compute_verdict(findings: List[Finding]):
    if not findings:
        return "SAFE", 5

    max_sev = max((_SEVERITY_RANK.get(f.severity, 0) for f in findings), default=0)
    count = len(findings)

    if max_sev >= 5:  # CRITICAL
        high_count = sum(1 for f in findings if _SEVERITY_RANK.get(f.severity, 0) >= 4)
        risk = min(100, 90 + min(high_count * 2, 10))
        return "MALICIOUS", risk
    elif max_sev == 4:  # HIGH, no CRITICAL
        med_count = sum(1 for f in findings if _SEVERITY_RANK.get(f.severity, 0) >= 3)
        risk = min(89, 60 + min(med_count * 5, 29))
        return "SUSPICIOUS", risk
    elif max_sev == 3:  # MEDIUM
        risk = min(59, 30 + min(count * 5, 29))
        return "SUSPICIOUS", risk
    else:
        risk = min(29, count * 3)
        return "SAFE", risk


class ModelScanner:
    SUPPORTED_EXTENSIONS = {'.pkl', '.pt', '.h5', '.safetensors', '.joblib', '.npy'}

    def __init__(self):
        from src.scanners.format_scanner import FormatScanner
        from src.scanners.pickle_scanner import PickleScanner
        from src.scanners.yara_scanner import YaraScanner
        from src.scanners.deep_scanner import DeepScanner
        self._format = FormatScanner()
        self._pickle = PickleScanner()
        self._yara = YaraScanner()
        self._deep = DeepScanner()

    def scan(self, file_path: str) -> ScanResult:
        path = Path(file_path)
        start = time.time()
        file_size = path.stat().st_size
        sha256 = self._sha256(path)
        findings: List[Finding] = []
        layers_completed: List[str] = []

        # Layer 1 — Format
        try:
            findings.extend(self._format.scan(path))
        except Exception as e:
            findings.append(Finding("format", "LOW", "Format scanner error", str(e), ""))
        layers_completed.append("format")

        # Layer 2 — Pickle (only for pickle-based formats)
        if path.suffix.lower() in {'.pkl', '.pt', '.joblib'}:
            try:
                findings.extend(self._pickle.scan(path))
            except Exception as e:
                findings.append(Finding("pickle", "LOW", "Pickle scanner error", str(e), ""))
        layers_completed.append("pickle")

        # Layer 3 — YARA
        try:
            findings.extend(self._yara.scan(path))
        except Exception as e:
            findings.append(Finding("yara", "INFO", "YARA scanner error", str(e), ""))
        layers_completed.append("yara")

        # Layer 4 — Deep
        try:
            findings.extend(self._deep.scan(path))
        except Exception as e:
            findings.append(Finding("deep", "LOW", "Deep scanner error", str(e), ""))
        layers_completed.append("deep")

        duration_ms = int((time.time() - start) * 1000)
        verdict, risk_score = _compute_verdict(findings)

        return ScanResult(
            file_path=str(path.resolve()),
            file_name=path.name,
            file_size=file_size,
            sha256=sha256,
            scan_duration_ms=duration_ms,
            verdict=verdict,
            risk_score=risk_score,
            findings=findings,
            scanned_at=datetime.utcnow(),
            layers_completed=layers_completed,
        )

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
