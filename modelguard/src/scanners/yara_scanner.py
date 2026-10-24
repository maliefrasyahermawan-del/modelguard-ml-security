from pathlib import Path
from typing import List

RULES_DIR = Path(__file__).parent.parent.parent / "rules"

RULE_SEVERITY = {
    "DetectReverseShell":     "CRITICAL",
    "DetectShellcode":        "CRITICAL",
    "DetectEncodedPowerShell": "HIGH",
    "SuspiciousImports":      "HIGH",
    "DetectC2Domain":         "HIGH",
    "DetectBase64Payload":    "MEDIUM",
}


class YaraScanner:
    def __init__(self):
        self._rules = None
        self._available = False
        self._error = None
        self._load()

    def _load(self):
        try:
            import yara
            rule_files = list(RULES_DIR.glob("*.yar"))
            if not rule_files:
                self._error = "No .yar rule files found in rules/"
                return
            filepaths = {f.stem: str(f) for f in rule_files}
            self._rules = yara.compile(filepaths=filepaths)
            self._available = True
        except ImportError:
            self._error = "yara-python not installed (pip install yara-python)"
        except Exception as e:
            self._error = str(e)

    def scan(self, path: Path) -> List:
        from src.scanner import Finding
        findings = []

        if not self._available:
            findings.append(Finding(
                "yara", "INFO",
                "YARA layer skipped",
                f"YARA is not available: {self._error}",
                "Install yara-python and YARA binary to enable this layer.",
            ))
            return findings

        try:
            import yara
            matches = self._rules.match(str(path))
            for match in matches:
                sev = RULE_SEVERITY.get(match.rule, "MEDIUM")
                instances = []
                for s in match.strings:
                    for inst in s.instances:
                        try:
                            val = inst.matched_data.decode("latin-1")[:60]
                        except Exception:
                            val = repr(inst.matched_data[:30])
                        instances.append(f"0x{inst.offset:X}: {s.identifier}={val!r}")
                findings.append(Finding(
                    "yara", sev,
                    f"YARA match: {match.rule}",
                    match.meta.get("description", f"Rule '{match.rule}' matched."),
                    "; ".join(instances[:5]) or "no string details",
                ))
        except Exception as e:
            findings.append(Finding(
                "yara", "INFO", "YARA scan error", str(e), ""
            ))

        return findings
