import math
import re
from pathlib import Path
from typing import List

URL_RE = re.compile(rb"https?://[^\s\x00-\x1f\x7f-\xff]{10,}")
IP_RE  = re.compile(rb"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
SUSPICIOUS_DOMAIN_RE = re.compile(
    rb"(?:\.onion|\.bit|\.i2p|pastebin\.com|ngrok\.io|serveo\.net|"
    rb"dyndns\.org|no-ip\.org|ddns\.net|freeddns)",
    re.IGNORECASE,
)

BLOCK_SIZE = 1024
HIGH_ENTROPY = 7.5


class DeepScanner:
    def scan(self, path: Path) -> List:
        with open(path, "rb") as f:
            data = f.read()

        findings = []
        findings.extend(self._entropy_check(data))
        findings.extend(self._string_check(data))
        findings.extend(self._modelscan_check(path))

        ext = path.suffix.lower()
        if ext == ".h5":
            findings.extend(self._h5_check(path))
        elif ext in (".pt", ".safetensors"):
            findings.extend(self._tensor_check(path, ext))

        return findings

    # ------------------------------------------------------------------
    def _entropy(self, block: bytes) -> float:
        if not block:
            return 0.0
        counts = [0] * 256
        for b in block:
            counts[b] += 1
        n = len(block)
        return -sum((c / n) * math.log2(c / n) for c in counts if c > 0)

    def _entropy_check(self, data: bytes) -> List:
        from src.scanner import Finding
        high = total = 0
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i: i + BLOCK_SIZE]
            if len(block) < 64:
                continue
            total += 1
            if self._entropy(block) > HIGH_ENTROPY:
                high += 1
        if total == 0:
            return []
        ratio = high / total
        if ratio > 0.5:
            return [Finding(
                "deep", "MEDIUM",
                "High-entropy content detected",
                (
                    f"{high}/{total} 1KB blocks have Shannon entropy > {HIGH_ENTROPY}. "
                    "This is consistent with encrypted or compressed payloads hidden inside the file."
                ),
                f"High-entropy ratio: {ratio:.1%}",
            )]
        return []

    def _string_check(self, data: bytes) -> List:
        from src.scanner import Finding
        findings = []

        urls = URL_RE.findall(data)
        if urls:
            decoded = [u.decode("ascii", errors="ignore") for u in urls[:10]]
            findings.append(Finding(
                "deep", "MEDIUM",
                "URLs embedded in model file",
                "Model file contains hardcoded URLs. May indicate C2 callback or data exfiltration.",
                "; ".join(decoded[:5]),
            ))

        if SUSPICIOUS_DOMAIN_RE.search(data):
            matches = SUSPICIOUS_DOMAIN_RE.findall(data)
            domains = [m.decode("ascii", errors="ignore") for m in matches[:5]]
            findings.append(Finding(
                "deep", "HIGH",
                "Suspicious domain references found",
                "Model references domains commonly used for C2 communication or anonymization.",
                ", ".join(domains),
            ))

        for m in IP_RE.finditer(data):
            parts = [int(m.group(i)) for i in range(1, 5)]
            if all(0 <= p <= 255 for p in parts):
                ip = ".".join(str(p) for p in parts)
                if not (ip.startswith("127.") or ip.startswith("0.") or ip == "255.255.255.255"):
                    findings.append(Finding(
                        "deep", "LOW",
                        "IP address found in model file",
                        "Hardcoded IP addresses may indicate C2 infrastructure.",
                        ip,
                    ))
                    break  # report once

        return findings

    def _modelscan_check(self, path: Path) -> List:
        from src.scanner import Finding
        findings = []
        try:
            from modelscan.modelscan import ModelScan
            ms = ModelScan()
            result = ms.scan(path)
            for issue in getattr(result, "issues", []) or []:
                findings.append(Finding(
                    "deep", "HIGH",
                    f"modelscan: {getattr(issue, 'code', 'ISSUE')}",
                    str(getattr(issue, "description", issue)),
                    str(issue),
                ))
        except ImportError:
            pass
        except Exception:
            pass
        return findings

    def _h5_check(self, path: Path) -> List:
        from src.scanner import Finding
        findings = []
        try:
            import h5py
            keys = []
            with h5py.File(str(path), "r") as f:
                f.visit(lambda k: keys.append(k))
            bad = [k for k in keys if any(
                kw in k.lower() for kw in ("exec", "eval", "shell", "cmd", "payload", "code")
            )]
            if bad:
                findings.append(Finding(
                    "deep", "HIGH",
                    "Suspicious HDF5 dataset names",
                    "HDF5 file contains dataset keys with suspicious names.",
                    ", ".join(bad[:5]),
                ))
        except ImportError:
            pass
        except Exception:
            pass
        return findings

    def _tensor_check(self, path: Path, ext: str) -> List:
        from src.scanner import Finding
        findings = []
        try:
            if ext == ".safetensors":
                from safetensors import safe_open
                with safe_open(str(path), framework="pt") as f:
                    for key in f.keys():
                        tensor = f.get_tensor(key)
                        shape = list(tensor.shape)
                        if len(shape) == 1 and shape[0] > 10_000_000:
                            findings.append(Finding(
                                "deep", "LOW",
                                "Unusually large 1-D tensor",
                                f"Tensor '{key}' is a huge 1-D vector which may conceal arbitrary data.",
                                f"Shape: {shape}",
                            ))
        except ImportError:
            pass
        except Exception:
            pass
        return findings
