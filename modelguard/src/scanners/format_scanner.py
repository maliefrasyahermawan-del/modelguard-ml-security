from pathlib import Path
from typing import List

MAGIC_SIGNATURES = {
    ".pkl":     [(0, b"\x80")],
    ".joblib":  [(0, b"\x80")],
    ".pt":      [(0, b"PK")],
    ".h5":      [(0, b"\x89HDF\r\n\x1a\n")],
    ".npy":     [(0, b"\x93NUMPY")],
}


class FormatScanner:
    def scan(self, path: Path) -> List:
        from src.scanner import Finding
        findings = []
        ext = path.suffix.lower()

        if ext == ".safetensors":
            findings.extend(self._check_safetensors(path))
            return findings

        if ext not in MAGIC_SIGNATURES:
            return findings

        expected = MAGIC_SIGNATURES[ext]
        with open(path, "rb") as f:
            header = f.read(16)

        for offset, magic in expected:
            chunk = header[offset: offset + len(magic)]
            if chunk != magic:
                findings.append(Finding(
                    layer="format",
                    severity="MEDIUM",
                    title="Magic bytes mismatch",
                    description=(
                        f"File extension is '{ext}' but magic bytes do not match expected signature. "
                        "The file may be disguised with the wrong extension."
                    ),
                    evidence=f"Expected {magic.hex()!r}, got {chunk.hex()!r}",
                ))
        return findings

    def _check_safetensors(self, path: Path) -> List:
        from src.scanner import Finding
        findings = []
        try:
            import json as _json
            with open(path, "rb") as f:
                size_bytes = f.read(8)
                if len(size_bytes) < 8:
                    raise ValueError("File too small for safetensors header")
                header_size = int.from_bytes(size_bytes, "little")
                if header_size > 100 * 1024 * 1024:
                    raise ValueError(f"Header size too large: {header_size}")
                header_data = f.read(header_size)
                _json.loads(header_data)
        except Exception as e:
            findings.append(Finding(
                layer="format",
                severity="MEDIUM",
                title="Invalid safetensors format",
                description="File does not have a valid safetensors JSON header.",
                evidence=str(e),
            ))
        return findings
