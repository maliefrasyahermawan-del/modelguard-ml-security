import contextlib
import io
import pickletools
import re
import sys
from pathlib import Path
from typing import List, Tuple

# ML framework modules that are safe to instantiate from pickle
SAFE_MODULE_PREFIXES = (
    "sklearn", "scipy", "pandas", "torch", "tensorflow",
    "keras", "xgboost", "lightgbm", "catboost", "joblib",
    "numpy", "_codecs", "copyreg", "copy_reg",
    "collections", "_collections", "_abc", "abc", "io",
    # Specific builtins that are harmless in pickle reconstruction context
    "builtins.object", "builtins.type", "builtins.super",
    "builtins.slice", "builtins.tuple", "builtins.list",
    "builtins.dict", "builtins.set", "builtins.frozenset",
    "builtins.int", "builtins.float", "builtins.str",
    "builtins.bytes", "builtins.bool", "builtins.complex",
    "builtins.bytearray", "builtins.memoryview", "builtins.range",
)

# (module_prefix, func_name, severity)  —  empty func_name = any func in module
DANGEROUS_PAIRS: List[Tuple[str, str, str]] = [
    ("os",          "system",        "CRITICAL"),
    ("os",          "popen",         "CRITICAL"),
    ("os",          "execv",         "CRITICAL"),
    ("os",          "execve",        "CRITICAL"),
    ("nt",          "system",        "CRITICAL"),
    ("nt",          "popen",         "CRITICAL"),
    ("posix",       "system",        "CRITICAL"),
    ("posix",       "popen",         "CRITICAL"),
    ("subprocess",  "call",          "CRITICAL"),
    ("subprocess",  "run",           "CRITICAL"),
    ("subprocess",  "Popen",         "CRITICAL"),
    ("subprocess",  "check_output",  "CRITICAL"),
    ("builtins",    "eval",          "CRITICAL"),
    ("builtins",    "exec",          "CRITICAL"),
    ("builtins",    "__import__",    "CRITICAL"),
    ("builtins",    "compile",       "HIGH"),
    ("builtins",    "print",         "CRITICAL"),  # never in legit ML pickle
    ("builtins",    "open",          "HIGH"),
    ("builtins",    "input",         "HIGH"),
    ("builtins",    "vars",          "MEDIUM"),
    ("builtins",    "locals",        "MEDIUM"),
    ("builtins",    "globals",       "MEDIUM"),
    ("socket",      "",              "HIGH"),
    ("ctypes",      "",              "HIGH"),
    ("importlib",   "import_module", "HIGH"),
    ("sys",         "exit",          "HIGH"),
    ("sys",         "modules",       "MEDIUM"),
    ("sys",         "path",          "MEDIUM"),
]

RAW_BYTE_PATTERNS = [
    (b"os.system",       "HIGH"),
    (b"subprocess",      "HIGH"),
    (b"__import__",      "HIGH"),
    (b"exec(",           "MEDIUM"),
    (b"eval(",           "MEDIUM"),
    (b"compile(",        "MEDIUM"),
    (b"socket.connect",  "HIGH"),
    (b"reverse_shell",   "HIGH"),
]

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class PickleScanner:
    def scan(self, path: Path) -> List:
        from src.scanner import Finding
        try:
            data = path.read_bytes()
        except Exception as e:
            return [Finding("pickle", "LOW", "Cannot read file", str(e), "")]

        findings = []
        for stream in self._extract_streams(data, path.suffix.lower()):
            findings.extend(self._analyze(stream))
        return findings

    # ── stream extraction ──────────────────────────────────────────────
    def _extract_streams(self, data: bytes, ext: str) -> List[bytes]:
        if ext in (".pkl", ".joblib"):
            return [data]
        if ext == ".pt":
            try:
                import zipfile
                streams = []
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for name in zf.namelist():
                        raw = zf.read(name)
                        if raw[:1] in (b"\x80", b"c", b"("):
                            streams.append(raw)
                return streams or [data]
            except Exception:
                return [data]
        return [data]

    # ── main analysis ──────────────────────────────────────────────────
    def _analyze(self, data: bytes) -> List:
        from src.scanner import Finding
        findings: List[Finding] = []

        # 1. Disassemble — use redirect_stdout for compatibility (Python 3.14
        #    removed the output= kwarg from pickletools.dis)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                pickletools.dis(data)
            disasm = buf.getvalue()
        except Exception as e:
            findings.append(Finding(
                "pickle", "MEDIUM",
                "Pickle disassembly failed",
                "Could not disassemble the pickle stream — may be malformed or obfuscated.",
                str(e),
            ))
            return findings

        has_reduce = "REDUCE" in disasm
        has_stack_global = "STACK_GLOBAL" in disasm

        # 2. Extract module.name pairs from both opcode styles
        pairs = self._extract_global_pairs(disasm)

        # 3. Check each pair against dangerous list
        for mod_name in pairs:
            for d_mod, d_func, severity in DANGEROUS_PAIRS:
                expected = f"{d_mod}.{d_func}" if d_func else None
                mod_match = (
                    mod_name == expected
                    or (not d_func and mod_name.startswith(d_mod + "."))
                    or (not d_func and mod_name == d_mod)
                )
                if mod_match:
                    label = f"{d_mod}.{d_func}" if d_func else d_mod
                    findings.append(Finding(
                        "pickle", severity,
                        f"Dangerous callable in pickle: {label}",
                        (
                            f"Pickle stream contains a reference to '{label}' "
                            "which executes code when the model is loaded."
                        ),
                        f"Global reference: {mod_name}",
                    ))

        # 4. REDUCE/STACK_GLOBAL + non-whitelisted callable → CRITICAL
        if has_reduce or has_stack_global:
            unsafe = [
                p for p in pairs
                if not any(p.startswith(prefix) for prefix in SAFE_MODULE_PREFIXES)
                # Skip pairs already caught by DANGEROUS_PAIRS above
                and not any(
                    p == f"{d_mod}.{d_func}" or (not d_func and p.startswith(d_mod + "."))
                    for d_mod, d_func, _ in DANGEROUS_PAIRS
                )
            ]
            already_critical = any(f.severity == "CRITICAL" for f in findings)
            if unsafe and not already_critical:
                findings.append(Finding(
                    "pickle", "CRITICAL",
                    "__reduce__ with non-whitelisted callable",
                    (
                        "Model uses __reduce__ deserialization with a callable outside "
                        "known ML framework modules. This is the primary attack vector "
                        "for pickle malware."
                    ),
                    "Unrecognized globals: " + ", ".join(unsafe[:5]),
                ))
            elif unsafe:
                findings.append(Finding(
                    "pickle", "HIGH",
                    "__reduce__ method with custom callable",
                    "Model serialization uses __reduce__ with a non-standard callable.",
                    "Unrecognized globals: " + ", ".join(unsafe[:5]),
                ))

        # 5. Raw byte pattern scan (catches strings embedded in data arguments)
        for pattern, severity in RAW_BYTE_PATTERNS:
            if pattern in data:
                offset = data.index(pattern)
                findings.append(Finding(
                    "pickle", severity,
                    f"Suspicious string in pickle data: {pattern.decode('latin-1')}",
                    f"The string '{pattern.decode('latin-1')}' is embedded directly in the pickle stream.",
                    f"Offset 0x{offset:X}",
                ))

        # 6. fickling AST (best-effort, may not be installed)
        findings.extend(self._fickling_check(data))

        return findings

    # ── global pair extraction ─────────────────────────────────────────
    def _extract_global_pairs(self, disasm: str) -> List[str]:
        """Return list of 'module.name' strings from GLOBAL and STACK_GLOBAL opcodes."""
        pairs = []
        lines = disasm.splitlines()

        for i, line in enumerate(lines):
            # Protocol ≤2: GLOBAL 'module name' on one line
            m = re.search(r"\bGLOBAL\s+'([^']+)'", line)
            if m:
                ref = m.group(1)
                parts = ref.split(None, 1)
                pairs.append(f"{parts[0]}.{parts[1]}" if len(parts) == 2 else parts[0])
                continue

            # Protocol ≥4: two string pushes immediately before STACK_GLOBAL
            if "STACK_GLOBAL" in line:
                strings = []
                j = i - 1
                while j >= 0 and len(strings) < 2:
                    prev = lines[j]
                    ms = re.search(
                        r'(?:SHORT_BINUNICODE|BINUNICODE|SHORT_BINSTRING|BINSTRING)\s+\'([^\']+)\'',
                        prev,
                    )
                    if ms:
                        strings.insert(0, ms.group(1))
                    elif re.search(r'\b(MEMOIZE|BINPUT|FRAME)\b', prev):
                        pass  # skip memo/frame opcodes, keep searching
                    else:
                        break  # any other opcode means these aren't our strings
                    j -= 1
                if len(strings) == 2:
                    pairs.append(f"{strings[0]}.{strings[1]}")

        return pairs

    # ── fickling ──────────────────────────────────────────────────────
    def _fickling_check(self, data: bytes) -> List:
        from src.scanner import Finding
        findings = []
        try:
            import fickling.pickle as fpickle
            pkl = fpickle.Pickled.load(io.BytesIO(data))
            ast_str = str(pkl.ast)
            for bad, sev in [
                ("os.system",  "CRITICAL"),
                ("subprocess", "CRITICAL"),
                ("eval(",      "CRITICAL"),
                ("exec(",      "CRITICAL"),
                ("__import__", "HIGH"),
            ]:
                if bad in ast_str:
                    findings.append(Finding(
                        "pickle", sev,
                        f"fickling AST: {bad} detected",
                        f"fickling static analysis found '{bad}' in the pickle AST.",
                        ast_str[:300],
                    ))
        except ImportError:
            pass
        except Exception:
            pass
        return findings
