"""
ModelGuard CLI

Usage:
    python cli.py scan <file>             Scan a model file
    python cli.py scan <file> --verbose   Scan with full finding details
    python cli.py history                 Show last 10 scans from DB
    python cli.py generate-test           Generate test_models/*.pkl fixtures
"""

import sys
import os
from pathlib import Path

# Force UTF-8 output on Windows so unicode symbols render correctly
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Ensure project root is on path when run as `python cli.py` from modelguard/
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ── colour helpers (Windows-safe) ────────────────────────────────────
try:
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(
        ctypes.windll.kernel32.GetStdHandle(-11), 7
    )
    _COLOUR = True
except Exception:
    _COLOUR = os.name != "nt"

_C = {
    "red":    "\033[91m" if _COLOUR else "",
    "orange": "\033[93m" if _COLOUR else "",
    "green":  "\033[92m" if _COLOUR else "",
    "cyan":   "\033[96m" if _COLOUR else "",
    "bold":   "\033[1m"  if _COLOUR else "",
    "reset":  "\033[0m"  if _COLOUR else "",
    "grey":   "\033[90m" if _COLOUR else "",
}

SEV_COLOUR = {
    "CRITICAL": _C["red"],
    "HIGH":     _C["orange"],
    "MEDIUM":   "\033[33m" if _COLOUR else "",
    "LOW":      "\033[34m" if _COLOUR else "",
    "INFO":     _C["grey"],
}

VERDICT_COLOUR = {
    "MALICIOUS":  _C["red"],
    "SUSPICIOUS": _C["orange"],
    "SAFE":       _C["green"],
}

VERDICT_ICON = {
    "MALICIOUS":  "⛔",
    "SUSPICIOUS": "⚠️ ",
    "SAFE":       "✅",
}

LAYER_NAMES = {
    "format": "Format Validator",
    "pickle": "Pickle Analyzer ",
    "yara":   "YARA Scanner    ",
    "deep":   "Deep Content    ",
}

SEP = "=" * 62


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{_C['reset']}"


# ── scan command ─────────────────────────────────────────────────────
def cmd_scan(file_path: str, verbose: bool = False):
    path = Path(file_path)
    if not path.exists():
        print(f"Error: file not found: {file_path}")
        sys.exit(1)

    from src.scanner import ModelScanner
    from src.database import init_db, save_scan

    init_db()
    scanner = ModelScanner()

    print()
    print(_c(_C["bold"], SEP))
    print(_c(_C["bold"], "  ModelGuard Scanner v1.0"))
    print(_c(_C["bold"], SEP))
    print(f"  File    : {path.name}")
    print(f"  Size    : {path.stat().st_size:,} bytes")

    result = scanner.scan(str(path))

    print(f"  SHA256  : {result.sha256[:16]}…{result.sha256[-8:]}")
    print()

    # Layer summary
    layers = ["format", "pickle", "yara", "deep"]
    for layer in layers:
        layer_findings = [f for f in result.findings if f.layer == layer]
        severe = [f for f in layer_findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
        name = LAYER_NAMES.get(layer, layer)
        if severe:
            worst = max(severe, key=lambda f: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(f.severity, 0))
            count = len(severe)
            colour = SEV_COLOUR.get(worst.severity, "")
            marker = _c(colour, f"✗ FOUND {count} {worst.severity} finding{'s' if count > 1 else ''}")
        else:
            marker = _c(_C["green"], "✓ PASS")
        print(f"  [Layer {layers.index(layer)+1}] {name}  {marker}")

    print()
    print(_c(_C["bold"], SEP))

    vc = VERDICT_COLOUR.get(result.verdict, "")
    vi = VERDICT_ICON.get(result.verdict, "")
    print(f"  {_C['bold']}VERDICT    : {_c(vc, vi + ' ' + result.verdict)}{_C['reset']}")

    score = result.risk_score
    sc = _C["red"] if score >= 60 else (_C["orange"] if score >= 30 else _C["green"])
    print(f"  {_C['bold']}RISK SCORE : {_c(sc, str(score))}/100{_C['reset']}")
    print(f"  Duration  : {result.scan_duration_ms} ms")
    print()

    # Findings
    sorted_findings = sorted(
        result.findings,
        key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 5),
    )

    if sorted_findings:
        print("  FINDINGS:")
        for f in sorted_findings:
            sc2 = SEV_COLOUR.get(f.severity, "")
            tag = _c(sc2, f"[{f.severity}]")
            print(f"  {tag:<30} {f.title}")
            if verbose or f.severity in ("CRITICAL", "HIGH"):
                print(f"  {_C['grey']}           {f.description}{_C['reset']}")
            if f.evidence:
                print(f"  {_C['grey']}           Evidence: {f.evidence[:120]}{_C['reset']}")
            print()
    else:
        print(f"  {_c(_C['green'], 'No findings — file appears clean.')}")
        print()

    print(_c(_C["bold"], SEP))
    print()

    # Save to DB
    try:
        scan_id = save_scan(result)
        print(f"  Scan saved to database (ID: {scan_id})")
        print(f"  Web report: http://localhost:8000/report/{scan_id}")
    except Exception as e:
        print(f"  [warn] Could not save to database: {e}")
    print()


# ── history command ──────────────────────────────────────────────────
def cmd_history():
    from src.database import init_db, get_recent_scans
    init_db()
    scans = get_recent_scans(10)
    if not scans:
        print("No scan history found. Run: python cli.py scan <file>")
        return

    print()
    print(_c(_C["bold"], SEP))
    print(_c(_C["bold"], "  ModelGuard — Scan History (last 10)"))
    print(_c(_C["bold"], SEP))
    fmt = "  {:<4}  {:<28}  {:<12}  {:>5}  {}"
    print(_c(_C["grey"], fmt.format("ID", "Filename", "Verdict", "Risk", "Scanned At")))
    print(_c(_C["grey"], "  " + "-" * 58))
    for s in scans:
        vc = VERDICT_COLOUR.get(s["verdict"], "")
        vi = VERDICT_ICON.get(s["verdict"], "")
        verdict_str = _c(vc, f"{vi} {s['verdict']}")
        name = s["file_name"][:26] + ".." if len(s["file_name"]) > 28 else s["file_name"]
        ts = s["scanned_at"][:16].replace("T", " ")
        print(fmt.format(s["id"], name, verdict_str, f"{s['risk_score']}/100", ts))
    print()


# ── generate-test command ────────────────────────────────────────────
def cmd_generate_test():
    import subprocess
    script = ROOT / "test_models" / "generate_test_models.py"
    if not script.exists():
        print(f"Error: {script} not found")
        sys.exit(1)
    result = subprocess.run([sys.executable, str(script)], cwd=str(ROOT))
    sys.exit(result.returncode)


# ── entry point ──────────────────────────────────────────────────────
def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    cmd = args[0]

    if cmd == "scan":
        if len(args) < 2:
            print("Usage: python cli.py scan <file_path> [--verbose]")
            sys.exit(1)
        verbose = "--verbose" in args or "-v" in args
        cmd_scan(args[1], verbose=verbose)

    elif cmd == "history":
        cmd_history()

    elif cmd == "generate-test":
        cmd_generate_test()

    else:
        print(f"Unknown command: {cmd}")
        print("Commands: scan, history, generate-test")
        sys.exit(1)


if __name__ == "__main__":
    main()
