# ModelGuard

ML Model Security Scanner — detects malicious payloads hidden inside `.pkl`, `.pt`, `.h5`, `.safetensors`, `.joblib`, and `.npy` files before they are loaded.

## Why this exists

When an ML model is loaded with `pickle.load()`, Python automatically executes any callable referenced by the pickle `REDUCE` opcode. This means a `.pkl` file downloaded from the internet can silently run `os.system()`, spawn a reverse shell, or exfiltrate data the moment your team calls `model = joblib.load("model.pkl")`.

ModelGuard scans model files through a 4-layer pipeline before they are used.

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> **Windows YARA note:** YARA must be installed separately for Layer 3 to activate.
> The scanner runs fine without it but skips Layer 3 with a warning.
>
> ```powershell
> choco install yara   # Windows
> # or
> apt install yara     # Debian/Ubuntu
> ```

### 2. Generate test models

```bash
python test_models/generate_test_models.py
```

### 3. Run CLI scans

```bash
# Should print: VERDICT: SAFE
python cli.py scan test_models/safe_model.pkl

# Should print: VERDICT: MALICIOUS | RISK: 91+/100
python cli.py scan test_models/malicious_model.pkl

# Should print: VERDICT: SUSPICIOUS
python cli.py scan test_models/suspicious_model.pkl
```

### 4. Start the Web UI

```bash
python run.py
```

Open **http://localhost:8000** — drag & drop any model file to scan it and view the full report.

---

## Architecture

```
[Upload / CLI arg]
       │
       ▼
[Layer 1] Format Validator     — magic bytes vs. claimed extension
       │
       ▼
[Layer 2] Pickle Bytecode Analyzer — GLOBAL / REDUCE / STACK_GLOBAL opcode inspection
       │                             fickling AST analysis
       ▼
[Layer 3] YARA Rule Scanner    — binary pattern matching (5 rule files)
       │
       ▼
[Layer 4] Deep Content Scanner — Shannon entropy, embedded URLs/IPs,
                                  HDF5 metadata, tensor shape anomalies,
                                  modelscan (if installed)
       │
       ▼
[Report] SAFE / SUSPICIOUS / MALICIOUS + per-finding detail
```

### Verdict rules

| Highest severity found | Verdict    | Risk score |
|------------------------|------------|------------|
| CRITICAL               | MALICIOUS  | 90 – 100   |
| HIGH (no CRITICAL)     | SUSPICIOUS | 60 – 89    |
| MEDIUM (no HIGH)       | SUSPICIOUS | 30 – 59    |
| LOW / INFO only        | SAFE       | 0 – 29     |

---

## Project Layout

```
modelguard/
├── src/
│   ├── scanner.py          # Orchestrator — runs all 4 layers, returns ScanResult
│   ├── report.py           # JSON serialisation helpers
│   ├── database.py         # SQLite scan history (auto-created on first run)
│   └── scanners/
│       ├── format_scanner.py   # Layer 1
│       ├── pickle_scanner.py   # Layer 2
│       ├── yara_scanner.py     # Layer 3
│       └── deep_scanner.py     # Layer 4
├── rules/                  # YARA rule files
├── web/                    # FastAPI app + Jinja2 templates
├── test_models/            # Test fixtures + generator script
├── uploads/                # Temporary scan uploads (auto-created)
├── cli.py                  # Command-line interface
├── run.py                  # Uvicorn web server entry point
└── requirements.txt
```

---

## CLI Reference

```bash
python cli.py scan <file>              # scan a file
python cli.py scan <file> --verbose    # scan with full finding details
python cli.py history                  # show last 10 scans from database
python cli.py generate-test            # regenerate test_models/*.pkl
```

## Web API

| Endpoint             | Method | Description                    |
|----------------------|--------|--------------------------------|
| `/`                  | GET    | Upload page + scan history     |
| `/scan`              | POST   | Upload & scan file             |
| `/report/{id}`       | GET    | HTML report for scan ID        |
| `/report/{id}/json`  | GET    | JSON report for scan ID        |

---

## YARA Rules

| File                    | Rule                   | Severity |
|-------------------------|------------------------|----------|
| suspicious_imports.yar  | SuspiciousImports      | HIGH     |
| reverse_shell.yar       | DetectReverseShell     | CRITICAL |
| encoded_payload.yar     | DetectBase64Payload    | MEDIUM   |
| encoded_payload.yar     | DetectEncodedPowerShell| HIGH     |
| c2_indicators.yar       | DetectC2Domain         | HIGH     |
| shellcode.yar           | DetectShellcode        | CRITICAL |

---

## Supported File Types

`.pkl` `.pt` `.h5` `.safetensors` `.joblib` `.npy`
