# ModelGuard — ML Model Security Scanner

> A defensive scanner that inspects serialized machine-learning model files for malicious payloads before they are loaded.

## What this project does

ModelGuard reduces supply-chain risk from downloaded `.pkl`, `.pt`, `.h5`, `.safetensors`, `.joblib`, and `.npy` artifacts. It examines a file without executing it, then returns a SAFE, SUSPICIOUS, or MALICIOUS verdict with a risk score and detailed findings.

## Core functions

- Validate file format against claimed extension and magic bytes.
- Inspect pickle bytecode for dangerous opcodes and callable references.
- Scan binary content with YARA rules for suspicious imports, reverse shells, encoded payloads, C2 indicators, and shellcode.
- Check entropy, embedded URLs/IPs, HDF5 metadata, and tensor anomalies.
- Provide CLI scanning, a web upload workflow, JSON reports, and local scan history.

## Architecture

```text
Model file → format validator → pickle bytecode analysis → YARA scanner → deep content scanner
                                                                         │
                                                                         ▼
                                                verdict + risk score → CLI | web report | JSON
```

## Technology and local run

Python, FastAPI, Jinja2, Fickling, YARA, optional ModelScan, and SQLite/Peewee.

```bash
cd modelguard
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python test_models/generate_test_models.py
python cli.py scan test_models/safe_model.pkl
python run.py
```

## Safety note

Never load an untrusted model merely to test it. Use ModelGuard as an additional screening layer in an isolated environment; it cannot guarantee detection of every malicious artifact.
