"""
Entry point for the ModelGuard web UI.

Run from the modelguard/ directory:
    python run.py

Then open http://localhost:8000 in your browser.
"""

import sys
from pathlib import Path

# Ensure the modelguard/ directory is on sys.path so all src.* imports resolve.
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "web.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
