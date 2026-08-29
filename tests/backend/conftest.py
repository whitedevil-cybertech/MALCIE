import sys
from pathlib import Path

BACKEND_SRC = Path(__file__).resolve().parents[2] / "src" / "backend"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))
