"""
Додає src/ у sys.path (src/ не є пакетом) — кожен тест робить `import _pathfix` першим рядком.
Докладніше: docs/dev-notes.md → "tests/_pathfix.py + tests/__init__.py".
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
