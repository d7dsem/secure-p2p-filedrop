"""
`src/` не є Python-пакетом (модулі імпортують один одного напряму, напр.
`from tuning import CONNECTION`, без префіксу `src.`), тому тестові модулі
роблять `import _pathfix` першим рядком, щоб додати `src/` у sys.path до
того, як щось із нього імпортувати. Працює незалежно від того, як саме
запущено тести (`unittest discover` з/без `-t`, прямий запуск файлу тощо).
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
