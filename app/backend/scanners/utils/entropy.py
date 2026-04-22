"""ファイルまたはバイト列のエントロピー（情報量）を計算"""

import math
from collections import Counter
from pathlib import Path


def calc_entropy(data: bytes) -> float:
    """Shannon entropy を計算（0.0〜8.0）"""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def file_entropy(file_path: Path) -> float:
    return calc_entropy(file_path.read_bytes())
