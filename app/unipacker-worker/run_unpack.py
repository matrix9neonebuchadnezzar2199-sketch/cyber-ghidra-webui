"""Headless unipacker run for subprocess timeout isolation."""
from __future__ import annotations

import sys
from pathlib import Path

from unipacker.core import Sample
from unipacker.io_handler import IOHandler


def main() -> None:
    if len(sys.argv) != 3:
        print("usage: run_unpack.py <input_pe> <dest_dir>", file=sys.stderr)
        sys.exit(1)
    input_path = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    samples = list(Sample.get_samples(str(input_path), interactive=False))
    if not samples:
        sys.exit(2)
    IOHandler(samples, str(out_dir), False)


if __name__ == "__main__":
    main()
