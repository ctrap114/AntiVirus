#!/usr/bin/env python3
"""Wrapper for training the Transformer variant of EverbloomSecurity's AI engine."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    script = Path(__file__).with_name('train_ai_model.py')
    argv = [sys.executable, str(script), '--arch', 'transformer'] + sys.argv[1:]
    return subprocess.call(argv)


if __name__ == '__main__':
    raise SystemExit(main())
