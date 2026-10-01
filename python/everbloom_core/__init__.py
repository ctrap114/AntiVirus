"""Python wrapper for the native EverbloomSecurity core extension.

This module tries to import the compiled Rust extension `libeverbloom_rs` and
provides a small helper to create a `YaraRuleEngine` instance from Python
with a clear error if the native extension isn't built/installed.
"""

import importlib
from typing import Any
from pathlib import Path

try:
    _native = importlib.import_module("libeverbloom_rs")
    _import_err = None
except Exception as e:
    _native = None
    _import_err = e

# Try to import python-yara as a pure-Python fallback
try:
    import yara  # type: ignore
    _pyyara = yara
except Exception:
    _pyyara = None


def _require_native():
    if _native is None:
        raise RuntimeError(
            "native extension 'libeverbloom_rs' not available. "
            "Build and install it (see python/everbloom_core/README.md).\n"
            f"Import error: {_import_err}"
        )
    return _native


def create_yara_engine(*args: Any, **kwargs: Any):
    """Return a `YaraRuleEngine` instance from the native extension.

    Usage:
        from everbloom_core import create_yara_engine
        eng = create_yara_engine()
    """
    # Prefer native extension
    if _native is not None:
        nat = _require_native()
        return nat.YaraRuleEngine(*args, **kwargs)

    # Fallback to python-yara implementation if available
    if _pyyara is not None:
        class PyYaraEngine:
            def __init__(self):
                self.rules = None

            def load_rules(self, source: str) -> bool:
                p = Path(source)
                try:
                    if p.exists():
                        self.rules = _pyyara.compile(filepath=str(p))
                    else:
                        # treat as rule text
                        self.rules = _pyyara.compile(source=source)
                    return True
                except Exception as e:
                    raise RuntimeError(f"failed to compile rules: {e}")

            def load_rules_from_string(self, rules_text: str) -> bool:
                try:
                    self.rules = _pyyara.compile(source=rules_text)
                    return True
                except Exception as e:
                    raise RuntimeError(f"failed to compile rules: {e}")

            def scan_bytes(self, buf: bytes):
                if self.rules is None:
                    raise RuntimeError("no rules loaded")
                try:
                    matches = self.rules.match(data=buf)
                    return {"count": len(matches), "matched_rules": [m.rule for m in matches]}
                except Exception as e:
                    raise RuntimeError(f"YARA scan failed: {e}")

            def scan_path(self, path: str):
                p = Path(path)
                if not p.exists():
                    raise FileNotFoundError("scan path does not exist")
                if self.rules is None:
                    raise RuntimeError("no rules loaded")
                try:
                    matches = self.rules.match(filepath=str(p))
                    return {"count": len(matches), "matched_rules": [m.rule for m in matches]}
                except Exception as e:
                    raise RuntimeError(f"YARA scan failed: {e}")

        return PyYaraEngine()

    # No available backend
    return _require_native()


# Expose the raw native module if needed
def get_native_module():
    return _require_native()
