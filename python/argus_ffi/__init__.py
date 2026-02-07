"""Python import package for argus_ffi (PyO3 extension)."""
from .argus_ffi import ArgusScanner, PyMatchRecord, ScanOptions, scan, scan_json  # type: ignore

__all__ = [
	"ArgusScanner",
	"PyMatchRecord",
	"ScanOptions",
	"scan",
	"scan_json",
]

__version__ = "1.1.0"
