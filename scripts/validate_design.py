"""Run the historical checker without rewriting the preserved design package."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    source = Path(__file__).resolve().parents[1] / "docs" / "design"
    with tempfile.TemporaryDirectory(prefix="tfir-design-check-") as temporary:
        copied = Path(temporary) / "design"
        shutil.copytree(source, copied)
        subprocess.run(  # noqa: S603 - fixed checked-in validator; no user-supplied command
            [sys.executable, str(copied / "verification" / "validate_design.py")],
            check=True,
            cwd=copied,
        )
        report = Path("verification/validation_report.json")
        # Ignore platform text encoding/newline output in this disposable generated report.
        # The original package still has to pass its independent exact-byte hash check.
        if json.loads((copied / report).read_text(encoding="utf-8")) != json.loads(
            (source / report).read_text(encoding="utf-8")
        ):
            raise ValueError("Historical design validation results changed")


if __name__ == "__main__":
    main()
