import hashlib
import logging
import subprocess
from typing import List

from secretscanning.patterns import SecretScanningAlert


def createSnapshot(path: str, results: List[SecretScanningAlert]):
    """Create snapshot from SecretScanningAlert to CSV"""

    header = [
        "secret_type",
        "secret_type_display_name",
        "secret",
        "path",
        "start_line",
        "end_line",
        "start_column",
        "end_column",
    ]

    with open(path, "w") as f:
        f.write(f"{','.join(header)}\n")
        for result in results:
            #
            for location in result.locations:
                # skip non-commit locations
                if location.get("type") != "commit":
                    continue
                details = location.get("details", {})
                if details.get("path", "").startswith(".venv"):
                    continue

                secret = hashlib.sha256(result.secret.encode("utf-8")).hexdigest()
                content = f'"{result.secret_type}","{result.secret_type_display_name}","{secret}",'
                # location info
                content += f'"{details.get("path")}",'
                content += f'"{details.get("start_line")}","{details.get("end_line")}",'
                content += (
                    f'"{details.get("start_column")}","{details.get("end_column")}",'
                )

                f.write(f"{content}\n")


def compareSnapshots(default: str, current: str) -> List[str]:
    """Compare two snapshots and return a list of differences"""
    logging.debug(f"Comparing snapshots: {default} {current}")
    command = [
        "git",
        "diff",
        "--no-index",
        "--no-prefix",
        "--color=always",
        "--exit-code",
        "--",
        default,
        current,
    ]
    logging.debug(f"Running command: {command}")
    result = subprocess.run(command, capture_output=True)
    logging.debug(f"Command result: {result}")
    if result.returncode != 0:
        return result.stdout.decode("utf-8").split("\n")[4:]
    return []
