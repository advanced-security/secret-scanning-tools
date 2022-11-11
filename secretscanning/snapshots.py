import hashlib
import subprocess
from typing import List, Dict, Optional

from secretscanning.patterns import *


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
            # TODO: This might need to be removed
            if result.path.startswith(".venv"):
                continue
            secret = hashlib.sha256(result.secret.encode("utf-8")).hexdigest()
            content = ""
            for head in header:
                if head == "secret":
                    content += f'"{secret}"'
                else:
                    content += f'"{getattr(result, head) or ""}"'
                content += ","

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
    with open(os.devnull, "w") as devnull:
        result = subprocess.run(command, capture_output=True)
    logging.debug(f"Command result: {result}")
    if result.returncode != 0:
        return result.stdout.decode("utf-8").split("\n")[4:]
    return []
