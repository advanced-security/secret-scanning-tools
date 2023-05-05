#!/usr/bin/env python3

"""
Combine several GitHub Advanced Security secret scanning custom pattern
config files into one for eaasy upload using the Field browser extension
"""

import yaml
import json
import logging
import os
import argparse
from pathlib import Path
from typing import Any


LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def add_args(parser: argparse.ArgumentParser) -> None:
    """Add CLI args."""
    parser.add_argument("--debug", "-d", action="store_true", help="Debug output")
    parser.add_argument("input_dir", help="Directory with custom pattern config files in YAML format")


def main() -> None:
    """Main entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig()

    if args.debug:
        LOG.setLevel(logging.DEBUG)

    patterns: list[Any] = []

    # find patterns.yml in directory by walking it
    for root, dirs, filenames in os.walk(args.input_dir):
        for filename in filenames:
            if filename == "patterns.yml":
                print(f"{root}/{filename}")

                with open(str(Path(root) / filename), "r") as f:
                    # read in YAML
                    data = yaml.safe_load(f)

                    if 'patterns' in data:
                        patterns.append(data['patterns'])

    print(json.dump({'name': 'Collection of custom patterns', 'patterns': patterns}))


if __name__ == "__main__":
    main()

