#!/usr/bin/env python3

"""
Combine several GitHub Advanced Security secret scanning custom pattern
config files into one for eaasy upload using the Field browser extension
"""

import fnmatch
import yaml
import json
import logging
import os
import sys
import argparse
from pathlib import Path
from typing import Any, List, Dict


LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def add_args(parser: argparse.ArgumentParser) -> None:
    """Add CLI args."""
    parser.add_argument("--debug", "-d", action="store_true", help="Debug output")
    parser.add_argument(
        "input_dir", help="Directory with custom pattern config files in YAML format"
    )
    parser.add_argument(
        "--exclude-type", type=str, nargs="+", help="Exclude patterns with a 'type' with these globs"
    )
    parser.add_argument(
        "--exclude-name", type=str, nargs="+", help="Exclude patterns with a 'name' with these globs"
    )
    parser.add_argument(
        "--include-type", type=str, nargs="+", help="Include patterns with a 'name' with these globs"
    )
    parser.add_argument(
        "--include-name", type=str, nargs="+", help="Include patterns with a 'name' with these globs"
    )


def glob_match(field: str, exclude: List[str]) -> bool:
    """Check if field matches any of the exclude globs, using globbing library."""
    if exclude is None or not exclude:
        return False
    for pattern in exclude:
        if fnmatch.fnmatch(field, pattern):
            return True
    return False


def main() -> None:
    """Main entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig()

    if args.debug:
        LOG.setLevel(logging.DEBUG)

    LOG.debug(args.include_name)

    patterns: List[Dict[str, Any]] = []

    # find patterns.yml in directory by walking it
    for root, dirs, filenames in os.walk(args.input_dir):
        for filename in filenames:
            if filename == "patterns.yml":
                print(f"{root}/{filename}", file=sys.stderr)

                with open(str(Path(root) / filename), "r") as f:
                    # read in YAML
                    data = yaml.safe_load(f)

                    if "patterns" in data:
                        for pattern in data["patterns"]:
                            include = True
                            if args.include_name is not None or args.include_type is not None:
                                include = False
                                if "name" in pattern and args.include_name is not None:
                                    name = pattern.get("name", None)
                                    if glob_match(name, args.include_name):
                                        include = True
                                    else:
                                        LOG.debug("Excluding pattern named: %s", name)
                                if "type" in pattern and args.include_type is not None:
                                    type_ = pattern.get("type", None)
                                    if glob_match(type_, args.include_type):
                                        include = True
                                    else:
                                        LOG.debug("Excluding pattern 'type': %s", type_)
                            if "type" in pattern and args.exclude_type is not None:
                                type_ = pattern.get("type", None)
                                if not glob_match(type_, args.exclude_type):
                                    pass
                                else:
                                    if include:
                                        include = False
                                        LOG.debug("Excluding pattern 'type': %s", type_)
                            if "name" in pattern and args.exclude_name is not None:
                                name = pattern.get("name", None)
                                if not glob_match(name, args.exclude_name):
                                    pass
                                else:
                                    if include:
                                        include = False
                                        LOG.debug("Excluding pattern 'name': %s", name)
                            if include:
                                patterns.append(pattern)


    print(yaml.dump({"name": "Collection of custom patterns", "patterns": patterns}))


#    print(json.dumps({'name': 'Collection of custom patterns', 'patterns': patterns}))


if __name__ == "__main__":
    main()
