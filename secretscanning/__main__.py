#!/usr/bin/env python

import os
import sys
import logging
import argparse

import collections
from typing import Dict

from ghastoolkit import GitHub, SecretScanning

from secretscanning import __here__
from secretscanning.markdown import createMarkdown
from secretscanning.patterns import PatternsConfig, loadPatternFiles
from secretscanning.snapshots import compareSnapshots, createSnapshot

__TEMPLATE__ = os.path.join(__here__, "templates")

parser = argparse.ArgumentParser(description="Validate a directory of files.")
parser.add_argument("--debug", action="store_true", help="Print debug messages")
parser.add_argument("-p", "--path", default="./", help="Directory to scan")
parser.add_argument("--cwd", default=os.getcwd(), help="Set Current Working Directory")

parser_modes = parser.add_argument_group("GitHub")
parser.add_argument(
    "--github-repository",
    default=os.environ.get("GITHUB_REPOSITORY"),
    help="GitHub Repository",
)
parser.add_argument(
    "--github-token", default=os.environ.get("GITHUB_TOKEN"), help="GitHub token to use"
)
parser.add_argument(
    "--no-github",
    action="store_true",
    help="Do not connect to GitHub, do not require a repository or token",
)

parser_modes = parser.add_argument_group("modes")
parser_modes.add_argument("--all", action="store_true")
parser_modes.add_argument("--validate", action="store_true")
parser_modes.add_argument("--snapshot", action="store_true")
parser_modes.add_argument("--markdown", action="store_true")

parser_templates = parser.add_argument_group("templates")
parser_templates.add_argument(
    "-tr", "--templates", default=__TEMPLATE__, help="Template directory"
)
parser_templates.add_argument(
    "-tm", "--templates-main", default="README.md", help="Main README template"
)
parser_templates.add_argument(
    "-tp", "--templates-patterns", default="PATTERNS.md", help="Patterns template"
)


if __name__ == "__main__":
    arguments = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if arguments.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    path = arguments.path
    # If a file is provided, point to the directory
    if os.path.isfile(path):
        path = os.path.dirname(path)

    if not arguments.no_github and (
        arguments.github_repository is None or "/" not in arguments.github_repository
    ):
        logging.error(
            "GitHub repository should be set with --github-repository, in the <org>/<repo> format"
        )
        sys.exit(0)

    configs: Dict[str, PatternsConfig] = loadPatternFiles(path)
    # Sort by name
    configs = collections.OrderedDict(sorted(configs.items()))

    errors = []

    if len(configs) == 0:
        logging.warning("No patterns found")
        sys.exit(0)

    GitHub.init(arguments.github_repository, token=arguments.github_token)

    secret_scanning = SecretScanning()

    try:
        # TODO: add caching
        all_secrets = secret_scanning.getAlerts(state="open")
    except Exception as err:
        logging.error(f"Error occurred while fetching secrets: {err}")
        logging.error(f"Please check your token has the right access and try again")
        sys.exit(1)

    logging.info(f"Found '{len(all_secrets)}' total secrets")

    for file_path, pattern_config in configs.items():
        if pattern_config.path is not None:
            pattern_path = os.path.dirname(pattern_config.path)

        # Markdown mode
        if arguments.markdown:
            createMarkdown(
                path,
                os.path.join(pattern_path, "README.md"),
                templates=arguments.templates,
                template=arguments.templates_patterns,
                config=pattern_config,
            )
            continue

        if not arguments.no_github:
            for pattern in pattern_config.patterns:
                logging.info(f"Checking {pattern.name}")

                snapshot_dir = f"{pattern_path}/__snapshots__"
                if not os.path.exists(snapshot_dir):
                    os.mkdir(snapshot_dir)

                snapshot_path = f"{snapshot_dir}/{pattern.type}.csv"

                # list of secrets for a specific pattern
                results = [
                    secret
                    for secret in all_secrets
                    if secret.secret_type == pattern.type
                ]
                logging.info(f"Found secrets :: {len(results)}")

                if arguments.snapshot:
                    logging.info(
                        f"Creating snapshot for {pattern.name} in {pattern_path}"
                    )
                    createSnapshot(snapshot_path, results)
                else:
                    logging.debug(f"Creating current snapshot for {pattern.name}")
                    current_snapshot = snapshot_path.replace(".csv", "-current.csv")
                    createSnapshot(current_snapshot, results)

                    diff = compareSnapshots(snapshot_path, current_snapshot)
                    if len(diff) > 0:
                        logging.info(f"Found differences")
                        for line in diff:
                            print(line)
                        errors.append(f"{pattern.name}")
                    else:
                        logging.info(f"No differences found")
                        os.remove(current_snapshot)

    if arguments.markdown:
        createMarkdown(
            os.path.join(arguments.cwd, "README.md"),
            templates=arguments.templates,
            template=arguments.templates_main,
            configs=configs,
        )

    if errors:
        logging.error(f"Found {len(errors)} errors")
        sys.exit(1)
