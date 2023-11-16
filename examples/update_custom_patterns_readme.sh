#!/bin/bash

GITHUB_REPOSITORY="{$GITHUB_REPOSITORY:-advanced-security/secret-scanning-custom-patterns}"
CUSTOM_PATTERNS_PATH="${CUSTOM_PATTERNS_PATH:-$HOME/secret-scanning-custom-patterns}"

pipenv run markdown --github-repository "${GITHUB_REPOSITORY}"  -p "${CUSTOM_PATTERNS_PATH}"

cd "${CUSTOM_PATTERNS_PATH}" || exit 1
find . -type f -name 'README.md' -exec git add {} \;
git commit -S -m "Updated README.md"
git push
