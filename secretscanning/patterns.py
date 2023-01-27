import os
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass, field

import yaml


@dataclass
class Regex:
    pattern: str
    version: Optional[str] = "0.1"
    start: Optional[str] = None
    end: Optional[str] = None
    additional_match: Optional[List[str]] = field(default_factory=list)
    additional_not_match: Optional[List[str]] = field(default_factory=list)

    def __post_init__(self):
        if self.version is not None:
            if isinstance(self.version, (int, float)):
                self.version = str(self.version)
            if not self.version.startswith("v"):
                self.version = "v" + self.version
        if self.pattern:
            self.pattern = self.pattern.strip()
        if self.start:
            self.start = self.start.strip()
        if self.end:
            self.end = self.end.strip()


@dataclass
class Pattern:
    """A pattern to match against a file."""

    name: str
    description: Optional[str] = None
    experimental: bool = False

    regex: Regex = field(default_factory=Regex)

    expected: Optional[List[Dict[str, str]]] = None

    type: Optional[str] = None
    comments: List[str] = field(default_factory=list)

    def __post_init__(self):
        if isinstance(self.regex, dict):
            self.regex = Regex(**self.regex)


@dataclass
class PatternsConfig:
    """A configuration for a set of patterns."""

    name: str

    patterns: List[Pattern] = field(default_factory=list)

    path: Optional[str] = field(default=None)

    def __post_init__(self):
        _tmp = self.patterns
        self.patterns = []

        for pattern in _tmp:
            self.patterns.append(Pattern(**pattern))


@dataclass
class SecretScanningAlert:
    secret_type: str
    secret_type_display_name: str
    secret: str

    path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    start_column: Optional[int] = None
    end_column: Optional[int] = None


def loadPatternFiles(path: str) -> Dict[str, PatternsConfig]:
    """Find all files that match a pattern."""
    logging.info(f"Path being proccessed: {path}")
    patterns: Dict[PatternsConfig] = {}

    for root, dirs, files in os.walk(path):
        for file in files:
            if file == "patterns.yml":
                path = os.path.join(root, file)
                logging.debug(f"Found patterns file: {path}")

                with open(path) as f:
                    data = yaml.safe_load(f)

                    config = PatternsConfig(path=path, **data)

                    logging.debug(
                        f"Loaded :: PatternsConfig('{config.name}' patterns='{len(config.patterns)})'"
                    )

                    patterns[path] = config
    return patterns
