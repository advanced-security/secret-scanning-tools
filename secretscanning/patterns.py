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
class Test:
    data: Optional[str] = None
    start_offset: Optional[int] = None
    end_offset: Optional[int] = None

    def __post_init__(self):
        if self.start_offset is not None and self.start_offset < -1:
            raise ValueError(
                "The start offset should be zero, positive, or -1 (the end of the data)"
            )

        if self.end_offset is not None and (
            self.end_offset == 0 or self.end_offset < -1
        ):
            raise ValueError(
                "The expected end offset should be positive, or -1 (the end of the data)"
            )


@dataclass
class Expected:
    name: str
    start_offset: Optional[int] = None
    end_offset: Optional[int] = None

    def __post_init__(self):
        if self.start_offset is not None and self.start_offset < -1:
            raise ValueError(
                "The start offset should be zero, positive, or -1 (the end of the data)"
            )

        if self.end_offset is not None and (
            self.end_offset == 0 or self.end_offset < -1
        ):
            raise ValueError(
                "The expected end offset should be positive, or -1 (the end of the data)"
            )


@dataclass
class Pattern:
    """A pattern to match against a file."""

    name: str
    description: Optional[str] = None
    experimental: bool = False
    regex: Regex = field(default_factory=Regex)
    test: Optional[Test] = field(default_factory=Test)
    expected: Optional[List[Expected]] = field(default_factory=list)
    type: Optional[str] = None
    comments: List[str] = field(default_factory=list)

    def __post_init__(self):
        if isinstance(self.regex, dict):
            self.regex = Regex(**self.regex)
        if isinstance(self.test, dict):
            self.test = Test(**self.test)
        self.expected = [
            Expected(**expected)
            for expected in self.expected
            if isinstance(expected, dict)
        ]


@dataclass
class PatternsConfig:
    """A configuration for a set of patterns."""

    name: str

    display: bool = True

    patterns: List[Pattern] = field(default_factory=list)

    path: Optional[str] = field(default=None)

    def __post_init__(self):
        _tmp = self.patterns
        self.patterns = []

        for pattern in _tmp:
            try:
                self.patterns.append(Pattern(**pattern))
            except Exception as err:
                logging.error("Failed to validate pattern: %s", err)
                logging.error("%s", yaml.dump(pattern))


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
