#!/usr/bin/env python3
"""
Test GitHub Advanced Security Secret Scanning Custom Patterns

Copyright (C) GitHub 2022

Author: GitHub Advanced Security Field Services
"""

import os
from pathlib import Path
from argparse import ArgumentParser
import logging
import json
from functools import partial
from typing import Union, Any, Optional
import platform
from threading import Lock
from random import randbytes, choices  # noqa: DUO102
from string import printable
from itertools import zip_longest
import tempfile
from tqdm import tqdm
from git import Repo  # type: ignore
from git.exc import GitCommandError
from colorama import Fore, Style
import hyperscan
import yaml
import pcre

LOG = logging.getLogger(__name__)
LOCK = Lock()
PATTERNS_FILENAME = "patterns.yml"
RESULTS: dict[str, list[dict[str, Any]]] = {}
PATH_EXCLUDES = ('.git',)
FILENAME_EXCLUDES = ('README.md', PATTERNS_FILENAME)
MATCHES_LIMIT = 5


def LOCKED_LOG(*args: Any, **kwargs: Any) -> None:
    """Acquire lock then do log message."""
    with LOCK:
        logging.log(*args, **kwargs)


class Pattern():
    """Store hyperscan patterns."""

    default_start = r'\A|[^0-9A-Za-z]'
    default_end = r'\z|[^0-9A-Za-z]'

    def __init__(self, name: str, _type: str, description: str, start: str, pattern: str, end: str,
                 additional_matches: list[str], additional_not_matches: list[str], expected: list[dict[str,
                                                                                                       Any]]) -> None:
        self.name = name.strip() if name is not None else None
        self.type = _type.strip() if _type is not None else None
        self.description = description.strip() if description is not None else None
        self.start = start.strip() if start is not None else None
        self.pattern = pattern.strip()
        self.end = end.strip() if end is not None else None
        self.additional_not_matches = [add_match.strip() for add_match in additional_not_matches
                                      ] if additional_not_matches is not None else []
        self.additional_matches = [add_match.strip() for add_match in additional_matches
                                  ] if additional_matches is not None else []

        self.expected = expected

    def regex_string(self) -> bytes:
        """Concatenate and UTF-8 encode."""
        return f"({self.start if self.start is not None else Pattern.default_start})({self.pattern})({self.end if self.end is not None else Pattern.default_end})".encode(
            'utf-8')

    def pcre_regex(self) -> pcre.Pattern:
        """Concatenate, label capture groups, and UTF-8 encode."""
        pcre_string = f"(?P<start>{self.start if self.start is not None else Pattern.default_start})(?P<pattern>{self.pattern})(?P<end>{self.end if self.end is not None else Pattern.default_end})"

        try:
            return pcre.compile(pcre_string.encode('utf-8'))
        except pcre.PCREError as err:
            LOG.error("Cannot compile regex with PCRE: %s; error: %s", pcre_string, err)
            exit(1)


def parse_patterns(patterns_dir: str,
                   include: Optional[list[str]] = None,
                   exclude: Optional[list[str]] = None,
                   no_warn_on_additional_matches_number: bool = True,
                   lt_ghes_3_8: bool = False) -> list[Pattern]:
    """Parse patterns found in YAML files."""
    global MATCHES_LIMIT

    patterns = []
    patterns_file: str = os.path.join(patterns_dir, PATTERNS_FILENAME)

    with open(patterns_file, "r") as pf:
        data = yaml.safe_load(pf)

        for pattern in data["patterns"]:
            LOG.debug("Pattern: %s", json.dumps(pattern, indent=2))

            pattern_type = pattern.get("type")
            if include:
                if pattern_type not in include:
                    continue
            if exclude:
                if pattern_type in exclude:
                    continue

            name = pattern.get("name")
            _type = pattern.get("type")
            description = pattern.get("description")

            regex = pattern["regex"]

            additional_not_matches = regex.get("additional_not_match", [])
            additional_matches = regex.get("additional_match", [])

            if not no_warn_on_additional_matches_number:
                matches_count = len(additional_not_matches) + len(additional_matches)
                if matches_count > MATCHES_LIMIT:
                    LOG.warning("Number of additional matches is greater than the limit for upload in the UI: %s vs %s",
                                matches_count, MATCHES_LIMIT)

            if lt_ghes_3_8:
                for item in additional_not_matches + additional_matches:
                    if item.startswith('^') or item.endswith('$'):
                        LOG.warning("GHES <= 3.7 does not support anchors in additional matches")

            expected = pattern.get("expected", [])

            patterns.append(
                Pattern(name, _type, description, regex.get('start'), regex.get('pattern'), regex.get('end'),
                        additional_matches, additional_not_matches, expected))

    return patterns


def hs_compile(db: hyperscan.Database,
               regex: Union[str | list[str] | bytes | list[bytes]],
               labels: Optional[list[str]] = None) -> bool:
    """Compile one or more hyperscan regexes into the given database."""
    regex_bytes: list[bytes]
    labels = labels if labels is not None else []

    if isinstance(regex, str):
        regex_bytes = [regex.encode('utf-8')]
    elif isinstance(regex, bytes):
        regex_bytes = [regex]
    elif isinstance(regex, list):
        if len(regex) == 0:
            return False

        if isinstance(regex[0], str):
            regex_bytes = [r.encode('utf-8') for r in regex]  # type: ignore
        elif isinstance(regex[0], bytes):
            regex_bytes = regex  # type: ignore
        else:
            raise ValueError("Regex is not a str or bytes")
    else:
        raise ValueError("Regex is not a str or bytes")

    # TODO: also do with hyperscan.HS_FLAG_UCP so we can test them in that encoding - \x00A\x00B etc. (Windows style)
    try:
        db.compile(regex_bytes, flags=hyperscan.HS_FLAG_SOM_LEFTMOST | hyperscan.HS_FLAG_UTF8)
    except hyperscan.error:
        LOG.debug("Failed to compile a rule: %s", str(regex_bytes))
        for label, regex in zip_longest(labels, regex_bytes):
            try:
                db.compile([regex], flags=hyperscan.HS_FLAG_SOM_LEFTMOST | hyperscan.HS_FLAG_UTF8)
            except hyperscan.error as err:
                LOG.error("❌ Failed to compile %s%s: %s", str(regex), ' (' + label + ')' if label is not None else '',
                          err)

                return False

    return True


# sideffect: writes to global RESULT
# context: run in a thread by hyperscan
def report_scan_results(patterns: list[Pattern], path: Path, content: bytes, verbose: bool, quiet: bool,
                        write_to_results: bool, dry_run: bool, only_match: bool, no_additional_matches: bool,
                        rule_id: int, start_offset: int, end_offset: int, flags: int, context: Optional[Any]) -> None:
    """Hyperscan callback."""
    match_content: bytes = content[start_offset:end_offset]
    pattern: Pattern = patterns[rule_id]

    if LOG.level == logging.DEBUG:
        with LOCK:
            LOG.debug("Matched '%s' id %d at %d:%d with flags %s and context %s", pattern.name, rule_id, start_offset,
                      end_offset, flags, context)
            LOG.debug("Matched: %s", match_content)

    regex_string: bytes = pattern.regex_string()

    if LOG.level == logging.DEBUG:
        with LOCK:
            LOG.debug("Pattern was: %s", regex_string)

    # extract separate parts of match using PCRE
    pcre_result_match(pattern,
                      path,
                      match_content,
                      start_offset,
                      end_offset,
                      verbose=verbose,
                      quiet=quiet,
                      write_to_results=write_to_results,
                      dry_run=dry_run,
                      only_match=only_match,
                      no_additional_matches=no_additional_matches)


def path_offsets_match(first: dict[str, Any], second: dict[str, Any]) -> bool:
    """Check file path and start and end offsets match."""
    for key in ('name', 'start_offset', 'end_offset'):
        if not first.get(key) == second.get(key):
            return False
    return True


# sideffect: writes to global RESULTS
# content: run in a thread by hyperscan
def pcre_result_match(pattern: Pattern,
                      path: Path,
                      content: bytes,
                      start_offset: int,
                      end_offset: int,
                      verbose: bool = False,
                      quiet: bool = False,
                      dry_run: bool = False,
                      write_to_results: bool = False,
                      only_match: bool = False,
                      no_additional_matches: bool = False) -> None:
    """Use PCRE to extract start, pattern and end matches."""
    global RESULTS

    LOCKED_LOG(logging.DEBUG, "Matching with PCRE regex: %s", str(pattern.pcre_regex()))

    if m := pattern.pcre_regex().match(content):
        try:
            parts = {
                'start': m.group('start').decode('utf-8'),
                'pattern': m.group('pattern').decode('utf-8'),
                'end': m.group('end').decode('utf-8')
            }
        except UnicodeDecodeError:
            try:
                parts = {
                    'start': m.group('start').decode('ascii'),
                    'pattern': m.group('pattern').decode('ascii'),
                    'end': m.group('end').decode('ascii')
                }
            except UnicodeDecodeError:
                parts = {'start': str(m.group('start')), 'pattern': str(m.group('pattern')), 'end': str(m.group('end'))}

        if not no_additional_matches:
            try:
                if pattern.additional_matches:
                    if not all([pcre.compile(pat).match(m.group('pattern')) for pat in pattern.additional_matches]):
                        LOCKED_LOG(logging.DEBUG, "One of the required additional pattern matches did not hold")
                        return

                if pattern.additional_not_matches:
                    if any([pcre.compile(pat).match(m.group('pattern')) for pat in pattern.additional_not_matches]):
                        LOCKED_LOG(logging.DEBUG, "One of the additional NOT pattern matches held")
                        return
            except pcre.PCREError as err:
                LOG.error("Cannot compile one of the additional/not match regex for '%s': %s", pattern.name, err)
                exit(1)

        file_details = {
            'name': path.name if not dry_run else str(path),
            'start_offset': start_offset + len(m.group('start')),
            'end_offset': end_offset - len(m.group('end'))
        }

        if not dry_run:
            if not any([path_offsets_match(file_details, loc) for loc in pattern.expected]):
                if not quiet:
                    LOCKED_LOG(logging.ERROR if pattern.expected else logging.INFO,
                               "%s result '%s' for '%s' in path '%s'; %s:%d-%d",
                               "❌ unexpected" if pattern.expected else "ℹ️  found", parts['pattern'], pattern.name,
                               path.parent, file_details['name'], file_details['start_offset'],
                               file_details['end_offset'])
            else:
                if not quiet or LOG.level == logging.DEBUG:
                    LOCKED_LOG(logging.INFO if verbose else logging.DEBUG,
                               "✅ expected result '%s' for '%s' in path '%s'; %s:%d-%d", parts['pattern'], pattern.name,
                               path.parent, file_details['name'], file_details['start_offset'],
                               file_details['end_offset'])

        if write_to_results:
            with LOCK:
                if pattern.name not in RESULTS:
                    RESULTS[pattern.name] = []

                RESULTS[pattern.name].append({'file': file_details, 'groups': parts})

            LOCKED_LOG(logging.DEBUG, (json.dumps({'name': pattern.name, 'file': file_details, 'groups': parts})))

        if dry_run:
            # for dry-run, TODO: improve to be single-line grep or SARIF output
            if only_match:
                output = f"{repr(parts['pattern'])[1:-1]}"
            else:
                output = f"{repr(file_details['name'])[1:-1]}:{int(str(file_details['start_offset']))}-{int(str(file_details['end_offset']))}: {repr(parts['start'])[1:-1]}{Fore.RED}{repr(parts['pattern'])[1:-1]}{Style.RESET_ALL}{repr(parts['end'])[1:-1]} (with '{repr(pattern.name)[1:-1]}')"
            with LOCK:
                print(output)


def test_patterns(tests_path: str,
                  include: Optional[list[str]] = None,
                  exclude: Optional[list[str]] = None,
                  verbose: bool = False,
                  quiet: bool = False,
                  no_additional_matches: bool = False,
                  no_warn_on_additional_matches_number: bool = False,
                  lt_ghes_3_8: bool = False) -> bool:
    """Run all of the discovered patterns in the given path."""
    global RESULTS
    RESULTS = {}

    found_patterns: bool = False
    ret: bool = True

    if not os.path.isdir(tests_path):
        if not quiet:
            LOG.error("❌ testing directory not found: %s", tests_path)
        exit(1)

    db = hyperscan.Database()

    for dirpath, dirnames, filenames in os.walk(tests_path):
        if PATTERNS_FILENAME in filenames:
            rel_dirpath = Path(dirpath).relative_to(tests_path)
            LOG.debug("Found patterns in %s", rel_dirpath)

            patterns = parse_patterns(dirpath,
                                      include=include,
                                      exclude=exclude,
                                      no_warn_on_additional_matches_number=no_warn_on_additional_matches_number,
                                      lt_ghes_3_8=lt_ghes_3_8)

            if len(patterns) == 0:
                continue

            found_patterns = True

            if not hs_compile(db, [pattern.regex_string() for pattern in patterns],
                              labels=[pattern.type for pattern in patterns]):
                if not quiet:
                    LOG.error("❌ hyperscan pattern compilation error in '%s'", rel_dirpath)
                    exit(1)
            for filename in [f for f in filenames if f not in FILENAME_EXCLUDES]:
                path = (Path(dirpath) / filename).relative_to(tests_path)
                with (Path(tests_path) / path).resolve().open("rb") as f:
                    content = f.read()

                    # sideffect: writes to global RESULTS
                    scan(db,
                         path,
                         content,
                         patterns,
                         verbose=verbose,
                         quiet=quiet,
                         no_additional_matches=no_additional_matches)

            # threads should all exit before here, so we don't need to use LOCK
            for pattern in patterns:
                # did we match everything we expected?
                ok: bool = True

                if pattern.expected:
                    for expected in pattern.expected:
                        pattern_results = RESULTS.get(pattern.name, [])
                        if not any([path_offsets_match(expected, result.get('file', {})) for result in pattern_results
                                   ]):
                            if not quiet:
                                try:
                                    with (Path(dirpath) / expected.get('name', '')).resolve().open("rb") as f:
                                        content = f.read()
                                        LOG.error(
                                            "❌ unmatched expected location for: '%s'; %s:%d-%d; %s", pattern.type,
                                            expected.get('name'), expected.get('start_offset'),
                                            expected.get('end_offset'),
                                            content[expected.get('start_offset', 0):expected.get('end_offset', 0)])
                                except OSError as err:
                                    LOG.error(
                                        "❌ unmatched expected location for: '%s'; %s:%d-%d; could not open/read file: %s",
                                        pattern.type, expected.get('name'), expected.get('start_offset'),
                                        expected.get('end_offset'), err)
                            ok = False

                    # did we match anything unexpected?
                    if any([
                            not any(
                                [path_offsets_match(expected, result.get('file', {}))
                                 for expected in pattern.expected])
                            for result in pattern_results
                    ]):
                        if not quiet:
                            LOG.error("❌ matched unexpected results for: '%s'", pattern.type)
                        ok = False

                    if ok and not quiet:
                        LOG.info("✅ '%s' in '%s'", pattern.type, rel_dirpath)

                    if not ok:
                        ret = False

                else:
                    if not quiet:
                        LOG.info("ℹ️  '%s' in '%s': no expected patterns defined", pattern.type, rel_dirpath)

    if not found_patterns:
        LOG.error("❌ Failed to find any patterns in %s", str(tests_path))
        ret = False

    return ret


def dry_run_patterns(db: hyperscan.Database,
                     patterns: list[Pattern],
                     extra_directory: str,
                     verbose: bool = False,
                     quiet: bool = False,
                     clear_results: bool = True,
                     size_read: int = 0,
                     files_read: int = 0,
                     only_match: bool = False,
                     no_additional_matches: bool = False) -> tuple[int, int]:
    """Dry run all of the discovered patterns in the given path against the extra directory, recursively."""
    global RESULTS

    if clear_results:
        RESULTS = {}

    for dirpath, dirnames, filenames in os.walk(extra_directory):
        # TODO: exclude using globs
        # TODO: take as an argument
        if not any([parent.name in PATH_EXCLUDES for parent in Path(dirpath).parents if parent != '']):
            for filename in filenames:
                path = (Path(dirpath) / filename).relative_to(extra_directory)
                try:
                    file_path = (Path(extra_directory) / path).resolve()
                    with file_path.open("rb") as f:
                        # TODO: memory map instead?
                        content = f.read()

                        size_read += len(content)
                        files_read += 1

                        scan(db,
                             path,
                             content,
                             patterns,
                             verbose=verbose,
                             quiet=quiet,
                             write_to_results=(not clear_results) or (not quiet),
                             dry_run=True,
                             only_match=only_match,
                             no_additional_matches=no_additional_matches)
                except (OSError, RuntimeError) as err:
                    LOG.debug("Failed to open and read file '%s': %s", str(file_path), err)

    if not quiet:
        print_summary(size_read, files_read)

    return size_read, files_read


def print_summary(size_read: int, files_read: int) -> None:
    """Print summary of results."""
    global RESULTS

    with LOCK:
        LOG.info("ℹ️  Summary: processed %d bytes in %d files", size_read, files_read)

        for pattern_name, results in RESULTS.items():
            LOG.info("%s: %d", pattern_name, sum((1 for result in results)))


def random_test_patterns(db: hyperscan.Database,
                         patterns: list[Pattern],
                         verbose: bool = False,
                         quiet: bool = False,
                         progress: bool = False,
                         only_match: bool = False,
                         no_additional_matches: bool = False) -> None:
    """Run patterns over random binary and printable ASCII data."""
    global RESULTS
    RESULTS = {}

    size_read: int = 0

    binary_goal = 1_000_000_000
    ascii_goal = 1_000_000_000
    binary_chunk_size = 100_000_000
    ascii_chunk_size = 100_000_000

    if progress:
        pb = tqdm(total=binary_goal + ascii_goal, unit_scale=True, unit='B')

    # read 1GB of random binary data
    while size_read < binary_goal:
        # read random bytes, 100MB at a time
        binary_content = randbytes(binary_chunk_size)

        scan(db,
             None,
             binary_content,
             patterns,
             verbose=verbose,
             quiet=quiet,
             write_to_results=True,
             dry_run=True,
             only_match=only_match,
             no_additional_matches=no_additional_matches)

        size_read += binary_chunk_size
        if progress:
            pb.update(binary_chunk_size)

    # read 1GB of random ascii data
    while size_read < binary_goal + ascii_goal:
        # some random ASCII (printable characters)
        ascii_content = ''.join(choices(printable, k=ascii_chunk_size)).encode('utf-8')  # nosec

        scan(db,
             None,
             ascii_content,
             patterns,
             verbose=verbose,
             quiet=quiet,
             write_to_results=True,
             dry_run=True,
             only_match=only_match,
             no_additional_matches=no_additional_matches)

        size_read += ascii_chunk_size
        if progress:
            pb.update(ascii_chunk_size)

    if progress:
        pb.close()

    with LOCK:
        LOG.info("Summary: processed %d random bytes", size_read)

        for pattern_name, results in RESULTS.items():
            count = sum((1 for result in results))
            if count > 0:
                LOG.info("%s: %d", pattern_name, count)


def build_hyperscan_patterns(tests_path: str,
                             include: Optional[list[str]] = None,
                             exclude: Optional[list[str]] = None,
                             quiet: bool = False) -> tuple[hyperscan.Database, list[Pattern]]:
    """Build a hyperscan database from a path of tests, and return the database and the patterns used to build it."""
    db = hyperscan.Database()
    patterns = []

    for dirpath, dirnames, filenames in os.walk(tests_path):
        if PATTERNS_FILENAME in filenames:
            patterns.extend(parse_patterns(dirpath, include=include, exclude=exclude))

    if not hs_compile(db, [pattern.regex_string() for pattern in patterns],
                      labels=[pattern.type for pattern in patterns]):
        if not quiet:
            LOG.error("❌ hyperscan pattern compilation error in '%s'", dirpath)
            return None, patterns
    return db, patterns


def repo_test_patterns(db: hyperscan.Database,
                       patterns: list[Pattern],
                       repos_path: str,
                       verbose: bool = False,
                       quiet: bool = False,
                       progress: bool = False,
                       only_match: bool = False,
                       no_additional_matches: bool = False) -> None:
    """Test a set of repos provided in a file. Clone repos into a local directory."""
    global RESULTS
    RESULTS = {}

    if not Path(repos_path).is_file:
        LOG.error("❌ cannot find repos file at '%s'", repos_path)
        exit(1)

    size_read: int = 0
    files_read: int = 0

    # make cloning path in home folder
    home = os.environ.get("HOME")
    tmp_dir = None
    if home is None:
        tmp_dir = tempfile.TemporaryDirectory()
        home = tmp_dir.name
        LOG.warning("Cannot find HOME, using temporary directory instead: %s", home)
    clone_path = Path(home) / '.local' / 'secret_scanning_tools' / 'repos'

    os.makedirs(clone_path, exist_ok=True)

    LOG.info("Cloned repos path at: %s", str(clone_path))

    try:
        with open(repos_path) as repos:
            repo_list = [repo.strip() for repo in repos.readlines() if '/' in repo]
            total = len(repo_list)

            if progress:
                pb = tqdm(total=total)

            for repo_name in repo_list:
                try:
                    repo_tuple = repo_name.split('/')
                    repo_path = clone_path / repo_tuple[0] / repo_tuple[1]
                    Repo.clone_from(f"https://github.com/{repo_tuple[0]}/{repo_tuple[1]}", repo_path)
                except GitCommandError as err:
                    LOG.debug("Failed to clone repo '%s', does it exist? Was it already cloned? Error: %s", repo_name,
                              err)

                LOG.info("Scanning repo: %s", repo_name)
                # now scan the repo
                size_read_run, files_read_run = dry_run_patterns(db,
                                                                 patterns,
                                                                 str(repo_path),
                                                                 verbose,
                                                                 quiet=True,
                                                                 clear_results=False,
                                                                 size_read=size_read,
                                                                 files_read=files_read,
                                                                 only_match=only_match,
                                                                 no_additional_matches=no_additional_matches)
                size_read += size_read_run
                files_read += files_read_run

                if progress:
                    pb.update(1)

        if tmp_dir is not None:
            tmp_dir.cleanup()
    except OSError as err:
        LOG.error("❌ cannot find repos file at '%s': %s", repos_path, err)
        exit(1)

    print_summary(size_read, files_read)


# sideffect: writes to global RESULTS
def scan(db: hyperscan.Database,
         path: Optional[Path],
         content: bytes,
         patterns: list[Pattern],
         verbose: bool = False,
         quiet: bool = False,
         write_to_results: bool = True,
         dry_run: bool = False,
         only_match: bool = False,
         no_additional_matches: bool = False) -> None:
    """Scan content with database. Results are handled in a thread launched by hyperscan (running the `partial` we pass in)."""
    db.scan(
        content,
        partial(report_scan_results, patterns, path, content, verbose, quiet, write_to_results, dry_run, only_match,
                no_additional_matches))


def add_args(parser: ArgumentParser) -> None:
    """Add arguments to the command line parser."""
    parser.add_argument("--tests",
                        "-t",
                        default=Path(__file__).parent.parent,
                        required=False,
                        help="Root test directory (defaults to directory above script directory)")
    parser.add_argument("--debug", "-d", action="store_true", help="Debug output on")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show expected matches")
    parser.add_argument("--quiet", "-q", action="store_true", help="Don't output anything other than exit error codes")
    parser.add_argument("--extra", "-e", required=False, help="Extra directory for running tests over all contents")
    parser.add_argument("--random",
                        "-r",
                        action="store_true",
                        help="Extra directory for running tests over all contents")
    parser.add_argument("--progress", "-p", action="store_true", help="Show a progress bar where relevant")
    parser.add_argument("--include", "-i", nargs="*", help="Include these pattern IDs")
    parser.add_argument("--exclude", "-x", nargs="*", help="Exclude these pattern IDs")
    parser.add_argument("--repos", "-R", help="File containing list of repos to clone from GitHub and scan")
    parser.add_argument("--only-match",
                        "-o",
                        action="store_true",
                        help="Only show the matching pattern part of any results")
    parser.add_argument("--continue-on-fail", "-c", action="store_true", help="Continue if testing patterns fails")
    parser.add_argument("--no-additional-matches",
                        "-A",
                        action="store_true",
                        help="Do not match using additional matches")
    parser.add_argument("--no-warn-on-additional-matches-number",
                        "-W",
                        action="store_true",
                        help="Do not warn on more than 5 additional matches")
    parser.add_argument(
        "--lt-ghes-3-8",
        "-lt",
        action="store_true",
        help="The GHES these will be used on is v <= 3.7, so does not support anchors in additional matches")
    parser.add_argument("--additional-matches-limit", "-a", type=int, default=5, help="Set the matches limit")


def check_platform() -> None:
    """Check we are on an Intel-compatible machine.

    Exit if not.
    """
    if platform.machine() not in ("x86_64", "amd64"):
        LOG.error("❌ cannot run hyperscan on non-Intel-compatible platform")
        exit(1)


def main() -> None:
    """Main command line entrypoint."""
    global MATCHES_LIMIT

    check_platform()

    parser = ArgumentParser(description="Test Secret Scanning Custom Patterns")
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig()
    LOG.setLevel(logging.INFO)
    if args.debug:
        LOG.setLevel(logging.DEBUG)

    MATCHES_LIMIT = args.additional_matches_limit

    if not test_patterns(args.tests,
                         include=args.include,
                         exclude=args.exclude,
                         verbose=args.verbose,
                         quiet=args.quiet,
                         no_additional_matches=args.no_additional_matches,
                         no_warn_on_additional_matches_number=args.no_warn_on_additional_matches_number,
                         lt_ghes_3_8=args.lt_ghes_3_8) and not args.continue_on_fail:
        exit(1)

    db, patterns = build_hyperscan_patterns(args.tests, include=args.include, exclude=args.exclude, quiet=args.quiet)
    if db is None:
        exit(1)

    if args.extra is not None:
        dry_run_patterns(db,
                         patterns,
                         args.extra,
                         verbose=args.verbose,
                         quiet=args.quiet,
                         only_match=args.only_match,
                         no_additional_matches=args.no_additional_matches)

    if args.random:
        random_test_patterns(db,
                             patterns,
                             verbose=args.verbose,
                             quiet=args.quiet,
                             progress=args.progress,
                             only_match=args.only_match,
                             no_additional_matches=args.no_additional_matches)

    if args.repos:
        repo_test_patterns(db,
                           patterns,
                           args.repos,
                           verbose=args.verbose,
                           quiet=args.quiet,
                           progress=args.progress,
                           only_match=args.only_match,
                           no_additional_matches=args.no_additional_matches)


if __name__ == "__main__":
    main()
