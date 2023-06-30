#!/usr/bin/env python3

"""Read git blobs and trees."""

import pygit2
import argparse
import logging

from typing import Callable


LOG = logging.getLogger(__name__)


def add_args(parser) -> None:
    """Add arguments to the parser."""
    parser.add_argument("--debug", "-d", action="store_true", help="Debug mode")
    parser.add_argument("directory", help="Directory that uses git (not the .git directory itself)")


def robust_decode(byte_string: bytes) -> str:
    """Robustly decode bytes as text encodings."""
    for encoding in ('utf-8', 'win-1252', 'iso-8859-1', 'ascii'):
        try:
            return byte_string.decode(encoding)
        except Exception:
            continue
    raise ValueError("No suitable decoding for %s", byte_string)


def scan_repo(repo_name: str, callback: Callable) -> None:
    """Scan a git repository for commits and blobs, and call the callback for each one."""
    try:
        repo = pygit2.Repository(repo_name)
    except pygit2.GitError as err:
        LOG.error(err)
        return

    if repo.is_empty:
        LOG.error("Repository is empty")
        return

    scanned_commit_ids = set()

    # get a list of all branches
    try:
        branches = repo.raw_listall_branches(pygit2.GIT_BRANCH_LOCAL)
    except pygit2.GitError as err:
        LOG.error(err)
        return

    LOG.debug("Branches: %s", branches)

    # checkout each branch
    for branch_name in branches:
        LOG.info("Branch: %s", branch_name)
        try:
            branch = repo.lookup_branch(branch_name)
            ref = repo.lookup_reference(branch.name)
            repo.checkout(ref)

            branch_name = robust_decode(branch_name)

            # walk the branch
            for commit in repo.walk(repo.head.target, pygit2.GIT_SORT_TOPOLOGICAL):
                if commit.oid in scanned_commit_ids:
                    continue

                scanned_commit_ids.add(commit.oid)

                # scan the commit message
                LOG.info("%s", commit.message.encode(commit.message_encoding if commit.message_encoding else "utf-8"))

                if callback is not None:
                    callback(branch_name, None, commit.oid, commit.message.encode(commit.message_encoding if commit.message_encoding else "utf-8"))

                # get the commit diff
                if commit.parents:
                    for parent in commit.parents:
                        diff = repo.diff(parent, commit)
                        for patch in diff:
                            target_file = patch.delta.new_file.path
                            LOG.debug("File: %s", target_file)
                            content = False
                            for line in patch.data.split(b"\n"):
                                if line.startswith(b"@@"):
                                    content = True
                                    continue
                                if content and line.startswith(b"+"):
                                    line_data = line[1:]
                                    LOG.debug("%s", line_data)

                                    if callback is not None:
                                        callback(branch_name, target_file, commit.oid, line_data)
                # first commit, so no diff
                else:
                    for obj in commit.tree:
                        LOG.debug("%s: %s", obj.name, obj.oid)
                        if hasattr(obj, 'data'):
                            LOG.debug(obj.data)
                            if callback is not None:
                                callback(branch_name, obj.name, obj.oid, obj.data)
        except pygit2.GitError as err:
            LOG.error(err)
            continue

    # find orphaned blobs, i.e. blobs that are not referenced by any tree
    # list all blobs, remove any blob that is referenced by a tree
    index = repo.index
    index.read()

    # list all ids in the index
    index_ids = {entry.oid for entry in index}

    # list all ids we didn't find as commits using a set disjunction between index_ids and scanned_commit_ids
    orphaned_ids = index_ids - scanned_commit_ids

    # get data for all blobs for the orphaned ids
    for blob_id in orphaned_ids:
        blob = repo.get(blob_id)
        LOG.info("Blob: %s, %s", blob.name, blob.oid)
        LOG.debug("Blob data: %s", blob.read_raw())
        if callback is not None:
            callback(None, blob.name, blob.oid, blob.read_raw())


def print_out_data(branch_name: str, target_file: str, commit_id: str, line_data: bytes) -> None:
    """Print out the data."""
    print(f"{branch_name if branch_name is not None else 'orphan'}: {target_file if target_file else 'N/A'}, {commit_id}, {line_data}")


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    if args.debug:
        LOG.setLevel(logging.DEBUG)

    scan_repo(args.directory, callback=print_out_data)


if __name__ == "__main__":
    main()
