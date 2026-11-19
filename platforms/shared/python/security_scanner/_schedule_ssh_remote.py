"""Fixed read-only helper sent to the scheduled source over SSH."""

import fnmatch
import os
import shutil
import stat
import sys


def open_directories(directory, parts, flags):
    """Take ownership of a directory descriptor and walk its children."""
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def open_entries(directory, name, flags):
    child = os.open(name, flags, dir_fd=directory)
    try:
        return child, os.scandir(child)
    except BaseException:
        os.close(child)
        raise


def list_files(root, excludes, directory_flags):
    output = sys.stdout.buffer
    root_directory, root_entries = open_entries(root, ".", directory_flags)
    pending = [("", root_directory, root_entries)]
    try:
        while pending:
            prefix, directory, entries = pending[-1]
            entry = next(entries, None)
            if entry is None:
                pending.pop()
                os.close(directory)
                continue
            path = prefix + entry.name
            if any(fnmatch.fnmatchcase(path, pattern) for pattern in excludes):
                continue
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child, child_entries = open_entries(directory, entry.name, directory_flags)
                pending.append((path + "/", child, child_entries))
            elif stat.S_ISREG(metadata.st_mode):
                if any(ord(char) < 32 for char in path):
                    raise ValueError("unsupported remote filename")
                fields = "\t{}\t{}\n".format(metadata.st_size, metadata.st_mtime)
                output.write(os.fsencode(path) + fields.encode("ascii"))
    finally:
        for _, directory, entries in reversed(pending):
            entries.close()
            os.close(directory)


def fetch_file(root, path, search_flags):
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("invalid remote file path")
    # Open each component relative to the already opened parent. The final
    # type check and content read both use the descriptor returned by open.
    directory = open_directories(os.dup(root), parts[:-1], search_flags)
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("remote entry is not a regular file")
            shutil.copyfileobj(source, sys.stdout.buffer, 64 * 1024)
    finally:
        os.close(directory)


def main():
    if sys.version_info < (3, 7):
        raise ValueError("scheduled source collection requires Python 3.7 or later")
    mode, root_path, *arguments = sys.argv[1:]
    parts = root_path.split("/")
    if not root_path.startswith("/") or ".." in parts:
        raise ValueError("remote directory must be an absolute path without parent components")
    directory_flags = os.O_DIRECTORY | os.O_NOFOLLOW
    # Linux O_PATH allows traversal through ancestors with search permission.
    search_flags = directory_flags | getattr(os, "O_PATH", os.O_RDONLY)
    root = open_directories(os.open("/", search_flags), (part for part in parts if part not in {"", "."}), search_flags)
    try:
        if mode == "list":
            list_files(root, arguments, directory_flags | os.O_RDONLY)
        elif mode == "fetch" and len(arguments) == 1:
            fetch_file(root, arguments[0], search_flags)
        else:
            raise ValueError("invalid scheduled source operation")
    finally:
        os.close(root)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print("scheduled source collection: {}".format(error), file=sys.stderr)
        sys.exit(125)
