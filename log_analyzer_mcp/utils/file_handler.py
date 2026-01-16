"""File handling utilities for streaming log file operations."""

import gzip
import os
from collections import deque
from collections.abc import Iterator
from pathlib import Path

import chardet

# Type alias for file path arguments
PathLike = str | Path


def _ensure_str_path(file_path: PathLike) -> str:
    """Convert Path to string if needed."""
    if isinstance(file_path, Path):
        return str(file_path)
    return file_path


# ============================================================================
# Encoding Detection
# ============================================================================


def detect_encoding(file_path: PathLike, sample_size: int = 65536) -> str:
    """
    Detect file encoding using chardet.

    Reads a sample of the file to determine encoding. Falls back to utf-8
    if detection fails or confidence is low.

    Args:
        file_path: Path to the file
        sample_size: Number of bytes to sample for detection

    Returns:
        Detected encoding name (e.g., 'utf-8', 'latin-1')
    """
    file_path = _ensure_str_path(file_path)
    try:
        with open(file_path, "rb") as f:
            raw_data = f.read(sample_size)

        if not raw_data:
            return "utf-8"

        result = chardet.detect(raw_data)

        # Use detected encoding if confidence is high enough
        if result["encoding"] and result["confidence"] and result["confidence"] > 0.7:
            encoding = result["encoding"].lower()
            # Normalize common encoding names
            if encoding in ("ascii", "utf-8-sig"):
                return "utf-8"
            return encoding

    except OSError:
        pass

    return "utf-8"


def is_gzip_file(file_path: PathLike) -> bool:
    """
    Check if file is gzip compressed.

    Checks both file extension and magic bytes.

    Args:
        file_path: Path to the file

    Returns:
        True if file is gzip compressed
    """
    file_path = _ensure_str_path(file_path)
    # Check extension first
    if file_path.endswith(".gz"):
        return True

    # Check magic bytes
    try:
        with open(file_path, "rb") as f:
            magic = f.read(2)
            return magic == b"\x1f\x8b"
    except OSError:
        return False


# ============================================================================
# File Streaming
# ============================================================================


def stream_file(
    file_path: PathLike,
    encoding: str | None = None,
    max_lines: int | None = None,
    skip_empty: bool = False,
) -> Iterator[tuple[int, str]]:
    """
    Stream file lines without loading entire file into memory.

    Handles gzip files transparently and auto-detects encoding if not specified.

    Args:
        file_path: Path to the log file
        encoding: File encoding (auto-detected if None)
        max_lines: Maximum lines to yield (None for all)
        skip_empty: Whether to skip empty lines

    Yields:
        Tuples of (line_number, line_content) with line_number 1-indexed
    """
    file_path = _ensure_str_path(file_path)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    # Detect encoding if not provided
    if encoding is None:
        encoding = detect_encoding(file_path)

    # Determine if gzip compressed
    is_gzip = is_gzip_file(file_path)

    line_number = 0
    yielded = 0

    try:
        if is_gzip:
            opener = gzip.open(file_path, "rt", encoding=encoding, errors="replace")  # noqa: SIM115
        else:
            opener = open(file_path, encoding=encoding, errors="replace")  # noqa: SIM115

        with opener as f:
            for line in f:
                line_number += 1
                line = line.rstrip("\n\r")

                if skip_empty and not line.strip():
                    continue

                yield line_number, line
                yielded += 1

                if max_lines is not None and yielded >= max_lines:
                    break

    except UnicodeDecodeError:
        # Retry with latin-1 as fallback
        if encoding != "latin-1":
            yield from stream_file(
                file_path, encoding="latin-1", max_lines=max_lines, skip_empty=skip_empty
            )


def stream_file_chunk(
    file_path: PathLike,
    start_line: int = 1,
    end_line: int | None = None,
    encoding: str | None = None,
) -> Iterator[tuple[int, str]]:
    """
    Stream a specific chunk of lines from a file.

    Args:
        file_path: Path to the log file
        start_line: First line to include (1-indexed)
        end_line: Last line to include (None for all remaining)
        encoding: File encoding (auto-detected if None)

    Yields:
        Tuples of (line_number, line_content)
    """
    for line_num, line in stream_file(file_path, encoding=encoding):
        if line_num < start_line:
            continue
        if end_line is not None and line_num > end_line:
            break
        yield line_num, line


# ============================================================================
# Tail Operations
# ============================================================================


def read_tail(
    file_path: PathLike,
    n_lines: int = 50,
    encoding: str | None = None,
) -> list[tuple[int, str]]:
    """
    Read last N lines from file efficiently.

    Uses seek from end for large files to avoid reading entire file.

    Args:
        file_path: Path to the log file
        n_lines: Number of lines to read from end
        encoding: File encoding (auto-detected if None)

    Returns:
        List of (line_number, line_content) tuples for last N lines
    """
    file_path = _ensure_str_path(file_path)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    if encoding is None:
        encoding = detect_encoding(file_path)

    is_gzip = is_gzip_file(file_path)

    # For gzip files, we must read through entire file
    if is_gzip:
        return _read_tail_sequential(file_path, n_lines, encoding, is_gzip=True)

    # For regular files, try efficient seek-based approach
    file_size = os.path.getsize(file_path)

    # Small files: just read sequentially
    if file_size < 1024 * 1024:  # < 1MB
        return _read_tail_sequential(file_path, n_lines, encoding, is_gzip=False)

    # Large files: use seek-based approach
    return _read_tail_seek(file_path, n_lines, encoding)


def _read_tail_sequential(
    file_path: str,
    n_lines: int,
    encoding: str,
    is_gzip: bool,
) -> list[tuple[int, str]]:
    """Read tail by streaming through file."""
    buffer: deque[tuple[int, str]] = deque(maxlen=n_lines)

    for line_num, line in stream_file(file_path, encoding=encoding):
        buffer.append((line_num, line))

    return list(buffer)


def _read_tail_seek(
    file_path: str,
    n_lines: int,
    encoding: str,
) -> list[tuple[int, str]]:
    """Read tail using seek from end of file."""
    with open(file_path, "rb") as f:
        # Start from end
        f.seek(0, 2)  # Seek to end
        file_size = f.tell()

        # Read chunks from end until we have enough lines
        chunk_size = 8192
        lines_found: list[bytes] = []
        position = file_size

        while len(lines_found) <= n_lines and position > 0:
            # Calculate next chunk position
            read_size = min(chunk_size, position)
            position -= read_size
            f.seek(position)

            chunk = f.read(read_size)

            # Split into lines and prepend to buffer
            chunk_lines = chunk.split(b"\n")

            # Merge with existing partial line
            if lines_found:
                chunk_lines[-1] = chunk_lines[-1] + lines_found[0]
                lines_found = chunk_lines + lines_found[1:]
            else:
                lines_found = chunk_lines

            # Double chunk size for faster convergence
            chunk_size = min(chunk_size * 2, 65536)

    # Decode and take last N lines
    result_lines = lines_found[-n_lines:] if lines_found else []

    # Now we need line numbers - count total lines
    total_lines = sum(1 for _ in stream_file(file_path, encoding=encoding))
    start_line_num = max(1, total_lines - len(result_lines) + 1)

    result: list[tuple[int, str]] = []
    for i, line_bytes in enumerate(result_lines):
        try:
            line_str = line_bytes.decode(encoding, errors="replace").rstrip("\r")
            result.append((start_line_num + i, line_str))
        except Exception:
            result.append(
                (start_line_num + i, line_bytes.decode("latin-1", errors="replace").rstrip("\r"))
            )

    return result


# ============================================================================
# File Information
# ============================================================================


def get_file_info(file_path: PathLike) -> dict[str, str | int | float | bool]:
    """
    Get information about a log file.

    Args:
        file_path: Path to the log file

    Returns:
        Dictionary with file information
    """
    file_path = _ensure_str_path(file_path)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    stat = os.stat(file_path)
    encoding = detect_encoding(file_path)
    is_gzip = is_gzip_file(file_path)

    return {
        "path": file_path,
        "size_bytes": stat.st_size,
        "size_human": _format_size(stat.st_size),
        "encoding": encoding,
        "is_compressed": is_gzip,
        "modified_time": stat.st_mtime,
    }


def count_lines(file_path: PathLike, encoding: str | None = None) -> int:
    """
    Count total lines in file efficiently.

    Args:
        file_path: Path to the log file
        encoding: File encoding (auto-detected if None)

    Returns:
        Total number of lines
    """
    count = 0
    for _ in stream_file(file_path, encoding=encoding):
        count += 1
    return count


def _format_size(size_bytes: int) -> str:
    """Format byte size as human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes = int(size_bytes / 1024)
    return f"{size_bytes:.1f} PB"


# ============================================================================
# Context Window
# ============================================================================


def get_lines_with_context(
    file_path: PathLike,
    target_lines: list[int],
    context_before: int = 3,
    context_after: int = 3,
    encoding: str | None = None,
) -> dict[int, dict[str, list[str] | str]]:
    """
    Get specific lines with surrounding context.

    Args:
        file_path: Path to the log file
        target_lines: Line numbers to get (1-indexed)
        context_before: Lines to include before each target
        context_after: Lines to include after each target
        encoding: File encoding (auto-detected if None)

    Returns:
        Dictionary mapping line numbers to context dicts
    """
    # Calculate which lines we need to cache
    min_target = min(target_lines) if target_lines else 1
    max_target = max(target_lines) if target_lines else 1
    start_cache = max(1, min_target - context_before)
    end_cache = max_target + context_after

    # Read relevant lines
    line_cache: dict[int, str] = {}
    for line_num, line in stream_file(file_path, encoding=encoding):
        if line_num < start_cache:
            continue
        if line_num > end_cache:
            break
        line_cache[line_num] = line

    # Build result
    result: dict[int, dict[str, list[str] | str]] = {}
    for target in target_lines:
        if target not in line_cache:
            continue

        before = [line_cache[i] for i in range(target - context_before, target) if i in line_cache]
        after = [
            line_cache[i] for i in range(target + 1, target + context_after + 1) if i in line_cache
        ]

        result[target] = {
            "before": before,
            "line": line_cache[target],
            "after": after,
        }

    return result
