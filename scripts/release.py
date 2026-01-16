#!/usr/bin/env python3
"""Release automation script for log-analyzer-mcp.

Updates version numbers in pyproject.toml and __init__.py,
and adds a new entry to CHANGELOG.md.

Usage:
    python scripts/release.py 0.4.0
"""

import re
import sys
from datetime import date
from pathlib import Path


def update_pyproject_toml(version: str) -> None:
    """Update version in pyproject.toml."""
    path = Path("pyproject.toml")
    content = path.read_text()

    # Match version = "x.y.z" pattern
    new_content = re.sub(
        r'^version = "[^"]+"',
        f'version = "{version}"',
        content,
        flags=re.MULTILINE,
    )

    if new_content == content:
        print("Warning: No version found in pyproject.toml")
        return

    path.write_text(new_content)
    print(f"  Updated pyproject.toml to {version}")


def update_init_py(version: str) -> None:
    """Update version in __init__.py."""
    path = Path("codesdevs_log_analyzer/__init__.py")
    content = path.read_text()

    # Match __version__ = "x.y.z" pattern
    new_content = re.sub(
        r'^__version__ = "[^"]+"',
        f'__version__ = "{version}"',
        content,
        flags=re.MULTILINE,
    )

    if new_content == content:
        print("Warning: No __version__ found in __init__.py")
        return

    path.write_text(new_content)
    print(f"  Updated __init__.py to {version}")


def update_changelog(version: str) -> None:
    """Add new version entry to CHANGELOG.md."""
    path = Path("CHANGELOG.md")
    content = path.read_text()

    today = date.today().isoformat()

    # Check if this version already exists
    if f"## [{version}]" in content:
        print(f"  Changelog already has entry for {version}")
        return

    # Find the first ## [x.y.z] entry and insert before it
    new_entry = f"""## [{version}] - {today}

### Changed

- (Add your changes here)

"""

    # Insert after the header section (after "adheres to Semantic Versioning")
    pattern = r'(\[Semantic Versioning\]\([^)]+\)\.)\n\n'
    new_content = re.sub(
        pattern,
        f'\\1\n\n{new_entry}',
        content,
    )

    if new_content == content:
        print("Warning: Could not find insertion point in CHANGELOG.md")
        return

    path.write_text(new_content)
    print(f"  Added CHANGELOG.md entry for {version}")


def validate_version(version: str) -> bool:
    """Validate semantic version format."""
    pattern = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$'
    return bool(re.match(pattern, version))


def get_current_version() -> str:
    """Get current version from pyproject.toml."""
    path = Path("pyproject.toml")
    content = path.read_text()
    match = re.search(r'^version = "([^"]+)"', content, flags=re.MULTILINE)
    if match:
        return match.group(1)
    return "unknown"


def main() -> int:
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: python scripts/release.py VERSION")
        print("  Example: python scripts/release.py 0.4.0")
        return 1

    version = sys.argv[1]

    # Strip 'v' prefix if provided
    if version.startswith('v'):
        version = version[1:]

    if not validate_version(version):
        print(f"Error: Invalid version format '{version}'")
        print("  Expected format: x.y.z (e.g., 0.4.0, 1.0.0-beta)")
        return 1

    current = get_current_version()
    print(f"Updating version: {current} → {version}")

    update_pyproject_toml(version)
    update_init_py(version)
    update_changelog(version)

    print(f"✅ Version updated to {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
