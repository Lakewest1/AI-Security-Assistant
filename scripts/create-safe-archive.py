#!/usr/bin/env python3
"""Create a source archive after independent path and content checks."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
CHUNK_SIZE = 64 * 1024
SCAN_OVERLAP = 1024

# Exact path components avoid excluding ordinary source files whose names merely
# contain words such as "build" or "cache".
EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "out",
    "coverage",
    ".cache",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".vite",
    ".turbo",
    ".next",
    ".parcel-cache",
    ".nyc_output",
    ".venv",
    "venv",
    "bower_components",
    ".idea",
    "logs",
    "tmp",
    "temp",
}
EXCLUDED_FILENAMES = {
    ".ds_store",
    "thumbs.db",
    "desktop.ini",
    "npm-debug.log",
    "yarn-debug.log",
    "yarn-error.log",
    "pnpm-debug.log",
    "local.settings.json",
    "credentials.json",
    "service-account.json",
    "secrets.json",
    "secrets.yml",
    "secrets.yaml",
}
EXCLUDED_SUFFIXES = {
    ".log",
    ".tmp",
    ".temp",
    ".swp",
    ".swo",
    ".bak",
    ".orig",
    ".rej",
    ".pyc",
    ".pyo",
    ".class",
    ".zip",
    ".7z",
    ".tar",
    ".gz",
}
PRIVATE_KEY_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".keystore"}
PRIVATE_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
TEMPLATE_SUFFIXES = (".example", ".sample", ".template")

# Detection rules are intentionally narrow. Findings contain only this rule ID
# and the relative path; matched bytes are never included in messages.
SECRET_PATTERNS = (
    ("pem-private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key-id", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    (
        "credential-assignment",
        re.compile(
            rb"(?im)^\s*[{,]?\s*[\"']?(?:[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|CLIENT[_-]?SECRET|PASSWORD|PASSWD|SECRET|TOKEN)[A-Z0-9_]*)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{12,512})"
        ),
    ),
)
PLACEHOLDER_RE = re.compile(
    rb"(?i)(?:your[-_].*|.*placeholder.*|.*example.*|changeme|change[-_ ]?me|replace[-_ ]?me|<[^>]+>|\$\{[^}]+\}|\.\.\.)"
)
ASSIGNMENT_SCAN_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".properties", ".example", ".sample", ".template"}


class ArchivePolicyError(Exception):
    def __init__(self, message: str, *, path: str | None = None, rule: str | None = None):
        super().__init__(message)
        self.path = path
        self.rule = rule


def _safe_relative_name(name: str) -> tuple[str, tuple[str, ...]]:
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ArchivePolicyError("unsafe archive member name", path=str(name), rule="unsafe-path")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ArchivePolicyError("unsafe archive member name", path=name, rule="unsafe-path")
    if "\\" in name:
        # ZIP names must be canonical POSIX paths. Treat backslashes as path
        # separators for detection, then reject the noncanonical spelling.
        normalized_for_check = name.replace("\\", "/")
        raise ArchivePolicyError(
            "noncanonical archive path separator",
            path=normalized_for_check,
            rule="unsafe-separator",
        )
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or name.startswith("//"):
        raise ArchivePolicyError("absolute archive member path", path=name, rule="absolute-path")
    is_directory = name.endswith("/")
    body = name[:-1] if is_directory else name
    parts = tuple(body.split("/"))
    if not body or any(part in {"", ".", ".."} for part in parts):
        raise ArchivePolicyError("unsafe archive member path component", path=name, rule="path-traversal")
    if any(":" in part for part in parts):
        raise ArchivePolicyError("unsafe archive path syntax", path=name, rule="unsafe-path")
    return "/".join(parts), parts


def _is_template(name: str) -> bool:
    return name.lower().endswith(TEMPLATE_SUFFIXES)


def prohibited_member_rule(name: str) -> str | None:
    """Return an exclusion rule ID for a normalized, relative POSIX path."""
    normalized, parts = _safe_relative_name(name.rstrip("/"))
    lower_parts = tuple(part.lower() for part in parts)
    basename = lower_parts[-1]

    if any(part in EXCLUDED_DIRS for part in lower_parts[:-1]):
        return "generated-or-local-directory"
    if basename == ".git" or basename == ".env" or (basename.startswith(".env.") and basename != ".env.example"):
        return "environment-or-repository-metadata"
    if basename in EXCLUDED_FILENAMES:
        return "local-credentials-or-generated-file"
    if ".local." in basename or basename.endswith(".local"):
        return "local-only-configuration"

    # Explicit templates are permitted, except environment variants other than
    # the single reviewed .env.example file.
    if basename == ".env.example":
        return None
    if basename.startswith(".env."):
        return "environment-file"
    if _is_template(basename):
        return None

    suffix = Path(basename).suffix.lower()
    if suffix in EXCLUDED_SUFFIXES:
        return "generated-or-temporary-file"
    if ".log." in basename or suffix in {".map", ".tsbuildinfo"}:
        return "generated-or-temporary-file"
    if suffix in PRIVATE_KEY_SUFFIXES or basename in PRIVATE_KEY_NAMES or any(
        basename.startswith(key_name + ".") for key_name in PRIVATE_KEY_NAMES
    ):
        return "private-key-file"
    if basename.endswith("~"):
        return "temporary-file"
    return None


def _scan_stream(stream: Iterable[bytes], *, include_assignments: bool = False) -> str | None:
    overlap = b""
    for chunk in stream:
        data = overlap + chunk
        for rule, pattern in SECRET_PATTERNS:
            if rule == "credential-assignment" and not include_assignments:
                continue
            match = pattern.search(data)
            if match:
                if rule == "credential-assignment":
                    value = match.group(1)
                    if PLACEHOLDER_RE.fullmatch(value):
                        continue
                    if any(reference in value.lower() for reference in (b"process.env", b"options.", b"config.", b"getenv", b"undefined", b"null")):
                        continue
                return rule
        overlap = data[-SCAN_OVERLAP:]
    return None


def scan_file(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            include_assignments = path.suffix.lower() in ASSIGNMENT_SCAN_SUFFIXES
            return _scan_stream(iter(lambda: stream.read(CHUNK_SIZE), b""), include_assignments=include_assignments)
    except OSError:
        raise ArchivePolicyError("unable to read candidate file", path=path.name, rule="read-error") from None


def iter_candidates(root: Path) -> Iterable[Path]:
    root = root.resolve()
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs = []
        for dirname in dirs:
            candidate_dir = current_path / dirname
            if dirname.lower() in EXCLUDED_DIRS or candidate_dir.is_symlink():
                continue
            rel_dir = candidate_dir.relative_to(root).as_posix()
            if prohibited_member_rule(rel_dir + "/") is None:
                kept_dirs.append(dirname)
        dirs[:] = kept_dirs

        for filename in files:
            path = current_path / filename
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if prohibited_member_rule(relative) is None:
                yield path


def validate_candidate_tree(root: Path) -> int:
    count = 0
    for path in iter_candidates(root):
        relative = path.relative_to(root).as_posix()
        rule = scan_file(path)
        if rule:
            raise ArchivePolicyError("credential pattern detected", path=relative, rule=rule)
        count += 1
    return count


def validate_zip(archive_path: Path) -> int:
    """Independently check all member names and content without extraction."""
    count = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for info in archive.infolist():
                # ZipInfo.filename normalizes backslashes on Windows. Inspect
                # orig_filename so the check sees the spelling stored in ZIP.
                raw_name = getattr(info, "orig_filename", info.filename)
                normalized, parts = _safe_relative_name(raw_name)
                rule = prohibited_member_rule(normalized)
                if rule:
                    raise ArchivePolicyError("prohibited ZIP member", path=normalized, rule=rule)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ArchivePolicyError("symbolic link member is prohibited", path=normalized, rule="symlink-member")
                if info.is_dir():
                    continue
                with archive.open(info, "r") as stream:
                    include_assignments = Path(normalized).suffix.lower() in ASSIGNMENT_SCAN_SUFFIXES
                    rule = _scan_stream(
                        iter(lambda: stream.read(CHUNK_SIZE), b""),
                        include_assignments=include_assignments,
                    )
                if rule:
                    raise ArchivePolicyError("credential pattern detected", path=normalized, rule=rule)
                count += 1
    except ArchivePolicyError:
        raise
    except Exception:
        # Avoid formatting exception text: ZIP errors can embed member details.
        raise ArchivePolicyError("unable to validate completed ZIP", rule="invalid-zip") from None
    return count


def _resolve_output(output: str, root: Path) -> Path:
    path = Path(output).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return resolved
    raise ArchivePolicyError("output path must be outside the source tree", path="<output>", rule="output-inside-source")


def _report_error(error: ArchivePolicyError) -> None:
    details = []
    if error.path:
        safe_path = str(error.path).encode("unicode_escape", errors="backslashreplace").decode("ascii")
        details.append(f"path={safe_path}")
    if error.rule:
        details.append(f"rule={error.rule}")
    suffix = f" ({', '.join(details)})" if details else ""
    print(f"Archive validation failed{suffix}.", file=sys.stderr)


def main(argv: list[str] | None = None, *, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description="Create a validated source ZIP outside the project tree.")
    parser.add_argument("--output", required=True, help="new ZIP path outside the source tree (must not already exist)")
    parser.add_argument("--check-only", action="store_true", help="scan eligible files without creating a ZIP")
    args = parser.parse_args(argv)

    temporary_path: Path | None = None
    try:
        root = root.resolve()
        output = _resolve_output(args.output, root)
        if os.path.lexists(output):
            raise ArchivePolicyError("output already exists", path="<output>", rule="output-exists")
        if not output.parent.is_dir():
            raise ArchivePolicyError("output directory does not exist", path="<output>", rule="output-directory")

        if args.check_only:
            count = validate_candidate_tree(root)
            print(f"Candidate check passed: {count} eligible files scanned; no archive created.")
            return 0

        candidates = list(iter_candidates(root))
        for path in candidates:
            relative = path.relative_to(root).as_posix()
            rule = scan_file(path)
            if rule:
                raise ArchivePolicyError("credential pattern detected", path=relative, rule=rule)

        fd, temp_name = tempfile.mkstemp(prefix=".safe-archive-", suffix=".tmp", dir=output.parent)
        os.close(fd)
        temporary_path = Path(temp_name)
        with zipfile.ZipFile(temporary_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in candidates:
                archive.write(path, path.relative_to(root).as_posix())

        count = validate_zip(temporary_path)
        # Hard-link publication is atomic and fails if another process created
        # the destination after the initial existence check. The temp is in the
        # same directory, so this does not cross filesystems.
        os.link(temporary_path, output)
        temporary_path.unlink()
        temporary_path = None
        print(f"Validated archive created: {output} ({count} files).")
        return 0
    except ArchivePolicyError as error:
        _report_error(error)
        return 1
    except OSError:
        print("Archive creation failed (rule=io-error).", file=sys.stderr)
        return 1
    except Exception:
        # Keep unexpected library errors bounded and avoid echoing file content.
        print("Archive creation failed (rule=unexpected-error).", file=sys.stderr)
        return 1
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                print("Temporary archive cleanup failed (rule=cleanup-error).", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
