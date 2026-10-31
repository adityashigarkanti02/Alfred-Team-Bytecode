#!/usr/bin/env python3
"""
ALFRED Local Filesystem Sandbox — Strict Folder Chroot Jail.

Enforces that file operations (read, write, edit, delete, list) are strictly
confined to a single designated folder (e.g. ALFRED_WORKSPACE_DIR).
Attempts to escape via '..', absolute paths, or symlinks pointing outside
are strictly blocked and audited.
"""
from __future__ import annotations

import hashlib
import os
import posixpath
import shutil
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_WORKSPACE = os.path.abspath(
    os.environ.get("ALFRED_WORKSPACE_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "workspace"))
)


class SandboxSecurityError(Exception):
    """Raised when a path traversal or escape from the designated folder is attempted."""
    pass


def get_workspace_dir() -> str:
    """Return the absolute, canonical workspace root directory."""
    path = os.environ.get("ALFRED_WORKSPACE_DIR", DEFAULT_WORKSPACE)
    canonical = os.path.realpath(os.path.abspath(path))
    os.makedirs(canonical, exist_ok=True)
    return canonical


def is_path_inside_sandbox(resolved_path: str, workspace_root: str) -> bool:
    """Check if resolved_path is inside workspace_root."""
    try:
        common = os.path.commonpath([resolved_path, workspace_root])
        return common == workspace_root
    except ValueError:
        # Different drives or mismatched roots
        return False


def resolve_safe_path(requested_path: str, must_exist: bool = False) -> Tuple[str, str]:
    """
    Safely resolves a path strictly within the workspace sandbox folder.

    Returns:
        (canonical_absolute_path, relative_path_from_workspace)

    Raises:
        SandboxSecurityError: if the path traverses or resolves outside the workspace.
    """
    workspace = get_workspace_dir()
    raw = str(requested_path or "").strip()

    if not raw:
        raise SandboxSecurityError("Empty file path is not allowed.")

    if "\0" in raw:
        raise SandboxSecurityError("Null bytes in file path are rejected.")

    # Normalize slashes
    clean = raw.replace("\\", "/")

    # If the user passed an absolute path that starts with the workspace root, keep it;
    # otherwise, treat absolute paths as relative to the workspace root.
    if os.path.isabs(clean):
        # Check if it literally starts with the workspace root
        if clean == workspace or clean.startswith(workspace + "/"):
            candidate = clean
        else:
            # Strip leading slashes and append to workspace
            rel = clean.lstrip("/")
            candidate = os.path.join(workspace, rel)
    else:
        candidate = os.path.join(workspace, clean)

    # Resolve all symlinks and '..' components
    canonical = os.path.realpath(os.path.abspath(candidate))

    # Strict chroot containment check
    if not is_path_inside_sandbox(canonical, workspace):
        raise SandboxSecurityError(
            f"Path traversal violation: '{raw}' resolves to '{canonical}' outside sandbox '{workspace}'"
        )

    # Check for forbidden sensitive directories within the sandbox (e.g. .git, .env)
    rel_path = os.path.relpath(canonical, workspace).replace("\\", "/")
    parts = rel_path.split("/")
    if any(p == ".git" for p in parts) or rel_path in (".env", "id_rsa", "id_ed25519"):
        raise SandboxSecurityError(f"Access to protected internal file '{rel_path}' is denied.")

    if must_exist and not os.path.exists(canonical):
        raise FileNotFoundError(f"File '{rel_path}' does not exist in sandbox workspace.")

    return canonical, rel_path


def read_file(path: str, max_chars: int = 100000) -> Dict[str, Any]:
    """Read actual file from the workspace sandbox."""
    canonical, rel_path = resolve_safe_path(path, must_exist=True)

    if os.path.isdir(canonical):
        raise IsADirectoryError(f"'{rel_path}' is a directory, not a file.")

    size = os.path.getsize(canonical)
    with open(canonical, "rb") as f:
        raw_bytes = f.read(max_chars + 1024)

    # Attempt UTF-8 decoding; fall back to replace
    try:
        text = raw_bytes.decode("utf-8")
        is_binary = False
    except UnicodeDecodeError:
        text = raw_bytes.decode("latin-1", errors="replace")
        is_binary = True

    sha256 = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
    truncated = len(text) > max_chars
    visible_text = text[:max_chars]

    return {
        "path": "/" + rel_path,
        "canonical_path": canonical,
        "content": visible_text,
        "size": size,
        "is_binary": is_binary,
        "truncated": truncated,
        "sha256": sha256,
    }


def write_file(path: str, content: str) -> Dict[str, Any]:
    """Write actual file to the workspace sandbox, creating parent dirs if needed."""
    canonical, rel_path = resolve_safe_path(path, must_exist=False)

    parent_dir = os.path.dirname(canonical)
    os.makedirs(parent_dir, exist_ok=True)

    text = str(content if content is not None else "")
    raw_bytes = text.encode("utf-8")

    with open(canonical, "wb") as f:
        f.write(raw_bytes)

    sha256 = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()

    return {
        "path": "/" + rel_path,
        "canonical_path": canonical,
        "bytes": len(raw_bytes),
        "sha256": sha256,
        "created": True,
    }


def edit_file(
    path: str,
    target: Optional[str] = None,
    replacement: Optional[str] = None,
    content: Optional[str] = None,
    append: bool = False,
) -> Dict[str, Any]:
    """
    Edit an actual file in the workspace sandbox.

    Modes:
    1. append=True: Appends content to the end of the file.
    2. target & replacement: Replaces exact occurrences of target string.
    3. content provided: Overwrites entire file content.
    """
    canonical, rel_path = resolve_safe_path(path, must_exist=not append)

    if not os.path.exists(canonical) and not append:
        raise FileNotFoundError(f"Cannot edit '{rel_path}': file does not exist.")

    old_content = ""
    if os.path.exists(canonical):
        with open(canonical, "r", encoding="utf-8", errors="replace") as f:
            old_content = f.read()

    old_sha256 = "sha256:" + hashlib.sha256(old_content.encode("utf-8")).hexdigest()

    if append:
        add_text = str(content or replacement or "")
        new_content = old_content + add_text
        mode_used = "append"
        replaced_count = 1
    elif target is not None:
        if target not in old_content:
            raise SandboxSecurityError(f"Target text not found in '{rel_path}' for replacement.")
        replaced_count = old_content.count(target)
        new_content = old_content.replace(target, replacement or "")
        mode_used = "replace_target"
    elif content is not None:
        new_content = str(content)
        mode_used = "overwrite"
        replaced_count = 1
    else:
        raise SandboxSecurityError("Must provide either 'target' & 'replacement', 'content', or 'append=True'.")

    # Write new content
    parent_dir = os.path.dirname(canonical)
    os.makedirs(parent_dir, exist_ok=True)
    raw_bytes = new_content.encode("utf-8")
    with open(canonical, "wb") as f:
        f.write(raw_bytes)

    new_sha256 = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()

    return {
        "path": "/" + rel_path,
        "canonical_path": canonical,
        "mode": mode_used,
        "replaced_count": replaced_count,
        "bytes": len(raw_bytes),
        "old_sha256": old_sha256,
        "sha256": new_sha256,
    }


def delete_file(path: str) -> Dict[str, Any]:
    """Delete an actual file from the workspace sandbox."""
    canonical, rel_path = resolve_safe_path(path, must_exist=False)

    if not os.path.exists(canonical):
        return {"path": "/" + rel_path, "deleted": False, "note": "File did not exist"}

    if os.path.isdir(canonical):
        shutil.rmtree(canonical)
    else:
        os.remove(canonical)

    return {"path": "/" + rel_path, "deleted": True}


def list_files(subpath: str = "") -> List[Dict[str, Any]]:
    """List actual files in the workspace sandbox."""
    workspace = get_workspace_dir()
    if subpath:
        target_dir, _ = resolve_safe_path(subpath, must_exist=True)
    else:
        target_dir = workspace

    results = []
    for root, dirs, files in os.walk(target_dir):
        # Skip .git
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, workspace).replace("\\", "/")
            try:
                sz = os.path.getsize(full)
                results.append({
                    "path": "/" + rel,
                    "size": sz,
                    "is_file": True,
                })
            except OSError:
                pass

    results.sort(key=lambda x: x["path"])
    return results
