from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any


TOOL_VERSION = "2026.05.07-compact-essential-compressed"
DEFAULT_BACKUP_ROOT = Path(r"F:\backup\windowsapps\AppsBackups\installed")
MAX_HASH_BYTES = 64 * 1024 * 1024
RESTORE_CONFIRM_TEXT = "RESTORE INSTALLED APPS"
WSL_PROBE_TIMEOUT_SECONDS = 30
DEFAULT_WSL_IDLE_WAIT_SECONDS = 7200
FILE_INDEX_ARCHIVE_PATH = "metadata/file-index.jsonl"
SKIPPED_FILE_INDEX_ARCHIVE_PATH = "metadata/skipped-file-index.jsonl"
ZIP_COMPRESSION_METHOD = zipfile.ZIP_DEFLATED
ZIP_COMPRESSLEVEL = 6

RESTORE_COVERAGE_ARCHIVE_FRAGMENTS = (
    "Microsoft/Windows/Start Menu/Programs/Startup",
    "Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar",
    "Microsoft/Windows/Start Menu",
    "Microsoft/Windows/Recent/AutomaticDestinations",
    "Microsoft/Windows/Recent/CustomDestinations",
    "/Desktop/",
    "SetUserFTA.exe",
    "Microsoft/Vault",
    "Microsoft/Credentials",
    "Microsoft/Protect",
    "Microsoft/Crypto",
    "Microsoft/Ngc",
    "Google/Chrome/User Data",
    "Microsoft/Edge/User Data",
    "Mozilla/Firefox",
    "Telegram Desktop/tdata",
    "Todoist",
    ".codex",
    ".claude",
    ".docker",
    "Docker",
)

START_MENU_SHELL_DESKTOP_INI_FOLDERS = {
    "accessibility",
    "accessories",
    "administrative tools",
    "maintenance",
    "startup",
    "system tools",
    "windows accessories",
    "windows administrative tools",
    "windows ease of access",
    "windows powershell",
}

VOLATILE_PART_SEQUENCES = (
    ("appdata", "local", "temp"),
    ("appdata", "local", "crashdumps"),
    ("appdata", "local", "microsoft", "windows", "inetcache"),
    ("appdata", "local", "microsoft", "windows", "explorer"),
    ("appdata", "local", "packages", "microsoft.windows.search"),
    ("programdata", "microsoft", "windows defender", "scans", "history"),
    ("programdata", "microsoft", "windows", "wer"),
    ("programdata", "microsoft", "search", "data"),
)

RECREATABLE_PART_SEQUENCES = (
    ("appdata", "local", "pip", "cache"),
    ("appdata", "local", "npm-cache"),
    ("appdata", "local", "pnpm", "store"),
    ("appdata", "local", "yarn", "cache"),
    ("appdata", "local", "microsoft", "visualstudio", "packages"),
    ("programdata", "package cache"),
    ("programdata", "microsoft", "visualstudio", "packages"),
    ("programdata", "microsoft", "visualstudio", "setup"),
    ("programdata", "chocolatey", "cache"),
    (".nuget", "packages"),
)

CACHE_DIRECTORY_NAMES = {
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "cache",
    "cache2",
    "caches",
    "cachestorage",
    "code cache",
    "crashpad",
    "crashes",
    "dawncache",
    "gpucache",
    "gpu cache",
    "logs",
    "log",
    "shadercache",
    "temp",
    "tmp",
}

USER_RECREATABLE_DIRECTORY_NAMES = {
    ".git",
    ".gradle",
    ".tox",
    ".venv",
    "__pypackages__",
    "node_modules",
    "venv",
}

WSL_PACKAGE_PUBLISHER_PREFIXES = (
    "canonicalgrouplimited.",
    "thedebianproject.",
    "suselinux.",
    "kali-linux.",
    "oraclelinux.",
)

OS_MANAGED_PART_SEQUENCES = (
    ("program files", "windowsapps"),
    ("program files", "windows defender"),
    ("program files", "windows defender advanced threat protection"),
    ("program files", "windowspowershell"),
    ("program files", "wsl"),
    ("programdata", "microsoft", "windows defender"),
    ("programdata", "microsoft", "windows", "apprepository"),
    ("programdata", "microsoft", "windows", "clipsvc"),
    ("programdata", "microsoft", "windows", "containers", "layers"),
)

BINARY_EXTENSIONS = {
    ".appx",
    ".dll",
    ".exe",
    ".msi",
    ".msix",
    ".node",
    ".pyd",
    ".sys",
}

BACKUP_SKIP_NAMES = {
    "$recycle.bin",
    "system volume information",
    "pagefile.sys",
    "swapfile.sys",
    "hiberfil.sys",
    "memory.dmp",
    "dumpstack.log.tmp",
}


class ToolError(Exception):
    pass


def now_local() -> dt.datetime:
    return dt.datetime.now().astimezone()


def text_for_console(text: str, encoding: str | None = None) -> str:
    target_encoding = encoding or getattr(sys.stdout, "encoding", None) or "utf-8"
    return text.encode(target_encoding, errors="backslashreplace").decode(target_encoding, errors="replace")


def console_print(message: str = "") -> None:
    print(text_for_console(message))


def normalize_backup_root(value: str | Path | None, create: bool = False) -> Path:
    root = DEFAULT_BACKUP_ROOT if value in (None, "") else Path(value).expanduser()
    root = root.resolve()
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


def is_elevated() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_command(args: list[str], timeout: int = 120, cwd: Path | None = None) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return {
            "args": args,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timed_out": False,
        }
    except FileNotFoundError as exc:
        return {"args": args, "returncode": 9009, "stdout": "", "stderr": str(exc), "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        return {
            "args": args,
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"Timed out after {timeout}s",
            "timed_out": True,
        }


def write_command_output(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = result.get("stdout") or result.get("stderr") or ""
    if result.get("timed_out") and "Timed out" not in text:
        text = (text + "\n" if text else "") + str(result.get("stderr") or "Timed out")
    path.write_text(str(text), encoding="utf-8", errors="replace")


def command_export_record(name: str, output: Path, metadata_dir: Path, result: dict[str, Any]) -> dict[str, Any]:
    status = "ok" if result["returncode"] == 0 and not result.get("timed_out") else "missing_or_failed"
    return {
        "name": name,
        "file": str(output.relative_to(metadata_dir)),
        "returncode": result["returncode"],
        "status": status,
        "timed_out": result.get("timed_out", False),
    }


def powershell_json(script: str, timeout: int = 120, executable: str = "powershell.exe") -> Any:
    result = run_command(
        [executable, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout,
    )
    if result["returncode"] != 0:
        raise ToolError(result["stderr"] or f"{executable} returned {result['returncode']}")
    output = result["stdout"].strip()
    if not output:
        return None
    return json.loads(output)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_jsonl_record(handle: Any, data: dict[str, Any]) -> None:
    handle.write(json.dumps(data, separators=(",", ":")) + "\n")


def normalized_archive_fragment(fragment: str) -> str:
    return fragment.replace("\\", "/").casefold()


def ensure_archive_presence_map(manifest: dict[str, Any]) -> dict[str, bool]:
    existing = manifest.get("archive_path_presence")
    if not isinstance(existing, dict):
        existing = {}
        manifest["archive_path_presence"] = existing
    for fragment in RESTORE_COVERAGE_ARCHIVE_FRAGMENTS:
        existing.setdefault(normalized_archive_fragment(fragment), False)
    return existing


def mark_archive_path_presence(manifest: dict[str, Any], archive_path: str) -> None:
    presence = ensure_archive_presence_map(manifest)
    normalized_path = normalized_archive_fragment(archive_path)
    for fragment in RESTORE_COVERAGE_ARCHIVE_FRAGMENTS:
        normalized_fragment = normalized_archive_fragment(fragment)
        if not presence.get(normalized_fragment) and normalized_fragment in normalized_path:
            presence[normalized_fragment] = True


def normalized_path_parts(path: Path) -> list[str]:
    return [part.casefold() for part in path.parts if part not in (path.anchor, "\\", "/")]


def find_contiguous_parts(parts: list[str], sequence: tuple[str, ...]) -> int | None:
    sequence_folded = tuple(part.casefold() for part in sequence)
    if not sequence_folded:
        return None
    for index in range(0, len(parts) - len(sequence_folded) + 1):
        if tuple(parts[index : index + len(sequence_folded)]) == sequence_folded:
            return index
    return None


def is_start_menu_programs_shell_desktop_ini_parts(parts: list[str]) -> bool:
    if not parts or parts[-1] != "desktop.ini":
        return False
    index = find_contiguous_parts(parts, ("microsoft", "windows", "start menu", "programs"))
    if index is None:
        return False
    after_programs = parts[index + 4 : -1]
    if not after_programs:
        return True
    return len(after_programs) == 1 and after_programs[0] in START_MENU_SHELL_DESKTOP_INI_FOLDERS


def is_windows_shell_desktop_ini(path: Path) -> bool:
    return is_start_menu_programs_shell_desktop_ini_parts(normalized_path_parts(path))


def should_skip_restore_item(item: dict[str, Any], destination: Path) -> bool:
    return is_windows_shell_desktop_ini(destination)


def should_skip_backup_path(path: Path) -> bool:
    parts = normalized_path_parts(path)
    if not parts:
        return False
    if parts[-1] in BACKUP_SKIP_NAMES:
        return True
    if any(part in CACHE_DIRECTORY_NAMES for part in parts):
        return True
    if is_windows_shell_desktop_ini(path):
        return True
    if is_exported_wsl_package_vhdx_duplicate(path, parts):
        return True
    if is_docker_wsl_raw_data_duplicate(path, parts):
        return True
    if is_user_recreatable_dependency_tree(parts):
        return True
    if any(find_contiguous_parts(parts, sequence) is not None for sequence in OS_MANAGED_PART_SEQUENCES):
        return True
    return any(
        find_contiguous_parts(parts, sequence) is not None
        for sequence in (*VOLATILE_PART_SEQUENCES, *RECREATABLE_PART_SEQUENCES)
    )


def is_exported_wsl_package_vhdx_duplicate(path: Path, parts: list[str] | None = None) -> bool:
    parts = parts or normalized_path_parts(path)
    if not parts or parts[-1] != "ext4.vhdx":
        return False
    package_index = find_contiguous_parts(parts, ("appdata", "local", "packages"))
    if package_index is None or "localstate" not in parts[package_index + 3 :]:
        return False
    package_name_index = package_index + 3
    if package_name_index >= len(parts):
        return False
    package_name = parts[package_name_index]
    return package_name.startswith(WSL_PACKAGE_PUBLISHER_PREFIXES)


def is_docker_wsl_raw_data_duplicate(path: Path, parts: list[str] | None = None) -> bool:
    parts = parts or normalized_path_parts(path)
    if not parts or parts[-1] != "ext4.vhdx":
        return False
    return find_contiguous_parts(parts, ("appdata", "local", "docker", "wsl")) is not None


def is_user_recreatable_dependency_tree(parts: list[str]) -> bool:
    if not any(part in USER_RECREATABLE_DIRECTORY_NAMES for part in parts):
        return False
    if "users" not in parts:
        return False
    if find_contiguous_parts(parts, ("appdata", "local", "programs")) is not None:
        return False
    return True


def select_latest_windowsapps_dirs(names: list[str]) -> set[str]:
    grouped: dict[tuple[str, str, str], tuple[tuple[int | str, ...], str]] = {}
    for name in names:
        if "__" not in name:
            grouped[(name.casefold(), "", "")] = ((0,), name)
            continue
        left, publisher = name.rsplit("__", 1)
        segments = left.split("_")
        if len(segments) < 3:
            grouped[(name.casefold(), "", publisher.casefold())] = ((0,), name)
            continue
        identity = "_".join(segments[:-2])
        version = segments[-2]
        arch = segments[-1]
        version_key = tuple(int(part) if part.isdigit() else part.casefold() for part in version.split("."))
        key = (identity.casefold(), arch.casefold(), publisher.casefold())
        current = grouped.get(key)
        if current is None or version_key > current[0]:
            grouped[key] = (version_key, name)
    return {name for _, name in grouped.values()}


def is_reparse_point(path: Path) -> bool:
    try:
        return bool(path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, OSError):
        return False


def dedupe_existing_paths(candidates: list[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        identity = str(resolved).casefold()
        if identity in seen or not candidate.exists():
            continue
        if any(is_path_relative_to(resolved, existing) for existing in result):
            continue
        seen.add(identity)
        result.append(candidate)
    return result


def is_path_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def discover_file_roots() -> list[Path]:
    user_profile = Path.home()
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("ProgramData", r"C:\ProgramData")),
        user_profile / "Desktop",
        user_profile / "Documents",
        user_profile / "AppData" / "Local",
        user_profile / "AppData" / "Roaming",
        user_profile / "AppData" / "LocalLow",
        user_profile / ".codex",
        user_profile / ".claude",
        user_profile / ".openclaw",
        user_profile / ".clawdbot",
        user_profile / ".docker",
        user_profile / ".ssh",
        user_profile / ".gitconfig",
        user_profile / ".wslconfig",
        user_profile / "scoop",
        user_profile / ".bun",
        user_profile / ".dotnet",
        user_profile / ".nuget",
        user_profile / ".cargo",
        user_profile / ".rustup",
        user_profile / "AppData" / "Roaming" / "npm",
        user_profile / "AppData" / "Local" / "Programs",
        Path(r"C:\tools"),
        Path(r"C:\msys64"),
        Path(r"C:\Strawberry"),
        Path(r"C:\Python"),
    ]
    for child in Path("C:/").glob("Python*"):
        candidates.append(child)
    return dedupe_existing_paths(candidates)


def discover_registry_keys() -> list[str]:
    return [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        r"HKCU\Environment",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Control Panel\Desktop",
        r"HKCU\Software\Policies\Microsoft\Windows\System",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
        r"HKLM\SOFTWARE\Classes\Applications",
        r"HKCU\Software\Classes\Applications",
        r"HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts",
        r"HKLM\SOFTWARE\Clients\StartMenuInternet",
        r"HKCU\Software\Clients\StartMenuInternet",
    ]


def build_inventory() -> dict[str, Any]:
    roots = discover_file_roots()
    package_commands = [definition["name"] for definition in package_snapshot_definitions()]
    return {
        "tool": "installed_state_backup_restore",
        "tool_version": TOOL_VERSION,
        "created_at": now_local().isoformat(),
        "is_elevated": is_elevated(),
        "file_roots": [str(path) for path in roots],
        "registry_keys": discover_registry_keys(),
        "package_managers": package_commands,
        "recovery_risk_model": build_recovery_risk_model(),
        "backup_root": str(DEFAULT_BACKUP_ROOT),
        "note": (
            "This captures installed application files, package-manager metadata, and registry surfaces. "
            "Broad personal media/download folders are intentionally excluded from this compact installed-state backup; "
            "a full Windows image or file backup remains the only no-exception personal-data migration boundary."
        ),
    }


def build_recovery_risk_model() -> dict[str, Any]:
    return {
        "source_urls": {
            "reset_this_pc": "https://support.microsoft.com/en-us/windows/reset-your-pc-0ef73740-b927-549b-b7c9-e6f2b48d275e",
            "fix_problems_using_windows_update": "https://support.microsoft.com/en-au/windows/fix-issues-by-reinstalling-the-current-version-of-windows-497ac6da-7cac-4641-82a5-f50398d879a0",
        },
        "reset_this_pc_keep_my_files_cloud_download": {
            "apps": "removed",
            "settings": "removed",
            "personal_files": "preserved",
            "cloud_download": "downloads a fresh Windows copy",
            "backup_target": "everything installed outside personal documents, plus package managers, drivers, features, tasks, services, credentials inventory, and user app/profile state",
        },
        "fix_problems_using_windows_update": {
            "apps": "preserved",
            "settings": "preserved",
            "personal_files": "preserved",
            "backup_target": "safety backup anyway, but Microsoft documents this path as preserving apps/files/settings",
        },
        "hard_limits": [
            "Credential Manager, Windows Vault, Windows Hello, and DPAPI-bound secrets are backed up as accessible protected files plus inventory, but Windows may refuse to decrypt them after a format/new SID/TPM boundary.",
            "Store/Appx packages can be inventoried and user package state can be backed up, but package reinstall still depends on Microsoft Store/source availability.",
            "A full disk image is the only literal no-exception backup for boot/recovery partitions and every locked Windows component.",
        ],
    }


def package_snapshot_definitions() -> list[dict[str, Any]]:
    ps_modules = (
        "Get-InstalledModule -ErrorAction SilentlyContinue | "
        "Select-Object Name,Version,Repository,InstalledLocation | ConvertTo-Json -Depth 4"
    )
    appx = "Get-AppxPackage | Select-Object Name,PackageFullName,Version,InstallLocation | ConvertTo-Json -Depth 4"
    return [
        {"name": "winget-version", "file": "winget-version.txt", "args": ["winget", "--version"]},
        {"name": "winget-sources", "file": "winget-sources.txt", "args": ["winget", "source", "list"]},
        {
            "name": "winget-list",
            "file": "winget-list.txt",
            "args": ["winget", "list", "--accept-source-agreements"],
            "timeout": 240,
        },
        {
            "name": "winget-export",
            "file": "winget-export.json",
            "args": ["winget", "export", "--output", "__OUTPUT__", "--accept-source-agreements"],
            "timeout": 240,
            "output_arg": True,
        },
        {"name": "choco-list", "file": "choco-list.txt", "args": ["choco", "list", "--local-only", "--limit-output"]},
        {
            "name": "choco-export",
            "file": "choco-packages.config",
            "args": ["choco", "export", "--output-file", "__OUTPUT__", "-y"],
            "timeout": 180,
            "output_arg": True,
        },
        {"name": "npm-list-global", "file": "npm-list-global.json", "args": ["npm", "list", "-g", "--depth=0", "--json"]},
        {"name": "npm-config", "file": "npm-config.txt", "args": ["npm", "config", "list", "-l"]},
        {"name": "pnpm-list-global", "file": "pnpm-list-global.json", "args": ["pnpm", "list", "-g", "--depth=0", "--json"]},
        {"name": "pnpm-config", "file": "pnpm-config.txt", "args": ["pnpm", "config", "list"]},
        {"name": "yarn-global-list", "file": "yarn-global-list.txt", "args": ["yarn", "global", "list"]},
        {"name": "yarn-config", "file": "yarn-config.txt", "args": ["yarn", "config", "list"]},
        {"name": "bun-version", "file": "bun-version.txt", "args": ["bun", "--version"]},
        {"name": "bun-global-list", "file": "bun-global-list.txt", "args": ["bun", "pm", "ls", "-g"]},
        {"name": "python-version", "file": "python-version.txt", "args": ["python", "--version"]},
        {"name": "pip-freeze", "file": "pip-freeze.txt", "args": ["python", "-m", "pip", "freeze"], "timeout": 180},
        {"name": "pip-list", "file": "pip-list.json", "args": ["python", "-m", "pip", "list", "--format=json"], "timeout": 180},
        {"name": "dotnet-tool-list", "file": "dotnet-tool-list.txt", "args": ["dotnet", "tool", "list", "-g"]},
        {"name": "dotnet-sdks", "file": "dotnet-sdks.txt", "args": ["dotnet", "--list-sdks"]},
        {"name": "dotnet-runtimes", "file": "dotnet-runtimes.txt", "args": ["dotnet", "--list-runtimes"]},
        {
            "name": "powershell5-modules",
            "file": "powershell5-modules.json",
            "args": ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_modules],
            "timeout": 180,
        },
        {
            "name": "powershell7-modules",
            "file": "powershell7-modules.json",
            "args": ["pwsh", "-NoProfile", "-Command", ps_modules],
            "timeout": 180,
        },
        {
            "name": "appx-packages",
            "file": "appx-packages.json",
            "args": ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", appx],
            "timeout": 240,
        },
        {"name": "scoop-list", "file": "scoop-list.json", "args": ["scoop", "list", "--json"]},
        {"name": "scoop-buckets", "file": "scoop-buckets.txt", "args": ["scoop", "bucket", "list"]},
        {"name": "pipx-list", "file": "pipx-list.json", "args": ["pipx", "list", "--json"], "timeout": 120},
        {"name": "uv-tool-list", "file": "uv-tool-list.txt", "args": ["uv", "tool", "list"], "timeout": 120},
        {"name": "cargo-install-list", "file": "cargo-install-list.txt", "args": ["cargo", "install", "--list"], "timeout": 120},
        {"name": "gh-extension-list", "file": "gh-extension-list.txt", "args": ["gh", "extension", "list"], "timeout": 120},
        {"name": "codex-version", "file": "codex-version.txt", "args": ["codex", "--version"], "timeout": 60},
        {"name": "claude-version", "file": "claude-version.txt", "args": ["claude", "--version"], "timeout": 60},
    ]


def collect_package_manager_snapshots(metadata_dir: Path) -> list[dict[str, Any]]:
    package_dir = metadata_dir / "package-managers"
    package_dir.mkdir(parents=True, exist_ok=True)
    snapshots: list[dict[str, Any]] = []
    for definition in package_snapshot_definitions():
        output_file = package_dir / definition["file"]
        args = list(definition["args"])
        if definition.get("output_arg"):
            args = [str(output_file) if arg == "__OUTPUT__" else arg for arg in args]
        result = run_command(args, timeout=int(definition.get("timeout", 120)))
        if definition.get("output_arg"):
            if output_file.exists():
                status = "ok" if result["returncode"] == 0 else "created_with_nonzero_exit"
            else:
                output_file.write_text(result["stdout"] or result["stderr"], encoding="utf-8", errors="replace")
                status = "missing_or_failed"
        else:
            output_file.write_text(result["stdout"] or result["stderr"], encoding="utf-8", errors="replace")
            status = "ok" if result["returncode"] == 0 else "missing_or_failed"
        snapshots.append(
            {
                "name": definition["name"],
                "file": str(output_file.relative_to(metadata_dir)),
                "args": args,
                "returncode": result["returncode"],
                "status": status,
                "timed_out": result.get("timed_out", False),
            }
        )
    write_package_replay_scripts(metadata_dir, snapshots)
    return snapshots


def ps_single_quote(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def write_package_replay_scripts(metadata_dir: Path, snapshots: list[dict[str, Any]]) -> None:
    replay = metadata_dir / "package-managers" / "restore-package-managers.ps1"
    replay.parent.mkdir(parents=True, exist_ok=True)
    snapshot_status_lines = ["$SnapshotStatus = @{"]
    for snapshot in snapshots:
        snapshot_status_lines.append(
            f"  {ps_single_quote(snapshot.get('name', 'unknown'))} = {ps_single_quote(snapshot.get('status', 'missing_or_failed'))}"
        )
    snapshot_status_lines.append("}")
    lines = [
        "$ErrorActionPreference = 'Continue'",
        "Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force",
        "Write-Host 'Replaying package-manager metadata captured by backins.'",
        "$Root = Split-Path -Parent $MyInvocation.MyCommand.Path",
        *snapshot_status_lines,
        "",
        "function Test-Command { param([string]$Name); return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }",
        "function Test-SnapshotOk {",
        "  param([string]$Name)",
        "  return ($SnapshotStatus.ContainsKey($Name) -and $SnapshotStatus[$Name] -eq 'ok')",
        "}",
        "function Restore-ConfigLines {",
        "  param([string]$Tool, [string]$File)",
        "  if (-not (Test-Command $Tool) -or -not (Test-Path $File)) { return }",
        "  Get-Content $File | ForEach-Object {",
        "    if ($_ -match '^\\s*;|^\\s*#|^\\s*$') { return }",
        "    if ($_ -match '^\\s*([^=\\s]+)\\s*=\\s*(.+?)\\s*$') {",
        "      & $Tool config set $Matches[1] $Matches[2] 2>$null",
        "    }",
        "  }",
        "}",
        "function Invoke-BunGlobalReplay {",
        "  param([string]$File)",
        "  if (-not (Test-Path $File)) { return }",
        "  if (-not (Test-Command bun)) { Install-WingetPackageIfMissing 'Oven-sh.Bun' }",
        "  if (-not (Test-Command bun)) { return }",
        "  Get-Content $File | ForEach-Object {",
        "    $line = $_.Trim()",
        "    if (-not $line -or $line -match '^(bun|Global|Dependencies|devDependencies|peerDependencies)\\b') { return }",
        "    if ($line -match '((?:@[^/\\s]+/)?[^@\\s]+)@[^\\s]+') { bun add -g $Matches[1] 2>$null }",
        "  }",
        "}",
        "function Ensure-Chocolatey {",
        "  if (Test-Command choco) { return }",
        "  Write-Host 'Installing Chocolatey because it was present in the backup metadata but is missing now.'",
        "  Set-ExecutionPolicy Bypass -Scope Process -Force",
        "  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
        "  Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
        "  $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')",
        "}",
        "function Install-WingetPackageIfMissing {",
        "  param([string]$Id)",
        "  if (-not (Test-Command winget)) { return }",
        "  winget install --id $Id --exact --accept-package-agreements --accept-source-agreements --silent",
        "}",
        "function Install-CriticalRuntimePackages {",
        "  if (-not (Test-Command winget)) { return }",
        "  $runtimeIds = @(",
        "    'Microsoft.VCRedist.2005.x86','Microsoft.VCRedist.2005.x64','Microsoft.VCRedist.2008.x86','Microsoft.VCRedist.2008.x64',",
        "    'Microsoft.VCRedist.2010.x86','Microsoft.VCRedist.2010.x64','Microsoft.VCRedist.2012.x86','Microsoft.VCRedist.2012.x64',",
        "    'Microsoft.VCRedist.2013.x86','Microsoft.VCRedist.2013.x64','Microsoft.VCRedist.2015+.x86','Microsoft.VCRedist.2015+.x64',",
        "    'Microsoft.DirectX','Microsoft.XNARedist',",
        "    'Microsoft.DotNet.Runtime.3_1','Microsoft.DotNet.Runtime.5','Microsoft.DotNet.Runtime.6','Microsoft.DotNet.Runtime.7','Microsoft.DotNet.Runtime.8','Microsoft.DotNet.Runtime.9','Microsoft.DotNet.Runtime.10','Microsoft.DotNet.Runtime.Preview',",
        "    'Microsoft.DotNet.DesktopRuntime.3_1','Microsoft.DotNet.DesktopRuntime.5','Microsoft.DotNet.DesktopRuntime.6','Microsoft.DotNet.DesktopRuntime.7','Microsoft.DotNet.DesktopRuntime.8','Microsoft.DotNet.DesktopRuntime.8.x64','Microsoft.DotNet.DesktopRuntime.9','Microsoft.DotNet.DesktopRuntime.10','Microsoft.DotNet.DesktopRuntime.Preview',",
        "    'Microsoft.DotNet.AspNetCore.3_1','Microsoft.DotNet.AspNetCore.5','Microsoft.DotNet.AspNetCore.6','Microsoft.DotNet.AspNetCore.7','Microsoft.DotNet.AspNetCore.8','Microsoft.DotNet.AspNetCore.9','Microsoft.DotNet.AspNetCore.10','Microsoft.DotNet.AspNetCore.Preview',",
        "    'Microsoft.DotNet.SDK.3_1','Microsoft.DotNet.SDK.5','Microsoft.DotNet.SDK.6','Microsoft.DotNet.SDK.7','Microsoft.DotNet.SDK.8','Microsoft.DotNet.SDK.9','Microsoft.DotNet.SDK.10','Microsoft.DotNet.SDK.Preview',",
        "    'Microsoft.WindowsSDK.10.0.26100','Microsoft.WindowsADK','Microsoft.WindowsADK.WinPEAddon'",
        "  )",
        "  foreach ($id in $runtimeIds) { Install-WingetPackageIfMissing $id }",
        "}",
        "if (-not (Test-Command python)) { Install-WingetPackageIfMissing 'Python.Python.3.12' }",
        "if (-not (Test-Command pwsh)) { Install-WingetPackageIfMissing 'Microsoft.PowerShell' }",
        "if (-not (Test-Command git)) { Install-WingetPackageIfMissing 'Git.Git' }",
        "if (-not (Test-Command gh)) { Install-WingetPackageIfMissing 'GitHub.cli' }",
        "if (-not (Test-Command node)) { Install-WingetPackageIfMissing 'OpenJS.NodeJS.LTS' }",
        "if (-not (Test-Command docker)) { Install-WingetPackageIfMissing 'Docker.DockerDesktop' }",
        "if (-not (Test-Command codex)) { Install-WingetPackageIfMissing 'OpenAI.Codex' }",
        "if (-not (Test-Command claude)) { Install-WingetPackageIfMissing 'Anthropic.Claude' }",
        "Install-CriticalRuntimePackages",
        "",
        "if (Test-Command winget) { winget source reset --force 2>$null; winget source update 2>$null }",
        "if ((Test-SnapshotOk 'winget-export') -and (Test-Path (Join-Path $Root 'winget-export.json'))) {",
        "  if (Test-Command winget) { winget import --import-file (Join-Path $Root 'winget-export.json') --accept-package-agreements --accept-source-agreements }",
        "}",
        "if ((Test-SnapshotOk 'choco-export') -and (Test-Path (Join-Path $Root 'choco-packages.config'))) {",
        "  Ensure-Chocolatey",
        "  if (Test-Command choco) { choco install (Join-Path $Root 'choco-packages.config') -y }",
        "}",
        "if ((Test-SnapshotOk 'pip-freeze') -and (Test-Path (Join-Path $Root 'pip-freeze.txt'))) {",
        "  if (Test-Command python) { python -m pip install --upgrade pip; python -m pip install -r (Join-Path $Root 'pip-freeze.txt') }",
        "}",
        "if ((Test-SnapshotOk 'npm-list-global') -and (Test-Path (Join-Path $Root 'npm-list-global.json'))) {",
        "  if (Test-SnapshotOk 'npm-config') { Restore-ConfigLines npm (Join-Path $Root 'npm-config.txt') }",
        "  try {",
        "    $npm = Get-Content (Join-Path $Root 'npm-list-global.json') -Raw | ConvertFrom-Json",
        "    foreach ($prop in @($npm.dependencies.PSObject.Properties)) {",
        "      $pkg = $prop.Name",
        "      $version = $prop.Value.version",
        "      if ($pkg) { if ($version) { npm install -g \"$pkg@$version\" } else { npm install -g $pkg } }",
        "    }",
        "  } catch { Write-Warning \"npm global replay failed: $($_.Exception.Message)\" }",
        "}",
        "if ((Test-SnapshotOk 'pnpm-list-global') -and (Test-Path (Join-Path $Root 'pnpm-list-global.json'))) {",
        "  if (-not (Test-Command pnpm) -and (Test-Command npm)) { npm install -g pnpm }",
        "  if (Test-SnapshotOk 'pnpm-config') { Restore-ConfigLines pnpm (Join-Path $Root 'pnpm-config.txt') }",
        "  try {",
        "    $pnpm = Get-Content (Join-Path $Root 'pnpm-list-global.json') -Raw | ConvertFrom-Json",
        "    foreach ($item in @($pnpm)) { if ($item.name) { if ($item.version) { pnpm add -g \"$($item.name)@$($item.version)\" } else { pnpm add -g $item.name } } }",
        "  } catch { Write-Warning \"pnpm global replay failed: $($_.Exception.Message)\" }",
        "}",
        "if ((Test-SnapshotOk 'yarn-global-list') -and (Test-Path (Join-Path $Root 'yarn-global-list.txt'))) {",
        "  if (-not (Test-Command yarn) -and (Test-Command npm)) { npm install -g yarn }",
        "  if (Test-SnapshotOk 'yarn-config') { Restore-ConfigLines yarn (Join-Path $Root 'yarn-config.txt') }",
        "  Get-Content (Join-Path $Root 'yarn-global-list.txt') | ForEach-Object {",
        "    if ($_ -match 'info \"([^@\\s]+)(?:@[^\\s\"]+)?\"') { yarn global add $Matches[1] }",
        "  }",
        "}",
        "if ((Test-SnapshotOk 'bun-global-list') -and (Test-Path (Join-Path $Root 'bun-global-list.txt'))) {",
        "  Invoke-BunGlobalReplay (Join-Path $Root 'bun-global-list.txt')",
        "}",
        "if ((Test-SnapshotOk 'powershell5-modules') -and (Test-Path (Join-Path $Root 'powershell5-modules.json'))) {",
        "  try {",
        "    $mods = Get-Content (Join-Path $Root 'powershell5-modules.json') -Raw | ConvertFrom-Json",
        "    foreach ($mod in @($mods)) { if ($mod.Name) { Install-Module -Name $mod.Name -RequiredVersion $mod.Version -Scope CurrentUser -Force -AllowClobber -ErrorAction Continue } }",
        "  } catch { Write-Warning \"PowerShell 5 module replay failed: $($_.Exception.Message)\" }",
        "}",
        "if ((Test-SnapshotOk 'powershell7-modules') -and (Test-Path (Join-Path $Root 'powershell7-modules.json'))) {",
        "  try {",
        "    $mods = Get-Content (Join-Path $Root 'powershell7-modules.json') -Raw | ConvertFrom-Json",
        "    if (Test-Command pwsh) { foreach ($mod in @($mods)) { if ($mod.Name) { pwsh -NoProfile -Command \"Install-Module -Name '$($mod.Name)' -RequiredVersion '$($mod.Version)' -Scope CurrentUser -Force -AllowClobber -ErrorAction Continue\" } } }",
        "  } catch { Write-Warning \"PowerShell 7 module replay failed: $($_.Exception.Message)\" }",
        "}",
        "if ((Test-SnapshotOk 'dotnet-tool-list') -and (Test-Path (Join-Path $Root 'dotnet-tool-list.txt'))) {",
        "  Get-Content (Join-Path $Root 'dotnet-tool-list.txt') | Select-Object -Skip 2 | ForEach-Object {",
        "    $parts = ($_ -split '\\s+') | Where-Object { $_ }",
        "    if ($parts.Count -ge 1 -and $parts[0] -notmatch '^-+$') { dotnet tool install -g $parts[0] 2>$null; dotnet tool update -g $parts[0] 2>$null }",
        "  }",
        "}",
        "if ((Test-SnapshotOk 'scoop-list') -and (Test-Path (Join-Path $Root 'scoop-list.json'))) {",
        "  if (-not (Test-Command scoop)) {",
        "    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force",
        "    Invoke-RestMethod get.scoop.sh | Invoke-Expression",
        "  }",
        "  try {",
        "    $scoop = Get-Content (Join-Path $Root 'scoop-list.json') -Raw | ConvertFrom-Json",
        "    foreach ($app in @($scoop)) { if ($app.Name) { scoop install $app.Name } }",
        "  } catch { Write-Warning \"Scoop replay failed: $($_.Exception.Message)\" }",
        "}",
        "if ((Test-SnapshotOk 'pipx-list') -and (Test-Path (Join-Path $Root 'pipx-list.json'))) {",
        "  if (-not (Test-Command pipx) -and (Test-Command python)) { python -m pip install --upgrade pipx }",
        "  try {",
        "    $pipx = Get-Content (Join-Path $Root 'pipx-list.json') -Raw | ConvertFrom-Json",
        "    foreach ($venv in @($pipx.venvs.PSObject.Properties.Name)) { if ($venv -and (Test-Command pipx)) { pipx install $venv 2>$null; pipx upgrade $venv 2>$null } }",
        "  } catch { Write-Warning \"pipx replay failed: $($_.Exception.Message)\" }",
        "}",
        "if ((Test-SnapshotOk 'uv-tool-list') -and (Test-Path (Join-Path $Root 'uv-tool-list.txt'))) {",
        "  if (-not (Test-Command uv) -and (Test-Command python)) { python -m pip install --upgrade uv }",
        "  if (Test-Command uv) { Get-Content (Join-Path $Root 'uv-tool-list.txt') | ForEach-Object { $name = ($_ -split '\\s+')[0]; if ($name -and $name -notmatch '^-') { uv tool install $name 2>$null; uv tool upgrade $name 2>$null } } }",
        "}",
        "if ((Test-SnapshotOk 'cargo-install-list') -and (Test-Path (Join-Path $Root 'cargo-install-list.txt'))) {",
        "  if (Test-Command cargo) { Get-Content (Join-Path $Root 'cargo-install-list.txt') | ForEach-Object { if ($_ -match '^([^\\s]+)\\s+v[0-9]') { cargo install $Matches[1] 2>$null } } }",
        "}",
        "if ((Test-SnapshotOk 'gh-extension-list') -and (Test-Path (Join-Path $Root 'gh-extension-list.txt'))) {",
        "  if (Test-Command gh) { Get-Content (Join-Path $Root 'gh-extension-list.txt') | ForEach-Object { $name = ($_ -split '\\s+')[0]; if ($name -match '/') { gh extension install $name 2>$null; gh extension upgrade $name 2>$null } } }",
        "}",
        "Write-Host 'Package-manager replay finished.'",
    ]
    replay.write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_json(metadata_dir / "package-managers" / "snapshot-summary.json", snapshots)


def export_registry_keys(metadata_dir: Path) -> list[dict[str, Any]]:
    registry_dir = metadata_dir / "registry"
    registry_dir.mkdir(parents=True, exist_ok=True)
    exports: list[dict[str, Any]] = []
    for key in discover_registry_keys():
        safe_name = key.replace("\\", "__").replace(":", "")
        output = registry_dir / f"{safe_name}.reg"
        result = run_command(["reg.exe", "export", key, str(output), "/y"], timeout=120)
        exports.append(
            {
                "key": key,
                "file": str(output.relative_to(metadata_dir)) if output.exists() else None,
                "returncode": result["returncode"],
                "stderr": result["stderr"],
                "status": "ok" if result["returncode"] == 0 and output.exists() else "missing_or_failed",
            }
        )
    return exports


def safe_metadata_name(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in value.strip())
    return safe.strip("._") or "item"


def clean_wsl_output(text: str) -> str:
    return text.replace("\x00", "")


def export_scheduled_task_xml(metadata_dir: Path) -> dict[str, Any]:
    task_dir = metadata_dir / "system" / "scheduled-tasks-xml"
    task_dir.mkdir(parents=True, exist_ok=True)
    query = run_command(["schtasks.exe", "/Query", "/FO", "CSV", "/V"], timeout=180)
    exported: list[dict[str, Any]] = []
    if query["returncode"] == 0 and query["stdout"].strip():
        reader = csv.DictReader(io.StringIO(query["stdout"]))
        task_names = sorted({(row.get("TaskName") or "").strip() for row in reader if (row.get("TaskName") or "").strip()})
        for task_name in task_names:
            safe_parts = [safe_metadata_name(part) for part in task_name.strip("\\").split("\\") if part]
            safe_rel = Path(*safe_parts) if safe_parts else Path("root")
            target = task_dir / safe_rel.with_suffix(".xml")
            result = run_command(["schtasks.exe", "/Query", "/TN", task_name, "/XML"], timeout=45)
            status = "ok" if result["returncode"] == 0 and "<Task" in result["stdout"] else "missing_or_failed"
            if status == "ok":
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(result["stdout"], encoding="utf-8", errors="replace")
            exported.append(
                {
                    "task_name": task_name,
                    "file": str(target.relative_to(metadata_dir)) if target.exists() else None,
                    "returncode": result["returncode"],
                    "status": status,
                    "timed_out": result.get("timed_out", False),
                }
            )
    write_json(task_dir / "scheduled-tasks-manifest.json", exported)
    status = "ok" if query["returncode"] == 0 and any(item["status"] == "ok" for item in exported) else "missing_or_failed"
    return {
        "name": "scheduled-tasks-xml",
        "file": str(task_dir.relative_to(metadata_dir)),
        "returncode": query["returncode"],
        "status": status,
        "timed_out": query.get("timed_out", False),
        "exported": sum(1 for item in exported if item["status"] == "ok"),
    }


def export_wifi_profiles(metadata_dir: Path) -> dict[str, Any]:
    wifi_dir = metadata_dir / "system" / "wifi-profiles"
    wifi_dir.mkdir(parents=True, exist_ok=True)
    result = run_command(["netsh.exe", "wlan", "export", "profile", "key=clear", f"folder={wifi_dir}"], timeout=180)
    return {"name": "wifi-profiles", "file": str(wifi_dir.relative_to(metadata_dir)), "returncode": result["returncode"], "status": "ok" if result["returncode"] == 0 else "missing_or_failed"}


def export_driver_store(metadata_dir: Path) -> dict[str, Any]:
    driver_dir = metadata_dir / "system" / "driver-store-export"
    driver_dir.mkdir(parents=True, exist_ok=True)
    result = run_command(["pnputil.exe", "/export-driver", "*", str(driver_dir)], timeout=3600)
    file_count = sum(1 for item in driver_dir.rglob("*") if item.is_file())
    return {
        "name": "driver-store-export",
        "file": str(driver_dir.relative_to(metadata_dir)),
        "returncode": result["returncode"],
        "status": "ok" if result["returncode"] == 0 and file_count else "missing_or_failed",
        "file_count": file_count,
    }


def parse_wsl_verbose(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    known_states = {"running", "stopped", "installing", "uninstalling", "converting"}
    for raw_line in clean_wsl_output(output).splitlines():
        line = raw_line.strip()
        if not line or line.casefold().startswith("name"):
            continue
        default = line.startswith("*")
        if default:
            line = line[1:].strip()
        parts = line.split()
        if len(parts) >= 3 and parts[-1] in {"1", "2"} and parts[-2].casefold() in known_states:
            rows.append({"name": " ".join(parts[:-2]), "state": parts[-2], "version": parts[-1], "default": str(default).lower()})
        elif len(parts) >= 2 and parts[-1].casefold() in known_states:
            rows.append({"name": " ".join(parts[:-1]), "state": parts[-1], "version": "", "default": str(default).lower()})
    return rows


def wsl_verbose_state(timeout: int = WSL_PROBE_TIMEOUT_SECONDS) -> dict[str, Any]:
    result = run_command(["wsl.exe", "--list", "--verbose"], timeout=timeout)
    return {"distros": parse_wsl_verbose(result.get("stdout", "")), **result}


def wait_for_wsl_idle(timeout_seconds: int, poll_seconds: int = 30) -> dict[str, Any]:
    deadline = time.monotonic() + max(0, timeout_seconds)
    checks: list[dict[str, Any]] = []
    while True:
        state = wsl_verbose_state()
        checks.append(
            {
                "returncode": state["returncode"],
                "timed_out": state.get("timed_out", False),
                "distros": state.get("distros", []),
            }
        )
        running = [
            distro
            for distro in state.get("distros", [])
            if distro.get("state", "").casefold() == "running"
        ]
        if state["returncode"] == 0 and not running:
            return {"status": "idle", "checks": checks, "last_state": state}
        if time.monotonic() >= deadline:
            return {"status": "timed_out_waiting_for_idle", "checks": checks, "last_state": state}
        time.sleep(min(poll_seconds, max(1, int(deadline - time.monotonic()))))


def export_wsl_status_files(metadata_dir: Path) -> list[dict[str, Any]]:
    extra_dir = metadata_dir / "system"
    records: list[dict[str, Any]] = []
    for filename, args in [
        ("wsl-list.txt", ["wsl.exe", "--list", "--verbose"]),
        ("wsl-status.txt", ["wsl.exe", "--status"]),
    ]:
        result = run_command(args, timeout=WSL_PROBE_TIMEOUT_SECONDS)
        output = extra_dir / filename
        write_command_output(output, result)
        records.append(command_export_record(filename, output, metadata_dir, result))
    return records


def stop_docker_for_wsl_export() -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    docker_processes = [
        "Docker Desktop.exe",
        "com.docker.backend.exe",
        "com.docker.build.exe",
        "docker-sandbox.exe",
        "docker-agent.exe",
    ]
    for process_name in docker_processes:
        actions.append(
            {
                "step": "taskkill-docker",
                "process": process_name,
                **run_command(["taskkill.exe", "/IM", process_name, "/F", "/T"], timeout=45),
            }
        )
    actions.append({"step": "stop-docker-service", **run_command(["net.exe", "stop", "com.docker.service", "/y"], timeout=90)})
    return actions


def restart_docker_after_wsl_export() -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    actions.append({"step": "start-docker-service", **run_command(["net.exe", "start", "com.docker.service"], timeout=90)})
    docker_desktop = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "Docker Desktop.exe"
    if docker_desktop.exists():
        try:
            subprocess.Popen([str(docker_desktop), "--minimize"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            actions.append({"step": "start-docker-desktop", "returncode": 0, "path": str(docker_desktop)})
        except OSError as exc:
            actions.append({"step": "start-docker-desktop", "returncode": 1, "path": str(docker_desktop), "stderr": str(exc)})
    return actions


def force_stop_wsl_runtime() -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    actions.append({"step": "taskkill-wsl", **run_command(["taskkill.exe", "/IM", "wsl.exe", "/F", "/T"], timeout=45)})
    actions.append({"step": "taskkill-wslhost", **run_command(["taskkill.exe", "/IM", "wslhost.exe", "/F", "/T"], timeout=45)})
    actions.append({"step": "taskkill-wslrelay", **run_command(["taskkill.exe", "/IM", "wslrelay.exe", "/F", "/T"], timeout=45)})
    actions.append({"step": "wsl-shutdown-after-taskkill", **run_command(["wsl.exe", "--shutdown"], timeout=60)})
    return actions


def export_wsl_distros(metadata_dir: Path, idle_wait_seconds: int = DEFAULT_WSL_IDLE_WAIT_SECONDS) -> dict[str, Any]:
    wsl_dir = metadata_dir / "system" / "wsl-exports"
    wsl_dir.mkdir(parents=True, exist_ok=True)
    list_result = run_command(["wsl.exe", "--list", "--quiet"], timeout=WSL_PROBE_TIMEOUT_SECONDS)
    exported: list[dict[str, Any]] = []
    if list_result["returncode"] != 0:
        write_json(wsl_dir / "wsl-exports-manifest.json", exported)
        return {
            "name": "wsl-exports",
            "file": str(wsl_dir.relative_to(metadata_dir)),
            "returncode": list_result["returncode"],
            "status": "missing_or_failed",
            "timed_out": list_result.get("timed_out", False),
            "exports": exported,
        }
    distros = [clean_wsl_output(line).strip() for line in list_result["stdout"].splitlines() if clean_wsl_output(line).strip()]
    idle_result = wait_for_wsl_idle(idle_wait_seconds) if distros else {"status": "idle", "checks": []}
    terminate_results: list[dict[str, Any]] = []
    docker_stop_actions = stop_docker_for_wsl_export() if distros else []
    if idle_result["status"] != "idle":
        write_json(wsl_dir / "wsl-idle-wait.json", idle_result)
        for distro in distros:
            terminate_results.append({"distro": distro, **run_command(["wsl.exe", "--terminate", distro], timeout=60)})
        terminate_results.extend(force_stop_wsl_runtime())
    shutdown_result = run_command(["wsl.exe", "--shutdown"], timeout=60) if distros else None
    if distros:
        time.sleep(3)
    post_shutdown_state = wsl_verbose_state(timeout=WSL_PROBE_TIMEOUT_SECONDS) if distros else {"distros": []}
    for distro in distros:
        target = wsl_dir / f"{safe_metadata_name(distro)}.tar"
        result = run_command(["wsl.exe", "--export", distro, str(target)], timeout=7200)
        exported.append(
            {
                "distro": distro,
                "file": str(target.relative_to(metadata_dir)),
                "returncode": result["returncode"],
                "status": "ok" if result["returncode"] == 0 and target.exists() else "missing_or_failed",
                "timed_out": result.get("timed_out", False),
            }
        )
    write_json(wsl_dir / "wsl-exports-manifest.json", exported)
    write_json(wsl_dir / "wsl-idle-wait.json", idle_result)
    write_json(wsl_dir / "wsl-terminate-results.json", terminate_results)
    write_json(wsl_dir / "docker-stop-for-wsl-export.json", docker_stop_actions)
    write_json(wsl_dir / "wsl-post-shutdown-state.json", post_shutdown_state)
    docker_restart_actions = restart_docker_after_wsl_export() if docker_stop_actions else []
    write_json(wsl_dir / "docker-restart-after-wsl-export.json", docker_restart_actions)
    status = "ok"
    if distros and not all(item["status"] == "ok" for item in exported):
        status = "missing_or_failed"
    return {
        "name": "wsl-exports",
        "file": str(wsl_dir.relative_to(metadata_dir)),
        "returncode": 0,
        "status": status,
        "idle_status": idle_result["status"],
        "wsl_shutdown_returncode": shutdown_result["returncode"] if shutdown_result else None,
        "wsl_terminate_count": len(terminate_results),
        "docker_stop_action_count": len(docker_stop_actions),
        "docker_restart_action_count": len(docker_restart_actions),
        "post_shutdown_state": post_shutdown_state.get("distros", []),
        "exports": exported,
    }


def probe_wsl_distros(timeout: int = WSL_PROBE_TIMEOUT_SECONDS) -> dict[str, Any]:
    result = run_command(["wsl.exe", "--list", "--quiet"], timeout=timeout)
    distros = [
        clean_wsl_output(line).strip()
        for line in result.get("stdout", "").splitlines()
        if clean_wsl_output(line).strip()
    ]
    return {"name": "wsl-preflight", "distros": distros, **result}


def preflight_critical_backup_state() -> dict[str, Any]:
    wsl_probe = probe_wsl_distros()
    issues: list[dict[str, Any]] = []
    if wsl_probe["returncode"] == 124:
        issues.append(
            {
                "component": "WSL",
                "severity": "critical",
                "reason": f"wsl.exe --list --quiet timed out after {WSL_PROBE_TIMEOUT_SECONDS}s; Ubuntu cannot be proven/exported.",
            }
        )
    elif wsl_probe["returncode"] not in (0, 50):
        issues.append(
            {
                "component": "WSL",
                "severity": "critical",
                "reason": wsl_probe.get("stderr") or f"wsl.exe returned {wsl_probe['returncode']}",
            }
        )
    return {"ok": not issues, "issues": issues, "wsl": wsl_probe}


def assert_critical_system_exports(preflight: dict[str, Any], system_exports: list[dict[str, Any]]) -> None:
    expected_wsl_distros = preflight.get("wsl", {}).get("distros") or []
    if not expected_wsl_distros:
        return
    wsl_export = next((item for item in system_exports if item.get("name") == "wsl-exports"), None)
    if not wsl_export or wsl_export.get("status") != "ok":
        raise ToolError("Backup refused: WSL distros were detected, but WSL export did not complete successfully.")


def command_repair_wsl(args: argparse.Namespace) -> int:
    actions: list[dict[str, Any]] = []
    actions.append({"step": "preflight", **probe_wsl_distros(timeout=10)})
    shutdown = run_command(["wsl.exe", "--shutdown"], timeout=20)
    actions.append({"step": "wsl-shutdown", **shutdown})
    if shutdown["returncode"] != 0:
        actions.append({"step": "taskkill-wsl", **run_command(["taskkill.exe", "/IM", "wsl.exe", "/F", "/T"], timeout=30)})
        actions.append({"step": "taskkill-wslhost", **run_command(["taskkill.exe", "/IM", "wslhost.exe", "/F", "/T"], timeout=30)})
    if is_elevated():
        actions.append({"step": "net-stop-wslservice", **run_command(["net.exe", "stop", "WslService", "/y"], timeout=45)})
        actions.append({"step": "net-start-wslservice", **run_command(["net.exe", "start", "WslService"], timeout=45)})
    actions.append({"step": "postflight", **probe_wsl_distros(timeout=30)})
    console_print(json.dumps({"actions": actions, "ok": actions[-1]["returncode"] == 0}, indent=2, sort_keys=True))
    return 0 if actions[-1]["returncode"] == 0 else 1


def export_power_state(metadata_dir: Path) -> dict[str, Any]:
    power_dir = metadata_dir / "system" / "power"
    power_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for filename, args, timeout in [
        ("active-scheme.txt", ["powercfg.exe", "/GETACTIVESCHEME"], 60),
        ("schemes.txt", ["powercfg.exe", "/L"], 60),
        ("query.txt", ["powercfg.exe", "/Q"], 180),
    ]:
        result = run_command(args, timeout=timeout)
        output = power_dir / filename
        write_command_output(output, result)
        results.append(command_export_record(filename, output, metadata_dir, result))
    active_text = (power_dir / "active-scheme.txt").read_text(encoding="utf-8", errors="replace")
    match = re.search(r"([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})", active_text)
    active_guid = match.group(1) if match else None
    export_status = "missing_or_failed"
    export_returncode = 1
    if active_guid:
        pow_file = power_dir / "active-scheme.pow"
        export_result = run_command(["powercfg.exe", "/EXPORT", str(pow_file), active_guid], timeout=120)
        export_status = "ok" if export_result["returncode"] == 0 and pow_file.exists() else "missing_or_failed"
        export_returncode = export_result["returncode"]
        results.append(command_export_record("active-scheme.pow", pow_file, metadata_dir, export_result))
    write_json(power_dir / "power-summary.json", {"active_guid": active_guid, "exports": results})
    return {
        "name": "power-state",
        "file": str(power_dir.relative_to(metadata_dir)),
        "returncode": export_returncode,
        "status": "ok" if active_guid and export_status == "ok" else "missing_or_failed",
        "active_guid": active_guid,
    }


def export_docker_state(metadata_dir: Path) -> dict[str, Any]:
    docker_dir = metadata_dir / "system" / "docker"
    docker_dir.mkdir(parents=True, exist_ok=True)
    commands = [
        ("version.txt", ["docker", "version"], 60),
        ("info.txt", ["docker", "info"], 90),
        ("contexts.txt", ["docker", "context", "ls"], 60),
        ("images.txt", ["docker", "images", "--digests", "--no-trunc"], 180),
        ("containers.txt", ["docker", "ps", "-a", "--no-trunc"], 120),
        ("volumes.txt", ["docker", "volume", "ls"], 120),
        ("networks.txt", ["docker", "network", "ls"], 120),
    ]
    records: list[dict[str, Any]] = []
    for filename, args, timeout in commands:
        output = docker_dir / filename
        result = run_command(args, timeout=timeout)
        write_command_output(output, result)
        records.append(command_export_record(filename, output, metadata_dir, result))
    write_json(docker_dir / "docker-summary.json", records)
    return {
        "name": "docker-state",
        "file": str(docker_dir.relative_to(metadata_dir)),
        "returncode": 0 if any(item["status"] == "ok" for item in records) else 1,
        "status": "ok" if any(item["status"] == "ok" for item in records) else "missing_or_failed",
    }


def export_bluetooth_state(metadata_dir: Path) -> dict[str, Any]:
    bluetooth_dir = metadata_dir / "system" / "bluetooth"
    bluetooth_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    commands = [
        ("pnputil-bluetooth-devices.txt", ["pnputil.exe", "/enum-devices", "/class", "Bluetooth"], 120),
        ("pnputil-connected-bluetooth-devices.txt", ["pnputil.exe", "/enum-devices", "/class", "Bluetooth", "/connected"], 120),
    ]
    for filename, args, timeout in commands:
        output = bluetooth_dir / filename
        result = run_command(args, timeout=timeout)
        write_command_output(output, result)
        records.append(command_export_record(filename, output, metadata_dir, result))
    write_json(bluetooth_dir / "bluetooth-summary.json", records)
    return {
        "name": "bluetooth-state",
        "file": str(bluetooth_dir.relative_to(metadata_dir)),
        "returncode": 0 if any(item["status"] == "ok" for item in records) else 1,
        "status": "ok" if any(item["status"] == "ok" for item in records) else "missing_or_failed",
    }


def export_shell_state(metadata_dir: Path) -> dict[str, Any]:
    shell_dir = metadata_dir / "system" / "shell-state"
    shell_dir.mkdir(parents=True, exist_ok=True)
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$paths = @(
  @{ Name = 'taskbar-pins'; Path = Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar' },
  @{ Name = 'quick-launch'; Path = Join-Path $env:APPDATA 'Microsoft\Internet Explorer\Quick Launch' },
  @{ Name = 'user-start-menu'; Path = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu' },
  @{ Name = 'common-start-menu'; Path = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu' },
  @{ Name = 'user-startup-folder'; Path = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup' },
  @{ Name = 'common-startup-folder'; Path = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup' },
  @{ Name = 'recent-items'; Path = Join-Path $env:APPDATA 'Microsoft\Windows\Recent' },
  @{ Name = 'jump-list-automatic'; Path = Join-Path $env:APPDATA 'Microsoft\Windows\Recent\AutomaticDestinations' },
  @{ Name = 'jump-list-custom'; Path = Join-Path $env:APPDATA 'Microsoft\Windows\Recent\CustomDestinations' },
  @{ Name = 'start-menu-experience-state'; Path = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState' },
  @{ Name = 'windows-shell-local-state'; Path = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Shell' }
)
$pathSummaries = foreach ($entry in $paths) {
  $exists = Test-Path -LiteralPath $entry.Path
  $files = @()
  if ($exists) {
    $files = @(Get-ChildItem -LiteralPath $entry.Path -Recurse -Force -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTimeUtc)
  }
  [pscustomobject]@{
    Name = $entry.Name
    Path = $entry.Path
    Exists = $exists
    FileCount = $files.Count
    Files = $files
  }
}
$startApps = @()
try { $startApps = @(Get-StartApps | Select-Object Name,AppID) } catch { }
[pscustomobject]@{
  Paths = $pathSummaries
  StartApps = $startApps
} | ConvertTo-Json -Depth 8
"""
    output = shell_dir / "shell-state.json"
    result = run_command(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=240)
    write_command_output(output, result)
    return {
        "name": "shell-state",
        "file": str(shell_dir.relative_to(metadata_dir)),
        "returncode": result["returncode"],
        "status": "ok" if result["returncode"] == 0 and output.exists() else "missing_or_failed",
    }


def summarize_files_under(path: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    exists = path.exists()
    if exists:
        for current, dirs, names in os.walk(path, onerror=lambda exc: errors.append({"path": getattr(exc, "filename", ""), "error": str(exc)})):
            current_path = Path(current)
            kept_dirs = []
            for dirname in dirs:
                child = current_path / dirname
                try:
                    child.stat()
                    kept_dirs.append(dirname)
                except OSError as exc:
                    errors.append({"path": str(child), "error": str(exc)})
            dirs[:] = kept_dirs
            for name in names:
                file_path = current_path / name
                try:
                    stat_result = file_path.stat()
                except OSError as exc:
                    errors.append({"path": str(file_path), "error": str(exc)})
                    continue
                files.append(
                    {
                        "FullName": str(file_path),
                        "Length": stat_result.st_size,
                        "LastWriteTimeUtc": dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc).isoformat(),
                    }
                )
    return {"Path": str(path), "Exists": exists, "FileCount": len(files), "Files": files, "Errors": errors}


def credential_file_summaries() -> list[dict[str, Any]]:
    local_appdata = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    appdata = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    paths = [
        ("local-vault", local_appdata / "Microsoft" / "Vault"),
        ("local-credentials", local_appdata / "Microsoft" / "Credentials"),
        ("roaming-credentials", appdata / "Microsoft" / "Credentials"),
        ("roaming-protect", appdata / "Microsoft" / "Protect"),
        ("roaming-crypto-rsa", appdata / "Microsoft" / "Crypto" / "RSA"),
        ("local-crypto", local_appdata / "Microsoft" / "Crypto"),
        ("local-ngc", local_appdata / "Microsoft" / "Ngc"),
    ]
    summaries = []
    for name, path in paths:
        summary = summarize_files_under(path)
        summary["Name"] = name
        summaries.append(summary)
    return summaries


def export_credential_state(metadata_dir: Path) -> dict[str, Any]:
    credential_dir = metadata_dir / "system" / "credential-state"
    credential_dir.mkdir(parents=True, exist_ok=True)
    commands = [
        ("cmdkey-list.txt", ["cmdkey.exe", "/list"], 60),
        ("vault-list.txt", ["vaultcmd.exe", "/list"], 60),
        ("vault-schema.txt", ["vaultcmd.exe", "/listschema"], 60),
        ("vault-web-creds.txt", ["vaultcmd.exe", "/listcreds:Web Credentials", "/all"], 60),
        ("vault-windows-creds.txt", ["vaultcmd.exe", "/listcreds:Windows Credentials", "/all"], 60),
    ]
    records: list[dict[str, Any]] = []
    for filename, args, timeout in commands:
        output = credential_dir / filename
        result = run_command(args, timeout=timeout)
        write_command_output(output, result)
        records.append(command_export_record(filename, output, metadata_dir, result))
    folder_output = credential_dir / "credential-files-summary.json"
    write_json(folder_output, credential_file_summaries())
    records.append(
        {
            "name": "credential-files-summary.json",
            "file": str(folder_output.relative_to(metadata_dir)),
            "returncode": 0,
            "status": "ok",
            "timed_out": False,
        }
    )
    write_json(
        credential_dir / "credential-restore-boundary.json",
        {
            "status": "inventory_and_protected_files_captured",
            "note": (
                "Accessible Vault/Credentials/Protect/Crypto/Ngc files are archived through AppData roots and inventoried here. "
                "DPAPI, Windows Hello, TPM, account-password, Microsoft-account, and app-token policy can still prevent decryption after a format."
            ),
        },
    )
    all_ok = bool(records) and all(item["status"] == "ok" for item in records)
    failed_subrecords = [item["name"] for item in records if item["status"] != "ok"]
    return {
        "name": "credential-state",
        "file": str(credential_dir.relative_to(metadata_dir)),
        "returncode": 0 if all_ok else 1,
        "status": "ok" if all_ok else "missing_or_failed",
        "subrecords": records,
        "subrecord_count": len(records),
        "failed_subrecords": failed_subrecords,
    }


def write_system_replay_script(metadata_dir: Path) -> dict[str, Any]:
    script = metadata_dir / "system" / "restore-system-state.ps1"
    script.parent.mkdir(parents=True, exist_ok=True)
    content = r"""
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$MetadataRoot = Split-Path -Parent $Root
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force

function Read-JsonFile {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
  catch {
    Write-Warning "Could not parse JSON: $Path"
    return $null
  }
}

function As-Array {
  param($Value)
  if ($null -eq $Value) { return @() }
  if ($Value -is [System.Array]) { return $Value }
  return @($Value)
}

$MachineEnvironment = Read-JsonFile (Join-Path $Root 'environment.json')
foreach ($entry in @($MachineEnvironment.PSObject.Properties)) {
  [Environment]::SetEnvironmentVariable($entry.Name, [string]$entry.Value, 'Machine')
}

$UserEnvironment = Read-JsonFile (Join-Path $Root 'user-environment.json')
foreach ($entry in @($UserEnvironment.PSObject.Properties)) {
  [Environment]::SetEnvironmentVariable($entry.Name, [string]$entry.Value, 'User')
}

$FeatureFile = Join-Path $Root 'enabled-windows-features.json'
foreach ($feature in (As-Array (Read-JsonFile $FeatureFile))) {
  $featureName = [string]$feature.FeatureName
  if (-not [string]::IsNullOrWhiteSpace($featureName)) {
    Enable-WindowsOptionalFeature -Online -FeatureName $featureName -All -NoRestart -ErrorAction Continue | Out-Null
  }
}

$CapabilityFile = Join-Path $Root 'installed-windows-capabilities.json'
foreach ($capability in (As-Array (Read-JsonFile $CapabilityFile))) {
  $capabilityName = [string]$capability.Name
  if (-not [string]::IsNullOrWhiteSpace($capabilityName)) {
    Add-WindowsCapability -Online -Name $capabilityName -ErrorAction Continue | Out-Null
  }
}

$ServiceFile = Join-Path $Root 'services-cim.json'
$StartupMap = @{ Auto = 'Automatic'; Automatic = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }
$NumericStartupMap = @{ 2 = 'Automatic'; 3 = 'Manual'; 4 = 'Disabled' }
foreach ($service in (As-Array (Read-JsonFile $ServiceFile))) {
  $serviceName = [string]$service.Name
  if ([string]::IsNullOrWhiteSpace($serviceName)) { $serviceName = [string]$service.PSChildName }
  if ([string]::IsNullOrWhiteSpace($serviceName)) { continue }
  $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($null -eq $existing) { continue }
  $pathValue = [string]$service.PathName
  if ([string]::IsNullOrWhiteSpace($pathValue)) { $pathValue = [string]$service.ImagePath }
  $servicePath = [Environment]::ExpandEnvironmentVariables($pathValue).Trim('"')
  if (-not [string]::IsNullOrWhiteSpace($servicePath) -and $servicePath.StartsWith($env:WINDIR, [System.StringComparison]::OrdinalIgnoreCase)) {
    continue
  }
  $startMode = [string]$service.StartMode
  if ([string]::IsNullOrWhiteSpace($startMode) -and $null -ne $service.Start) {
    $startNumber = [int]$service.Start
    if ($NumericStartupMap.ContainsKey($startNumber)) { $startMode = $NumericStartupMap[$startNumber] }
  }
  if ($StartupMap.ContainsKey($startMode)) {
    Set-Service -Name $serviceName -StartupType $StartupMap[$startMode] -ErrorAction Continue
  }
  if ([string]$service.State -eq 'Running') {
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
  }
}

$DriverRoot = Join-Path $Root 'driver-store-export'
if (Test-Path $DriverRoot) {
  pnputil.exe /add-driver "$DriverRoot\*.inf" /subdirs /install
}
$WifiRoot = Join-Path $Root 'wifi-profiles'
if (Test-Path $WifiRoot) {
  Get-ChildItem -LiteralPath $WifiRoot -Filter '*.xml' -File | ForEach-Object {
    netsh.exe wlan add profile filename="$($_.FullName)" user=all
  }
}

$PowerRoot = Join-Path $Root 'power'
$PowerSummary = Read-JsonFile (Join-Path $PowerRoot 'power-summary.json')
if ($PowerSummary.active_guid -and (Test-Path -LiteralPath (Join-Path $PowerRoot 'active-scheme.pow'))) {
  powercfg.exe /IMPORT (Join-Path $PowerRoot 'active-scheme.pow') $PowerSummary.active_guid
  powercfg.exe /SETACTIVE $PowerSummary.active_guid
}
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -monitor-timeout-ac 0
powercfg.exe -change -disk-timeout-ac 0
try {
  $computer = Get-CimInstance Win32_ComputerSystem
  $computer | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
  Get-CimInstance Win32_PageFileSetting | Remove-CimInstance -ErrorAction SilentlyContinue
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Value @() -ErrorAction Continue
} catch {
  Write-Warning "Pagefile replay failed or needs reboot to finish: $($_.Exception.Message)"
}
$TaskRoot = Join-Path $Root 'scheduled-tasks-xml'
if (Test-Path $TaskRoot) {
  Get-ChildItem -LiteralPath $TaskRoot -Filter '*.xml' -Recurse -File | ForEach-Object {
    try {
      [xml]$taskXml = Get-Content -LiteralPath $_.FullName -Raw
      $uri = [string]$taskXml.Task.RegistrationInfo.URI
      if ([string]::IsNullOrWhiteSpace($uri)) {
        $taskName = [IO.Path]::GetFileNameWithoutExtension($_.Name)
        $taskPath = '\'
      } else {
        if (-not $uri.StartsWith('\')) { $uri = '\' + $uri }
        if ($uri.StartsWith('\Microsoft\', [System.StringComparison]::OrdinalIgnoreCase)) {
          Write-Host "Skipping OS scheduled task already owned by fresh Windows: $uri"
          continue
        }
        $lastSlash = $uri.LastIndexOf('\')
        $taskName = $uri.Substring($lastSlash + 1)
        $taskPath = if ($lastSlash -le 0) { '\' } else { $uri.Substring(0, $lastSlash + 1) }
      }
      Register-ScheduledTask -Xml (Get-Content -LiteralPath $_.FullName -Raw) -TaskName $taskName -TaskPath $taskPath -Force -ErrorAction Continue | Out-Null
    } catch {
      Write-Warning "Scheduled task import failed for $($_.FullName): $($_.Exception.Message)"
    }
  }
}

$AppxFile = Join-Path $MetadataRoot 'package-managers\appx-packages.json'
foreach ($package in (As-Array (Read-JsonFile $AppxFile))) {
  $installLocation = [string]$package.InstallLocation
  if ([string]::IsNullOrWhiteSpace($installLocation)) { continue }
  $manifest = Join-Path $installLocation 'AppXManifest.xml'
  if (Test-Path -LiteralPath $manifest) {
    Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction Continue
  }
}

$WslManifest = Join-Path $Root 'wsl-exports\wsl-exports-manifest.json'
$ExistingDistros = @()
try {
  $ExistingDistros = @(wsl.exe --list --quiet 2>$null) | ForEach-Object { ($_ -replace [char]0, '').Trim() } | Where-Object { $_ }
} catch { }
foreach ($entry in (As-Array (Read-JsonFile $WslManifest))) {
  if ([string]$entry.status -ne 'ok') { continue }
  $distroName = [string]$entry.distro
  $tarPath = Join-Path $MetadataRoot ([string]$entry.file)
  if ([string]::IsNullOrWhiteSpace($distroName) -or -not (Test-Path -LiteralPath $tarPath)) { continue }
  if ($ExistingDistros -contains $distroName) { continue }
  $safeName = $distroName -replace '[\\/:*?"<>| ]+', '_'
  $targetDir = Join-Path $env:LOCALAPPDATA "WSL\$safeName"
  New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
  wsl.exe --import $distroName $targetDir $tarPath
}

$SetUserFta = Get-Command SetUserFTA.exe -ErrorAction SilentlyContinue
if ($SetUserFta) {
  $SetUserFtaPath = $SetUserFta.Source
  foreach ($association in @('http','https','.htm','.html')) {
    & $SetUserFtaPath $association ChromeHTML
  }
} else {
  Write-Host 'Chrome default-browser replay is protected by Windows user-choice hashing. Install SetUserFTA.exe before restore if a fully automatic default-browser switch is required.'
}

try {
  ie4uinit.exe -show
  Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
  Start-Process explorer.exe
} catch {
  Write-Warning "Explorer shell refresh failed: $($_.Exception.Message)"
}

Write-Host 'System replay finished. Credential secrets, printers, boot/recovery partitions, and unavailable Store/vendor sources may still need source-backed restore or a full disk image.'
"""
    script.write_text(content.strip() + "\n", encoding="utf-8")
    return {"name": "system-replay-script", "file": str(script.relative_to(metadata_dir)), "status": "ok", "returncode": 0}


def export_extra_system_metadata(metadata_dir: Path) -> list[dict[str, Any]]:
    extra_dir = metadata_dir / "system"
    extra_dir.mkdir(parents=True, exist_ok=True)
    services_registry_script = (
        "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' | ForEach-Object { "
        "$p = Get-ItemProperty -LiteralPath $_.PSPath; "
        "[pscustomobject]@{ PSChildName=$_.PSChildName; Name=$_.PSChildName; Start=$p.Start; ImagePath=$p.ImagePath; ObjectName=$p.ObjectName } "
        "} | ConvertTo-Json -Depth 5"
    )
    commands = [
        ("environment.json", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "[Environment]::GetEnvironmentVariables('Machine') | ConvertTo-Json -Depth 4"], 60),
        ("user-environment.json", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "[Environment]::GetEnvironmentVariables('User') | ConvertTo-Json -Depth 4"], 60),
        ("services.json", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Depth 4"], 90),
        ("services-cim.json", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", services_registry_script], 90),
        ("scheduled-tasks.csv", ["schtasks.exe", "/Query", "/FO", "CSV", "/V"], 180),
        ("firewall-rules.txt", ["netsh.exe", "advfirewall", "firewall", "show", "rule", "name=all"], 180),
        ("drivers.txt", ["pnputil.exe", "/enum-drivers"], 120),
        ("devices-net.txt", ["pnputil.exe", "/enum-devices", "/class", "Net"], 120),
        ("windows-features.txt", ["dism.exe", "/Online", "/Get-Features", "/Format:Table"], 120),
        ("enabled-windows-features.json", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' | Select-Object FeatureName,State | ConvertTo-Json -Depth 4"], 180),
        ("windows-capabilities.txt", ["dism.exe", "/Online", "/Get-Capabilities", "/Format:Table"], 180),
        ("installed-windows-capabilities.json", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-WindowsCapability -Online | Where-Object State -eq 'Installed' | Select-Object Name,State | ConvertTo-Json -Depth 4"], 180),
        ("printers.json", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-Printer | Select-Object Name,DriverName,PortName,Shared,Published | ConvertTo-Json -Depth 4"], 60),
        ("ipconfig-all.txt", ["ipconfig.exe", "/all"], 60),
        ("netsh-interfaces.txt", ["netsh.exe", "interface", "show", "interface"], 60),
        ("credentials-inventory.txt", ["cmdkey.exe", "/list"], 60),
        ("winre-info.txt", ["reagentc.exe", "/info"], 60),
        ("bcdedit-all.txt", ["bcdedit.exe", "/enum", "all"], 60),
        ("disks-partitions.txt", ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-Disk | Format-List *; Get-Partition | Format-List *"], 90),
    ]
    exports: list[dict[str, Any]] = []
    write_json(metadata_dir / "system" / "recovery-risk-model.json", build_recovery_risk_model())
    for filename, args, timeout in commands:
        result = run_command(args, timeout=timeout)
        output = extra_dir / filename
        write_command_output(output, result)
        exports.append(command_export_record(filename, output, metadata_dir, result))
    exports.append(export_scheduled_task_xml(metadata_dir))
    exports.append(export_wifi_profiles(metadata_dir))
    exports.append(export_power_state(metadata_dir))
    exports.append(export_docker_state(metadata_dir))
    exports.append(export_bluetooth_state(metadata_dir))
    exports.append(export_shell_state(metadata_dir))
    exports.append(export_credential_state(metadata_dir))
    exports.append(export_driver_store(metadata_dir))
    return exports


def archive_path_for_file(path: Path) -> str:
    drive = path.drive.rstrip(":").upper() or "NO_DRIVE"
    relative_parts = path.parts[1:] if path.drive else path.parts
    safe_parts = [part.replace(":", "_") for part in relative_parts]
    return "/".join(["files", drive, *safe_parts])


def sha256_file(path: Path, max_bytes: int = MAX_HASH_BYTES) -> tuple[str | None, str | None]:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None, f"larger_than_{max_bytes}_bytes"
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest(), None
    except (MemoryError, OSError) as exc:
        return None, str(exc)


def iter_backup_files(root: Path) -> tuple[list[Path], list[dict[str, Any]]]:
    files: list[Path] = []
    skipped: list[dict[str, Any]] = []
    for current, dirs, names in os.walk(root, topdown=True, onerror=None):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in dirs:
            child = current_path / dirname
            if is_reparse_point(child) or should_skip_backup_path(child):
                skipped.append({"path": str(child), "reason": "skipped_directory"})
                continue
            kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for name in names:
            file_path = current_path / name
            if should_skip_backup_path(file_path):
                skipped.append({"path": str(file_path), "reason": "volatile_or_shell_metadata"})
                continue
            if is_reparse_point(file_path):
                skipped.append({"path": str(file_path), "reason": "reparse_point"})
                continue
            files.append(file_path)
    return files, skipped


def record_skipped_file(manifest: dict[str, Any], skipped_index: Any, record: dict[str, Any]) -> None:
    manifest["skipped_count"] = int(manifest.get("skipped_count", 0)) + 1
    if skipped_index is not None:
        write_jsonl_record(skipped_index, record)
    else:
        manifest.setdefault("skipped_files", []).append(record)


def record_file_entry(manifest: dict[str, Any], file_index: Any, entry: dict[str, Any]) -> None:
    manifest["file_count"] = int(manifest.get("file_count", 0)) + 1
    mark_archive_path_presence(manifest, str(entry["archive_path"]))
    if file_index is not None:
        write_jsonl_record(file_index, entry)
    else:
        manifest.setdefault("files", []).append(entry)


def add_directory_to_zip(
    zf: zipfile.ZipFile,
    root: Path,
    manifest: dict[str, Any],
    file_index: Any | None = None,
    skipped_index: Any | None = None,
) -> None:
    for current, dirs, names in os.walk(root):
        current_path = Path(current)
        kept_dirs = []
        for dirname in dirs:
            child = current_path / dirname
            if is_reparse_point(child) or should_skip_backup_path(child):
                record_skipped_file(manifest, skipped_index, {"path": str(child), "reason": "skipped_directory"})
                continue
            kept_dirs.append(dirname)
        dirs[:] = kept_dirs
        for name in names:
            file_path = current_path / name
            if should_skip_backup_path(file_path):
                record_skipped_file(manifest, skipped_index, {"path": str(file_path), "reason": "volatile_or_shell_metadata"})
                continue
            if is_reparse_point(file_path):
                record_skipped_file(manifest, skipped_index, {"path": str(file_path), "reason": "reparse_point"})
                continue
            archive_path = archive_path_for_file(file_path)
            sha256, hash_error = sha256_file(file_path)
            try:
                zf.write(file_path, archive_path)
                stat_result = file_path.stat()
                record_file_entry(
                    manifest,
                    file_index,
                    {
                        "source_root": str(root),
                        "source": str(file_path),
                        "destination": str(file_path),
                        "archive_path": archive_path,
                        "size": stat_result.st_size,
                        "mtime": dt.datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
                        "sha256": sha256,
                        "hash_error": hash_error,
                    },
                )
            except OSError as exc:
                record_skipped_file(manifest, skipped_index, {"path": str(file_path), "reason": "copy_failed", "error": str(exc)})


def is_wsl_metadata_member(relative_path: Path) -> bool:
    parts = [part.casefold() for part in relative_path.parts]
    return len(parts) >= 2 and parts[0] == "system" and (parts[1].startswith("wsl") or parts[1] == "wsl-exports")


def create_zip_from_inventory(
    package: Path,
    metadata_dir: Path,
    inventory: dict[str, Any],
    manifest: dict[str, Any],
    final_metadata_callback: Any | None = None,
) -> None:
    written_metadata: set[str] = set()

    def write_metadata_files(zf: zipfile.ZipFile, wsl_only: bool = False) -> None:
        for metadata_file in sorted((item for item in metadata_dir.rglob("*") if item.is_file()), key=lambda item: item.relative_to(metadata_dir).as_posix().casefold()):
            relative = metadata_file.relative_to(metadata_dir)
            if is_wsl_metadata_member(relative) != wsl_only:
                continue
            archive_name = "metadata/" + relative.as_posix()
            if archive_name in written_metadata:
                continue
            zf.write(metadata_file, archive_name)
            written_metadata.add(archive_name)

    with zipfile.ZipFile(
        package,
        "w",
        compression=ZIP_COMPRESSION_METHOD,
        compresslevel=ZIP_COMPRESSLEVEL,
        allowZip64=True,
        strict_timestamps=False,
    ) as zf:
        write_metadata_files(zf, wsl_only=False)
        manifest["file_index"] = FILE_INDEX_ARCHIVE_PATH
        manifest["skipped_file_index"] = SKIPPED_FILE_INDEX_ARCHIVE_PATH
        manifest["file_count"] = int(manifest.get("file_count", 0))
        manifest["skipped_count"] = int(manifest.get("skipped_count", 0))
        ensure_archive_presence_map(manifest)
        file_index_path = metadata_dir / Path(FILE_INDEX_ARCHIVE_PATH).relative_to("metadata")
        skipped_index_path = metadata_dir / Path(SKIPPED_FILE_INDEX_ARCHIVE_PATH).relative_to("metadata")
        with file_index_path.open("w", encoding="utf-8", newline="\n") as file_index, skipped_index_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as skipped_index:
            for root_str in inventory["file_roots"]:
                root = Path(root_str)
                if root.exists():
                    add_directory_to_zip(zf, root, manifest, file_index=file_index, skipped_index=skipped_index)
        if final_metadata_callback is not None:
            final_metadata_callback()
        write_metadata_files(zf, wsl_only=True)
        write_metadata_files(zf, wsl_only=False)
        manifest["finished_at"] = now_local().isoformat()
        manifest["restore_coverage"] = build_restore_coverage_summary(manifest)
        manifest["status"] = "success"
        zf.writestr("manifest.json", json.dumps(manifest, separators=(",", ":")))


def command_inventory(args: argparse.Namespace) -> int:
    inventory = build_inventory()
    inventory["backup_root"] = str(normalize_backup_root(args.backup_root, create=False))
    console_print(json.dumps(inventory, indent=2, sort_keys=True))
    return 0


def command_backup(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=True)
    timestamp = now_local().strftime("%Y%m%d-%H%M%S")
    package = root / f"installed-state-{timestamp}.zip"
    partial = root / f"installed-state-{timestamp}.zip.partial"
    with tempfile.TemporaryDirectory(prefix="installed-state-metadata-") as temp:
        metadata_dir = Path(temp)
        inventory = build_inventory()
        inventory["backup_root"] = str(root)
        preflight = preflight_critical_backup_state()
        write_json(metadata_dir / "backup-preflight.json", preflight)
        if not preflight["ok"] and not args.allow_incomplete_system:
            raise ToolError(
                "Backup refused because critical reset-safe state is not healthy: "
                + "; ".join(issue["reason"] for issue in preflight["issues"])
                + ". Try running the repair-wsl command, then rerun backins. Rerun with --allow-incomplete-system only if you knowingly accept an incomplete restore backup."
            )
        package_snapshots = collect_package_manager_snapshots(metadata_dir)
        registry_exports = export_registry_keys(metadata_dir)
        system_exports = export_extra_system_metadata(metadata_dir)
        write_json(metadata_dir / "inventory.json", inventory)
        manifest: dict[str, Any] = {
            "tool": "installed_state_backup_restore",
            "tool_version": TOOL_VERSION,
            "backup_kind": "installed-app-state",
            "backup_root": str(root),
            "created_at": now_local().isoformat(),
            "file_roots": inventory["file_roots"],
            "registry_exports": registry_exports,
            "system_exports": system_exports,
            "preflight": preflight,
            "package_manager_snapshots": package_snapshots,
            "file_index": FILE_INDEX_ARCHIVE_PATH,
            "skipped_file_index": SKIPPED_FILE_INDEX_ARCHIVE_PATH,
            "file_count": 0,
            "skipped_count": 0,
            "archive_path_presence": {},
            "status": "creating",
            "fresh_windows_note": (
                "Package-manager manifests, replay scripts, shell/startup/taskbar state, and protected credential "
                "file inventories are captured in a compact compressed installed-state backup. Broad personal "
                "media/download folders are excluded to avoid backup garbage. True no-exception restore on a "
                "brand-new Windows install still requires source availability and may need vendor installers, "
                "provider re-auth, DPAPI acceptance, or a full image for Windows-protected secrets."
            ),
        }

        def finalize_wsl_metadata() -> None:
            system_exports.extend(export_wsl_status_files(metadata_dir))
            system_exports.append(export_wsl_distros(metadata_dir, idle_wait_seconds=args.wsl_idle_wait_seconds))
            if not args.allow_incomplete_system:
                assert_critical_system_exports(preflight, system_exports)
            system_exports.append(write_system_replay_script(metadata_dir))
            manifest["system_exports"] = system_exports

        create_zip_from_inventory(partial, metadata_dir, inventory, manifest, final_metadata_callback=finalize_wsl_metadata)
    if package.exists():
        package.unlink()
    partial.rename(package)
    (root / "latest.txt").write_text(str(package), encoding="utf-8")
    verification = verify_zip_package(package, full_hash=False)
    console_print(json.dumps(verification, indent=2, sort_keys=True))
    return 0


def load_manifest_from_zip(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path, "r") as zf:
        try:
            return json.loads(zf.read("manifest.json").decode("utf-8"))
        except KeyError as exc:
            raise ToolError(f"manifest.json missing from {path}") from exc


def manifest_inline_files(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    files = manifest.get("files")
    return files if isinstance(files, list) else []


def iter_file_records_from_open_zip(zf: zipfile.ZipFile, manifest: dict[str, Any]) -> Any:
    inline_files = manifest_inline_files(manifest)
    if inline_files:
        yield from inline_files
        return
    index_path = str(manifest.get("file_index") or FILE_INDEX_ARCHIVE_PATH)
    try:
        handle_context = zf.open(index_path, "r")
    except KeyError:
        if inline_files == [] and int(manifest.get("file_count", 0) or 0) == 0:
            return
        raise ToolError(f"File index missing from backup package: {index_path}")
    with handle_context as handle:
        for line in io.TextIOWrapper(handle, encoding="utf-8"):
            line = line.strip()
            if line:
                yield json.loads(line)


def iter_file_records_from_package(package: Path, manifest: dict[str, Any] | None = None) -> Any:
    manifest = manifest if manifest is not None else load_manifest_from_zip(package)
    with zipfile.ZipFile(package, "r") as zf:
        yield from iter_file_records_from_open_zip(zf, manifest)


def iter_file_records_from_extraction(extraction: Path, manifest: dict[str, Any]) -> Any:
    inline_files = manifest_inline_files(manifest)
    if inline_files:
        yield from inline_files
        return
    index_path = extraction / str(manifest.get("file_index") or FILE_INDEX_ARCHIVE_PATH)
    if not index_path.exists():
        if int(manifest.get("file_count", 0) or 0) == 0:
            return
        raise ToolError(f"File index missing from extracted backup: {index_path}")
    with index_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def find_latest_successful_backup(root: Path) -> Path:
    candidates: list[Path] = []
    marker = root / "latest.txt"
    if marker.exists():
        marker_value = marker.read_text(encoding="utf-8", errors="replace").strip()
        if marker_value:
            candidates.append(Path(marker_value))
    candidates.extend(sorted(root.glob("installed-state-*.zip"), reverse=True))
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        identity = str(resolved).casefold()
        if identity in seen or not resolved.exists():
            continue
        seen.add(identity)
        try:
            manifest = load_manifest_from_zip(resolved)
        except Exception:
            continue
        if manifest.get("status") == "success" and manifest.get("backup_kind") == "installed-app-state":
            return resolved
    raise ToolError(f"No successful installed-app backup found under {root}")


def verify_zip_package(path: Path, full_hash: bool = True) -> dict[str, Any]:
    if not path.exists():
        raise ToolError(f"Backup package not found: {path}")
    manifest = load_manifest_from_zip(path)
    if manifest.get("status") != "success":
        raise ToolError(f"Backup status is not success: {manifest.get('status')}")
    checked = 0
    file_count = 0
    hash_mismatches: list[dict[str, Any]] = []
    with zipfile.ZipFile(path, "r") as zf:
        names = set(zf.namelist())
        missing = []
        for item in iter_file_records_from_open_zip(zf, manifest):
            file_count += 1
            if item["archive_path"] not in names:
                missing.append(item["archive_path"])
                continue
            if full_hash:
                expected = item.get("sha256")
                if not expected:
                    continue
                digest = hashlib.sha256()
                with zf.open(item["archive_path"], "r") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                checked += 1
                actual = digest.hexdigest()
                if actual != expected:
                    hash_mismatches.append({"archive_path": item["archive_path"], "expected": expected, "actual": actual})
    return {
        "package": str(path),
        "status": manifest.get("status"),
        "file_count": file_count if file_count else int(manifest.get("file_count", 0) or 0),
        "skipped_count": int(manifest.get("skipped_count", len(manifest.get("skipped_files", []))) or 0),
        "hashes_checked": checked,
        "hash_mismatches": hash_mismatches,
        "missing_archive_members": missing,
        "ok": not missing and not hash_mismatches,
    }


def command_latest(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=False)
    console_print(str(find_latest_successful_backup(root)))
    return 0


def command_verify(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=False)
    package = Path(args.package) if args.package else find_latest_successful_backup(root)
    console_print(json.dumps(verify_zip_package(package, full_hash=not args.quick), indent=2, sort_keys=True))
    return 0


def manifest_archive_paths(manifest: dict[str, Any]) -> list[str]:
    return [str(item.get("archive_path", "")).casefold() for item in manifest.get("files", [])]


def manifest_has_archive_path_containing(manifest: dict[str, Any], fragment: str, archive_paths: list[str] | None = None) -> bool:
    needle = normalized_archive_fragment(fragment)
    presence = manifest.get("archive_path_presence")
    if isinstance(presence, dict) and needle in presence:
        return bool(presence[needle])
    paths = archive_paths if archive_paths is not None else manifest_archive_paths(manifest)
    return any(needle in archive_path for archive_path in paths)


def registry_export_ok(registry_keys: dict[str | None, dict[str, Any]], key: str) -> bool:
    return registry_keys.get(key, {}).get("status") == "ok"


def system_export_ok(system_files: dict[str, dict[str, Any]], name: str) -> bool:
    return system_files.get(name, {}).get("status") == "ok"


def system_export_subrecords_ok(system_files: dict[str, dict[str, Any]], name: str) -> bool:
    export = system_files.get(name, {})
    subrecords = export.get("subrecords") or []
    return export.get("status") == "ok" and bool(subrecords) and all(item.get("status") == "ok" for item in subrecords)


def failed_system_export_subrecords(system_files: dict[str, dict[str, Any]], name: str) -> list[str]:
    export = system_files.get(name, {})
    return [str(item.get("name") or item.get("file") or "unknown") for item in export.get("subrecords", []) if item.get("status") != "ok"]


def package_snapshot_ok(manifest: dict[str, Any], name: str) -> bool:
    return any(
        snapshot.get("name") == name and snapshot.get("status") == "ok"
        for snapshot in manifest.get("package_manager_snapshots", [])
    )


def package_snapshot_captured(manifest: dict[str, Any], name: str) -> bool:
    return any(
        snapshot.get("name") == name and snapshot.get("status") in {"ok", "created_with_nonzero_exit"}
        for snapshot in manifest.get("package_manager_snapshots", [])
    )


def build_restore_coverage_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    system_files = {snapshot["name"]: snapshot for snapshot in manifest.get("system_exports", [])}
    registry_keys = {snapshot.get("key"): snapshot for snapshot in manifest.get("registry_exports", [])}
    archive_paths = None if isinstance(manifest.get("archive_path_presence"), dict) else manifest_archive_paths(manifest)
    has_archive = lambda fragment: manifest_has_archive_path_containing(manifest, fragment, archive_paths)
    startup_folder_archived = has_archive("Microsoft/Windows/Start Menu/Programs/Startup")
    return {
        "runtime_and_package_replay": {
            "coverage_kind": "backup_capture_and_generated_replay_script",
            "restore_execution_proof_in_manifest": False,
            "restore_execution_proof_note": "A real restore writes a separate restore-execution-last.json log; backup manifest booleans prove captured payloads and generated replay intent only.",
            "has_winget_export": package_snapshot_ok(manifest, "winget-export"),
            "has_winget_source_inventory": package_snapshot_captured(manifest, "winget-sources"),
            "has_winget_list": package_snapshot_ok(manifest, "winget-list"),
            "has_choco_list": package_snapshot_ok(manifest, "choco-list"),
            "has_choco_replay_payload": package_snapshot_ok(manifest, "choco-export"),
            "has_appx_snapshot": package_snapshot_ok(manifest, "appx-packages"),
            "has_dotnet_sdk_snapshot": package_snapshot_ok(manifest, "dotnet-sdks"),
            "has_dotnet_runtime_snapshot": package_snapshot_ok(manifest, "dotnet-runtimes"),
            "has_pip_freeze": package_snapshot_ok(manifest, "pip-freeze"),
            "has_npm_global_snapshot": package_snapshot_ok(manifest, "npm-list-global"),
            "has_npm_config_snapshot": package_snapshot_captured(manifest, "npm-config"),
            "has_pnpm_global_snapshot": package_snapshot_ok(manifest, "pnpm-list-global"),
            "has_pnpm_config_snapshot": package_snapshot_captured(manifest, "pnpm-config"),
            "has_yarn_global_snapshot": package_snapshot_ok(manifest, "yarn-global-list"),
            "has_yarn_config_snapshot": package_snapshot_captured(manifest, "yarn-config"),
            "has_bun_global_snapshot": package_snapshot_ok(manifest, "bun-global-list"),
            "has_pipx_snapshot": package_snapshot_ok(manifest, "pipx-list"),
            "has_uv_tool_snapshot": package_snapshot_ok(manifest, "uv-tool-list"),
            "has_cargo_install_snapshot": package_snapshot_ok(manifest, "cargo-install-list"),
            "has_gh_extension_snapshot": package_snapshot_ok(manifest, "gh-extension-list"),
            "has_powershell7_modules": package_snapshot_ok(manifest, "powershell7-modules"),
            "source_availability_boundary": (
                "Replay uses captured manifests/configs where possible, but package reinstall still depends on package sources, "
                "publisher entitlements, and network availability at restore time."
            ),
            "replay_script_bootstraps": [
                "Python.Python.3.12",
                "Microsoft.PowerShell",
                "Git.Git",
                "GitHub.cli",
                "OpenJS.NodeJS.LTS",
                "Docker.DockerDesktop",
                "OpenAI.Codex",
                "Anthropic.Claude",
                "VC++ redistributables",
                "DirectX",
                "XNA",
                ".NET runtimes",
                ".NET SDKs",
                "Windows SDK",
                "Windows ADK",
            ],
        },
        "wsl_and_system_replay": {
            "has_wsl_export": system_export_ok(system_files, "wsl-exports"),
            "has_wsl_list_export": system_export_ok(system_files, "wsl-list.txt"),
            "has_wsl_status_export": system_export_ok(system_files, "wsl-status.txt"),
            "has_system_replay_script": system_export_ok(system_files, "system-replay-script"),
            "restore_note": "resins.bat passes --execute-system-replay, so the generated system replay script imports missing WSL distros from captured exports. This field proves script generation, not that a future restore already ran.",
        },
        "shell_and_startup": {
            "has_shell_state_export": system_export_ok(system_files, "shell-state"),
            "has_taskbar_pins_archived": has_archive("Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar"),
            "has_start_menu_archived": has_archive("Microsoft/Windows/Start Menu"),
            "has_startup_folder_files_archived": startup_folder_archived,
            "has_startup_folder_inventory": system_export_ok(system_files, "shell-state"),
            "has_startup_folder_restore_payload_or_scan_proof": startup_folder_archived or system_export_ok(system_files, "shell-state"),
            "startup_folder_restore_boundary": (
                "Archived Startup-folder files are directly restorable. Inventory-only coverage proves the folder was scanned, "
                "but cannot recreate missing Startup payloads unless the backup also contains those files."
            ),
            "has_jump_lists_archived": has_archive("Microsoft/Windows/Recent/AutomaticDestinations")
            or has_archive("Microsoft/Windows/Recent/CustomDestinations"),
            "has_run_registry_exports": registry_export_ok(
                registry_keys,
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            )
            and registry_export_ok(
                registry_keys,
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ),
            "has_wow64_run_registry_export": registry_export_ok(
                registry_keys,
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            ),
            "has_runonce_registry_exports": registry_export_ok(
                registry_keys,
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            )
            and registry_export_ok(
                registry_keys,
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ),
            "has_scheduled_task_xml_export": system_files.get("scheduled-tasks-xml", {}).get("status") == "ok",
            "has_startupapproved_registry_exports": registry_export_ok(
                registry_keys,
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
            )
            and registry_export_ok(
                registry_keys,
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
            ),
            "has_taskband_registry_export": registry_export_ok(
                registry_keys,
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband",
            ),
            "has_cloudstore_registry_export": registry_export_ok(
                registry_keys,
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore",
            ),
        },
        "default_apps_and_shortcuts": {
            "has_url_association_exports": registry_export_ok(
                registry_keys,
                r"HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations",
            ),
            "has_file_extension_association_exports": registry_export_ok(
                registry_keys,
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts",
            ),
            "has_startmenuinternet_exports": registry_export_ok(
                registry_keys,
                r"HKLM\SOFTWARE\Clients\StartMenuInternet",
            )
            and registry_export_ok(
                registry_keys,
                r"HKCU\Software\Clients\StartMenuInternet",
            ),
            "has_desktop_shortcuts_archived": has_archive("/Desktop/"),
            "has_start_menu_shortcuts_archived": has_archive("Microsoft/Windows/Start Menu"),
            "has_chrome_default_replay_attempt": system_export_ok(system_files, "system-replay-script"),
            "setuserfta_archived": has_archive("SetUserFTA.exe"),
            "default_association_restore_scope": "Chrome web defaults only: http, https, .htm, and .html, and only when SetUserFTA is available during restore.",
            "windows_userchoice_boundary": (
                "Raw association registry exports are captured, but Windows UserChoice hashes can reject generic imports. "
                "The system replay script attempts Chrome defaults for http, https, .htm, and .html when SetUserFTA is available."
            ),
        },
        "credentials_and_login_state": {
            "restore_mode": "capture_only_for_windows_protected_secrets",
            "has_credential_state_export": system_export_subrecords_ok(system_files, "credential-state"),
            "credential_subrecords_all_ok": system_export_subrecords_ok(system_files, "credential-state"),
            "credential_failed_subrecords": failed_system_export_subrecords(system_files, "credential-state"),
            "has_vault_files_archived": has_archive("Microsoft/Vault"),
            "has_credential_files_archived": has_archive("Microsoft/Credentials"),
            "has_dpapi_protect_archived": has_archive("Microsoft/Protect"),
            "has_crypto_key_files_archived": has_archive("Microsoft/Crypto"),
            "has_windows_hello_ngc_archived": has_archive("Microsoft/Ngc"),
            "truth_boundary": (
                "Protected files and inventories are captured, but DPAPI/Vault/Windows Hello/app tokens may remain "
                "non-decryptable after a format unless Windows/account/provider policy accepts the restored state."
            ),
        },
        "browser_and_app_profiles": {
            "has_chrome_profile_archived": has_archive("Google/Chrome/User Data"),
            "has_edge_profile_archived": has_archive("Microsoft/Edge/User Data"),
            "has_firefox_profile_archived": has_archive("Mozilla/Firefox"),
            "has_telegram_tdata_archived": has_archive("Telegram Desktop/tdata"),
            "has_todoist_profile_archived": has_archive("Todoist"),
            "has_codex_state_archived": has_archive(".codex"),
            "has_claude_state_archived": has_archive(".claude"),
            "has_docker_profile_archived": has_archive(".docker")
            or has_archive("Docker"),
        },
    }


def read_winget_package_ids_from_zip(package: Path) -> set[str]:
    ids: set[str] = set()
    try:
        with zipfile.ZipFile(package, "r") as zf:
            data = json.loads(zf.read("metadata/package-managers/winget-export.json").decode("utf-8"))
    except Exception:
        return ids
    for source in data.get("Sources", []):
        for item in source.get("Packages", []):
            package_id = item.get("PackageIdentifier")
            if package_id:
                ids.add(str(package_id))
    return ids


def build_runtime_package_health(package_ids: set[str]) -> dict[str, Any]:
    def has_any(*ids: str) -> bool:
        return any(package_id in package_ids for package_id in ids)

    critical_groups = {
        "visual_cpp_redistributables": [
            "Microsoft.VCRedist.2005.x86",
            "Microsoft.VCRedist.2005.x64",
            "Microsoft.VCRedist.2008.x86",
            "Microsoft.VCRedist.2008.x64",
            "Microsoft.VCRedist.2010.x86",
            "Microsoft.VCRedist.2010.x64",
            "Microsoft.VCRedist.2012.x86",
            "Microsoft.VCRedist.2012.x64",
            "Microsoft.VCRedist.2013.x86",
            "Microsoft.VCRedist.2013.x64",
            "Microsoft.VCRedist.2015+.x86",
            "Microsoft.VCRedist.2015+.x64",
        ],
        "directx": ["Microsoft.DirectX"],
        "xna": ["Microsoft.XNARedist"],
        "dotnet_sdks": [
            "Microsoft.DotNet.SDK.3_1",
            "Microsoft.DotNet.SDK.5",
            "Microsoft.DotNet.SDK.6",
            "Microsoft.DotNet.SDK.7",
            "Microsoft.DotNet.SDK.8",
            "Microsoft.DotNet.SDK.9",
            "Microsoft.DotNet.SDK.10",
            "Microsoft.DotNet.SDK.Preview",
        ],
        "dotnet_runtimes": [
            "Microsoft.DotNet.Runtime.3_1",
            "Microsoft.DotNet.Runtime.5",
            "Microsoft.DotNet.Runtime.6",
            "Microsoft.DotNet.Runtime.7",
            "Microsoft.DotNet.Runtime.8",
            "Microsoft.DotNet.Runtime.9",
            "Microsoft.DotNet.Runtime.10",
            "Microsoft.DotNet.Runtime.Preview",
            "Microsoft.DotNet.DesktopRuntime.3_1",
            "Microsoft.DotNet.DesktopRuntime.5",
            "Microsoft.DotNet.DesktopRuntime.6",
            "Microsoft.DotNet.DesktopRuntime.7",
            "Microsoft.DotNet.DesktopRuntime.8",
            "Microsoft.DotNet.DesktopRuntime.8.x64",
            "Microsoft.DotNet.DesktopRuntime.9",
            "Microsoft.DotNet.DesktopRuntime.10",
            "Microsoft.DotNet.DesktopRuntime.Preview",
            "Microsoft.DotNet.AspNetCore.3_1",
            "Microsoft.DotNet.AspNetCore.5",
            "Microsoft.DotNet.AspNetCore.6",
            "Microsoft.DotNet.AspNetCore.7",
            "Microsoft.DotNet.AspNetCore.8",
            "Microsoft.DotNet.AspNetCore.9",
            "Microsoft.DotNet.AspNetCore.10",
            "Microsoft.DotNet.AspNetCore.Preview",
        ],
        "windows_sdk_adk": [
            "Microsoft.WindowsSDK.10.0.26100",
            "Microsoft.WindowsADK",
            "Microsoft.WindowsADK.WinPEAddon",
        ],
    }
    return {
        name: {"present": has_any(*ids), "matched_ids": [package_id for package_id in ids if package_id in package_ids]}
        for name, ids in critical_groups.items()
    }


def command_health(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=False)
    package = find_latest_successful_backup(root)
    manifest = load_manifest_from_zip(package)
    winget_package_ids = read_winget_package_ids_from_zip(package)
    package_files = {snapshot["name"]: snapshot for snapshot in manifest.get("package_manager_snapshots", [])}
    system_files = {snapshot["name"]: snapshot for snapshot in manifest.get("system_exports", [])}
    registry_keys = {snapshot.get("key"): snapshot for snapshot in manifest.get("registry_exports", [])}
    health = {
        "latest_package": str(package),
        "verify": verify_zip_package(package, full_hash=False),
        "package_manager_snapshot_count": len(package_files),
        "system_export_count": len(system_files),
        "has_winget_snapshot": any(name.startswith("winget") for name in package_files),
        "has_choco_snapshot": any(name.startswith("choco") for name in package_files),
        "has_npm_snapshot": any(name.startswith("npm") for name in package_files),
        "has_pip_snapshot": any(name.startswith("pip") for name in package_files),
        "has_driver_store_export": system_files.get("driver-store-export", {}).get("status") == "ok",
        "driver_store_file_count": system_files.get("driver-store-export", {}).get("file_count", 0),
        "has_wsl_export": system_files.get("wsl-exports", {}).get("status") == "ok",
        "has_power_state": system_files.get("power-state", {}).get("status") == "ok",
        "has_scheduled_task_xml": system_files.get("scheduled-tasks-xml", {}).get("status") == "ok",
        "has_shell_state": system_files.get("shell-state", {}).get("status") == "ok",
        "has_credential_state": system_files.get("credential-state", {}).get("status") == "ok",
        "has_wifi_profiles": system_files.get("wifi-profiles", {}).get("status") == "ok",
        "runtime_package_health": build_runtime_package_health(winget_package_ids),
        "has_startup_registry_exports": all(
            registry_keys.get(key, {}).get("status") == "ok"
            for key in [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved",
            ]
        ),
        "restore_coverage": build_restore_coverage_summary(manifest),
        "file_roots_count": len(manifest.get("file_roots", [])),
        "fresh_windows_note": manifest.get("fresh_windows_note"),
    }
    console_print(json.dumps(health, indent=2, sort_keys=True))
    return 0


def resolve_package_arg(args: argparse.Namespace) -> Path:
    root = normalize_backup_root(args.backup_root, create=False)
    return Path(args.package) if args.package else find_latest_successful_backup(root)


def restore_flags_are_sufficient(args: argparse.Namespace) -> bool:
    return bool(
        args.execute_restore
        and args.i_understand_this_can_overwrite_files
        and args.yes_dangerous_restore
        and args.confirm_text == RESTORE_CONFIRM_TEXT
    )


def build_dry_run_report(package: Path, relocation_target: Path | None = None) -> dict[str, Any]:
    manifest = load_manifest_from_zip(package)
    skipped = []
    planned = []
    for item in iter_file_records_from_package(package, manifest):
        destination = Path(item["destination"])
        if should_skip_restore_item(item, destination):
            skipped.append({"destination": str(destination), "reason": "windows_shell_metadata"})
            continue
        planned.append(
            {
                "archive_path": item["archive_path"],
                "destination": str(relocated_destination(destination, relocation_target) if relocation_target else destination),
                "size": item.get("size"),
            }
        )
    return {
        "package": str(package),
        "relocation_target": str(relocation_target) if relocation_target else None,
        "planned_file_restores": len(planned),
        "skipped_file_restores": skipped,
        "registry_exports": manifest.get("registry_exports", []),
        "package_manager_replay": "metadata/package-managers/restore-package-managers.ps1",
        "system_replay": "metadata/system/restore-system-state.ps1",
        "restore_coverage": build_restore_coverage_summary(manifest),
        "fresh_windows_note": manifest.get("fresh_windows_note"),
        "sample": planned[:25],
    }


def command_restore_dry_run(args: argparse.Namespace) -> int:
    package = resolve_package_arg(args)
    relocation = Path(args.relocate_to).resolve() if args.relocate_to else None
    console_print(json.dumps(build_dry_run_report(package, relocation), indent=2, sort_keys=True))
    return 0


def safe_extract_member(zf: zipfile.ZipFile, member: str, destination: Path) -> Path:
    target = destination / member
    resolved_destination = destination.resolve()
    resolved_target = target.resolve()
    if not str(resolved_target).casefold().startswith(str(resolved_destination).casefold()):
        raise ToolError(f"Unsafe zip member path: {member}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with zf.open(member, "r") as source, target.open("wb") as output:
        shutil.copyfileobj(source, output)
    return target


def extract_package(package: Path, extraction_root: Path) -> None:
    with zipfile.ZipFile(package, "r") as zf:
        for member in zf.namelist():
            if member.endswith("/"):
                continue
            safe_extract_member(zf, member, extraction_root)


def relocated_destination(destination: Path, relocation_target: Path | None) -> Path:
    if relocation_target is None:
        return destination
    drive = destination.drive.rstrip(":").upper() or "NO_DRIVE"
    parts = destination.parts[1:] if destination.drive else destination.parts
    return relocation_target / drive / Path(*parts)


def is_program_files_binary(path: Path) -> bool:
    if path.suffix.casefold() not in BINARY_EXTENSIONS:
        return False
    program_roots = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
    ]
    return any(is_path_relative_to(path, root) for root in program_roots)


def restore_copy_skip_reason(
    destination: Path,
    destination_exists: bool,
    overwrite_installed_binaries: bool = False,
) -> str | None:
    if not destination_exists:
        return None
    if not overwrite_installed_binaries and is_program_files_binary(destination):
        return "existing_installed_binary_reset_safe"
    return None


def files_are_identical(source: Path, destination: Path) -> bool:
    if not destination.exists() or source.stat().st_size != destination.stat().st_size:
        return False
    return sha256_file(source)[0] == sha256_file(destination)[0]


def clear_destination_write_protection(destination: Path) -> None:
    if not destination.exists():
        return
    try:
        destination.chmod(destination.stat().st_mode | stat.S_IWRITE)
    except OSError:
        pass
    if os.name == "nt":
        run_command(["attrib", "-R", "-H", "-S", str(destination)], timeout=30)


def copy2_with_retries(source: Path, destination: Path, attempts: int = 8) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if files_are_identical(source, destination):
        return {"action": "identical", "attempts": 1, "destination": str(destination)}
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            clear_destination_write_protection(destination)
            temp_destination = destination.with_name(f".{destination.name}.restore-{os.getpid()}.tmp")
            shutil.copy2(source, temp_destination)
            os.replace(temp_destination, destination)
            return {"action": "copied", "attempts": attempt, "destination": str(destination)}
        except OSError as exc:
            last_error = str(exc)
    raise ToolError(f"Copy failed after {attempts} attempts: {source} -> {destination}: {last_error}")


def should_import_registry_key(key: str, import_uninstall_registry: bool = False) -> bool:
    key_folded = key.casefold()
    if not import_uninstall_registry and "\\currentversion\\uninstall" in key_folded:
        return False
    return True


def import_registry_exports(
    extraction: Path,
    manifest: dict[str, Any],
    import_uninstall_registry: bool = False,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for export in manifest.get("registry_exports", []):
        key = str(export.get("key") or "")
        if not should_import_registry_key(key, import_uninstall_registry):
            results.append({"key": key, "status": "skipped_reset_safe", "reason": "uninstall_registry_recreated_by_installers"})
            continue
        rel = export.get("file")
        if not rel:
            continue
        reg_file = extraction / "metadata" / rel
        if not reg_file.exists():
            results.append({"key": key, "status": "missing_export", "file": str(reg_file)})
            continue
        result = run_command(["reg.exe", "import", str(reg_file)], timeout=120)
        results.append(
            {
                "key": key,
                "file": str(reg_file),
                "returncode": result["returncode"],
                "stderr": result["stderr"],
                "status": "ok" if result["returncode"] == 0 else "failed",
            }
        )
    return results


def execute_package_replay(extraction: Path) -> dict[str, Any]:
    script = extraction / "metadata" / "package-managers" / "restore-package-managers.ps1"
    if not script.exists():
        return {"status": "missing", "script": str(script)}
    result = run_command(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        timeout=3600,
    )
    return {"status": "ok" if result["returncode"] == 0 else "failed", "script": str(script), **result}


def execute_system_replay(extraction: Path) -> dict[str, Any]:
    script = extraction / "metadata" / "system" / "restore-system-state.ps1"
    if not script.exists():
        return {"status": "missing", "script": str(script)}
    result = run_command(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        timeout=7200,
    )
    return {"status": "ok" if result["returncode"] == 0 else "failed", "script": str(script), **result}


def ensure_replay_result_ok(result: dict[str, Any] | None, label: str) -> None:
    if result is None:
        return
    if result.get("status") != "ok":
        script = result.get("script", "unknown script")
        raise ToolError(f"{label} did not complete successfully: {result.get('status')} ({script})")


def failed_registry_imports(registry_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [result for result in registry_results if result.get("status") == "failed"]


def ensure_registry_imports_ok(registry_results: list[dict[str, Any]]) -> None:
    failures = failed_registry_imports(registry_results)
    if failures:
        keys = ", ".join(str(item.get("key") or item.get("file") or "unknown") for item in failures[:5])
        suffix = "" if len(failures) <= 5 else f" and {len(failures) - 5} more"
        raise ToolError(f"Registry import did not complete successfully for {keys}{suffix}")


def write_restore_execution_report(args: argparse.Namespace, report: dict[str, Any]) -> None:
    try:
        root = normalize_backup_root(args.backup_root, create=True)
        report_dir = root / "logs"
        report_dir.mkdir(parents=True, exist_ok=True)
        write_json(report_dir / "restore-execution-last.json", report)
    except Exception as exc:  # pragma: no cover - reporting must never hide restore results.
        report["restore_execution_report_write_error"] = str(exc)


def command_restore(args: argparse.Namespace) -> int:
    package = resolve_package_arg(args)
    relocation = Path(args.relocate_to).resolve() if args.relocate_to else None
    if relocation is None and not restore_flags_are_sufficient(args):
        raise ToolError(
            "Live restore refused. Use --execute-restore --i-understand-this-can-overwrite-files "
            f"--yes-dangerous-restore --confirm-text \"{RESTORE_CONFIRM_TEXT}\"."
        )
    if relocation is None and not is_elevated():
        raise ToolError("Live restore requires an elevated Administrator shell.")
    manifest = load_manifest_from_zip(package)
    with tempfile.TemporaryDirectory(prefix="installed-restore-") as temp:
        extraction = Path(temp)
        extract_package(package, extraction)
        replay_result = None
        if relocation is None and args.execute_package_replay:
            replay_result = execute_package_replay(extraction)
            if replay_result.get("status") != "ok":
                report = {
                    "package": str(package),
                    "relocation_target": str(relocation) if relocation else None,
                    "restored_file_count": 0,
                    "skipped_file_restores": [],
                    "registry_results": [],
                    "package_replay_result": replay_result,
                    "system_replay_result": None,
                    "package_replay_script": str(extraction / "metadata" / "package-managers" / "restore-package-managers.ps1"),
                    "system_replay_script": str(extraction / "metadata" / "system" / "restore-system-state.ps1"),
                }
                write_restore_execution_report(args, report)
                console_print(json.dumps(report, indent=2, sort_keys=True))
                ensure_replay_result_ok(replay_result, "Package replay")
        restored: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for item in iter_file_records_from_extraction(extraction, manifest):
            destination = Path(item["destination"])
            if should_skip_restore_item(item, destination):
                skipped.append({"destination": str(destination), "reason": "windows_shell_metadata"})
                continue
            target = relocated_destination(destination, relocation)
            source = extraction / item["archive_path"]
            skip_reason = restore_copy_skip_reason(
                target,
                destination_exists=target.exists(),
                overwrite_installed_binaries=args.overwrite_installed_binaries,
            )
            if skip_reason:
                skipped.append({"destination": str(target), "reason": skip_reason, "archive_path": item["archive_path"]})
                continue
            restored.append({"archive_path": item["archive_path"], **copy2_with_retries(source, target)})
        registry_results = []
        if relocation is None and not args.skip_registry:
            registry_results = import_registry_exports(
                extraction,
                manifest,
                import_uninstall_registry=args.import_uninstall_registry,
            )
        system_replay_result = None
        if relocation is None and args.execute_system_replay:
            system_replay_result = execute_system_replay(extraction)
        report = {
            "package": str(package),
            "relocation_target": str(relocation) if relocation else None,
            "restored_file_count": len(restored),
            "skipped_file_restores": skipped,
            "registry_results": registry_results,
            "package_replay_result": replay_result,
            "system_replay_result": system_replay_result,
            "package_replay_script": str(extraction / "metadata" / "package-managers" / "restore-package-managers.ps1"),
            "system_replay_script": str(extraction / "metadata" / "system" / "restore-system-state.ps1"),
        }
        write_restore_execution_report(args, report)
        console_print(json.dumps(report, indent=2, sort_keys=True))
        ensure_registry_imports_ok(registry_results)
        ensure_replay_result_ok(system_replay_result, "System replay")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Back up and guarded-restore installed Windows application state.")
    parser.add_argument("--backup-root", default=str(DEFAULT_BACKUP_ROOT), help=f"Backup root. Default: {DEFAULT_BACKUP_ROOT}")
    parser.add_argument("-b", "--backup-now", action="store_true", help="Shortcut: run backup using the configured backup root.")
    parser.add_argument("-r", "--restore-now", action="store_true", help="Shortcut: run latest restore through restore safety gates.")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("inventory").set_defaults(func=command_inventory)
    backup = sub.add_parser("backup")
    backup.add_argument("--allow-incomplete-system", action="store_true", help="Create a backup even if WSL or other critical reset-safe exports cannot be proven.")
    backup.add_argument("--wsl-idle-wait-seconds", type=int, default=DEFAULT_WSL_IDLE_WAIT_SECONDS, help="Wait this long for WSL distros to become stopped before exporting them as the final backup step.")
    backup.set_defaults(func=command_backup)
    sub.add_parser("repair-wsl").set_defaults(func=command_repair_wsl)
    sub.add_parser("latest").set_defaults(func=command_latest)
    verify = sub.add_parser("verify")
    verify.add_argument("package", nargs="?")
    verify.add_argument("--quick", action="store_true", help="Verify package structure without re-hashing all zip members.")
    verify.set_defaults(func=command_verify)
    sub.add_parser("health").set_defaults(func=command_health)
    dry = sub.add_parser("restore-dry-run")
    dry.add_argument("package", nargs="?")
    dry.add_argument("--relocate-to")
    dry.set_defaults(func=command_restore_dry_run)
    restore = sub.add_parser("restore")
    restore.add_argument("package", nargs="?")
    restore.add_argument("--relocate-to")
    restore.add_argument("--execute-restore", action="store_true")
    restore.add_argument("--i-understand-this-can-overwrite-files", action="store_true")
    restore.add_argument("--yes-dangerous-restore", action="store_true")
    restore.add_argument("--confirm-text", default="")
    restore.add_argument("--skip-registry", action="store_true")
    restore.add_argument("--execute-package-replay", action="store_true")
    restore.add_argument("--execute-system-replay", action="store_true")
    restore.add_argument("--overwrite-installed-binaries", action="store_true", help="Overwrite existing Program Files binaries. Off by default for reset-safe restore.")
    restore.add_argument("--import-uninstall-registry", action="store_true", help="Import old uninstall registry keys. Off by default because installers recreate them.")
    restore.set_defaults(func=command_restore)
    return parser


def rewrite_shortcut_args(argv: list[str]) -> list[str]:
    rewritten: list[str] = []
    for arg in argv:
        if arg == "-b":
            rewritten.append("backup")
        elif arg == "-r":
            rewritten.append("restore")
        else:
            rewritten.append(arg)
    return rewritten


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(rewrite_shortcut_args(raw_args))
    if args.backup_now:
        args = parser.parse_args(["--backup-root", args.backup_root, "backup"])
    elif args.restore_now:
        args = parser.parse_args(["--backup-root", args.backup_root, "restore"])
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    try:
        return int(args.func(args))
    except ToolError as exc:
        console_print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
