#!/usr/bin/env python3
"""Backup and guarded restore tool for local Macrium Reflect application state."""

from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import fnmatch
import getpass
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:  # pragma: no cover - this script is intended for Windows.
    winreg = None  # type: ignore[assignment]


TOOL_VERSION = "1.0.0"
MANIFEST_SCHEMA_VERSION = "1"
DEFAULT_BACKUP_ROOT = Path(r"F:\backup\windowsapps\AppsBackups\Macrium")
BACKUP_PREFIX = "macrium-reflect-state"
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_NO_MACRIUM = 3
EXIT_ADMIN_REQUIRED = 12
MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024
MACRIUM_PATTERNS = ("*Macrium*", "*Reflect*", "*MRCBT*")
REGISTRY_CANDIDATES = (
    r"HKLM\SOFTWARE\Macrium",
    r"HKLM\SOFTWARE\WOW6432Node\Macrium",
    r"HKCU\Software\Macrium",
    r"HKLM\SYSTEM\CurrentControlSet\Services\MacriumService",
    r"HKLM\SYSTEM\CurrentControlSet\Services\mrcbt",
)
MACRIUM_RUNTIME_CANDIDATES = (
    r"C:\Program Files\Macrium",
    r"C:\Program Files (x86)\Macrium",
    r"F:\backup\windowsapps\installed\Reflect",
    r"C:\Windows\System32\drivers\mrcbt.sys",
    r"C:\Windows\System32\drivers\mrigflt.sys",
)
MACRIUM_SERVICE_NAMES = ("MacriumService",)
MACRIUM_PROCESS_NAMES = (
    "Reflect",
    "ReflectBin",
    "ReflectMonitor",
    "ReflectUI",
    "ReflectUpdater",
    "MacriumBackupMessage",
    "MacriumService",
    "MIGPopup",
    "RMBuilder",
    "viBoot",
    "mrauto",
    "mrcbttools",
)
SECRET_NAME_RE = re.compile(r"(license|serial|key|token|secret|password)", re.IGNORECASE)
WINDOWS_SHELL_METADATA_SKIP_REASON = "Windows shell-generated desktop.ini is not Macrium application state"
WINDOWS_START_MENU_SHELL_METADATA_FOLDERS = frozenset(
    {
        "accessibility",
        "accessories",
        "administrative tools",
        "maintenance",
        "startup",
        "system tools",
    }
)
BENIGN_BACKUP_SKIP_REASONS = (
    "source does not exist",
    "source is a reparse point",
    "directory is a reparse point",
    "unsafe generated archive member name",
    WINDOWS_SHELL_METADATA_SKIP_REASON,
)


class ToolError(Exception):
    def __init__(self, message: str, exit_code: int = EXIT_FAILURE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class Logger:
    def __init__(self, log_path: Path | None = None, verbose: bool = True) -> None:
        self.log_path = log_path
        self.verbose = verbose
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)

    def info(self, message: str) -> None:
        self._write("INFO", message)

    def warning(self, message: str) -> None:
        self._write("WARN", message)

    def error(self, message: str) -> None:
        self._write("ERROR", message)

    def _write(self, level: str, message: str) -> None:
        line = f"{dt.datetime.now().isoformat(timespec='seconds')} {level} {message}"
        if self.verbose:
            print(line)
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


def text_for_console(text: str, encoding: str | None = None) -> str:
    target_encoding = encoding or getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        text.encode(target_encoding)
        return text
    except (LookupError, UnicodeEncodeError):
        return text.encode(target_encoding, errors="backslashreplace").decode(target_encoding, errors="replace")


def console_print(message: str = "") -> None:
    print(text_for_console(message))


def now_local() -> dt.datetime:
    return dt.datetime.now().astimezone()


def normalize_backup_root(value: str | Path | None, create: bool = False) -> Path:
    root = DEFAULT_BACKUP_ROOT if value in (None, "") else Path(value).expanduser()
    if not root.is_absolute():
        raise ToolError(f"Backup root must be absolute. Received: {root}")
    if create:
        root.mkdir(parents=True, exist_ok=True)
    try:
        return root.resolve(strict=False)
    except OSError:
        return root.absolute()


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_command(args: list[str], timeout: int = 120) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "args": args,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "duration_seconds": round(time.time() - started, 3),
        }
    except Exception as exc:
        return {
            "args": args,
            "returncode": -1,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "duration_seconds": round(time.time() - started, 3),
        }


def powershell_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def powershell_json(script: str, timeout: int = 120) -> Any:
    result = run_command(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )
    if result["returncode"] != 0 or not result["stdout"].strip():
        return []
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return []


def match_macrium_name(path: Path) -> bool:
    text = str(path)
    return any(fnmatch.fnmatch(text, pattern) for pattern in MACRIUM_PATTERNS)


def path_identity(path: Path) -> str:
    return str(path.resolve(strict=False)).lower()


def has_reparse_point(path: Path) -> bool:
    try:
        return bool(path.stat().st_file_attributes & getattr(os.stat_result, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except Exception:
        return False


def normalized_path_parts(path: Path) -> list[str]:
    return [part.lower() for part in path.parts if part not in (path.anchor, path.drive, "\\", "/")]


def find_contiguous_parts(parts: list[str], sequence: tuple[str, ...]) -> int | None:
    if not sequence or len(sequence) > len(parts):
        return None
    sequence_length = len(sequence)
    for index in range(0, len(parts) - sequence_length + 1):
        if tuple(parts[index : index + sequence_length]) == sequence:
            return index
    return None


def is_start_menu_programs_shell_desktop_ini_parts(parts: list[str]) -> bool:
    if not parts or parts[-1] != "desktop.ini":
        return False
    index = find_contiguous_parts(parts, ("microsoft", "windows", "start menu", "programs"))
    if index is None:
        return False
    tail = parts[index + 4 :]
    if tail == ["desktop.ini"]:
        return True
    return len(tail) == 2 and tail[0] in WINDOWS_START_MENU_SHELL_METADATA_FOLDERS and tail[1] == "desktop.ini"


def is_windows_shell_desktop_ini(path: Path) -> bool:
    if path.name.lower() != "desktop.ini":
        return False
    return is_start_menu_programs_shell_desktop_ini_parts(normalized_path_parts(path))


def should_skip_restore_item(item: dict[str, Any], destination: Path) -> bool:
    archive_parts = [part for part in str(item.get("archive_path", "")).replace("\\", "/").lower().split("/") if part]
    if is_start_menu_programs_shell_desktop_ini_parts(archive_parts):
        return True
    return is_windows_shell_desktop_ini(destination)


def is_benign_backup_skip(item: dict[str, Any]) -> bool:
    reason = str(item.get("reason", ""))
    return any(reason.startswith(benign) for benign in BENIGN_BACKUP_SKIP_REASONS)


def find_critical_skipped_items(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in manifest.get("skipped_items", []) if not is_benign_backup_skip(item)]


def expand_existing_paths(candidates: list[str]) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()
    for raw in candidates:
        if not raw:
            continue
        path = Path(os.path.expandvars(raw)).expanduser()
        if path.exists():
            ident = path_identity(path)
            if ident not in seen:
                found.append(path)
                seen.add(ident)
    return found


def get_logical_drives() -> list[dict[str, Any]]:
    data = powershell_json(
        "Get-CimInstance Win32_LogicalDisk | "
        "Select-Object DeviceID,DriveType,VolumeName,FileSystem,Size,FreeSpace | "
        "ConvertTo-Json -Compress",
        timeout=60,
    )
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


def discover_common_paths(drives: list[dict[str, Any]]) -> tuple[list[Path], dict[str, Any]]:
    home = Path.home()
    candidates = [
        *MACRIUM_RUNTIME_CANDIDATES,
        r"%ProgramFiles%\Macrium",
        r"%ProgramFiles(x86)%\Macrium",
        r"%ProgramW6432%\Macrium",
        r"%ProgramData%\Macrium",
        r"%ProgramData%\Macrium\Reflect",
        r"%APPDATA%\Macrium",
        r"%LOCALAPPDATA%\Macrium",
        str(home / "Documents" / "Reflect"),
        str(home / "Documents" / "Macrium Reflect"),
        r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Macrium",
    ]
    fixed_drives = [d.get("DeviceID") for d in drives if d.get("DriveType") == 3 and d.get("DeviceID")]
    drive_scan_hits: list[str] = []
    for drive in fixed_drives:
        root = Path(str(drive) + "\\")
        try:
            for child in root.iterdir():
                if child.is_dir() and match_macrium_name(child):
                    candidates.append(str(child))
                    drive_scan_hits.append(str(child))
        except OSError:
            continue
    paths = expand_existing_paths(candidates)
    strategy = {
        "fixed_drives_scanned": fixed_drives,
        "scan_depth": "drive root immediate children plus known Windows Macrium locations, Macrium runtime roots, and Macrium driver files",
        "patterns": list(MACRIUM_PATTERNS),
        "drive_root_hits": drive_scan_hits,
        "runtime_candidates": list(MACRIUM_RUNTIME_CANDIDATES),
        "full_drive_crawl": False,
    }
    return paths, strategy


def discover_shortcuts_and_documents() -> list[Path]:
    roots = expand_existing_paths(
        [
            str(Path.home() / "Desktop"),
            r"C:\Users\Public\Desktop",
            r"%ProgramData%\Microsoft\Windows\Start Menu",
            str(Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu"),
        ]
    )
    found: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        try:
            for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
                current = Path(dirpath)
                if current != root and has_reparse_point(current):
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if not has_reparse_point(current / d)]
                for name in filenames:
                    path = current / name
                    if path.suffix.lower() in {".lnk", ".url", ".xml"} and match_macrium_name(path):
                        ident = path_identity(path)
                        if ident not in seen:
                            found.append(path)
                            seen.add(ident)
        except OSError:
            continue
    return found


def registry_root_and_subkey(key_path: str) -> tuple[Any, str]:
    if winreg is None:
        raise ToolError("winreg is unavailable; registry capture requires Windows Python.")
    hive, _, subkey = key_path.partition("\\")
    mapping = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    }
    if hive not in mapping:
        raise ToolError(f"Unsupported registry hive: {hive}")
    return mapping[hive], subkey


def read_registry_key(key_path: str) -> dict[str, Any] | None:
    if winreg is None:
        return None
    hive, subkey = registry_root_and_subkey(key_path)
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            return enumerate_registry_tree(key, key_path)
    except OSError:
        return None


def registry_value_to_json(name: str, value: Any, reg_type: int) -> dict[str, Any]:
    redacted = bool(SECRET_NAME_RE.search(name or ""))
    if isinstance(value, bytes):
        payload: Any = {
            "type": "binary",
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    elif isinstance(value, (str, int)):
        payload = "[redacted]" if redacted else value
    elif isinstance(value, (list, tuple)):
        payload = ["[redacted]" if redacted else str(item) for item in value]
    else:
        payload = str(value)
    return {"name": name, "registry_type": reg_type, "value": payload, "redacted": redacted}


def enumerate_registry_tree(open_key: Any, display_path: str) -> dict[str, Any]:
    values: list[dict[str, Any]] = []
    subkeys: list[dict[str, Any]] = []
    try:
        value_count = winreg.QueryInfoKey(open_key)[1]
        for index in range(value_count):
            name, value, reg_type = winreg.EnumValue(open_key, index)
            values.append(registry_value_to_json(name, value, reg_type))
    except OSError:
        pass
    try:
        subkey_count = winreg.QueryInfoKey(open_key)[0]
        for index in range(subkey_count):
            name = winreg.EnumKey(open_key, index)
            try:
                with winreg.OpenKey(open_key, name, 0, winreg.KEY_READ) as child:
                    subkeys.append(enumerate_registry_tree(child, display_path + "\\" + name))
            except OSError as exc:
                subkeys.append({"path": display_path + "\\" + name, "error": str(exc)})
    except OSError:
        pass
    return {"path": display_path, "values": values, "subkeys": subkeys}


def discover_registry() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for key_path in tuple(REGISTRY_CANDIDATES) + tuple(discover_uninstall_registry_paths()):
        data = read_registry_key(key_path)
        if data is not None:
            found.append(data)
    return found


def discover_uninstall_registry_paths() -> list[str]:
    if winreg is None:
        return []
    roots = (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    )
    matches: list[str] = []
    for root_path in roots:
        hive, subkey = registry_root_and_subkey(root_path)
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as root_key:
                for index in range(winreg.QueryInfoKey(root_key)[0]):
                    child_name = winreg.EnumKey(root_key, index)
                    child_path = root_path + "\\" + child_name
                    try:
                        with winreg.OpenKey(root_key, child_name, 0, winreg.KEY_READ) as child:
                            display_name = winreg.QueryValueEx(child, "DisplayName")[0]
                            if re.search(r"Macrium|Reflect", str(display_name), re.IGNORECASE):
                                matches.append(child_path)
                    except OSError:
                        continue
        except OSError:
            continue
    return matches


def discover_services() -> list[dict[str, Any]]:
    data = powershell_json(
        "Get-CimInstance Win32_Service | "
        "Where-Object { $_.Name -match 'Macrium|Reflect|MRCBT' -or $_.DisplayName -match 'Macrium|Reflect|MRCBT' } | "
        "Select-Object Name,DisplayName,State,StartMode,PathName,ServiceType,StartName,Description | "
        "ConvertTo-Json -Compress",
        timeout=60,
    )
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


def discover_scheduled_tasks() -> list[dict[str, Any]]:
    result = run_command(["schtasks.exe", "/query", "/fo", "CSV", "/v"], timeout=120)
    if result["returncode"] != 0:
        return [{"error": result["stderr"].strip(), "command": result["args"]}]
    rows = list(csv.DictReader(result["stdout"].splitlines()))
    matches: list[dict[str, Any]] = []
    for row in rows:
        joined = " ".join(str(v) for v in row.values())
        if re.search(r"Macrium|Reflect|MRCBT", joined, re.IGNORECASE):
            matches.append(dict(row))
    return matches


def build_inventory() -> dict[str, Any]:
    drives = get_logical_drives()
    common_paths, scan_strategy = discover_common_paths(drives)
    shortcut_paths = discover_shortcuts_and_documents()
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in common_paths + shortcut_paths:
        ident = path_identity(path)
        if ident in seen:
            continue
        seen.add(ident)
        kind = "directory" if path.is_dir() else "file"
        sources.append({"path": str(path), "kind": kind, "exists": True})
    registry = discover_registry()
    services = discover_services()
    tasks = discover_scheduled_tasks()
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "created_at": now_local().isoformat(),
        "machine": {
            "hostname": platform.node(),
            "username": getpass.getuser(),
            "platform": platform.platform(),
            "python": sys.version,
            "elevated": is_elevated(),
        },
        "drives": drives,
        "scan_strategy": scan_strategy,
        "sources": sources,
        "registry": registry,
        "scheduled_tasks": tasks,
        "services": services,
        "macrium_found": bool(sources or registry or services or tasks),
    }


def safe_archive_name_for_path(path: Path) -> str:
    resolved = path.resolve(strict=False)
    drive = resolved.drive.replace(":", "").replace("\\", "").replace("/", "") or "no-drive"
    parts = [part for part in resolved.parts if part not in (resolved.anchor, resolved.drive, "\\", "/")]
    return "/".join(["files", drive] + [sanitize_archive_part(part) for part in parts])


def sanitize_archive_part(part: str) -> str:
    cleaned = part.replace(":", "_").replace("\\", "_").replace("/", "_")
    return cleaned or "_"


def is_safe_archive_member(name: str) -> bool:
    if not name or "\x00" in name:
        return False
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return False
    if re.match(r"^[A-Za-z]:", normalized):
        return False
    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    if any(":" in part for part in parts):
        return False
    return True


def sha256_file(path: Path, max_bytes: int = MAX_HASH_BYTES) -> tuple[str | None, str | None]:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None, f"hash skipped because file size {size} exceeds limit {max_bytes}"
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest(), None
    except OSError as exc:
        return None, str(exc)


def sha256_zip_member(zf: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with zf.open(name, "r") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def files_are_identical(source: Path, destination: Path) -> bool:
    try:
        if not destination.exists() or not destination.is_file():
            return False
        if source.stat().st_size != destination.stat().st_size:
            return False
        source_hash, source_note = sha256_file(source)
        destination_hash, destination_note = sha256_file(destination)
        return bool(source_hash and destination_hash and not source_note and not destination_note and source_hash == destination_hash)
    except OSError:
        return False


def clear_destination_write_protection(destination: Path) -> None:
    try:
        destination.chmod(destination.stat().st_mode | stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        pass
    if os.name == "nt":
        run_command(["attrib", "-R", "-H", "-S", str(destination)], timeout=30)


def copy_source_into_staging(source: Path, staging: Path, manifest: dict[str, Any], logger: Logger) -> None:
    if not source.exists():
        manifest["skipped_items"].append({"path": str(source), "reason": "source does not exist"})
        return
    if has_reparse_point(source):
        manifest["skipped_items"].append({"path": str(source), "reason": "source is a reparse point"})
        return
    if source.is_file():
        copy_one_file(source, staging, manifest, logger)
        return
    for dirpath, dirnames, filenames in os.walk(source, topdown=True, followlinks=False):
        current = Path(dirpath)
        if has_reparse_point(current):
            dirnames[:] = []
            manifest["skipped_items"].append({"path": str(current), "reason": "directory is a reparse point"})
            continue
        kept_dirs = []
        for dirname in dirnames:
            child = current / dirname
            if has_reparse_point(child):
                manifest["skipped_items"].append({"path": str(child), "reason": "directory is a reparse point"})
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in filenames:
            copy_one_file(current / filename, staging, manifest, logger)


def copy_one_file(source: Path, staging: Path, manifest: dict[str, Any], logger: Logger) -> None:
    try:
        if is_windows_shell_desktop_ini(source):
            manifest["skipped_items"].append({"path": str(source), "reason": WINDOWS_SHELL_METADATA_SKIP_REASON})
            return
        archive_name = safe_archive_name_for_path(source)
        if not is_safe_archive_member(archive_name):
            manifest["skipped_items"].append({"path": str(source), "reason": "unsafe generated archive member name"})
            return
        destination = staging / Path(*archive_name.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        stat = source.stat()
        digest, hash_note = sha256_file(destination)
        entry = {
            "source_path": str(source.resolve(strict=False)),
            "archive_path": archive_name,
            "restore_destination": str(source.resolve(strict=False)),
            "size": stat.st_size,
            "mtime": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat(),
            "sha256": digest,
            "hash_note": hash_note,
        }
        manifest["sources"].append(entry)
    except OSError as exc:
        logger.warning(f"Skipped inaccessible file {source}: {exc}")
        manifest["skipped_items"].append({"path": str(source), "reason": str(exc)})


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def export_registry_keys(staging: Path, manifest: dict[str, Any], logger: Logger) -> None:
    exports_dir = staging / "registry_exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    for reg_entry in manifest["registry"]:
        key_path = reg_entry.get("path")
        if not key_path:
            continue
        export_name = sanitize_archive_part(key_path.replace("\\", "__")) + ".reg"
        export_path = exports_dir / export_name
        result = run_command(["reg.exe", "export", key_path, str(export_path), "/y"], timeout=60)
        record = {
            "key": key_path,
            "archive_path": f"registry_exports/{export_name}",
            "returncode": result["returncode"],
        }
        if result["returncode"] != 0:
            record["error"] = result["stderr"].strip() or result["stdout"].strip()
            manifest["warnings"].append(f"Registry export failed for {key_path}: {record['error']}")
            logger.warning(f"Registry export failed for {key_path}: {record['error']}")
        manifest["registry_exports"].append(record)


def export_scheduled_tasks(staging: Path, manifest: dict[str, Any], logger: Logger) -> None:
    exports_dir = staging / "task_exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    for task in manifest["scheduled_tasks"]:
        task_name = task.get("TaskName") or task.get("Task To Run")
        if not task_name or str(task_name).upper() == "N/A":
            continue
        export_name = sanitize_archive_part(str(task_name).strip("\\").replace("\\", "__")) + ".xml"
        result = run_command(["schtasks.exe", "/query", "/tn", str(task_name), "/xml"], timeout=60)
        record = {
            "task_name": task_name,
            "archive_path": f"task_exports/{export_name}",
            "returncode": result["returncode"],
        }
        if result["returncode"] == 0:
            (exports_dir / export_name).write_text(result["stdout"], encoding="utf-8")
        else:
            record["error"] = result["stderr"].strip() or result["stdout"].strip()
            manifest["warnings"].append(f"Scheduled task export failed for {task_name}: {record['error']}")
            logger.warning(f"Scheduled task export failed for {task_name}: {record['error']}")
        manifest["task_exports"].append(record)


def create_restore_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "created_at": now_local().isoformat(),
        "file_restores": [
            {
                "archive_path": item["archive_path"],
                "destination": item["restore_destination"],
                "size": item.get("size"),
                "sha256": item.get("sha256"),
            }
            for item in manifest.get("sources", [])
        ],
        "registry_imports": [
            export for export in manifest.get("registry_exports", []) if export.get("returncode") == 0
        ],
        "task_imports": [export for export in manifest.get("task_exports", []) if export.get("returncode") == 0],
        "service_notes": manifest.get("services", []),
        "requires_elevation": restore_requires_elevation(manifest),
        "safety": {
            "real_restore_requires_flags": [
                "--execute-restore",
                "--i-understand-this-can-overwrite-files",
                "--yes-dangerous-restore or --confirm-text \"RESTORE MACRIUM\"",
            ],
            "dry_run_changes_system": False,
        },
        "skipped_file_restores": [
            {
                "archive_path": item.get("archive_path"),
                "destination": item.get("restore_destination"),
                "reason": WINDOWS_SHELL_METADATA_SKIP_REASON,
            }
            for item in manifest.get("sources", [])
            if should_skip_restore_item(item, Path(str(item.get("restore_destination", ""))))
        ],
    }


def restore_requires_elevation(manifest: dict[str, Any]) -> bool:
    protected_prefixes = (r"C:\Program Files", r"C:\Program Files (x86)", r"C:\ProgramData", r"C:\Windows")
    for item in manifest.get("sources", []):
        dest = str(item.get("restore_destination", ""))
        if dest.startswith(protected_prefixes):
            return True
    return bool(manifest.get("registry_exports") or manifest.get("task_exports"))


def verify_zip_package(path: Path, full_hash: bool = True) -> dict[str, Any]:
    if not path.exists():
        raise ToolError(f"Backup package does not exist: {path}")
    if path.suffix.lower() != ".zip":
        raise ToolError(f"Backup package must be a .zip file: {path}")
    with zipfile.ZipFile(path, "r") as zf:
        members = zf.namelist()
        unsafe = [name for name in members if not is_safe_archive_member(name)]
        if unsafe:
            raise ToolError(f"Unsafe archive member(s) found: {unsafe[:5]}")
        bad_member = zf.testzip()
        if bad_member:
            raise ToolError(f"Zip integrity check failed at member: {bad_member}")
        required = {"manifest.json", "inventory.json", "restore_plan.json"}
        missing = sorted(required - set(members))
        if missing:
            raise ToolError(f"Backup package missing required metadata: {missing}")
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
            raise ToolError(f"Unsupported manifest schema: {manifest.get('schema_version')}")
        if manifest.get("status") != "success":
            raise ToolError(f"Manifest status is not success: {manifest.get('status')}")
        checked = 0
        mismatches: list[dict[str, Any]] = []
        if full_hash:
            for item in manifest.get("sources", []):
                archive_path = item.get("archive_path")
                expected = item.get("sha256")
                if not archive_path or not expected:
                    continue
                if archive_path not in members:
                    mismatches.append({"archive_path": archive_path, "error": "missing from zip"})
                    continue
                actual = sha256_zip_member(zf, archive_path)
                checked += 1
                if actual != expected:
                    mismatches.append({"archive_path": archive_path, "expected": expected, "actual": actual})
        if mismatches:
            raise ToolError(f"Hash verification failed for {len(mismatches)} member(s): {mismatches[:3]}")
        return {
            "path": str(path.resolve(strict=False)),
            "schema_version": manifest.get("schema_version"),
            "created_at": manifest.get("created_at"),
            "status": manifest.get("status"),
            "file_count": len(manifest.get("sources", [])),
            "hashes_checked": checked,
            "package_size": path.stat().st_size,
        }


def find_latest_successful_backup(root: Path) -> Path:
    candidates = sorted(root.glob(f"{BACKUP_PREFIX}-*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    valid: list[tuple[str, Path]] = []
    for package in candidates:
        try:
            verify_zip_package(package, full_hash=False)
            with zipfile.ZipFile(package, "r") as zf:
                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                created_at = str(manifest.get("created_at") or "")
                valid.append((created_at, package))
        except Exception:
            continue
    if not valid:
        raise ToolError(f"No successful Macrium backup packages found in {root}. Run: python .\\macrium_state_backup_restore.py backup")
    valid.sort(key=lambda item: item[0], reverse=True)
    return valid[0][1]


def load_manifest_from_zip(path: Path) -> dict[str, Any]:
    verify_zip_package(path, full_hash=False)
    with zipfile.ZipFile(path, "r") as zf:
        return json.loads(zf.read("manifest.json").decode("utf-8"))


def safe_extract_member(zf: zipfile.ZipFile, member: str, destination: Path) -> Path:
    if not is_safe_archive_member(member):
        raise ToolError(f"Unsafe archive member rejected: {member}")
    target = destination / Path(*member.replace("\\", "/").split("/"))
    resolved_dest = destination.resolve(strict=False)
    resolved_target = target.resolve(strict=False)
    if resolved_dest != resolved_target and resolved_dest not in resolved_target.parents:
        raise ToolError(f"Archive member escapes extraction directory: {member}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with zf.open(member, "r") as src, target.open("wb") as dst:
        shutil.copyfileobj(src, dst, length=1024 * 1024)
    return target


def command_inventory(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=False)
    inventory = build_inventory()
    inventory["backup_root"] = str(root)
    print(json.dumps(inventory, indent=2, sort_keys=True))
    if not inventory["macrium_found"]:
        return EXIT_NO_MACRIUM
    return EXIT_OK


def command_backup(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=True)
    timestamp = now_local().strftime("%Y%m%d-%H%M%S")
    package_final = root / f"{BACKUP_PREFIX}-{timestamp}.zip"
    package_partial = root / f"{BACKUP_PREFIX}-{timestamp}.partial.zip"
    staging = root / f".{BACKUP_PREFIX}-{timestamp}.{os.getpid()}.staging"
    if staging.exists():
        raise ToolError(f"Refusing to reuse staging directory: {staging}")
    staging.mkdir(parents=True)
    log_path = staging / "logs" / "backup.log"
    logger = Logger(log_path=log_path)
    logger.info(f"Resolved backup root: {root}")
    try:
        inventory = build_inventory()
        if not inventory["macrium_found"]:
            write_json(staging / "inventory.json", inventory)
            raise ToolError("Macrium Reflect was not found in files, registry, services, or tasks.", EXIT_NO_MACRIUM)
        manifest: dict[str, Any] = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "tool_version": TOOL_VERSION,
            "created_at": now_local().isoformat(),
            "machine": inventory["machine"],
            "backup_root": str(root),
            "package_path": str(package_final),
            "status": "incomplete",
            "sources": [],
            "registry": inventory["registry"],
            "registry_exports": [],
            "scheduled_tasks": inventory["scheduled_tasks"],
            "task_exports": [],
            "services": inventory["services"],
            "skipped_items": [],
            "warnings": [],
            "verification": {},
            "scan_strategy": inventory["scan_strategy"],
        }
        write_json(staging / "inventory.json", inventory)
        for source in inventory.get("sources", []):
            copy_source_into_staging(Path(source["path"]), staging, manifest, logger)
        critical_skipped_items = find_critical_skipped_items(manifest)
        if critical_skipped_items:
            manifest["critical_skipped_items"] = critical_skipped_items
            write_json(staging / "manifest.json", manifest | {"status": "failed"})
            raise ToolError(f"Backup skipped {len(critical_skipped_items)} critical Macrium state item(s); refusing to mark it latest.")
        export_registry_keys(staging, manifest, logger)
        export_scheduled_tasks(staging, manifest, logger)
        restore_plan = create_restore_plan(manifest)
        write_json(staging / "restore_plan.json", restore_plan)
        manifest["status"] = "success"
        manifest["verification"] = {"staging_metadata_written": True, "zip_test": False}
        write_json(staging / "manifest.json", manifest)
        create_zip_from_staging(staging, package_partial)
        verification = verify_zip_package(package_partial, full_hash=True)
        manifest_verification = verification | {"zip_test": True, "path": str(package_final)}
        manifest["verification"] = manifest_verification
        write_json(staging / "manifest.json", manifest)
        package_partial.unlink()
        create_zip_from_staging(staging, package_partial)
        package_partial.replace(package_final)
        verification = verify_zip_package(package_final, full_hash=True)
        latest_marker = {
            "latest_successful_package": str(package_final),
            "updated_at": now_local().isoformat(),
            "verification": verification,
        }
        write_json(root / "latest-macrium-reflect-state.json", latest_marker)
        logger.info(f"Backup package created: {package_final}")
        logger.info(f"Package size bytes: {package_final.stat().st_size}")
        shutil.rmtree(staging)
        print(json.dumps(latest_marker, indent=2, sort_keys=True))
        return EXIT_OK
    except Exception:
        if package_partial.exists():
            failed = root / f"{BACKUP_PREFIX}-{timestamp}.failed.zip"
            try:
                package_partial.replace(failed)
            except OSError:
                pass
        raise


def create_zip_from_staging(staging: Path, package: Path) -> None:
    if package.exists():
        raise ToolError(f"Refusing to overwrite backup package: {package}")
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for dirpath, _, filenames in os.walk(staging):
            current = Path(dirpath)
            for filename in filenames:
                path = current / filename
                arcname = path.relative_to(staging).as_posix()
                if not is_safe_archive_member(arcname):
                    raise ToolError(f"Generated unsafe zip member: {arcname}")
                zf.write(path, arcname)


def command_latest(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=False)
    package = find_latest_successful_backup(root)
    print(str(package.resolve(strict=False)))
    return EXIT_OK


def command_verify(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=False)
    package = Path(args.package).resolve(strict=False) if args.package else find_latest_successful_backup(root)
    result = verify_zip_package(package, full_hash=True)
    print(json.dumps(result, indent=2, sort_keys=True))
    return EXIT_OK


def command_health(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=False)
    package = Path(args.package).resolve(strict=False) if args.package else find_latest_successful_backup(root)
    report = {
        "latest_package": str(package),
        "package_verification": verify_zip_package(package, full_hash=True),
        "bootstrap_assets": inspect_installer_media(root),
        "live_health": get_live_macrium_health(),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_OK


def resolve_package_arg(args: argparse.Namespace) -> Path:
    root = normalize_backup_root(args.backup_root, create=False)
    return Path(args.package).resolve(strict=False) if args.package else find_latest_successful_backup(root)


def restore_flags_are_sufficient(
    execute_restore: bool,
    understand_overwrite: bool,
    relocation_target: Path | None,
) -> bool:
    if relocation_target is not None:
        return True
    return bool(execute_restore and understand_overwrite)


def build_dry_run_report(package: Path, relocation_target: Path | None = None) -> dict[str, Any]:
    manifest = load_manifest_from_zip(package)
    plan = create_restore_plan(manifest)
    file_restores = []
    for item in plan["file_restores"]:
        destination = Path(item["destination"])
        actual_destination = relocated_destination(destination, relocation_target) if relocation_target else destination
        file_restores.append(
            item
            | {
                "actual_destination": str(actual_destination),
                "would_overwrite": actual_destination.exists(),
            }
        )
    return {
        "package": str(package),
        "manifest_schema_version": manifest.get("schema_version"),
        "created_at": manifest.get("created_at"),
        "status": manifest.get("status"),
        "relocation_target": str(relocation_target) if relocation_target else None,
        "file_restores": file_restores,
        "registry_imports": plan["registry_imports"],
        "task_imports": plan["task_imports"],
        "service_notes": plan["service_notes"],
        "requires_elevation": plan["requires_elevation"] and relocation_target is None,
        "changes_system": False,
    }


def command_restore_dry_run(args: argparse.Namespace) -> int:
    package = resolve_package_arg(args)
    relocation = Path(args.relocate_to).resolve(strict=False) if args.relocate_to else None
    report = build_dry_run_report(package, relocation)
    print_restore_report(report)
    return EXIT_OK


def print_restore_report(report: dict[str, Any]) -> None:
    console_print(f"Restore dry-run package: {report['package']}")
    console_print(f"Manifest schema version: {report['manifest_schema_version']}")
    console_print(f"Backup created at: {report['created_at']}")
    console_print(f"Relocation target: {report['relocation_target'] or '(none - live destinations)'}")
    console_print(f"Requires elevation for live restore: {report['requires_elevation']}")
    console_print("\nFile restores:")
    for item in report["file_restores"]:
        console_print(f"- {item['archive_path']} -> {item['actual_destination']} overwrite={item['would_overwrite']}")
    console_print("\nRegistry imports:")
    for item in report["registry_imports"]:
        console_print(f"- {item.get('key')} from {item.get('archive_path')}")
    console_print("\nScheduled task imports:")
    for item in report["task_imports"]:
        console_print(f"- {item.get('task_name')} from {item.get('archive_path')}")
    console_print("\nService notes:")
    for item in report["service_notes"]:
        console_print(f"- {item.get('Name') or item.get('DisplayName')}: {item.get('State') or item.get('StartMode')}")
    console_print("\nNo files, registry keys, tasks, or services were changed by this dry-run.")


def relocated_destination(destination: Path, relocation_target: Path | None) -> Path:
    if relocation_target is None:
        return destination
    resolved = destination.resolve(strict=False)
    drive = sanitize_archive_part(resolved.drive.replace(":", "") or "no-drive")
    parts = [sanitize_archive_part(part) for part in resolved.parts if part not in (resolved.anchor, resolved.drive, "\\", "/")]
    return relocation_target / drive / Path(*parts)


def inspect_installer_media(root: Path) -> dict[str, Any]:
    media = root / "installer_media"
    result: dict[str, Any] = {
        "path": str(media),
        "exists": media.exists(),
        "enumeration_returncode": None,
        "fresh_windows_bootstrap_ready": False,
        "note": "Fresh Windows proof requires readable installer media plus a VM uninstall/fresh-install restore test.",
    }
    if not media.exists():
        result["note"] = "installer_media is missing; state restore may repair an existing install but fresh Windows bootstrap is not proven."
        return result
    ps_path = powershell_literal(str(media))
    listing = run_command(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            (
                f"Get-ChildItem -LiteralPath {ps_path} -Force -ErrorAction Stop | "
                "Select-Object -First 20 Name,Length,LastWriteTime | ConvertTo-Json -Depth 3"
            ),
        ],
        timeout=10,
    )
    result["enumeration_returncode"] = listing["returncode"]
    result["enumeration_stderr"] = listing["stderr"].strip()
    result["enumeration_timed_out"] = listing["returncode"] == -1 and "TimeoutExpired" in listing["stderr"]
    installer = find_macrium_installer(root)
    result["installer"] = str(installer) if installer else None
    result["fresh_windows_bootstrap_ready"] = listing["returncode"] == 0 and installer is not None
    if result["fresh_windows_bootstrap_ready"]:
        result["note"] = "installer_media contains a launchable Macrium installer executable; VM proof is still required."
    elif result["enumeration_timed_out"]:
        result["note"] = "installer_media exists but did not enumerate within 10 seconds; repair or replace it before claiming fresh Windows readiness."
    return result


def find_macrium_installer(root: Path) -> Path | None:
    media = root / "installer_media"
    if not media.is_dir():
        return None
    candidates = sorted(
        [item for item in media.glob("*setup*x64*.exe") if item.is_file()],
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    if candidates:
        return candidates[0]
    candidates = sorted([item for item in media.glob("*.exe") if item.is_file()], key=lambda item: item.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def build_macrium_installer_command(installer: Path, log_path: Path) -> list[str]:
    name = installer.name.lower()
    if "reflect_wkstn_setup" in name:
        return [
            str(installer),
            "-silent",
            "-cbt",
            "-mig",
            "-viboot",
            "-shortcut",
            "-norestart",
            "-log",
        ]
    return [str(installer), "/passive", "/norestart", "/l", str(log_path)]


def collect_macrium_installer_log(destination: Path) -> str | None:
    vendor_log = Path(r"C:\Reflect_Install.log")
    if not vendor_log.exists():
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(vendor_log, destination)
        return str(destination)
    except OSError:
        return str(vendor_log)


def macrium_install_bootstrap_needed(manifest: dict[str, Any] | None = None) -> bool:
    health = get_live_macrium_health(manifest)
    files = health.get("files") if isinstance(health, dict) else []
    service_exe_present = any(
        item.get("Exists") and Path(str(item.get("Path", ""))).name.lower() == "macriumservice.exe"
        for item in files
        if isinstance(item, dict)
    )
    return not (health.get("reflect_exe_present") and service_exe_present)


def bootstrap_macrium_install_if_needed(root: Path, safety_root: Path, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    before = get_live_macrium_health(manifest)
    needed = macrium_install_bootstrap_needed(manifest)
    report: dict[str, Any] = {
        "needed": needed,
        "before": before,
        "installer": None,
        "returncode": None,
        "log_path": None,
        "after": None,
        "ran": False,
    }
    if not needed:
        report["after"] = before
        return report
    installer = find_macrium_installer(root)
    if not installer:
        raise ToolError(f"Macrium install bootstrap is needed but no installer was found under {root / 'installer_media'}")
    log_path = safety_root / "installer-bootstrap.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    report["installer"] = str(installer)
    report["log_path"] = str(log_path)
    result = run_command(build_macrium_installer_command(installer, log_path), timeout=900)
    report["ran"] = True
    report["returncode"] = result["returncode"]
    report["stdout"] = result["stdout"].strip()
    report["stderr"] = result["stderr"].strip()
    report["duration_seconds"] = result["duration_seconds"]
    report["collected_log_path"] = collect_macrium_installer_log(log_path)
    if result["returncode"] not in (0, 3010):
        raise ToolError(f"Macrium installer bootstrap failed with exit code {result['returncode']}. Log: {log_path}")
    time.sleep(3)
    report["after"] = get_live_macrium_health(manifest)
    return report


def get_live_health_file_candidates(manifest: dict[str, Any] | None = None) -> list[str]:
    candidates = [
        r"%ProgramFiles%\Macrium\Common\MacriumService.exe",
        r"%ProgramFiles%\Macrium\Reflect\Reflect.exe",
        r"%ProgramFiles%\Macrium\Reflect\ReflectBin.exe",
        r"%ProgramFiles(x86)%\Macrium\Common\MacriumService.exe",
        r"%ProgramFiles(x86)%\Macrium\Reflect\Reflect.exe",
        r"%ProgramFiles(x86)%\Macrium\Reflect\ReflectBin.exe",
        r"%ProgramW6432%\Macrium\Common\MacriumService.exe",
        r"%ProgramW6432%\Macrium\Reflect\Reflect.exe",
        r"%ProgramW6432%\Macrium\Reflect\ReflectBin.exe",
        r"F:\backup\windowsapps\installed\Reflect\Reflect.exe",
        r"F:\backup\windowsapps\installed\Reflect\ReflectBin.exe",
        r"C:\Windows\System32\drivers\mrcbt.sys",
        r"C:\Windows\System32\drivers\mrigflt.sys",
        str(Path.home() / "Documents" / "Reflect" / "My Backup.xml"),
    ]
    if manifest:
        interesting_names = {"reflect.exe", "reflectbin.exe", "macriumservice.exe", "mrcbt.sys", "mrigflt.sys"}
        for item in manifest.get("sources", []):
            destination = str(item.get("restore_destination", ""))
            if destination and Path(destination).name.lower() in interesting_names:
                candidates.append(destination)
    expanded: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        expanded_candidate = os.path.expandvars(candidate)
        if "%" in expanded_candidate:
            continue
        ident = expanded_candidate.lower()
        if ident not in seen:
            expanded.append(expanded_candidate)
            seen.add(ident)
    return expanded


def get_live_macrium_health(manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    service_names = ", ".join(powershell_literal(name) for name in MACRIUM_SERVICE_NAMES)
    process_names = ", ".join(powershell_literal(name) for name in MACRIUM_PROCESS_NAMES)
    file_paths = ", ".join(powershell_literal(path) for path in get_live_health_file_candidates(manifest))
    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$serviceNames = @({service_names})
$processNames = @({process_names})
$filePaths = @({file_paths})
$services = @(
  foreach ($name in $serviceNames) {{
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {{ [pscustomobject]@{{ Name = $svc.Name; DisplayName = $svc.DisplayName; Status = [string]$svc.Status; StartType = [string]$svc.StartType }} }}
    else {{ [pscustomobject]@{{ Name = $name; Missing = $true }} }}
  }}
)
$processes = @(
  foreach ($name in $processNames) {{
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {{
      [pscustomobject]@{{ Name = $_.Name; Id = $_.Id; Path = $_.Path }}
    }}
  }}
)
$files = @(
  foreach ($path in $filePaths) {{
    $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($item) {{
      $version = $null
      if ($item.VersionInfo) {{ $version = $item.VersionInfo.ProductVersion }}
      [pscustomobject]@{{ Path = $path; Exists = $true; Length = $item.Length; Version = $version }}
    }} else {{
      [pscustomobject]@{{ Path = $path; Exists = $false }}
    }}
  }}
)
$uninstall = @(
  Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue |
    Where-Object {{ $_.DisplayName -match 'Macrium|Reflect' }} |
    ForEach-Object {{ [pscustomobject]@{{ DisplayName = $_.DisplayName; DisplayVersion = $_.DisplayVersion; Publisher = $_.Publisher; UninstallString = $_.UninstallString }} }}
)
[pscustomobject]@{{
  services = $services
  processes = $processes
  files = $files
  uninstall_entries = $uninstall
  service_present = [bool]($services | Where-Object {{ -not $_.Missing -and $_.Name -eq 'MacriumService' }})
  service_running = [bool]($services | Where-Object {{ $_.Name -eq 'MacriumService' -and $_.Status -eq 'Running' }})
  service_runtime_ok = [bool]($services | Where-Object {{ $_.Name -eq 'MacriumService' -and $_.Status -eq 'Running' }})
  reflect_exe_present = [bool]($files | Where-Object {{ $_.Path -like '*Reflect.exe' -and $_.Exists }})
  uninstall_entry_present = [bool]$uninstall
}} | ConvertTo-Json -Depth 6
"""
    result = powershell_json(script, timeout=60)
    return result if isinstance(result, dict) else {"error": "PowerShell health check did not return JSON.", "raw": result}


def stop_macrium_runtime_for_restore() -> dict[str, Any]:
    service_names = ", ".join(powershell_literal(name) for name in MACRIUM_SERVICE_NAMES)
    process_names = ", ".join(powershell_literal(name) for name in MACRIUM_PROCESS_NAMES)
    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$serviceNames = @({service_names})
$processNames = @({process_names})
$actions = @()
foreach ($name in $processNames) {{
  foreach ($proc in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {{
    if ($proc.Id -ne $PID) {{
      $actions += [pscustomobject]@{{ Type = 'process'; Name = $proc.Name; Id = $proc.Id; Action = 'Stop-Process' }}
      Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }}
  }}
}}
foreach ($name in $serviceNames) {{
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne 'Stopped') {{
    $actions += [pscustomobject]@{{ Type = 'service'; Name = $svc.Name; Action = 'Stop-Service'; PreviousStatus = [string]$svc.Status }}
    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
    try {{ $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(25)) }} catch {{ $actions += [pscustomobject]@{{ Type = 'service'; Name = $svc.Name; Action = 'WaitForStatus'; Error = $_.Exception.Message }} }}
  }}
}}
Start-Sleep -Milliseconds 1000
foreach ($name in $processNames) {{
  foreach ($proc in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {{
    if ($proc.Id -ne $PID) {{
      $actions += [pscustomobject]@{{ Type = 'process'; Name = $proc.Name; Id = $proc.Id; Action = 'Stop-Process-after-service' }}
      Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }}
  }}
}}
Start-Sleep -Milliseconds 1000
$remainingProcesses = @(
  foreach ($name in $processNames) {{
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {{ [pscustomobject]@{{ Name = $_.Name; Id = $_.Id; Path = $_.Path }} }}
  }}
)
$services = @(
  foreach ($name in $serviceNames) {{
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {{ [pscustomobject]@{{ Name = $svc.Name; Status = [string]$svc.Status; StartType = [string]$svc.StartType }} }}
    else {{ [pscustomobject]@{{ Name = $name; Missing = $true }} }}
  }}
)
$runningServices = @($services | Where-Object {{ $_.Status -and $_.Status -ne 'Stopped' }})
[pscustomobject]@{{
  actions = $actions
  remaining_processes = $remainingProcesses
  services = $services
  running_services = $runningServices
  ok_to_copy = (($remainingProcesses.Count -eq 0) -and ($runningServices.Count -eq 0))
}} | ConvertTo-Json -Depth 6
"""
    result = powershell_json(script, timeout=90)
    if not isinstance(result, dict):
        raise ToolError(f"Could not inspect or stop Macrium runtime before live restore: {result}")
    if not result.get("ok_to_copy"):
        raise ToolError(f"Macrium runtime still has locks after stop attempt: {json.dumps(result, sort_keys=True)}")
    return result


def start_macrium_services_after_restore() -> dict[str, Any]:
    service_names = ", ".join(powershell_literal(name) for name in MACRIUM_SERVICE_NAMES)
    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$serviceNames = @({service_names})
$actions = @()
foreach ($name in $serviceNames) {{
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($svc) {{
    if ($svc.StartType -eq 'Disabled') {{
      $actions += [pscustomobject]@{{ Type = 'service'; Name = $svc.Name; Action = 'SetStartupAutomatic'; PreviousStartType = [string]$svc.StartType }}
      Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue
      $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    }}
    if ($svc.Status -ne 'Running') {{
      $actions += [pscustomobject]@{{ Type = 'service'; Name = $svc.Name; Action = 'Start-Service'; PreviousStatus = [string]$svc.Status }}
      Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
      try {{ $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(25)) }} catch {{ $actions += [pscustomobject]@{{ Type = 'service'; Name = $svc.Name; Action = 'WaitForRunning'; Error = $_.Exception.Message }} }}
    }}
  }} else {{
    $actions += [pscustomobject]@{{ Type = 'service'; Name = $name; Action = 'Missing' }}
  }}
}}
$services = @(
  foreach ($name in $serviceNames) {{
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc) {{ [pscustomobject]@{{ Name = $svc.Name; Status = [string]$svc.Status; StartType = [string]$svc.StartType }} }}
    else {{ [pscustomobject]@{{ Name = $name; Missing = $true }} }}
  }}
)
[pscustomobject]@{{ actions = $actions; services = $services }} | ConvertTo-Json -Depth 6
"""
    result = powershell_json(script, timeout=90)
    return result if isinstance(result, dict) else {"error": "Could not start or inspect Macrium services.", "raw": result}


def ensure_macrium_service_registered_after_restore() -> dict[str, Any]:
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$actions = @()
$serviceExe = 'C:\Program Files\Macrium\Common\MacriumService.exe'
$svc = Get-Service -Name 'MacriumService' -ErrorAction SilentlyContinue
if (-not $svc) {
  if (Test-Path -LiteralPath $serviceExe) {
    $actions += [pscustomobject]@{ Type = 'service'; Name = 'MacriumService'; Action = 'New-Service' }
    New-Service -Name 'MacriumService' -BinaryPathName "`"$serviceExe`"" -DisplayName 'Macrium Service' -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
    sc.exe description MacriumService "Provides scheduling and communication services for Macrium Reflect and associated products. This is a required service that should not be disabled or turned off." | Out-Null
  } else {
    $actions += [pscustomobject]@{ Type = 'service'; Name = 'MacriumService'; Action = 'MissingExecutable'; Path = $serviceExe }
  }
} else {
  $actions += [pscustomobject]@{ Type = 'service'; Name = 'MacriumService'; Action = 'AlreadyRegistered'; Status = [string]$svc.Status }
  if ($svc.StartType -eq 'Disabled') {
    $actions += [pscustomobject]@{ Type = 'service'; Name = 'MacriumService'; Action = 'SetStartupAutomatic'; PreviousStartType = [string]$svc.StartType }
    Set-Service -Name 'MacriumService' -StartupType Automatic -ErrorAction SilentlyContinue
  }
}
$svc = Get-Service -Name 'MacriumService' -ErrorAction SilentlyContinue
[pscustomobject]@{
  actions = $actions
  service = if ($svc) { [pscustomobject]@{ Name = $svc.Name; DisplayName = $svc.DisplayName; Status = [string]$svc.Status; StartType = [string]$svc.StartType } } else { [pscustomobject]@{ Name = 'MacriumService'; Missing = $true } }
  registered = [bool]$svc
} | ConvertTo-Json -Depth 6
"""
    result = powershell_json(script, timeout=90)
    if not isinstance(result, dict):
        raise ToolError(f"Could not register or inspect MacriumService after restore: {result}")
    if not result.get("registered"):
        raise ToolError(f"MacriumService is still missing after registration repair: {json.dumps(result, sort_keys=True)}")
    return result


def copy2_with_retries(source: Path, destination: Path, attempts: int = 8) -> dict[str, Any]:
    last_error: OSError | None = None
    for attempt in range(1, attempts + 1):
        temp_destination: Path | None = None
        try:
            if destination.exists() and not destination.is_file():
                raise ToolError(f"Refusing to overwrite non-file destination: {destination}")
            if files_are_identical(source, destination):
                return {"action": "identical", "attempts": attempt}
            destination.parent.mkdir(parents=True, exist_ok=True)
            temp_destination = destination.parent / f".{destination.name}.macrium-restore-{os.getpid()}-{uuid.uuid4().hex}.tmp"
            shutil.copy2(source, temp_destination)
            if destination.exists():
                clear_destination_write_protection(destination)
            os.replace(temp_destination, destination)
            return {"action": "copied", "attempts": attempt}
        except OSError as exc:
            last_error = exc
            if temp_destination is not None:
                try:
                    temp_destination.unlink()
                except OSError:
                    pass
            if attempt == attempts:
                break
            time.sleep(min(0.5 * attempt, 3.0))
    raise ToolError(f"Copy failed after {attempts} attempts: {source} -> {destination}: {last_error}")


def command_restore(args: argparse.Namespace) -> int:
    root = normalize_backup_root(args.backup_root, create=True)
    package = resolve_package_arg(args)
    relocation = Path(args.relocate_to).resolve(strict=False) if args.relocate_to else None
    if not restore_flags_are_sufficient(args.execute_restore, args.i_understand_this_can_overwrite_files, relocation):
        raise ToolError(
            "Live restore requires --execute-restore and --i-understand-this-can-overwrite-files. "
            "Use restore-dry-run first or provide --relocate-to for a harmless restore target."
        )
    if relocation is None:
        if not (args.yes_dangerous_restore or args.confirm_text == "RESTORE MACRIUM"):
            raise ToolError('Live restore requires --yes-dangerous-restore or --confirm-text "RESTORE MACRIUM".')
    manifest = load_manifest_from_zip(package)
    if relocation is None and restore_requires_elevation(manifest) and not is_elevated():
        raise ToolError("Live restore writes protected paths or imports registry/tasks; rerun from elevated PowerShell.", EXIT_ADMIN_REQUIRED)
    bootstrap_assets = inspect_installer_media(root)
    bootstrap_install: dict[str, Any] | None = None
    safety_root = root / "pre_restore" / now_local().strftime("%Y%m%d-%H%M%S")
    if relocation is None:
        bootstrap_install = bootstrap_macrium_install_if_needed(root, safety_root, manifest)
    runtime_stop: dict[str, Any] | None = None
    if relocation is None:
        runtime_stop = stop_macrium_runtime_for_restore()
    with tempfile.TemporaryDirectory(prefix="macrium-restore-") as td:
        extraction = Path(td)
        with zipfile.ZipFile(package, "r") as zf:
            for item in manifest.get("sources", []):
                safe_extract_member(zf, item["archive_path"], extraction)
            if relocation is None:
                for export in manifest.get("registry_exports", []):
                    if export.get("returncode") == 0:
                        safe_extract_member(zf, export["archive_path"], extraction)
                for export in manifest.get("task_exports", []):
                    if export.get("returncode") == 0:
                        safe_extract_member(zf, export["archive_path"], extraction)
        rollback: list[dict[str, Any]] = []
        prepare_safety_snapshot(manifest, safety_root, relocation, rollback)
        restored: list[dict[str, Any]] = []
        skipped_file_restores: list[dict[str, Any]] = []
        for item in manifest.get("sources", []):
            archive_path = item["archive_path"]
            extracted = extraction / Path(*archive_path.split("/"))
            destination = relocated_destination(Path(item["restore_destination"]), relocation)
            if should_skip_restore_item(item, destination):
                skipped_file_restores.append(
                    {
                        "archive_path": archive_path,
                        "destination": str(destination),
                        "reason": WINDOWS_SHELL_METADATA_SKIP_REASON,
                    }
                )
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            copy_result = copy2_with_retries(extracted, destination)
            restored.append({"archive_path": archive_path, "destination": str(destination), **copy_result})
        registry_results: list[dict[str, Any]] = []
        task_results: list[dict[str, Any]] = []
        service_registration: dict[str, Any] | None = None
        service_start: dict[str, Any] | None = None
        if relocation is None:
            registry_results = import_registry_exports(extraction, manifest)
            task_results = import_task_exports(extraction, manifest)
            service_registration = ensure_macrium_service_registered_after_restore()
            service_start = start_macrium_services_after_restore()
        write_json(safety_root / "rollback_manifest.json", {"package": str(package), "overwritten": rollback})
        post_restore_checks = validate_restored_macrium_surface(manifest, relocation)
        result = {
            "package": str(package),
            "relocation_target": str(relocation) if relocation else None,
            "bootstrap_assets": bootstrap_assets,
            "bootstrap_install": bootstrap_install,
            "runtime_stop": runtime_stop,
            "restored_files": restored,
            "skipped_file_restores": skipped_file_restores,
            "registry_results": registry_results,
            "task_results": task_results,
            "service_registration": service_registration,
            "service_start": service_start,
            "post_restore_checks": post_restore_checks,
            "safety_snapshot": str(safety_root),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
    return EXIT_OK


def validate_restored_macrium_surface(manifest: dict[str, Any], relocation: Path | None) -> dict[str, Any]:
    required_names = {"reflect.exe", "macriumservice.exe"}
    interesting_names = required_names | {"reflectbin.exe", "mrcbt.sys", "mrigflt.sys"}
    runtime_items = [
        item
        for item in manifest.get("sources", [])
        if Path(str(item.get("restore_destination", ""))).name.lower() in interesting_names
    ]
    captured_names = {Path(str(item.get("restore_destination", ""))).name.lower() for item in runtime_items}
    missing_required_names = sorted(required_names - captured_names)
    checks = []
    for item in runtime_items:
        expected = str(item.get("restore_destination", ""))
        destination = relocated_destination(Path(expected), relocation)
        checks.append(
            {
                "path": expected,
                "name": Path(expected).name.lower(),
                "actual_path": str(destination),
                "captured_in_manifest": True,
                "exists_after_restore": destination.exists(),
            }
        )
    all_required_present = not missing_required_names and all(item["exists_after_restore"] for item in checks)
    result: dict[str, Any] = {
        "required_runtime_files_present": all_required_present,
        "missing_required_runtime_names": missing_required_names,
        "checks": checks,
        "note": "This validates captured runtime files only; a full OS image is the only no-doubt application migration boundary documented by Macrium.",
    }
    if relocation is None:
        live_health = get_live_macrium_health(manifest)
        result["live_health"] = live_health
        result["live_restore_health_passed"] = bool(
            all_required_present
            and live_health.get("service_present")
            and live_health.get("service_runtime_ok")
            and live_health.get("reflect_exe_present")
        )
    else:
        result["live_restore_health_passed"] = None
    return result


def prepare_safety_snapshot(
    manifest: dict[str, Any],
    safety_root: Path,
    relocation: Path | None,
    rollback: list[dict[str, Any]],
) -> None:
    safety_root.mkdir(parents=True, exist_ok=True)
    for item in manifest.get("sources", []):
        destination = relocated_destination(Path(item["restore_destination"]), relocation)
        if should_skip_restore_item(item, destination):
            continue
        if not destination.exists():
            continue
        if not destination.is_file():
            raise ToolError(f"Refusing to overwrite non-file destination: {destination}")
        backup_path = safety_root / Path(*safe_archive_name_for_path(destination).split("/"))
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        copy2_with_retries(destination, backup_path)
        rollback.append({"original": str(destination), "safety_copy": str(backup_path)})


def import_registry_exports(extraction: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for export in manifest.get("registry_exports", []):
        if export.get("returncode") != 0:
            continue
        path = extraction / Path(*export["archive_path"].split("/"))
        result = run_command(["reg.exe", "import", str(path)], timeout=60)
        results.append({"key": export.get("key"), "returncode": result["returncode"], "stderr": result["stderr"].strip()})
        if result["returncode"] != 0:
            raise ToolError(f"Registry import failed for {export.get('key')}: {result['stderr'].strip()}")
    return results


def import_task_exports(extraction: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for export in manifest.get("task_exports", []):
        if export.get("returncode") != 0:
            continue
        path = extraction / Path(*export["archive_path"].split("/"))
        task_name = str(export.get("task_name"))
        result = run_command(["schtasks.exe", "/create", "/tn", task_name, "/xml", str(path), "/f"], timeout=60)
        results.append({"task_name": task_name, "returncode": result["returncode"], "stderr": result["stderr"].strip()})
        if result["returncode"] != 0:
            raise ToolError(f"Scheduled task import failed for {task_name}: {result['stderr'].strip()}")
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Back up and guarded-restore local Macrium Reflect application state.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python .\\macrium_state_backup_restore.py -b\n"
            "  python .\\macrium_state_backup_restore.py -r\n"
            "  python .\\macrium_state_backup_restore.py inventory\n"
            "  python .\\macrium_state_backup_restore.py backup\n"
            "  python .\\macrium_state_backup_restore.py latest\n"
            "  python .\\macrium_state_backup_restore.py verify\n"
            "  python .\\macrium_state_backup_restore.py health\n"
            "  python .\\macrium_state_backup_restore.py restore-dry-run\n"
            "  python .\\macrium_state_backup_restore.py restore --relocate-to .\\restore-test\n"
            "  python .\\macrium_state_backup_restore.py restore --execute-restore --i-understand-this-can-overwrite-files --confirm-text \"RESTORE MACRIUM\"\n"
        ),
    )
    parser.add_argument("-b", "--backup-now", action="store_true", help="Shortcut: run backup using the configured backup root.")
    parser.add_argument(
        "-r",
        "--restore-now",
        action="store_true",
        help="Shortcut: run latest restore through the normal restore safety gates.",
    )
    parser.add_argument("--backup-root", default=str(DEFAULT_BACKUP_ROOT), help=f"Backup root. Default: {DEFAULT_BACKUP_ROOT}")
    sub = parser.add_subparsers(dest="command", required=True)
    inventory = sub.add_parser("inventory", help="Print discovered Macrium files, registry, services, tasks, and drive strategy.")
    inventory.set_defaults(func=command_inventory)
    backup = sub.add_parser("backup", help="Create a timestamped verified Macrium state zip backup.")
    backup.set_defaults(func=command_backup)
    latest = sub.add_parser("latest", help="Print the newest successful backup package.")
    latest.set_defaults(func=command_latest)
    verify = sub.add_parser("verify", help="Verify a backup package or the newest successful backup.")
    verify.add_argument("package", nargs="?", help="Optional package path. Defaults to latest successful backup.")
    verify.set_defaults(func=command_verify)
    health = sub.add_parser("health", help="Verify latest package plus current live Macrium service/files/registry surface.")
    health.add_argument("package", nargs="?", help="Optional package path. Defaults to latest successful backup.")
    health.set_defaults(func=command_health)
    dry = sub.add_parser("restore-dry-run", help="Print restore plan for latest or specified backup without changing the system.")
    dry.add_argument("package", nargs="?", help="Optional package path. Defaults to latest successful backup.")
    dry.add_argument("--relocate-to", help="Show restore destinations under a harmless relocation root.")
    dry.set_defaults(func=command_restore_dry_run)
    restore = sub.add_parser("restore", help="Restore latest or specified backup. Live restore is dangerous and heavily gated.")
    restore.add_argument("package", nargs="?", help="Optional package path. Defaults to latest successful backup.")
    restore.add_argument("--relocate-to", help="Restore into a harmless relocation root instead of live destinations.")
    restore.add_argument("--execute-restore", action="store_true", help="Required for live destructive restore.")
    restore.add_argument("--i-understand-this-can-overwrite-files", action="store_true", help="Required for live destructive restore.")
    restore.add_argument("--yes-dangerous-restore", action="store_true", help="Skip typed confirmation for approved live restore.")
    restore.add_argument("--confirm-text", help='For live restore, must equal "RESTORE MACRIUM" unless --yes-dangerous-restore is used.')
    restore.set_defaults(func=command_restore)
    return parser


def rewrite_shortcut_args(argv: list[str]) -> list[str]:
    if "-b" in argv or "--backup-now" in argv:
        flag = "-b" if "-b" in argv else "--backup-now"
        index = argv.index(flag)
        return argv[:index] + argv[index + 1 :] + ["backup"]
    if "-r" in argv or "--restore-now" in argv:
        flag = "-r" if "-r" in argv else "--restore-now"
        index = argv.index(flag)
        return argv[:index] + ["restore"] + argv[index + 1 :]
    return argv


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = rewrite_shortcut_args(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ToolError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("ERROR: interrupted by user", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
