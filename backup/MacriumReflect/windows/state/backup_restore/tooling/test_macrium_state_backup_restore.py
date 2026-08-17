import json
import hashlib
import io
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import macrium_state_backup_restore as tool


class MacriumStateToolTests(unittest.TestCase):
    def test_default_backup_root_is_absolute_requested_path(self):
        root = tool.normalize_backup_root(None, create=False)
        self.assertEqual(root, Path(r"F:\backup\windowsapps\AppsBackups\Macrium"))

    def test_top_level_shortcuts_rewrite_to_commands(self):
        self.assertEqual(tool.rewrite_shortcut_args(["-b"]), ["backup"])
        self.assertEqual(
            tool.rewrite_shortcut_args(["--backup-root", r"F:\x", "-b"]),
            ["--backup-root", r"F:\x", "backup"],
        )
        restore = tool.rewrite_shortcut_args(["-r"])
        self.assertEqual(restore, ["restore"])
        relocated = tool.rewrite_shortcut_args(["-r", "--relocate-to", "out"])
        self.assertEqual(relocated, ["restore", "--relocate-to", "out"])

    def test_archive_member_validation_rejects_traversal_and_ads(self):
        unsafe = [
            "../escape.txt",
            r"..\escape.txt",
            r"C:\Windows\system32\bad.dll",
            "/absolute/path",
            "files/good.txt:evil",
        ]
        for name in unsafe:
            with self.subTest(name=name):
                self.assertFalse(tool.is_safe_archive_member(name))
        self.assertTrue(tool.is_safe_archive_member("files/C/ProgramData/Macrium/state.xml"))

    def test_latest_backup_ignores_incomplete_or_corrupt_packages(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            incomplete = root / "macrium-reflect-state-20260101-010101.zip"
            success = root / "macrium-reflect-state-20260102-010101.zip"
            newer_incomplete = root / "macrium-reflect-state-20260103-010101.zip"
            newer_broken_success = root / "macrium-reflect-state-20260104-010101.zip"
            self._write_package(incomplete, status="incomplete", created_at="2026-01-01T01:01:01")
            self._write_package(success, status="success", created_at="2026-01-02T01:01:01")
            self._write_package(newer_incomplete, status="failed", created_at="2026-01-03T01:01:01")
            with zipfile.ZipFile(newer_broken_success, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(
                    "manifest.json",
                    json.dumps(
                        {
                            "schema_version": tool.MANIFEST_SCHEMA_VERSION,
                            "created_at": "2026-01-04T01:01:01",
                            "status": "success",
                        }
                    ),
                )
            selected = tool.find_latest_successful_backup(root)
            self.assertEqual(selected, success)

    def test_real_restore_requires_dangerous_flags_without_relocation(self):
        self.assertFalse(
            tool.restore_flags_are_sufficient(
                execute_restore=True,
                understand_overwrite=False,
                relocation_target=None,
            )
        )
        self.assertTrue(
            tool.restore_flags_are_sufficient(
                execute_restore=False,
                understand_overwrite=False,
                relocation_target=Path(tempfile.gettempdir()),
            )
        )

    def test_registry_value_redaction_and_binary_hashing(self):
        redacted = tool.registry_value_to_json("LicenseKey", "secret-value", 1)
        self.assertEqual(redacted["value"], "[redacted]")
        self.assertTrue(redacted["redacted"])
        binary = tool.registry_value_to_json("Blob", b"abc", 3)
        self.assertEqual(binary["value"]["sha256"], hashlib.sha256(b"abc").hexdigest())
        self.assertFalse(binary["redacted"])

    def test_restore_plan_marks_registry_and_protected_files_as_elevated(self):
        manifest = {
            "sources": [
                {
                    "archive_path": "files/C/Program_Files/Macrium/app.exe",
                    "restore_destination": r"C:\Program Files\Macrium\app.exe",
                    "size": 1,
                    "sha256": "abc",
                }
            ],
            "registry_exports": [{"key": r"HKLM\SOFTWARE\Macrium", "archive_path": "registry_exports/hklm.reg", "returncode": 0}],
            "task_exports": [],
            "services": [{"Name": "MacriumService", "State": "Stopped"}],
        }
        plan = tool.create_restore_plan(manifest)
        self.assertTrue(plan["requires_elevation"])
        self.assertEqual(len(plan["file_restores"]), 1)
        self.assertEqual(len(plan["registry_imports"]), 1)

    def test_start_menu_desktop_ini_is_skipped_during_backup(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "Users" / "micha" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "desktop.ini"
            source.parent.mkdir(parents=True)
            source.write_text("[.ShellClassInfo]", encoding="utf-8")
            staging = root / "staging"
            manifest = {"sources": [], "skipped_items": []}
            logger = tool.Logger(verbose=False)

            tool.copy_one_file(source, staging, manifest, logger)

            self.assertEqual(manifest["sources"], [])
            self.assertEqual(manifest["skipped_items"][0]["reason"], tool.WINDOWS_SHELL_METADATA_SKIP_REASON)
            self.assertEqual(tool.find_critical_skipped_items(manifest), [])

    def test_common_paths_do_not_capture_whole_desktop_or_start_menu(self):
        paths, _ = tool.discover_common_paths([])
        normalized = {str(path).lower() for path in paths}
        self.assertNotIn(str(Path.home() / "Desktop").lower(), normalized)
        self.assertNotIn(
            str(Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs").lower(),
            normalized,
        )

    def test_macrium_start_menu_group_desktop_ini_is_not_silently_skipped(self):
        app_group = Path(r"C:\Users\micha\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Macrium\desktop.ini")
        self.assertFalse(tool.is_windows_shell_desktop_ini(app_group))
        item = {
            "archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Macrium/desktop.ini",
            "restore_destination": str(app_group),
        }
        self.assertFalse(tool.should_skip_restore_item(item, app_group))

    def test_restore_skips_packaged_start_menu_desktop_ini_from_older_backups(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            package = root / "macrium-reflect-state-20260101-010101.zip"
            restore_root = root / "restore"
            desktop_archive = "files/C/Users/micha/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/desktop.ini"
            state_archive = "files/C/ProgramData/Macrium/state.xml"
            manifest = {
                "schema_version": tool.MANIFEST_SCHEMA_VERSION,
                "created_at": "2026-01-01T01:01:01",
                "status": "success",
                "sources": [
                    {
                        "archive_path": desktop_archive,
                        "restore_destination": r"C:\Users\micha\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\desktop.ini",
                        "size": 1,
                        "sha256": "unused",
                    },
                    {
                        "archive_path": state_archive,
                        "restore_destination": r"C:\ProgramData\Macrium\state.xml",
                        "size": 5,
                        "sha256": "unused",
                    },
                ],
                "registry_exports": [],
                "task_exports": [],
                "services": [],
            }
            with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("inventory.json", "{}")
                zf.writestr("restore_plan.json", json.dumps(tool.create_restore_plan(manifest)))
                zf.writestr(desktop_archive, "shell")
                zf.writestr(state_archive, "state")

            args = self._restore_args(root, package, restore_root)
            output = io.StringIO()
            with redirect_stdout(output):
                result = tool.command_restore(args)

            self.assertEqual(result, tool.EXIT_OK)
            desktop_destination = tool.relocated_destination(Path(manifest["sources"][0]["restore_destination"]), restore_root)
            state_destination = tool.relocated_destination(Path(manifest["sources"][1]["restore_destination"]), restore_root)
            self.assertFalse(desktop_destination.exists())
            self.assertEqual(state_destination.read_text(encoding="utf-8"), "state")
            report = json.loads(output.getvalue())
            self.assertEqual(report["skipped_file_restores"][0]["reason"], tool.WINDOWS_SHELL_METADATA_SKIP_REASON)

    def test_restore_copy_failure_for_critical_file_is_not_hidden(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.bin"
            destination = root / "ProgramData" / "Macrium" / "state.bin"
            source.write_bytes(b"state")

            with mock.patch.object(tool.shutil, "copy2", side_effect=PermissionError("locked")):
                with self.assertRaises(tool.ToolError) as raised:
                    tool.copy2_with_retries(source, destination, attempts=1)

            self.assertIn("Copy failed after 1 attempts", str(raised.exception))

    def test_copy_with_retries_is_idempotent_for_identical_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.bin"
            destination = root / "destination.bin"
            source.write_bytes(b"same")
            destination.write_bytes(b"same")

            with mock.patch.object(tool.shutil, "copy2", wraps=tool.shutil.copy2) as copy2:
                result = tool.copy2_with_retries(source, destination, attempts=1)

            self.assertEqual(result["action"], "identical")
            copy2.assert_not_called()

    def test_macrium_workstation_installer_uses_dash_style_silent_arguments(self):
        installer = Path(r"F:\backup\windowsapps\AppsBackups\Macrium\installer_media\reflect_wkstn_setup_x64_v8.1.8631.exe")
        log_path = Path(r"C:\Temp\installer-bootstrap.log")
        command = tool.build_macrium_installer_command(installer, log_path)
        self.assertEqual(command[1:], ["-silent", "-cbt", "-mig", "-viboot", "-shortcut", "-norestart", "-log"])
        self.assertNotIn(str(log_path), command)

    def test_bootstrap_does_not_rerun_when_runtime_files_are_restored_without_uninstall_entry(self):
        health = {
            "reflect_exe_present": True,
            "uninstall_entry_present": False,
            "files": [
                {"Path": r"C:\Program Files\Macrium\Common\MacriumService.exe", "Exists": True},
            ],
        }
        with mock.patch.object(tool, "get_live_macrium_health", return_value=health):
            self.assertFalse(tool.macrium_install_bootstrap_needed())

    def test_installer_media_ready_requires_launchable_executable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            media = root / "installer_media"
            media.mkdir()
            (media / "offline-components.zip").write_text("not launchable", encoding="utf-8")
            report = tool.inspect_installer_media(root)
            self.assertFalse(report["fresh_windows_bootstrap_ready"])
            self.assertIsNone(report["installer"])

            exe = media / "reflect_wkstn_setup_x64_v8.1.8631.exe"
            exe.write_bytes(b"placeholder")
            report = tool.inspect_installer_media(root)
            self.assertTrue(report["fresh_windows_bootstrap_ready"])
            self.assertEqual(report["installer"], str(exe))

    def test_live_health_candidates_are_manifest_and_user_path_aware(self):
        manifest = {
            "sources": [
                {
                    "archive_path": "files/D/Apps/Macrium/Reflect.exe",
                    "restore_destination": r"D:\Apps\Macrium\Reflect.exe",
                }
            ]
        }
        candidates = tool.get_live_health_file_candidates(manifest)
        self.assertIn(r"D:\Apps\Macrium\Reflect.exe", candidates)
        self.assertTrue(any("Documents" in candidate and "Reflect" in candidate for candidate in candidates))

    def test_restore_surface_validation_uses_manifest_runtime_paths(self):
        with tempfile.TemporaryDirectory() as td:
            restore_root = Path(td) / "restore"
            manifest = {
                "sources": [
                    {
                        "archive_path": "files/D/Apps/Macrium/Reflect.exe",
                        "restore_destination": r"D:\Apps\Macrium\Reflect.exe",
                    },
                    {
                        "archive_path": "files/D/Apps/Macrium/MacriumService.exe",
                        "restore_destination": r"D:\Apps\Macrium\MacriumService.exe",
                    },
                ]
            }
            for item in manifest["sources"]:
                destination = tool.relocated_destination(Path(item["restore_destination"]), restore_root)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"ok")
            report = tool.validate_restored_macrium_surface(manifest, restore_root)
            self.assertTrue(report["required_runtime_files_present"])
            self.assertEqual(report["missing_required_runtime_names"], [])

    def test_sha256_file_and_relocation_destination(self):
        with tempfile.TemporaryDirectory() as td:
            file_path = Path(td) / "sample.txt"
            file_path.write_text("abc", encoding="utf-8")
            digest, note = tool.sha256_file(file_path)
            self.assertEqual(digest, hashlib.sha256(b"abc").hexdigest())
            self.assertIsNone(note)
            relocated = tool.relocated_destination(Path(r"C:\ProgramData\Macrium\state.xml"), Path(td) / "restore")
            self.assertIn("ProgramData", str(relocated))
            self.assertTrue(str(relocated).startswith(str(Path(td) / "restore")))

    def test_safe_extract_member_rejects_escape(self):
        with tempfile.TemporaryDirectory() as td:
            package = Path(td) / "bad.zip"
            with zipfile.ZipFile(package, "w") as zf:
                zf.writestr("../evil.txt", "bad")
            with zipfile.ZipFile(package, "r") as zf:
                with self.assertRaises(tool.ToolError):
                    tool.safe_extract_member(zf, "../evil.txt", Path(td) / "out")

    def test_logger_writes_diagnostic_levels_to_file(self):
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "logs" / "tool.log"
            logger = tool.Logger(log_path=log_path, verbose=False)
            logger.info("one")
            logger.warning("two")
            logger.error("three")
            text = log_path.read_text(encoding="utf-8")
            self.assertIn("INFO one", text)
            self.assertIn("WARN two", text)
            self.assertIn("ERROR three", text)

    def test_console_text_escapes_characters_not_supported_by_windows_codepage(self):
        text = "Macrium\uf03aReflect"
        safe = tool.text_for_console(text, encoding="cp1252")
        self.assertEqual(safe, r"Macrium\uf03aReflect")
        safe.encode("cp1252")

    def _write_package(self, path: Path, status: str, created_at: str) -> None:
        manifest = {
            "schema_version": tool.MANIFEST_SCHEMA_VERSION,
            "created_at": created_at,
            "status": status,
            "sources": [],
            "verification": {"zip_test": True},
        }
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest))
            zf.writestr("inventory.json", "{}")
            zf.writestr("restore_plan.json", "{}")

    def _restore_args(self, root: Path, package: Path, restore_root: Path):
        return type(
            "Args",
            (),
            {
                "backup_root": str(root),
                "package": str(package),
                "relocate_to": str(restore_root),
                "execute_restore": False,
                "i_understand_this_can_overwrite_files": False,
                "yes_dangerous_restore": False,
                "confirm_text": None,
            },
        )()


if __name__ == "__main__":
    unittest.main()
