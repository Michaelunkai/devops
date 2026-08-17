import json
import inspect
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import installed_state_backup_restore as tool


class InstalledStateBackupRestoreTests(unittest.TestCase):
    def test_default_backup_root_is_installed_apps_root(self):
        self.assertEqual(
            tool.DEFAULT_BACKUP_ROOT,
            Path(r"F:\backup\windowsapps\AppsBackups\installed"),
        )

    def test_compact_installed_backup_excludes_broad_personal_media_roots(self):
        roots = {path.name for path in tool.discover_file_roots()}
        self.assertNotIn("Downloads", roots)
        self.assertNotIn("Videos", roots)
        self.assertNotIn("Pictures", roots)
        self.assertNotIn("Music", roots)
        self.assertIn("Desktop", roots)
        self.assertIn("Documents", roots)

    def test_zip_backup_uses_compression_for_smallest_practical_size(self):
        self.assertEqual(tool.ZIP_COMPRESSION_METHOD, zipfile.ZIP_DEFLATED)
        self.assertGreater(tool.ZIP_COMPRESSLEVEL, 0)

    def test_restore_shortcut_does_not_auto_add_destructive_flags(self):
        self.assertEqual(tool.rewrite_shortcut_args(["-r"]), ["restore"])

    def test_backup_shortcut_rewrites_to_backup_command(self):
        self.assertEqual(tool.rewrite_shortcut_args(["-b"]), ["backup"])

    def test_shell_start_menu_desktop_ini_is_skipped(self):
        destination = Path(
            r"C:\Users\micha\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\desktop.ini"
        )
        item = {"destination": str(destination)}
        self.assertTrue(tool.should_skip_restore_item(item, destination))

    def test_app_group_desktop_ini_is_not_skipped(self):
        destination = Path(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\SomeApp\desktop.ini"
        )
        item = {"destination": str(destination)}
        self.assertFalse(tool.should_skip_restore_item(item, destination))

    def test_restore_requires_execute_and_two_danger_flags(self):
        args = SimpleNamespace(
            execute_restore=True,
            i_understand_this_can_overwrite_files=True,
            yes_dangerous_restore=False,
            confirm_text="RESTORE INSTALLED APPS",
        )
        self.assertFalse(tool.restore_flags_are_sufficient(args))
        args.yes_dangerous_restore = True
        self.assertTrue(tool.restore_flags_are_sufficient(args))

    def test_package_manager_snapshot_records_missing_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            metadata_dir = Path(temp)
            with mock.patch.object(tool, "run_command", return_value={"returncode": 9009, "stdout": "", "stderr": "missing"}):
                snapshots = tool.collect_package_manager_snapshots(metadata_dir)
            self.assertTrue(snapshots)
            self.assertTrue(all("name" in snapshot for snapshot in snapshots))
            self.assertTrue(any(snapshot["status"] == "missing_or_failed" for snapshot in snapshots))

    def test_verify_rejects_latest_marker_without_success_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "installed-state-20260505-010101.zip"
            with zipfile.ZipFile(package, "w") as zf:
                zf.writestr("manifest.json", json.dumps({"status": "failed"}))
            (root / "latest.txt").write_text(str(package), encoding="utf-8")
            with self.assertRaises(tool.ToolError):
                tool.find_latest_successful_backup(root)

    def test_relocated_destination_keeps_drive_under_target(self):
        target = Path(r"X:\restore-test")
        destination = Path(r"C:\Program Files\App\app.exe")
        self.assertEqual(
            tool.relocated_destination(destination, target),
            target / "C" / "Program Files" / "App" / "app.exe",
        )

    def test_volatile_cache_paths_are_backup_skips(self):
        self.assertTrue(tool.should_skip_backup_path(Path(r"C:\Users\micha\AppData\Local\Temp\x.tmp")))
        self.assertTrue(tool.should_skip_backup_path(Path(r"C:\ProgramData\Microsoft\Windows Defender\Scans\History\h")))
        self.assertTrue(tool.should_skip_backup_path(Path(r"C:\Users\micha\AppData\Local\Google\Chrome\User Data\Default\Cache\f_000001")))
        self.assertTrue(tool.should_skip_backup_path(Path(r"C:\ProgramData\Package Cache\setup.msi")))
        self.assertFalse(tool.should_skip_backup_path(Path(r"C:\Users\micha\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat")))
        self.assertFalse(tool.should_skip_backup_path(Path(r"C:\Program Files\App\app.exe")))

    def test_wsl_and_docker_raw_vhdx_duplicates_are_skipped(self):
        self.assertTrue(
            tool.should_skip_backup_path(
                Path(
                    r"C:\Users\micha\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState\ext4.vhdx"
                )
            )
        )
        self.assertTrue(tool.should_skip_backup_path(Path(r"C:\Users\micha\AppData\Local\Docker\wsl\data\ext4.vhdx")))
        self.assertFalse(tool.should_skip_backup_path(Path(r"C:\Users\micha\.docker\config.json")))

    def test_user_recreatable_dependency_trees_are_skipped(self):
        self.assertTrue(tool.should_skip_backup_path(Path(r"C:\Users\micha\Documents\project\node_modules\pkg\index.js")))
        self.assertTrue(tool.should_skip_backup_path(Path(r"C:\Users\micha\Documents\project\.venv\Scripts\python.exe")))
        self.assertTrue(tool.should_skip_backup_path(Path(r"C:\Users\micha\Documents\project\.git\objects\pack\a.pack")))
        self.assertFalse(tool.should_skip_backup_path(Path(r"C:\Users\micha\AppData\Local\Programs\App\resources\app\node_modules\pkg\index.js")))

    def test_windows_container_layers_are_skipped_but_storage_is_kept(self):
        self.assertTrue(
            tool.should_skip_backup_path(
                Path(r"C:\ProgramData\Microsoft\Windows\Containers\Layers\abc\Files\Windows\System32\a.dll")
            )
        )
        self.assertFalse(
            tool.should_skip_backup_path(
                Path(r"C:\ProgramData\Microsoft\Windows\Containers\ContainerStorages\abc\sandbox.vhdx")
            )
        )

    def test_raw_windowsapps_payloads_are_skipped_for_reset_safe_restore(self):
        self.assertTrue(
            tool.should_skip_backup_path(
                Path(r"C:\Program Files\WindowsApps\Microsoft.Paint_11.2601.441.0_x64__8wekyb3d8bbwe\PaintApp.exe")
            )
        )

    def test_latest_windowsapps_selector_keeps_only_newest_versions(self):
        kept = tool.select_latest_windowsapps_dirs(
            [
                "Microsoft.Paint_11.2512.211.0_x64__8wekyb3d8bbwe",
                "Microsoft.Paint_11.2601.441.0_x64__8wekyb3d8bbwe",
                "OpenAI.Codex_26.429.3425.0_x64__2p2nqsd0c76g0",
            ]
        )
        self.assertIn("Microsoft.Paint_11.2601.441.0_x64__8wekyb3d8bbwe", kept)
        self.assertNotIn("Microsoft.Paint_11.2512.211.0_x64__8wekyb3d8bbwe", kept)
        self.assertIn("OpenAI.Codex_26.429.3425.0_x64__2p2nqsd0c76g0", kept)

    def test_reset_safe_restore_does_not_overwrite_existing_program_files_binary(self):
        self.assertEqual(
            tool.restore_copy_skip_reason(Path(r"C:\Program Files\App\app.exe"), destination_exists=True, overwrite_installed_binaries=False),
            "existing_installed_binary_reset_safe",
        )
        self.assertIsNone(
            tool.restore_copy_skip_reason(Path(r"C:\Users\micha\AppData\Roaming\App\settings.json"), destination_exists=True, overwrite_installed_binaries=False)
        )

    def test_user_recovery_roots_are_included_when_present(self):
        roots = {str(path) for path in tool.discover_file_roots()}
        self.assertIn(str(Path.home() / "AppData" / "LocalLow"), roots)
        self.assertIn(str(Path.home() / ".codex"), roots)

    def test_registry_keys_include_startup_and_shell_surfaces(self):
        keys = set(tool.discover_registry_keys())
        self.assertIn(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", keys)
        self.assertIn(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", keys)
        self.assertIn(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved", keys)
        self.assertIn(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved", keys)
        self.assertIn(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", keys)
        self.assertIn(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband", keys)
        self.assertIn(r"HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore", keys)
        self.assertIn(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", keys)
        self.assertIn(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", keys)

    def test_recovery_risk_model_distinguishes_reset_from_repair_reinstall(self):
        model = tool.build_recovery_risk_model()
        self.assertEqual(model["reset_this_pc_keep_my_files_cloud_download"]["apps"], "removed")
        self.assertEqual(model["fix_problems_using_windows_update"]["apps"], "preserved")

    def test_system_replay_requires_separate_gate(self):
        parser = tool.build_parser()
        args = parser.parse_args(
            [
                "restore",
                "package.zip",
                "--execute-restore",
                "--i-understand-this-can-overwrite-files",
                "--yes-dangerous-restore",
                "--confirm-text",
                "RESTORE INSTALLED APPS",
            ]
        )
        self.assertFalse(args.execute_system_replay)

    def test_system_replay_script_contains_reset_repair_actions(self):
        with tempfile.TemporaryDirectory() as temp:
            metadata_dir = Path(temp)
            result = tool.write_system_replay_script(metadata_dir)
            script = metadata_dir / result["file"]
            content = script.read_text(encoding="utf-8")
        self.assertIn("Enable-WindowsOptionalFeature", content)
        self.assertIn("Add-WindowsCapability", content)
        self.assertIn("Register-ScheduledTask", content)
        self.assertIn("wsl.exe --import", content)
        self.assertIn("Add-AppxPackage", content)
        self.assertIn("SetEnvironmentVariable", content)
        self.assertIn("powercfg.exe /IMPORT", content)
        self.assertIn("AutomaticManagedPagefile", content)
        self.assertIn("SetUserFTA.exe", content)
        self.assertIn("ie4uinit.exe -show", content)
        self.assertIn("Start-Process explorer.exe", content)

    def test_preflight_blocks_timed_out_wsl(self):
        with mock.patch.object(
            tool,
            "run_command",
            return_value={"returncode": 124, "stdout": "", "stderr": "Timed out", "timed_out": True},
        ):
            preflight = tool.preflight_critical_backup_state()
        self.assertFalse(preflight["ok"])
        self.assertEqual(preflight["issues"][0]["component"], "WSL")

    def test_wsl_export_reports_failure_when_probe_times_out(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(
                tool,
                "run_command",
                return_value={"returncode": 124, "stdout": "", "stderr": "Timed out", "timed_out": True},
            ):
                result = tool.export_wsl_distros(Path(temp))
        self.assertEqual(result["status"], "missing_or_failed")
        self.assertTrue(result["timed_out"])

    def test_package_replay_bootstraps_common_package_managers(self):
        with tempfile.TemporaryDirectory() as temp:
            metadata_dir = Path(temp)
            tool.write_package_replay_scripts(metadata_dir, [])
            content = (metadata_dir / "package-managers" / "restore-package-managers.ps1").read_text(encoding="utf-8")
        self.assertIn("function Test-SnapshotOk", content)
        self.assertIn("Ensure-Chocolatey", content)
        self.assertIn("winget import", content)
        self.assertIn("Install-CriticalRuntimePackages", content)
        self.assertIn("Microsoft.VCRedist.2015+.x64", content)
        self.assertIn("Microsoft.DirectX", content)
        self.assertIn("Microsoft.XNARedist", content)
        self.assertIn("Microsoft.DotNet.SDK.10", content)
        self.assertIn("Microsoft.WindowsADK", content)
        self.assertIn("GitHub.cli", content)
        self.assertIn("OpenAI.Codex", content)
        self.assertIn("Anthropic.Claude", content)
        self.assertIn("npm install -g", content)
        self.assertIn("Restore-ConfigLines npm", content)
        self.assertIn("scoop install", content)
        self.assertIn("pnpm add -g", content)
        self.assertIn("Restore-ConfigLines pnpm", content)
        self.assertIn("yarn global add", content)
        self.assertIn("Restore-ConfigLines yarn", content)
        self.assertIn("Invoke-BunGlobalReplay", content)
        self.assertIn("pipx install", content)
        self.assertIn("uv tool install", content)
        self.assertIn("gh extension install", content)
        self.assertIn("PowerShell 7 module replay", content)

    def test_package_replay_script_gates_failed_snapshots_by_status(self):
        with tempfile.TemporaryDirectory() as temp:
            metadata_dir = Path(temp)
            tool.write_package_replay_scripts(
                metadata_dir,
                [
                    {"name": "bun-global-list", "status": "missing_or_failed"},
                    {"name": "yarn-global-list", "status": "missing_or_failed"},
                    {"name": "npm-list-global", "status": "ok"},
                ],
            )
            content = (metadata_dir / "package-managers" / "restore-package-managers.ps1").read_text(encoding="utf-8")
        self.assertIn("'bun-global-list' = 'missing_or_failed'", content)
        self.assertIn("'yarn-global-list' = 'missing_or_failed'", content)
        self.assertIn("'npm-list-global' = 'ok'", content)
        self.assertIn("Test-SnapshotOk 'bun-global-list'", content)
        self.assertIn("Test-SnapshotOk 'yarn-global-list'", content)
        self.assertIn("Test-SnapshotOk 'npm-list-global'", content)

    def test_package_replay_script_does_not_unlock_nonzero_exit_snapshots(self):
        with tempfile.TemporaryDirectory() as temp:
            metadata_dir = Path(temp)
            tool.write_package_replay_scripts(
                metadata_dir,
                [
                    {"name": "winget-export", "status": "created_with_nonzero_exit"},
                    {"name": "npm-list-global", "status": "created_with_nonzero_exit"},
                ],
            )
            content = (metadata_dir / "package-managers" / "restore-package-managers.ps1").read_text(encoding="utf-8")
        self.assertIn("'winget-export' = 'created_with_nonzero_exit'", content)
        self.assertIn("'npm-list-global' = 'created_with_nonzero_exit'", content)
        self.assertIn("return ($SnapshotStatus.ContainsKey($Name) -and $SnapshotStatus[$Name] -eq 'ok')", content)

    def test_restore_coverage_summary_reports_shell_credentials_and_profiles(self):
        manifest = {
            "files": [
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/App.lnk"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/App.lnk"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/StartupApp.lnk"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/a.automaticDestinations-ms"},
                {"archive_path": "files/C/Users/micha/AppData/Local/Microsoft/Vault/item.vcrd"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Credentials/cred"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Protect/SID/masterkey"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Crypto/RSA/key"},
                {"archive_path": "files/C/Users/micha/AppData/Local/Microsoft/Ngc/key"},
                {"archive_path": "files/C/Users/micha/AppData/Local/Google/Chrome/User Data/Default/Cookies"},
                {"archive_path": "files/C/Users/micha/AppData/Local/Microsoft/Edge/User Data/Default/Cookies"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Mozilla/Firefox/profiles.ini"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Telegram Desktop/tdata/key_datas"},
                {"archive_path": "files/C/Users/micha/AppData/Roaming/Todoist/session.json"},
                {"archive_path": "files/C/Users/micha/.codex/auth.json"},
                {"archive_path": "files/C/Users/micha/.claude/.credentials.json"},
                {"archive_path": "files/C/Users/micha/.docker/config.json"},
                {"archive_path": "files/C/Users/micha/Desktop/App.lnk"},
            ],
            "system_exports": [
                {"name": "shell-state", "status": "ok"},
                {
                    "name": "credential-state",
                    "status": "ok",
                    "subrecords": [
                        {"name": "cmdkey-list.txt", "status": "ok"},
                        {"name": "vault-list.txt", "status": "ok"},
                        {"name": "credential-files-summary.json", "status": "ok"},
                    ],
                },
                {"name": "scheduled-tasks-xml", "status": "ok"},
                {"name": "wsl-exports", "status": "ok"},
                {"name": "wsl-list.txt", "status": "ok"},
                {"name": "wsl-status.txt", "status": "ok"},
                {"name": "system-replay-script", "status": "ok"},
            ],
            "registry_exports": [
                {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "status": "ok"},
                {"key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "status": "ok"},
                {"key": r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "status": "ok"},
                {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "status": "ok"},
                {"key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "status": "ok"},
                {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved", "status": "ok"},
                {"key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved", "status": "ok"},
                {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband", "status": "ok"},
                {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore", "status": "ok"},
                {"key": r"HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations", "status": "ok"},
                {"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts", "status": "ok"},
                {"key": r"HKLM\SOFTWARE\Clients\StartMenuInternet", "status": "ok"},
                {"key": r"HKCU\Software\Clients\StartMenuInternet", "status": "ok"},
            ],
            "package_manager_snapshots": [
                {"name": "winget-export", "status": "ok"},
                {"name": "winget-sources", "status": "ok"},
                {"name": "choco-export", "status": "ok"},
                {"name": "npm-list-global", "status": "ok"},
                {"name": "npm-config", "status": "created_with_nonzero_exit"},
                {"name": "pnpm-list-global", "status": "ok"},
                {"name": "yarn-global-list", "status": "ok"},
                {"name": "bun-global-list", "status": "ok"},
                {"name": "pipx-list", "status": "ok"},
                {"name": "uv-tool-list", "status": "ok"},
                {"name": "cargo-install-list", "status": "ok"},
                {"name": "gh-extension-list", "status": "ok"},
                {"name": "dotnet-sdks", "status": "ok"},
                {"name": "dotnet-runtimes", "status": "ok"},
            ],
        }
        coverage = tool.build_restore_coverage_summary(manifest)
        self.assertEqual(coverage["runtime_and_package_replay"]["coverage_kind"], "backup_capture_and_generated_replay_script")
        self.assertFalse(coverage["runtime_and_package_replay"]["restore_execution_proof_in_manifest"])
        self.assertTrue(coverage["runtime_and_package_replay"]["has_choco_replay_payload"])
        self.assertTrue(coverage["runtime_and_package_replay"]["has_npm_global_snapshot"])
        self.assertTrue(coverage["runtime_and_package_replay"]["has_npm_config_snapshot"])
        self.assertTrue(coverage["runtime_and_package_replay"]["has_bun_global_snapshot"])
        self.assertTrue(coverage["runtime_and_package_replay"]["has_gh_extension_snapshot"])
        self.assertTrue(coverage["runtime_and_package_replay"]["has_dotnet_sdk_snapshot"])
        self.assertIn("DirectX", coverage["runtime_and_package_replay"]["replay_script_bootstraps"])
        self.assertTrue(coverage["wsl_and_system_replay"]["has_wsl_export"])
        self.assertTrue(coverage["wsl_and_system_replay"]["has_wsl_status_export"])
        self.assertTrue(coverage["wsl_and_system_replay"]["has_system_replay_script"])
        self.assertTrue(coverage["shell_and_startup"]["has_taskbar_pins_archived"])
        self.assertTrue(coverage["shell_and_startup"]["has_startup_folder_files_archived"])
        self.assertTrue(coverage["shell_and_startup"]["has_startup_folder_inventory"])
        self.assertTrue(coverage["shell_and_startup"]["has_run_registry_exports"])
        self.assertTrue(coverage["shell_and_startup"]["has_wow64_run_registry_export"])
        self.assertTrue(coverage["shell_and_startup"]["has_runonce_registry_exports"])
        self.assertTrue(coverage["shell_and_startup"]["has_scheduled_task_xml_export"])
        self.assertTrue(coverage["shell_and_startup"]["has_startupapproved_registry_exports"])
        self.assertTrue(coverage["shell_and_startup"]["has_taskband_registry_export"])
        self.assertTrue(coverage["default_apps_and_shortcuts"]["has_url_association_exports"])
        self.assertTrue(coverage["default_apps_and_shortcuts"]["has_file_extension_association_exports"])
        self.assertTrue(coverage["default_apps_and_shortcuts"]["has_startmenuinternet_exports"])
        self.assertTrue(coverage["default_apps_and_shortcuts"]["has_desktop_shortcuts_archived"])
        self.assertTrue(coverage["default_apps_and_shortcuts"]["has_chrome_default_replay_attempt"])
        self.assertFalse(coverage["default_apps_and_shortcuts"]["setuserfta_archived"])
        self.assertTrue(coverage["credentials_and_login_state"]["has_credential_state_export"])
        self.assertEqual(coverage["credentials_and_login_state"]["restore_mode"], "capture_only_for_windows_protected_secrets")
        self.assertTrue(coverage["credentials_and_login_state"]["credential_subrecords_all_ok"])
        self.assertTrue(coverage["credentials_and_login_state"]["has_dpapi_protect_archived"])
        self.assertTrue(coverage["browser_and_app_profiles"]["has_chrome_profile_archived"])
        self.assertTrue(coverage["browser_and_app_profiles"]["has_codex_state_archived"])

    def test_restore_coverage_does_not_treat_nonzero_export_as_replay_ready(self):
        manifest = {
            "files": [],
            "system_exports": [],
            "registry_exports": [],
            "package_manager_snapshots": [
                {"name": "winget-export", "status": "created_with_nonzero_exit"},
                {"name": "choco-export", "status": "missing_or_failed"},
                {"name": "winget-sources", "status": "created_with_nonzero_exit"},
            ],
        }
        coverage = tool.build_restore_coverage_summary(manifest)
        self.assertFalse(coverage["runtime_and_package_replay"]["has_winget_export"])
        self.assertFalse(coverage["runtime_and_package_replay"]["has_choco_replay_payload"])
        self.assertTrue(coverage["runtime_and_package_replay"]["has_winget_source_inventory"])

    def test_restore_coverage_reports_partial_credential_export_as_incomplete(self):
        manifest = {
            "files": [],
            "system_exports": [
                {
                    "name": "credential-state",
                    "status": "ok",
                    "subrecords": [
                        {"name": "cmdkey-list.txt", "status": "ok"},
                        {"name": "vault-list.txt", "status": "missing_or_failed"},
                    ],
                }
            ],
            "registry_exports": [],
        }
        coverage = tool.build_restore_coverage_summary(manifest)
        self.assertFalse(coverage["credentials_and_login_state"]["has_credential_state_export"])
        self.assertFalse(coverage["credentials_and_login_state"]["credential_subrecords_all_ok"])
        self.assertEqual(coverage["credentials_and_login_state"]["credential_failed_subrecords"], ["vault-list.txt"])

    def test_credential_file_inventory_suppresses_protected_file_errors(self):
        source = inspect.getsource(tool.export_credential_state)
        self.assertIn("credential_file_summaries()", source)
        self.assertNotIn("Get-ChildItem", source)

    def test_restore_coverage_separates_startup_payload_from_scan_proof(self):
        manifest = {
            "files": [{"archive_path": "files/C/Users/micha/Desktop/App.lnk"}],
            "system_exports": [{"name": "shell-state", "status": "ok"}],
            "registry_exports": [],
        }
        coverage = tool.build_restore_coverage_summary(manifest)
        self.assertFalse(coverage["shell_and_startup"]["has_startup_folder_files_archived"])
        self.assertTrue(coverage["shell_and_startup"]["has_startup_folder_inventory"])
        self.assertTrue(coverage["shell_and_startup"]["has_startup_folder_restore_payload_or_scan_proof"])

    def test_default_app_coverage_does_not_infer_registry_from_shortcuts(self):
        manifest = {
            "files": [{"archive_path": "files/C/Users/micha/Desktop/Chrome.lnk"}],
            "system_exports": [],
            "registry_exports": [],
        }
        coverage = tool.build_restore_coverage_summary(manifest)
        self.assertTrue(coverage["default_apps_and_shortcuts"]["has_desktop_shortcuts_archived"])
        self.assertFalse(coverage["default_apps_and_shortcuts"]["has_url_association_exports"])
        self.assertFalse(coverage["default_apps_and_shortcuts"]["has_file_extension_association_exports"])
        self.assertFalse(coverage["default_apps_and_shortcuts"]["has_startmenuinternet_exports"])

    def test_dry_run_includes_restore_coverage_and_system_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "package.zip"
            manifest = {
                "status": "success",
                "backup_kind": "installed-app-state",
                "files": [
                    {
                        "archive_path": "files/C/Users/micha/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/App.lnk",
                        "destination": r"C:\Users\micha\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\App.lnk",
                        "size": 1,
                    }
                ],
                "system_exports": [{"name": "shell-state", "status": "ok"}],
                "registry_exports": [],
            }
            with zipfile.ZipFile(package, "w") as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr(manifest["files"][0]["archive_path"], "x")
            report = tool.build_dry_run_report(package)
        self.assertEqual(report["planned_file_restores"], 1)
        self.assertEqual(report["system_replay"], "metadata/system/restore-system-state.ps1")
        self.assertIn("restore_coverage", report)

    def test_command_restore_relocation_copies_files_without_live_gates(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            package = temp_path / "package.zip"
            archive_path = "files/C/Users/micha/AppData/Roaming/App/settings.json"
            manifest = {
                "status": "success",
                "backup_kind": "installed-app-state",
                "files": [
                    {
                        "archive_path": archive_path,
                        "destination": r"C:\Users\micha\AppData\Roaming\App\settings.json",
                        "size": 2,
                    }
                ],
                "registry_exports": [],
            }
            with zipfile.ZipFile(package, "w") as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr(archive_path, "{}")
            target = temp_path / "relocated"
            args = SimpleNamespace(
                backup_root=str(temp_path),
                package=str(package),
                relocate_to=str(target),
                execute_restore=False,
                i_understand_this_can_overwrite_files=False,
                yes_dangerous_restore=False,
                confirm_text="",
                execute_package_replay=False,
                execute_system_replay=False,
                overwrite_installed_binaries=False,
                skip_registry=False,
                import_uninstall_registry=False,
            )
            self.assertEqual(tool.command_restore(args), 0)
            self.assertTrue((target / "C" / "Users" / "micha" / "AppData" / "Roaming" / "App" / "settings.json").exists())

    def test_command_restore_logs_and_fails_on_package_replay_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            package = temp_path / "package.zip"
            manifest = {
                "status": "success",
                "backup_kind": "installed-app-state",
                "files": [],
                "registry_exports": [],
            }
            with zipfile.ZipFile(package, "w") as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
            args = SimpleNamespace(
                backup_root=str(temp_path),
                package=str(package),
                relocate_to=None,
                execute_restore=True,
                i_understand_this_can_overwrite_files=True,
                yes_dangerous_restore=True,
                confirm_text="RESTORE INSTALLED APPS",
                execute_package_replay=True,
                execute_system_replay=False,
                overwrite_installed_binaries=False,
                skip_registry=True,
                import_uninstall_registry=False,
            )
            with mock.patch.object(tool, "is_elevated", return_value=True), mock.patch.object(
                tool,
                "execute_package_replay",
                return_value={"status": "failed", "script": "restore-package-managers.ps1", "returncode": 1},
            ):
                with self.assertRaises(tool.ToolError):
                    tool.command_restore(args)
            report = json.loads((temp_path / "logs" / "restore-execution-last.json").read_text(encoding="utf-8"))
        self.assertEqual(report["package_replay_result"]["status"], "failed")
        self.assertEqual(report["package_replay_result"]["returncode"], 1)
        self.assertEqual(report["package_replay_result"]["script"], "restore-package-managers.ps1")
        self.assertIn("restore-package-managers.ps1", report["package_replay_script"])
        self.assertEqual(report["restored_file_count"], 0)

    def test_command_restore_logs_and_fails_on_registry_import_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            package = temp_path / "package.zip"
            manifest = {
                "status": "success",
                "backup_kind": "installed-app-state",
                "files": [],
                "registry_exports": [{"key": r"HKCU\Software\Test", "file": "metadata/registry/test.reg"}],
            }
            with zipfile.ZipFile(package, "w") as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("metadata/registry/test.reg", "Windows Registry Editor Version 5.00\n")
            args = SimpleNamespace(
                backup_root=str(temp_path),
                package=str(package),
                relocate_to=None,
                execute_restore=True,
                i_understand_this_can_overwrite_files=True,
                yes_dangerous_restore=True,
                confirm_text="RESTORE INSTALLED APPS",
                execute_package_replay=False,
                execute_system_replay=False,
                overwrite_installed_binaries=False,
                skip_registry=False,
                import_uninstall_registry=False,
            )
            failed_registry = [{"key": r"HKCU\Software\Test", "file": "metadata/registry/test.reg", "status": "failed"}]
            with mock.patch.object(tool, "is_elevated", return_value=True), mock.patch.object(
                tool,
                "import_registry_exports",
                return_value=failed_registry,
            ):
                with self.assertRaises(tool.ToolError):
                    tool.command_restore(args)
            report = json.loads((temp_path / "logs" / "restore-execution-last.json").read_text(encoding="utf-8"))
        self.assertEqual(report["registry_results"][0]["status"], "failed")

    def test_safe_extract_member_blocks_zip_path_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "bad.zip"
            destination = Path(temp) / "extract"
            with zipfile.ZipFile(package, "w") as zf:
                zf.writestr("../escape.txt", "x")
            with zipfile.ZipFile(package) as zf:
                with self.assertRaises(tool.ToolError):
                    tool.safe_extract_member(zf, "../escape.txt", destination)

    def test_shell_and_credential_exports_write_health_metadata(self):
        ok = {"returncode": 0, "stdout": "[]", "stderr": "", "timed_out": False}
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(tool, "run_command", return_value=ok):
            metadata_dir = Path(temp)
            shell = tool.export_shell_state(metadata_dir)
            credential = tool.export_credential_state(metadata_dir)
            self.assertEqual(shell["status"], "ok")
            self.assertEqual(credential["status"], "ok")
            self.assertGreaterEqual(len(credential["subrecords"]), 1)
            self.assertTrue((metadata_dir / "system" / "credential-state" / "credential-restore-boundary.json").exists())

    def test_runtime_package_health_detects_critical_winget_packages(self):
        health = tool.build_runtime_package_health(
            {
                "Microsoft.VCRedist.2015+.x64",
                "Microsoft.DirectX",
                "Microsoft.XNARedist",
                "Microsoft.DotNet.SDK.10",
                "Microsoft.DotNet.Runtime.10",
                "Microsoft.WindowsADK",
            }
        )
        self.assertTrue(health["visual_cpp_redistributables"]["present"])
        self.assertTrue(health["directx"]["present"])
        self.assertTrue(health["xna"]["present"])
        self.assertTrue(health["dotnet_sdks"]["present"])
        self.assertTrue(health["dotnet_runtimes"]["present"])
        self.assertTrue(health["windows_sdk_adk"]["present"])

    def test_backup_parser_supports_incomplete_escape_hatch(self):
        parser = tool.build_parser()
        args = parser.parse_args(["backup", "--allow-incomplete-system", "--wsl-idle-wait-seconds", "5"])
        self.assertTrue(args.allow_incomplete_system)
        self.assertEqual(args.wsl_idle_wait_seconds, 5)

    def test_repair_wsl_command_is_available(self):
        parser = tool.build_parser()
        args = parser.parse_args(["repair-wsl"])
        self.assertIs(args.func, tool.command_repair_wsl)

    def test_zip_creation_clamps_pre_1980_timestamps(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            root = temp_path / "root"
            metadata = temp_path / "metadata"
            root.mkdir()
            metadata.mkdir()
            old_file = root / "old.txt"
            old_file.write_text("old", encoding="utf-8")
            os.utime(old_file, (1, 1))
            package = temp_path / "package.zip"
            manifest = {"files": [], "skipped_files": []}
            tool.create_zip_from_inventory(package, metadata, {"file_roots": [str(root)]}, manifest)
            self.assertTrue(package.exists())
            self.assertEqual(manifest["status"], "success")
            self.assertIn("restore_coverage", manifest)

    def test_zip_creation_streams_file_index_outside_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            root = temp_path / "root"
            metadata = temp_path / "metadata"
            root.mkdir()
            metadata.mkdir()
            (root / "app.txt").write_text("ok", encoding="utf-8")
            package = temp_path / "package.zip"
            manifest = {"files": [], "skipped_files": []}
            with mock.patch.object(tool, "should_skip_backup_path", return_value=False), mock.patch.object(tool, "is_reparse_point", return_value=False):
                tool.create_zip_from_inventory(package, metadata, {"file_roots": [str(root)]}, manifest)
            zipped_manifest = tool.load_manifest_from_zip(package)
            with zipfile.ZipFile(package) as zf:
                file_index = zf.read(tool.FILE_INDEX_ARCHIVE_PATH).decode("utf-8").strip().splitlines()
            self.assertEqual(zipped_manifest["file_index"], tool.FILE_INDEX_ARCHIVE_PATH)
            self.assertEqual(zipped_manifest["file_count"], 1)
            self.assertEqual(zipped_manifest.get("files"), [])
            self.assertEqual(len(file_index), 1)
            self.assertEqual(tool.verify_zip_package(package, full_hash=False)["file_count"], 1)
            self.assertEqual(tool.build_dry_run_report(package)["planned_file_restores"], 1)

    def test_wsl_metadata_is_written_after_file_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            root = temp_path / "root"
            metadata = temp_path / "metadata"
            (metadata / "system").mkdir(parents=True)
            root.mkdir()
            (metadata / "system" / "environment.json").write_text("{}", encoding="utf-8")
            (root / "app.txt").write_text("app", encoding="utf-8")
            package = temp_path / "package.zip"
            manifest = {"files": [], "skipped_files": []}

            def final_metadata() -> None:
                wsl_dir = metadata / "system" / "wsl-exports"
                wsl_dir.mkdir(parents=True)
                (wsl_dir / "ubuntu.tar").write_text("ubuntu", encoding="utf-8")

            with mock.patch.object(tool, "should_skip_backup_path", return_value=False), mock.patch.object(tool, "is_reparse_point", return_value=False):
                tool.create_zip_from_inventory(
                    package,
                    metadata,
                    {"file_roots": [str(root)]},
                    manifest,
                    final_metadata_callback=final_metadata,
                )
            with zipfile.ZipFile(package) as zf:
                names = zf.namelist()
            file_index = next(index for index, name in enumerate(names) if name.endswith("app.txt"))
            wsl_index = names.index("metadata/system/wsl-exports/ubuntu.tar")
            self.assertGreater(wsl_index, file_index)

    def test_wait_for_wsl_idle_detects_running_timeout(self):
        running = {
            "returncode": 0,
            "stdout": "NAME STATE VERSION\n* ubuntu Running 2\n",
            "stderr": "",
            "timed_out": False,
        }
        with mock.patch.object(tool, "run_command", return_value=running):
            result = tool.wait_for_wsl_idle(timeout_seconds=0)
        self.assertEqual(result["status"], "timed_out_waiting_for_idle")

    def test_wait_for_wsl_idle_parses_distro_names_with_spaces(self):
        rows = tool.parse_wsl_verbose("NAME STATE VERSION\n* Ubuntu Preview Running 2\n  Debian Stopped 2\n")
        self.assertEqual(rows[0]["name"], "Ubuntu Preview")
        self.assertEqual(rows[0]["state"], "Running")
        self.assertEqual(rows[1]["name"], "Debian")
        self.assertEqual(rows[1]["state"], "Stopped")

    def test_wsl_verbose_parser_accepts_rows_without_version(self):
        rows = tool.parse_wsl_verbose("NAME STATE\n* Legacy Ubuntu Running\n  Tools Stopped\n")
        self.assertEqual(rows[0]["name"], "Legacy Ubuntu")
        self.assertEqual(rows[0]["state"], "Running")
        self.assertEqual(rows[0]["version"], "")
        self.assertEqual(rows[1]["name"], "Tools")
        self.assertEqual(rows[1]["state"], "Stopped")

    def test_wsl_export_attempts_export_after_forced_shutdown_when_not_idle(self):
        def fake_run_command(args, timeout=0, **kwargs):
            if args[:3] == ["wsl.exe", "--list", "--quiet"]:
                return {"returncode": 0, "stdout": "ubuntu\n", "stderr": "", "timed_out": False}
            if args[:2] == ["wsl.exe", "--terminate"]:
                return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
            if args[:2] == ["wsl.exe", "--shutdown"]:
                return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
            if args[:3] == ["wsl.exe", "--list", "--verbose"]:
                return {"returncode": 0, "stdout": "NAME STATE VERSION\n* ubuntu Running 2\n", "stderr": "", "timed_out": False}
            if args[:2] == ["wsl.exe", "--export"]:
                Path(args[3]).write_text("ubuntu", encoding="utf-8")
                return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
            return {"returncode": 1, "stdout": "", "stderr": "unexpected", "timed_out": False}

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(tool, "wait_for_wsl_idle", return_value={"status": "timed_out_waiting_for_idle", "checks": []}):
                with mock.patch.object(tool, "run_command", side_effect=fake_run_command):
                    result = tool.export_wsl_distros(Path(temp), idle_wait_seconds=0)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["idle_status"], "timed_out_waiting_for_idle")
            self.assertGreaterEqual(result["wsl_terminate_count"], 1)
            self.assertTrue((Path(temp) / "system" / "wsl-exports" / "ubuntu.tar").exists())

    def test_wsl_export_stops_docker_and_restarts_after_export(self):
        calls = []

        def fake_run_command(args, timeout=0, **kwargs):
            calls.append(args)
            if args[:3] == ["wsl.exe", "--list", "--quiet"]:
                return {"returncode": 0, "stdout": "ubuntu\n", "stderr": "", "timed_out": False}
            if args[:3] == ["wsl.exe", "--list", "--verbose"]:
                return {"returncode": 0, "stdout": "NAME STATE VERSION\n* ubuntu Stopped 2\n", "stderr": "", "timed_out": False}
            if args[:2] == ["wsl.exe", "--export"]:
                Path(args[3]).write_text("ubuntu", encoding="utf-8")
                return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
            return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(tool, "wait_for_wsl_idle", return_value={"status": "idle", "checks": []}):
                with mock.patch.object(tool, "run_command", side_effect=fake_run_command):
                    with mock.patch.object(tool.subprocess, "Popen"):
                        result = tool.export_wsl_distros(Path(temp), idle_wait_seconds=0)
            self.assertEqual(result["status"], "ok")
            self.assertTrue(any(call[:3] == ["net.exe", "stop", "com.docker.service"] for call in calls))
            self.assertTrue(any(call[:3] == ["net.exe", "start", "com.docker.service"] for call in calls))
            self.assertTrue((Path(temp) / "system" / "wsl-exports" / "docker-stop-for-wsl-export.json").exists())

    def test_wsl_export_reports_mixed_success_as_failure(self):
        def fake_run_command(args, timeout=0, **kwargs):
            if args[:3] == ["wsl.exe", "--list", "--quiet"]:
                return {"returncode": 0, "stdout": "ubuntu\ndebian\n", "stderr": "", "timed_out": False}
            if args[:2] == ["wsl.exe", "--shutdown"]:
                return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
            if args[:3] == ["wsl.exe", "--list", "--verbose"]:
                return {"returncode": 0, "stdout": "NAME STATE VERSION\n* ubuntu Stopped 2\n  debian Stopped 2\n", "stderr": "", "timed_out": False}
            if args[:2] == ["wsl.exe", "--export"]:
                if args[2] == "ubuntu":
                    Path(args[3]).write_text("ubuntu", encoding="utf-8")
                    return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
                return {"returncode": 1, "stdout": "", "stderr": "export failed", "timed_out": False}
            return {"returncode": 1, "stdout": "", "stderr": "unexpected", "timed_out": False}

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(tool, "wait_for_wsl_idle", return_value={"status": "idle", "checks": []}):
                with mock.patch.object(tool, "run_command", side_effect=fake_run_command):
                    result = tool.export_wsl_distros(Path(temp), idle_wait_seconds=0)
            self.assertEqual(result["status"], "missing_or_failed")
            self.assertEqual(result["exports"][0]["status"], "ok")
            self.assertEqual(result["exports"][1]["status"], "missing_or_failed")

    def test_export_extra_system_metadata_defers_wsl(self):
        source = inspect.getsource(tool.export_extra_system_metadata)
        self.assertNotIn("wsl-list.txt", source)


if __name__ == "__main__":
    unittest.main()
