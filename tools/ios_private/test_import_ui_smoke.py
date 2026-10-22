"""Small host-side checks for the UI smoke simulator setup sequence."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import import_ui_smoke


class SimulatorSetupTests(unittest.TestCase):
    def test_boot_wait_and_single_install_without_termination(self):
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, "ok\n")

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "simulator-setup.log"
            import_ui_smoke._boot_and_install(
                "01234567-89AB-CDEF-0123-456789ABCDEF",
                Path(temp_dir) / "NFSU2iOS.app",
                log_path,
                runner=runner,
            )
            commands = [call[0] for call in calls]
            actions = [command[2] for command in commands]

            self.assertEqual(actions, ["boot", "bootstatus", "install"])
            self.assertEqual(actions.count("install"), 1)
            self.assertNotIn("terminate", actions)
            self.assertNotIn("uninstall", actions)
            self.assertEqual([call[1]["timeout"] for call in calls], [180, 600, 180])
            self.assertIn('"install"', log_path.read_text(encoding="utf-8"))

    def test_install_failure_is_logged_and_propagated(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[2] == "install":
                return subprocess.CompletedProcess(command, 17, "simulator install failed\n")
            return subprocess.CompletedProcess(command, 0, "ok\n")

        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "simulator-setup.log"
            with self.assertRaisesRegex(RuntimeError, "exit code 17"):
                import_ui_smoke._boot_and_install(
                    "01234567-89AB-CDEF-0123-456789ABCDEF",
                    Path(temp_dir) / "NFSU2iOS.app",
                    log_path,
                    runner=runner,
                )

            self.assertEqual([command[2] for command in calls], ["boot", "bootstatus", "install"])
            self.assertIn("simulator install failed", log_path.read_text(encoding="utf-8"))

    def test_boot_failure_still_writes_report_without_claiming_ui_pass(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            derived = root / "Derived"
            app = derived / import_ui_smoke.APP_RELATIVE
            app.mkdir(parents=True)
            products = derived / "Build/Products"
            products.mkdir(parents=True, exist_ok=True)
            (products / "ImportPickerSmoke.xctestrun").write_text("placeholder", encoding="utf-8")
            device_json = root / "device.json"
            device_json.write_text(json.dumps({
                "udid": "01234567-89AB-CDEF-0123-456789ABCDEF",
                "name": "iPad test device",
                "runtime": "com.apple.CoreSimulator.SimRuntime.iOS-18-5",
                "host_arch": "arm64",
            }), encoding="utf-8")
            out = root / "artifacts"

            with patch.object(import_ui_smoke, "_boot_and_install",
                              side_effect=RuntimeError("bootstatus failed")), \
                    patch.object(import_ui_smoke, "_simulator_state", return_value="Shutdown"), \
                    patch.object(import_ui_smoke, "_capture_simulator_screen", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "did not pass"):
                    import_ui_smoke.run(device_json, derived, out)

            report = json.loads((out / "import-ui-smoke-report.json").read_text(encoding="utf-8"))
            self.assertFalse(report["ui_test_passed"])
            self.assertFalse(report["overall_passed"])
            self.assertIn("bootstatus failed", report["setup_error"])
            self.assertIsNone(report["xctest_log"])


if __name__ == "__main__":
    unittest.main()
