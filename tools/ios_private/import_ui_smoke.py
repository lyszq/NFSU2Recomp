#!/usr/bin/env python3
"""Build and run the public, no-game-input iPad document-picker UI smoke test."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
IOS = ROOT / "ios"
BUNDLE = "dev.lyszq.nfsu2ios"
SCHEME = "ImportPickerSmoke"
APP_RELATIVE = Path("Build/Products/Release-iphonesimulator/NFSU2iOS.app")
TEST_TIMEOUT_SECONDS = 240

sys.path.insert(0, str(Path(__file__).resolve().parent))
from simulator_smoke import (  # noqa: E402
    capture,
    run_tests,
    select_device,
    supported_host_architecture,
)


def _read_device(path: Path) -> dict[str, str]:
    device = json.loads(path.read_text(encoding="utf-8"))
    if not re.fullmatch(r"[A-Fa-f0-9-]{36}", str(device.get("udid", ""))):
        raise ValueError("device selection does not contain a valid simulator UUID")
    if device.get("host_arch") not in ("arm64", "x86_64"):
        raise ValueError("device selection does not contain a supported host architecture")
    return device


def _prepare_dir(path: Path) -> Path:
    path = path.resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _run_logged(command: list[str], log_path: Path, timeout: int,
                cwd: Path = ROOT) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        try:
            subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=timeout, start_new_session=True)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"command exceeded its {timeout}-second bound; see {log_path}") from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"command failed with exit code {exc.returncode}; see {log_path}") from exc


def select(out: Path) -> dict[str, str]:
    """Choose an available iPad simulator matching the active simulator SDK."""
    sdk_version = capture("xcrun", "--sdk", "iphonesimulator", "--show-sdk-version")
    host_arch = supported_host_architecture(capture("uname", "-m"))
    print(f"Waiting for CoreSimulator inventory (SDK {sdk_version}, {host_arch})", flush=True)
    # The first simctl call starts CoreSimulatorService on a fresh CI host.
    # Its startup exceeded the shared 30-second capture bound on the ARM host.
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        inventory = json.loads(subprocess.check_output(
            ["xcrun", "simctl", "list", "devices", "available", "-j"],
            text=True, timeout=180))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        out.write_text(json.dumps({"sdk_version": sdk_version, "host_arch": host_arch,
                                   "selection_error": str(error)}, indent=2) + "\n", encoding="utf-8")
        raise
    device = select_device(inventory, sdk_version)
    device["host_arch"] = host_arch
    out.write_text(json.dumps(device, indent=2) + "\n", encoding="utf-8")
    print(f"Selected {device['name']} ({device['udid']}) on {device['runtime']}; host {device['host_arch']}")
    return device


def build(device_json: Path, derived: Path, out: Path) -> dict[str, str]:
    """Generate the diagnostic UI-test project and build before simulator boot."""
    device = _read_device(device_json)
    derived = derived.resolve()
    out = _prepare_dir(out)
    derived.mkdir(parents=True, exist_ok=True)
    prior_build_outputs = [out / name for name in ("xcodegen.log", "build.log", "build-report.json")
                           if (out / name).exists()]
    if prior_build_outputs:
        raise FileExistsError("preserving prior build outputs: " + ", ".join(map(str, prior_build_outputs)))

    _run_logged(
        ["xcodegen", "generate", "--spec", "project-import-ui.yml"],
        out / "xcodegen.log",
        timeout=120,
        cwd=IOS,
    )

    project = IOS / "NFSU2iOS.xcodeproj"
    command = [
        "xcodebuild", "-project", str(project),
        "-scheme", SCHEME,
        "-configuration", "Release",
        "-sdk", "iphonesimulator",
        "-destination", "generic/platform=iOS Simulator",
        "-jobs", "3",
        "-derivedDataPath", str(derived),
        f"ARCHS={device['host_arch']}",
        "ONLY_ACTIVE_ARCH=YES",
        "CODE_SIGNING_ALLOWED=NO",
        "CODE_SIGNING_REQUIRED=NO",
        "CODE_SIGN_IDENTITY=",
        "build-for-testing",
    ]
    _run_logged(command, out / "build.log", timeout=900)

    app = derived / APP_RELATIVE
    products = derived / "Build/Products"
    xctestruns = sorted(products.glob("*.xctestrun"))
    if not app.is_dir() or len(xctestruns) != 1:
        raise RuntimeError("build did not produce one diagnostic app and exactly one .xctestrun file")
    with (app / "Info.plist").open("rb") as plist_file:
        info = plistlib.load(plist_file)
    if info.get("CFBundleIdentifier") != BUNDLE:
        raise RuntimeError("built app bundle identifier differs from the expected diagnostic app")

    archs = capture("xcrun", "lipo", "-archs", str(app / "NFSU2iOS")).split()
    if archs != [device["host_arch"]]:
        raise RuntimeError(f"expected one host simulator architecture, got {archs}")

    manifest = {
        "scheme": SCHEME,
        "configuration": "Release",
        "simulator_sdk": "active iphonesimulator SDK",
        "host_architecture": device["host_arch"],
        "app": str(app),
        "xctestrun": str(xctestruns[0]),
        "project_spec": str(IOS / "project-import-ui.yml"),
        "full_runtime_macro_enabled": False,
        "game_input_staged": False,
    }
    (out / "build-report.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Built diagnostic {SCHEME} app for {device['host_arch']} without booting a simulator")
    return manifest


def _capture_simulator_screen(udid: str, destination: Path) -> str | None:
    try:
        subprocess.run(["xcrun", "simctl", "io", udid, "screenshot", str(destination)],
                       check=True, timeout=30, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        return None
    except (OSError, subprocess.SubprocessError) as exc:
        return str(exc)


def _run_simulator_command(
    command: list[str],
    log_path: Path,
    timeout: int,
    *,
    runner=None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run one bounded simctl command and keep its output for setup failures."""
    run_command = runner or subprocess.run
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log:
        log.write("$ " + json.dumps(command) + "\n")
        try:
            result = run_command(command, text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or exc.output or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            if output:
                log.write(output)
                if not output.endswith("\n"):
                    log.write("\n")
            message = f"simulator command exceeded its {timeout}-second bound; see {log_path}"
            log.write(message + "\n")
            raise TimeoutError(message) from exc
        output = result.stdout or ""
        log.write(output)
        if output and not output.endswith("\n"):
            log.write("\n")
    if check and result.returncode != 0:
        raise RuntimeError(
            f"simulator command failed with exit code {result.returncode}; see {log_path}"
        )
    return result


def _boot_and_install(udid: str, app: Path, log_path: Path, *, runner=None) -> None:
    """Boot the selected CI simulator and install the app once, without terminating it."""
    _run_simulator_command(["xcrun", "simctl", "boot", udid], log_path, 180,
                           runner=runner, check=False)
    _run_simulator_command(["xcrun", "simctl", "bootstatus", udid, "-b"], log_path, 600,
                           runner=runner)
    _run_simulator_command(["xcrun", "simctl", "install", udid, str(app)], log_path, 180,
                           runner=runner)


def _simulator_state(udid: str) -> str | None:
    try:
        inventory = json.loads(capture("xcrun", "simctl", "list", "devices", "-j"))
        for devices in inventory.get("devices", {}).values():
            for device in devices:
                if device.get("udid") == udid:
                    return str(device.get("state", "unknown"))
        return "not listed"
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return f"unavailable: {exc}"




def run(device_json: Path, derived: Path, out: Path) -> dict[str, object]:
    """Run XCTest on the selected CI simulator and verify Documents setup."""
    device = _read_device(device_json)
    derived = derived.resolve()
    out = _prepare_dir(out)
    app = derived / APP_RELATIVE
    xctestruns = sorted((derived / "Build/Products").glob("*.xctestrun"))
    if not app.is_dir() or len(xctestruns) != 1:
        raise RuntimeError("a successful build phase is required before run; expected one app and .xctestrun")

    result_path = out / "ImportPickerSmoke.xcresult"
    prior_run_outputs = [path for path in (
        result_path,
        out / "simulator-setup.log",
        out / "simulator-test.log",
        out / "simulator-screen.png",
        out / "import-ui-smoke-report.json",
    ) if path.exists()]
    if prior_run_outputs:
        raise FileExistsError("preserving prior run outputs: " + ", ".join(map(str, prior_run_outputs)))

    started = time.monotonic()
    setup_error: str | None = None
    xctest_error: str | None = None
    container_error: str | None = None
    simulator_state: str | None = None
    screenshot_path = out / "simulator-screen.png"
    screenshot_error: str | None = None
    folder_exists = False
    guide_exists = False
    app_install_succeeded = False
    ui_test_passed = False
    command = [
        "xcodebuild", "test-without-building",
        "-xctestrun", str(xctestruns[0]),
        "-destination", "id=" + device["udid"],
        "-parallel-testing-enabled", "NO",
        "-test-timeouts-enabled", "YES",
        "-maximum-test-execution-time-allowance", "180",
        "-resultBundlePath", str(result_path),
    ]
    try:
        _boot_and_install(device["udid"], app, out / "simulator-setup.log")
        app_install_succeeded = True
        try:
            run_tests(command, out / "simulator-test.log", timeout=TEST_TIMEOUT_SECONDS)
            ui_test_passed = True
        except TimeoutError:
            xctest_error = f"UI test exceeded its {TEST_TIMEOUT_SECONDS}-second bound; see simulator-test.log"
        except (subprocess.CalledProcessError, OSError) as exc:
            xctest_error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        setup_error = f"{type(exc).__name__}: {exc}"
    finally:
        simulator_state = _simulator_state(device["udid"])
        if app_install_succeeded:
            try:
                container = Path(capture(
                    "xcrun", "simctl", "get_app_container", device["udid"], BUNDLE, "data"
                ))
                documents = container / "Documents"
                folder_exists = (documents / "Game Import").is_dir()
                guide_exists = (documents / "NFSU2 Import Guide.txt").is_file()
            except (OSError, subprocess.SubprocessError) as exc:
                container_error = str(exc)
        screenshot_error = _capture_simulator_screen(device["udid"], screenshot_path)

    validation_error = None
    if not folder_exists or not guide_exists:
        validation_error = "first-launch Game Import folder or root guide is missing"
    overall_passed = (
        ui_test_passed
        and setup_error is None
        and xctest_error is None
        and container_error is None
        and validation_error is None
    )
    test_error = setup_error or xctest_error

    report: dict[str, object] = {
        "schema_version": 1,
        "test": "production executable picker cancel and reopen",
        "overall_passed": overall_passed,
        "ui_test_passed": ui_test_passed,
        "simulator_name": device["name"],
        "simulator_runtime": device["runtime"],
        "simulator_udid": device["udid"],
        "host_architecture": device["host_arch"],
        "app_container_reset_before_first_launch": False,
        "clean_app_container_assumption": "fresh GitHub-hosted runner per CI job; no simulator erase or app uninstall",
        "app_installed_once": app_install_succeeded,
        "simulator_state_after_test": simulator_state,
        "first_launch_documents_game_import_folder_present": folder_exists,
        "first_launch_documents_root_guide_present": guide_exists,
        "files_app_visibility_checked": False,
        "real_executable_or_game_assets_used": False,
        "gameplay_or_full_runtime_claimed": False,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "setup_log": str(out / "simulator-setup.log"),
        "xctest_log": str(out / "simulator-test.log") if (out / "simulator-test.log").exists() else None,
        "xcresult": str(result_path) if result_path.exists() else None,
        "simulator_screenshot": str(screenshot_path) if screenshot_path.exists() else None,
        "screenshot_error": screenshot_error,
        "test_error": test_error,
        "setup_error": setup_error,
        "xctest_error": xctest_error,
        "container_error": container_error,
        "validation_error": validation_error,
    }
    report_path = out / "import-ui-smoke-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not overall_passed:
        raise RuntimeError(f"import UI smoke did not pass; inspect {report_path}")
    print(f"PASS | picker cancel/reopen and first-launch Files folder setup on {device['name']}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    select_parser = sub.add_parser("select", help="select an available iPad SDK-matched simulator")
    select_parser.add_argument("--out", type=Path, required=True, help="write selected device JSON")

    build_parser = sub.add_parser("build", help="generate and build the diagnostic UI test without booting")
    build_parser.add_argument("--device-json", type=Path, required=True)
    build_parser.add_argument("--derived", type=Path, required=True)
    build_parser.add_argument("--out", type=Path, required=True)

    run_parser = sub.add_parser("run", help="boot, install, test, and verify first-launch Documents")
    run_parser.add_argument("--device-json", type=Path, required=True)
    run_parser.add_argument("--derived", type=Path, required=True)
    run_parser.add_argument("--out", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.mode == "select":
            select(args.out)
        elif args.mode == "build":
            build(args.device_json, args.derived, args.out)
        else:
            run(args.device_json, args.derived, args.out)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FAIL | {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
