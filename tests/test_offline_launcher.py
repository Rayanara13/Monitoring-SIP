import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
from pathlib import Path


LAUNCHER = Path(__file__).resolve().parents[1] / "offline" / "run.py"


def test_offline_launcher_imports_application_modules_and_vendored_dependencies(tmp_path, monkeypatch):
    monkeypatch.delenv("MONITORING_SIP_ROLE", raising=False)
    shutil.copyfile(LAUNCHER, tmp_path / "run.py")
    app = tmp_path / "app"
    app.mkdir()
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (app / "kit_local_module.py").write_text("VALUE = 'app'", encoding="utf-8")
    (vendor / "kit_vendored_module.py").write_text("VALUE = 'vendor'", encoding="utf-8")
    (app / "release_install.py").write_text(
        "from kit_local_module import VALUE as app_value\n"
        "from kit_vendored_module import VALUE as vendor_value\n"
        "def supervise(kit_root, data_dir):\n"
        "    assert data_dir == kit_root / 'app'\n"
        "    print(app_value, vendor_value)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "-I", str(tmp_path / "run.py")],
        capture_output=True,
        input="",
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == "app vendor"
    env = app / ".env"
    assert env.read_text().splitlines() == ["MONITORING_SIP_ROLE=node"]
    if os.name == "posix":
        assert stat.S_IMODE(env.stat().st_mode) == 0o600


def first_start(monkeypatch):
    monkeypatch.delenv("MONITORING_SIP_ROLE", raising=False)
    monkeypatch.delenv("MONITORING_SIP_SETUP", raising=False)
    def unexpected_prompt(*args):
        raise AssertionError("Fresh offline startup prompted for connection settings")

    monkeypatch.setattr("builtins.input", unexpected_prompt)
    return runpy.run_path(str(LAUNCHER))["configure_first_start"]


def test_first_launch_creates_node_configuration_without_prompting(tmp_path, monkeypatch):
    configure = first_start(monkeypatch)
    env = tmp_path / ".env"

    configure(env)
    configure(env)

    assert env.read_text().splitlines() == ["MONITORING_SIP_ROLE=node"]


def test_existing_env_requires_setup_opt_in(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("APP_SECRET_KEY=legacy-secret", encoding="utf-8")
    configure = first_start(monkeypatch)
    configure(env)
    assert env.read_text() == "APP_SECRET_KEY=legacy-secret"

    monkeypatch.setenv("MONITORING_SIP_SETUP", "1")
    configure(env)
    assert env.read_text().splitlines() == [
        "APP_SECRET_KEY=legacy-secret",
        "MONITORING_SIP_ROLE=node",
    ]


def test_lab_launcher_bypasses_office_startup_and_forwards_arguments(tmp_path):
    shutil.copyfile(LAUNCHER, tmp_path / "run.py")
    simulator = tmp_path / "app" / "simulator"
    simulator.mkdir(parents=True)
    (simulator / "__init__.py").touch()
    (simulator / "app.py").write_text(
        "import json, sys\n"
        "def main():\n"
        "    print(json.dumps(sys.argv[1:]))\n"
        "    return 0\n",
        encoding="utf-8",
    )
    office_env = simulator.parent / ".env"
    office_env.write_text("existing configuration", encoding="utf-8")
    flags = ["--open", "--port", "18082"]

    result = subprocess.run(
        [sys.executable, "-I", str(tmp_path / "run.py"), "--lab", *flags],
        capture_output=True, input="", text=True,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == flags
    assert office_env.read_text() == "existing configuration"


def test_managed_launcher_accepts_only_absolute_data_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("MONITORING_SIP_ROLE", raising=False)
    shutil.copyfile(LAUNCHER, tmp_path / "run.py")
    app = tmp_path / "app"
    app.mkdir()
    (app / "release_install.py").write_text(
        "def supervise(kit_root, data_dir):\n"
        "    assert data_dir == kit_root / 'persistent'\n"
        "    return 0\n",
        encoding="utf-8",
    )
    command = [sys.executable, "-I", str(tmp_path / "run.py"), "--data-dir"]
    relative = subprocess.run([*command, "persistent"], capture_output=True, input="")
    assert relative.returncode == 2
    data = tmp_path / "persistent"
    assert not data.exists()

    absolute = subprocess.run([*command, str(data)], capture_output=True, input="", text=True)

    assert absolute.returncode == 0, absolute.stderr
    assert (data / ".env").read_text().splitlines() == ["MONITORING_SIP_ROLE=node"]
    assert not (app / ".env").exists()
