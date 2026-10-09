from pathlib import Path

import pytest

from netlane import APP_NAME, utils

HOME = Path("/home/user")


@pytest.mark.parametrize(
    "platform, env, expected",
    [
        pytest.param("linux", {}, HOME / ".config" / APP_NAME, id="linux"),
        pytest.param(
            "linux",
            {"XDG_CONFIG_HOME": "/xdg"},
            Path("/xdg") / APP_NAME,
            id="linux xdg",
        ),
        pytest.param(
            "linux",
            {"XDG_CONFIG_HOME": "relative"},
            HOME / ".config" / APP_NAME,
            id="linux ignores relative xdg",
        ),
        pytest.param(
            "darwin", {}, HOME / "Library/Application Support" / APP_NAME, id="macos"
        ),
        pytest.param(
            "win32",
            {"APPDATA": "/appdata"},
            Path("/appdata") / APP_NAME / "config",
            id="windows",
        ),
        pytest.param(
            "win32",
            {},
            HOME / "AppData/Roaming" / APP_NAME / "config",
            id="windows without APPDATA",
        ),
    ],
)
def test_config_dir(monkeypatch, platform, env, expected):
    monkeypatch.setattr(utils.sys, "platform", platform)
    monkeypatch.setattr(utils.Path, "home", lambda: HOME)
    for variable in ("XDG_CONFIG_HOME", "APPDATA"):
        monkeypatch.delenv(variable, raising=False)
    for variable, value in env.items():
        monkeypatch.setenv(variable, value)

    assert utils.config_dir() == expected


@pytest.mark.parametrize("secret, logged", [(False, True), (True, False)])
def test_run_cmd_logs_stdout_unless_secret(caplog, secret, logged):
    caplog.set_level("DEBUG")
    utils.run_cmd(["echo", "private-key"], secret=secret)

    assert "Executing: echo private-key" in caplog.text
    assert ("stdout:\nprivate-key" in caplog.text) == logged


def test_single_sigint_is_ignored():
    handler = utils.teardown_sigint_handler()
    handler(None, None)


def test_second_sigint_within_window_aborts(monkeypatch):
    times = iter([100.0, 101.0])
    monkeypatch.setattr(utils.time, "monotonic", lambda: next(times))
    handler = utils.teardown_sigint_handler()

    handler(None, None)
    with pytest.raises(KeyboardInterrupt):
        handler(None, None)


def test_second_sigint_after_window_is_ignored(monkeypatch):
    times = iter([100.0, 100.0 + utils.ABORT_WINDOW + 1])
    monkeypatch.setattr(utils.time, "monotonic", lambda: next(times))
    handler = utils.teardown_sigint_handler()

    handler(None, None)
    handler(None, None)
