import logging
import re
import shutil
import signal
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from netlane import APP_NAME, adb
from netlane.config import AdbReverseOpts, Profile
from netlane.modes.interface import StepError
from netlane.rulesets.iptables import (
    generate_iptables_rules,
    ipv6_tunnel_rules,
    remove_iptables_rules,
)
from netlane.utils import teardown_sigint_handler

logger = logging.getLogger(__name__)

SUMMARY = "iptables on a rooted device, ADB reverse tunnels to local ports"
STEPS = ("up", "down")

CHAIN_NAME = APP_NAME


def setup(name: str, profile: Profile[AdbReverseOpts], distro: str) -> None:
    raise RuntimeError("adb_reverse has no setup step")


def pair(
    name: str, profile: Profile[AdbReverseOpts], save_path: Optional[Path], force: bool
) -> None:
    raise RuntimeError("adb_reverse has no pair step")


def up(name: str, profile: Profile[AdbReverseOpts]) -> None:
    """Applies the profile and keeps its tunnels open until Ctrl-C or the device disconnects."""
    mode_opts = profile.mode_opts
    serial = mode_opts.serial
    ports = mode_opts.tunnels.values()

    if shutil.which("adb") is None:
        raise StepError("ADB ('adb') not found locally. Install it first.")
    _require_device(serial)
    _require_root(serial, mode_opts.elevation)
    _require_down(name, serial, mode_opts.elevation)
    _require_ports_free(serial, ports)
    ipv6_nat = _check_ipv6_nat(serial, mode_opts.elevation)
    if not ipv6_nat:
        logger.warning("Device has no IPv6 NAT. IPv6 NAT rules cannot be applied.")
        rules = ipv6_tunnel_rules(profile)
        if rules:
            raise StepError(
                f"Tunnel rule(s) {', '.join(map(repr, rules))} match IPv6. "
                'Restrict them to IPv4 with daddr = ["0.0.0.0/0"].'
            )

    ruleset = generate_iptables_rules(
        profile,
        CHAIN_NAME,
        _resolve_app_uids(serial, profile),
        _adbd_ports(serial, mode_opts.elevation),
        ipv6_nat,
    )
    watcher = None

    try:
        _run_hook(serial, mode_opts.elevation, profile.hooks.get("pre_up", ""))
        _apply_script(serial, mode_opts.elevation, ruleset)
        _start_reverse_tunnels(serial, ports)
        _run_hook(serial, mode_opts.elevation, profile.hooks.get("post_up", ""))

        watcher = adb.start(serial, ["wait-for-disconnect"])
        logger.info(
            "Local tunnel endpoints: " + ", ".join(f"localhost:{p}" for p in ports)
        )
        watcher.wait()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        _teardown(name, profile, watcher)
    except BaseException:
        _teardown(name, profile, watcher)
        raise
    else:
        raise StepError(
            f"Device disconnected. Rules remain active until 'down {name}' or a reboot."
        )


def down(name: str, profile: Profile[AdbReverseOpts]) -> None:
    """Removes the profile's tunnels and rules. Safe to run when nothing is up."""
    mode_opts = profile.mode_opts
    serial = mode_opts.serial

    _require_root(serial, mode_opts.elevation)
    _run_hook(serial, mode_opts.elevation, profile.hooks.get("pre_down", ""))
    _stop_reverse_tunnels(serial, mode_opts.tunnels.values())
    logger.info("Removing iptables rules on the device...")
    _apply_script(serial, mode_opts.elevation, remove_iptables_rules(CHAIN_NAME))
    _run_hook(serial, mode_opts.elevation, profile.hooks.get("post_down", ""))


def _teardown(name: str, profile: Profile[AdbReverseOpts], watcher) -> None:
    previous_handler = signal.signal(signal.SIGINT, teardown_sigint_handler())
    try:
        if watcher is not None and watcher.poll() is None:
            watcher.terminate()
            watcher.wait()
        down(name, profile)
    finally:
        signal.signal(signal.SIGINT, previous_handler)


def _require_device(serial: Optional[str]) -> None:
    result = adb.run(serial, ["get-state"], check=False)
    if result.returncode != 0:
        error = result.stderr.decode("utf-8").strip()
        raise StepError(f"Device not available: {error}")


def _require_root(serial: Optional[str], elevation: str) -> None:
    """iptables-restore reports a missing root shell as an uninitialized table, so check it up front."""
    result = adb.run_script(serial, elevation, "id -u", check=False)
    if result.stdout.decode("utf-8").strip() != "0":
        raise StepError(
            'Device shell is not root. Set elevation (e.g. "su"), '
            "or run 'adb root' on a debuggable build."
        )


def _require_down(name: str, serial: Optional[str], elevation: str) -> None:
    cmd = f"if iptables -w -t nat -S {CHAIN_NAME} >/dev/null 2>&1; then echo up; fi"
    result = adb.run_script(serial, elevation, cmd)
    if result.stdout.decode("utf-8").strip() == "up":
        raise StepError(f"Profile '{name}' is already up. Run 'down {name}' first.")


def _check_ipv6_nat(serial: Optional[str], elevation: str) -> bool:
    cmd = "if ip6tables -w -t nat -S >/dev/null 2>&1; then echo yes; fi"
    result = adb.run_script(serial, elevation, cmd)
    return result.stdout.decode("utf-8").strip() == "yes"


def _require_ports_free(serial: Optional[str], ports: Iterable[int]) -> None:
    listing = adb.run(serial, ["reverse", "--list"]).stdout.decode("utf-8")
    device_specs = {line.split()[1] for line in listing.splitlines() if line.strip()}
    in_use = [p for p in ports if f"tcp:{p}" in device_specs]
    if in_use:
        raise StepError(
            f"Device port(s) {', '.join(map(str, in_use))} already reversed. "
            "Remove them with 'adb reverse --remove' first."
        )


def _adbd_ports(serial: Optional[str], elevation: str) -> List[int]:
    """Device-side TCP ports adbd listens on. Empty when ADB runs over USB only."""
    script = "readlink /proc/$(pidof adbd)/fd/*; cat /proc/net/tcp /proc/net/tcp6"
    output = adb.run_script(serial, elevation, script, check=False).stdout.decode()
    inodes = set(re.findall(r"^socket:\[(\d+)\]$", output, re.MULTILINE))
    ports = set()
    # /proc/net/tcp fields: sl local_address rem_address st ... uid timeout inode
    # State 0A is LISTEN.
    for fields in map(str.split, output.splitlines()):
        if len(fields) > 9 and fields[3] == "0A" and fields[9] in inodes:
            ports.add(int(fields[1].rsplit(":", 1)[1], 16))
    return sorted(ports)


def _resolve_app_uids(
    serial: Optional[str], profile: Profile[AdbReverseOpts]
) -> Dict[str, List[int]]:
    """Maps each package of the profile's app rules to its uids across all users."""
    apps = sorted({app for rule in profile.rules for app in rule.app or []})
    if not apps:
        return {}

    app_uids = {app: set() for app in apps}
    for user in _list_users(serial):
        package_uids = _list_package_uids(serial, user)
        for app in apps:
            app_uids[app].update(package_uids.get(app, []))

    for app, uids in app_uids.items():
        if not uids:
            raise StepError(f"App '{app}' is not installed on the device.")
    return {app: sorted(uids) for app, uids in app_uids.items()}


def _list_users(serial: Optional[str]) -> List[str]:
    output = adb.shell(serial, "pm list users").stdout.decode("utf-8")
    users = re.findall(r"UserInfo\{(\d+):", output)
    if not users:
        raise StepError("Could not list device users.")
    return users


def _list_package_uids(serial: Optional[str], user: str) -> Dict[str, List[int]]:
    """Maps each package installed for `user` to its uids."""
    cmd = f"cmd package list packages -U --user {user}"
    output = adb.shell(serial, cmd).stdout.decode("utf-8")
    matches = re.findall(r"^package:(\S+) uid:([\d,]+)", output, re.MULTILINE)
    return {package: [int(u) for u in uids.split(",")] for package, uids in matches}


def _apply_script(serial: Optional[str], elevation: str, script: str) -> None:
    logger.info(f"Applying on the device:\n{script}")
    adb.run_script(serial, elevation, script)


def _start_reverse_tunnels(serial: Optional[str], ports: Iterable[int]) -> None:
    logger.info("Starting ADB reverse tunnels...")
    for port in ports:
        adb.run(serial, ["reverse", "--no-rebind", f"tcp:{port}", f"tcp:{port}"])


def _stop_reverse_tunnels(serial: Optional[str], ports: Iterable[int]) -> None:
    logger.info("Stopping ADB reverse tunnels...")
    for port in ports:
        adb.run(serial, ["reverse", "--remove", f"tcp:{port}"], check=False)


def _run_hook(serial: Optional[str], elevation: str, hook_cmd: str) -> None:
    if not hook_cmd:
        return
    adb.run_script(serial, elevation, hook_cmd)
