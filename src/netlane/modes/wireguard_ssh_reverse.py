import logging
import shutil
import signal
import sys
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Optional

import qrcode

from netlane import APP_NAME, remote
from netlane.config import Profile, WireguardSSHReverseOpts
from netlane.modes.interface import StepError
from netlane.rulesets.nftables import generate_nft_rules, remove_nft_rules
from netlane.utils import run_cmd, teardown_sigint_handler, write_private_file

logger = logging.getLogger(__name__)

SUMMARY = "WireGuard gateway on a VPS, SSH reverse tunnels to local ports"
STEPS = ("setup", "pair", "up", "down")

DISTRO_SCRIPTS = {"ubuntu": files(APP_NAME) / "scripts" / "ubuntu" / "install.sh"}

TABLE_NAME = APP_NAME
WG_IFACE = "wg0"
CLIENT_SUBNET_V4 = "10.10.10.0/24"
CLIENT_SUBNET_V6 = "fd10:10:10::/64"
WG_SERVER_ADDR_V4 = "10.10.10.1"
WG_SERVER_ADDR_V6 = "fd10:10:10::1"
WG_LISTEN_PORT = 51820

# The install script's base firewall, passed to it as arguments.
# Its set of trusted interfaces is the only way past its drop policies.
BASE_TABLE = "base_filter"
TRUSTED_IFACES_SET = "trusted_ifaces"


def setup(name: str, profile: Profile[WireguardSSHReverseOpts], distro: str) -> None:
    """Runs the distro's install script on the profile's server."""
    mode_opts = profile.mode_opts
    ssh_target = _ssh_target(mode_opts)
    script = DISTRO_SCRIPTS[distro]
    confirm_install(ssh_target, script)
    run_install_script(ssh_target, mode_opts.elevation, script)


def pair(
    name: str,
    profile: Profile[WireguardSSHReverseOpts],
    save_path: Optional[Path],
    force: bool,
) -> None:
    """Deploys new keys to the server and shows the client config as a QR code."""
    mode_opts = profile.mode_opts
    ssh_target = _ssh_target(mode_opts)

    _require_set_up(name, ssh_target)
    _require_down(name, ssh_target)
    if _check_config_exists(ssh_target, mode_opts.elevation, WG_IFACE) and not force:
        raise StepError(
            f"Profile '{name}' is already paired. Use --force to replace its keys."
        )
    if shutil.which("wg") is None:
        raise StepError("WireGuard tools ('wg') not found locally. Install them first.")

    logger.info("Generating WireGuard keypairs and config...")
    server_conf, client_conf = _generate_configs(mode_opts.ssh_host)
    _deploy_server_config(ssh_target, mode_opts.elevation, WG_IFACE, server_conf)
    _display_qr_code(client_conf)

    if save_path is not None:
        write_private_file(save_path, client_conf)
        logger.info(f"Client config saved to '{save_path}'")


def up(name: str, profile: Profile[WireguardSSHReverseOpts]) -> None:
    """Applies the profile and keeps its tunnels open until Ctrl-C."""
    mode_opts = profile.mode_opts
    ssh_target = _ssh_target(mode_opts)

    _require_set_up(name, ssh_target)
    if not _check_config_exists(ssh_target, mode_opts.elevation, WG_IFACE):
        raise StepError(
            f"Profile '{name}' has no WireGuard keys yet. "
            f"Run 'pair {name}' to create them and show the QR code."
        )
    _require_down(name, ssh_target)

    ruleset = generate_nft_rules(
        profile,
        TABLE_NAME,
        WG_IFACE,
        CLIENT_SUBNET_V4,
        CLIENT_SUBNET_V6,
        WG_SERVER_ADDR_V4,
        WG_SERVER_ADDR_V6,
    )
    tunnel_proc = None

    try:
        _start_wireguard(ssh_target, mode_opts.elevation, WG_IFACE)

        _run_hook(ssh_target, mode_opts.elevation, profile.hooks.get("pre_up", ""))
        # The table's own restriction must be in place before wg0 is trusted at
        # the base layer - otherwise there's a window where wg0 is trusted
        # but nothing yet restricts what it can reach.
        _apply_nft_script(ssh_target, mode_opts.elevation, ruleset)
        _flush_conntrack(ssh_target, mode_opts.elevation)
        _register_trusted_iface(ssh_target, mode_opts.elevation, WG_IFACE)
        _run_hook(ssh_target, mode_opts.elevation, profile.hooks.get("post_up", ""))

        tunnel_proc = _start_reverse_tunnel(
            ssh_target,
            mode_opts.tunnels.values(),
            WG_SERVER_ADDR_V4,
            WG_SERVER_ADDR_V6,
        )
        logger.info(
            "Local tunnel endpoints: "
            + ", ".join(
                f"127.0.0.1:{p} / [::1]:{p}" for p in mode_opts.tunnels.values()
            )
        )
        tunnel_proc.wait()
        logger.error("Tunnel closed unexpectedly.")

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        previous_handler = signal.signal(signal.SIGINT, teardown_sigint_handler())
        try:
            if tunnel_proc is not None and tunnel_proc.poll() is None:
                tunnel_proc.terminate()
                tunnel_proc.wait()
            down(name, profile)
        finally:
            signal.signal(signal.SIGINT, previous_handler)


def down(name: str, profile: Profile[WireguardSSHReverseOpts]) -> None:
    """Stops WireGuard and removes the profile's rules. Safe to run when nothing is up."""
    mode_opts = profile.mode_opts
    ssh_target = _ssh_target(mode_opts)

    _run_hook(ssh_target, mode_opts.elevation, profile.hooks.get("pre_down", ""))
    _stop_wireguard(ssh_target, mode_opts.elevation, WG_IFACE)
    _teardown_nft(ssh_target, mode_opts.elevation)
    _flush_conntrack(ssh_target, mode_opts.elevation)
    _run_hook(ssh_target, mode_opts.elevation, profile.hooks.get("post_down", ""))


def confirm_install(ssh_target: str, script: Traversable) -> None:
    """Raises StepError unless the SSH target is typed back on stdin."""
    logger.debug(f"Install script {script.name}:\n{script.read_text()}")
    print(
        f"WARNING: This configures the remote server '{ssh_target}' and assumes "
        "it is not used for anything else. Its firewall will only accept SSH "
        "on port 22.",
        file=sys.stderr,
    )
    print(f"Type '{ssh_target}' to confirm: ", end="", file=sys.stderr, flush=True)
    answer = sys.stdin.readline().strip()
    if answer != ssh_target:
        raise StepError("Aborted.")


def run_install_script(ssh_target: str, elevation: str, script: Traversable) -> None:
    logger.info(f"Running persistent install script {script.name}...")
    args = [APP_NAME, BASE_TABLE, TRUSTED_IFACES_SET, str(WG_LISTEN_PORT)]
    remote.run_script(ssh_target, elevation, script.read_text(), ["bash"], args)


def _ssh_target(mode_opts: WireguardSSHReverseOpts) -> str:
    return f"{mode_opts.ssh_user}@{mode_opts.ssh_host}"


def _require_set_up(name, ssh_target):
    if not _check_set_up(ssh_target):
        raise StepError(f"Server for '{name}' is not set up. Run 'setup {name}' first.")


def _require_down(name, ssh_target):
    if _check_iface_up(ssh_target, WG_IFACE):
        raise StepError(f"Profile '{name}' is already up. Run 'down {name}' first.")


def _generate_keypair():
    priv_result = run_cmd(["wg", "genkey"], secret=True)
    privkey = priv_result.stdout.decode("utf-8").strip()

    pub_result = run_cmd(["wg", "pubkey"], input_bytes=privkey.encode("utf-8"))
    pubkey = pub_result.stdout.decode("utf-8").strip()

    return privkey, pubkey


def _generate_configs(server_host):
    server_priv, server_pub = _generate_keypair()
    client_priv, client_pub = _generate_keypair()
    endpoint_host = f"[{server_host}]" if ":" in server_host else server_host

    server_conf = f"""[Interface]
Address = {WG_SERVER_ADDR_V4}/24, {WG_SERVER_ADDR_V6}/64
ListenPort = {WG_LISTEN_PORT}
PrivateKey = {server_priv}

[Peer]
PublicKey = {client_pub}
AllowedIPs = 10.10.10.2/32, fd10:10:10::2/128
"""

    client_conf = f"""[Interface]
Address = 10.10.10.2/24, fd10:10:10::2/64
PrivateKey = {client_priv}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pub}
Endpoint = {endpoint_host}:{WG_LISTEN_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    return server_conf, client_conf


def _display_qr_code(data):
    qr = qrcode.QRCode()
    qr.add_data(data)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def _wg_conf_path(wg_iface):
    return f"/etc/wireguard/{wg_iface}.conf"


def _deploy_server_config(ssh_target, elevation, wg_iface, server_conf):
    logger.info(f"Deploying {wg_iface}.conf to remote server...")
    remote.install_file(ssh_target, elevation, server_conf, _wg_conf_path(wg_iface))


def _start_wireguard(ssh_target, elevation, wg_iface):
    logger.info("Starting WireGuard interface and setting dynamic routing...")
    remote_cmd = (
        "sysctl -w net.ipv4.ip_forward=1 ; "
        "sysctl -w net.ipv6.conf.all.forwarding=1 ; "
        f"wg-quick up {wg_iface}"
    )
    remote.run(ssh_target, remote_cmd, elevation, tty=True)


def _stop_wireguard(ssh_target, elevation, wg_iface):
    logger.info("Stopping WireGuard interface and disabling forwarding...")
    remote_cmd = (
        f"wg-quick down {wg_iface} || true ; "
        "sysctl -w net.ipv4.ip_forward=0 ; "
        "sysctl -w net.ipv6.conf.all.forwarding=0"
    )
    remote.run(ssh_target, remote_cmd, elevation, tty=True)


def _check_config_exists(ssh_target, elevation, wg_iface):
    # Exit code 2 marks a missing file, as a failed elevation also exits with 1.
    cmd = f"if test -f {_wg_conf_path(wg_iface)}; then exit 0; else exit 2; fi"
    result = remote.run(ssh_target, cmd, elevation, tty=True, check=False)
    if result.returncode not in (0, 2):
        raise StepError("Elevation on the remote server failed.")
    return result.returncode == 0


def _check_set_up(ssh_target):
    cmd = "command -v wg && command -v conntrack"
    return remote.run(ssh_target, cmd, check=False).returncode == 0


def _check_iface_up(ssh_target, wg_iface):
    cmd = f"ip link show {wg_iface}"
    return remote.run(ssh_target, cmd, check=False).returncode == 0


def _apply_nft_script(ssh_target, elevation, script):
    logger.info(f"Applying nftables ruleset on remote server:\n{script}")
    remote.run_script(ssh_target, elevation, script, ["nft", "-f"])


def _register_trusted_iface(ssh_target, elevation, iface):
    logger.info(f"Registering {iface} as a trusted interface on remote server...")
    script = "\n".join(
        [
            f"flush set inet {BASE_TABLE} {TRUSTED_IFACES_SET}",
            f"add element inet {BASE_TABLE} {TRUSTED_IFACES_SET} {{ {iface} }}",
        ]
    )
    _apply_nft_script(ssh_target, elevation, script)


def _teardown_nft(ssh_target, elevation):
    logger.info("Deregistering trusted interfaces and removing nftables ruleset...")
    script = "\n".join(
        [
            f"flush set inet {BASE_TABLE} {TRUSTED_IFACES_SET}",
            remove_nft_rules(TABLE_NAME),
        ]
    )
    _apply_nft_script(ssh_target, elevation, script)


def _flush_conntrack(ssh_target, elevation):
    """Deletes the client's connections, as forwarding accepts established ones without evaluating the rules."""
    logger.info("Flushing client connections from conntrack...")
    # conntrack exits with 1 when there is nothing to delete.
    remote_cmd = " && ".join(
        f"{{ conntrack -D -f {family} -s {subnet} || [ $? -eq 1 ] ; }}"
        for family, subnet in (("ipv4", CLIENT_SUBNET_V4), ("ipv6", CLIENT_SUBNET_V6))
    )
    remote.run(ssh_target, remote_cmd, elevation, tty=True)


def _run_hook(ssh_target, elevation, hook_cmd):
    if not hook_cmd:
        return
    remote.run(ssh_target, hook_cmd, elevation, tty=True)


def _tunnel_forward_args(ports, wg_server_addr_v4, wg_server_addr_v6):
    args = []
    for port in ports:
        args += ["-R", f"{wg_server_addr_v4}:{port}:127.0.0.1:{port}"]
        args += ["-R", f"[{wg_server_addr_v6}]:{port}:[::1]:{port}"]
    return args


def _start_reverse_tunnel(ssh_target, ports, wg_server_addr_v4, wg_server_addr_v6):
    forward_args = _tunnel_forward_args(ports, wg_server_addr_v4, wg_server_addr_v6)
    return remote.start(ssh_target, ["-N", *forward_args])
