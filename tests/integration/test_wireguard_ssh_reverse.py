import subprocess

import pytest

from netlane import APP_NAME
from netlane.config import load_config
from netlane.modes.wireguard_ssh_reverse import TABLE_NAME

pytestmark = pytest.mark.integration

# Written by the setup script.
GATEWAYPORTS_CONF = f"/etc/ssh/sshd_config.d/99-{APP_NAME}-gatewayports.conf"


def _assert_vps_clean(vps_exec):
    # 1. wg0 interface no longer exists
    assert vps_exec("ip link show wg0", check=False).returncode != 0

    # 2. The nftables table is removed
    assert vps_exec(f"nft list table inet {TABLE_NAME}", check=False).returncode != 0

    # 3. wg0 is removed from trusted_ifaces set
    trusted = vps_exec("nft list set inet base_filter trusted_ifaces")
    assert "wg0" not in trusted.stdout

    # 4. Kernel forwarding is disabled
    assert vps_exec("sysctl -n net.ipv4.ip_forward").stdout.strip() == "0"
    assert vps_exec("sysctl -n net.ipv6.conf.all.forwarding").stdout.strip() == "0"


def test_setup_installs_wireguard(setup_vps, vps_exec):
    res = vps_exec("which wg")
    assert res.returncode == 0
    assert "/wg" in res.stdout


def test_setup_installs_conntrack(setup_vps, vps_exec):
    res = vps_exec("which conntrack")
    assert res.returncode == 0
    assert "/conntrack" in res.stdout


def test_setup_enables_nftables(setup_vps, vps_exec):
    res = vps_exec("systemctl is-active nftables")
    assert res.stdout.strip() == "active"


def test_setup_configures_nftables_rules(setup_vps, vps_exec):
    res = vps_exec("nft list table inet base_filter")
    assert res.returncode == 0
    assert "set trusted_ifaces" in res.stdout
    assert "chain input" in res.stdout
    assert "chain forward" in res.stdout


def test_setup_configures_sshd_gatewayports(setup_vps, vps_exec):
    res = vps_exec(f"cat {GATEWAYPORTS_CONF}")
    assert res.returncode == 0
    assert "GatewayPorts clientspecified" in res.stdout


def test_setup_is_idempotent(setup_vps, netlane, vps_exec):
    res = netlane.setup("jailed", distro="ubuntu")
    assert res.returncode == 0

    # Verify everything remains correctly installed and configured after re-running setup
    res_wg = vps_exec("which wg")
    assert res_wg.returncode == 0
    assert "/wg" in res_wg.stdout

    res_nft = vps_exec("systemctl is-active nftables")
    assert res_nft.stdout.strip() == "active"

    res_table = vps_exec("nft list table inet base_filter")
    assert res_table.returncode == 0
    assert "set trusted_ifaces" in res_table.stdout

    res_sshd = vps_exec(f"cat {GATEWAYPORTS_CONF}")
    assert res_sshd.returncode == 0
    assert "GatewayPorts clientspecified" in res_sshd.stdout


def test_pair_generates_and_deploys_configs(netlane, tmp_path, vps_exec):
    client_conf_path = tmp_path / "client.conf"
    res = netlane.pair("jailed", save_path=client_conf_path, force=True)
    assert res.returncode == 0

    # 1. Verify client config on local host
    assert client_conf_path.exists()
    assert oct(client_conf_path.stat().st_mode & 0o777) == "0o600"
    client_content = client_conf_path.read_text()
    assert "[Interface]" in client_content
    assert "Address = 10.10.10.2/24, fd10:10:10::2/64" in client_content
    assert "PrivateKey =" in client_content
    assert "[Peer]" in client_content
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in client_content
    assert ":51820" in client_content

    # 2. Verify server config on VPS
    stat_res = vps_exec("stat -c '%a %U:%G' /etc/wireguard/wg0.conf")
    assert stat_res.returncode == 0
    assert stat_res.stdout.strip() == "600 root:root"

    cat_res = vps_exec("cat /etc/wireguard/wg0.conf")
    assert cat_res.returncode == 0
    server_content = cat_res.stdout
    assert "[Interface]" in server_content
    assert "Address = 10.10.10.1/24, fd10:10:10::1/64" in server_content
    assert "ListenPort = 51820" in server_content
    assert "[Peer]" in server_content
    assert "AllowedIPs = 10.10.10.2/32, fd10:10:10::2/128" in server_content


def test_pair_refuses_without_force_when_already_paired(paired_vps, netlane):
    res = netlane.pair("jailed", force=False, check=False)
    assert res.returncode != 0
    assert "Use --force to replace its keys" in (res.stdout + res.stderr)


def test_up_and_down_lifecycle(paired_vps, netlane, vps_exec):
    with netlane.up("jailed"):
        # 1. WireGuard interface wg0 exists with dual-stack IPs
        addr_res = vps_exec("ip -br addr show wg0")
        assert addr_res.returncode == 0
        assert "10.10.10.1/24" in addr_res.stdout
        assert "fd10:10:10::1/64" in addr_res.stdout

        # 2. The nftables table and its chains exist with the configured rules
        nft_res = vps_exec(f"nft list table inet {TABLE_NAME}")
        assert nft_res.returncode == 0
        assert "chain prerouting" in nft_res.stdout
        assert "chain input" in nft_res.stdout
        assert "chain forward" in nft_res.stdout
        assert "chain postrouting" in nft_res.stdout
        assert "masquerade" in nft_res.stdout
        assert "dnat ip to 10.10.10.1:8080" in nft_res.stdout

        # 3. wg0 is in trusted_ifaces set of base_filter table
        trusted_res = vps_exec("nft list set inet base_filter trusted_ifaces")
        assert trusted_res.returncode == 0
        assert "wg0" in trusted_res.stdout

        # 4. Kernel forwarding is enabled for both IPv4 and IPv6
        fwd4_res = vps_exec("sysctl -n net.ipv4.ip_forward")
        assert fwd4_res.stdout.strip() == "1"
        fwd6_res = vps_exec("sysctl -n net.ipv6.conf.all.forwarding")
        assert fwd6_res.stdout.strip() == "1"

        # 5. Reverse SSH tunnel is active and listening on the VPS
        ports_res = vps_exec("ss -tln")
        assert ports_res.returncode == 0
        assert "10.10.10.1:8080" in ports_res.stdout
        assert "fd10:10:10::1" in ports_res.stdout and ":8080" in ports_res.stdout

    # Leaving the context ran `down`
    _assert_vps_clean(vps_exec)


def test_client_traffic_is_redirected_to_local_port(
    paired_client, netlane, local_listener
):
    with local_listener(8080) as received:
        with netlane.up("jailed"):
            # 192.0.2.1 is unroutable (TEST-NET-1), only the DNAT rule can answer.
            sent = paired_client.send("192.0.2.1", 80)

    assert received == [sent.line]
    assert sent.reply == "pong\n"


def test_client_cannot_reach_tunnel_port_directly(
    paired_client, netlane, local_listener
):
    with local_listener(8080) as received:
        with netlane.up("jailed"):
            # Only connections redirected by a tunnel rule may enter the tunnel.
            sent = paired_client.send("10.10.10.1", 8080, timeout=3)

    assert sent.returncode != 0
    assert received == []


def test_client_ipv6_traffic_is_rejected(paired_client, netlane, local_listener):
    # IPv6 connections leave the tunnel on the local IPv6 loopback.
    with local_listener(8080, host="::1") as received:
        with netlane.up("jailed"):
            # 2001:db8::1 is unroutable (documentation prefix). Without the reject
            # rule, the HTTP rule would redirect it into the tunnel.
            sent = paired_client.send("2001:db8::1", 80)

    assert sent.returncode != 0
    assert received == []


def test_rule_targets_and_default_deny(
    setup_vps,
    wireguard_config,
    tmp_path,
    create_netlane,
    wg_client,
    local_listener,
    remote,
):
    cfg = tmp_path / "targets_config.toml"
    cfg.write_text(
        wireguard_config(
            "targets",
            """
  { name = "Drop", protocol = ["tcp"], dport = [8443], target = "action:drop" },
  { name = "Reject", protocol = ["tcp"], dport = [443], target = "action:reject" },
  { name = "Redirect HTTP", protocol = ["tcp"], dport = [80], target = "tunnel:proxy_main" },
  { name = "Pass DNS", protocol = ["udp"], dport = [53], target = "action:passthrough" },
""",
        )
    )
    runner = create_netlane(cfg)
    client_conf_path = tmp_path / "targets_client.conf"
    runner.pair("targets", save_path=client_conf_path, force=True)

    with (
        wg_client(client_conf_path.read_text()) as client,
        local_listener(8080) as received,
        local_listener(8080, host="::1") as received_v6,
        runner.up("targets"),
    ):
        redirected = client.send(remote.address, 80)
        redirected_v6 = client.send("2001:db8::1", 80)
        dropped = client.send(remote.address, 8443, timeout=3)
        rejected = client.send(remote.address, 443, timeout=3)
        unmatched = client.send(remote.address, 8444, timeout=3)
        passed = client.send(remote.address, 53, udp=True)
        passed_peers = remote.peers("udp/53", passed.payload, wait=5)

    # tunnel: both address families end up on the local port
    assert received == [redirected.line]
    assert received_v6 == [redirected_v6.line]
    assert remote.peers("tcp/80", redirected.payload) == []

    # action:drop times out, action:reject fails at once
    assert dropped.returncode == 124
    assert remote.peers("tcp/8443", dropped.payload) == []
    assert rejected.returncode == 1
    assert remote.peers("tcp/443", rejected.payload) == []

    # Traffic matching no rule is dropped
    assert unmatched.returncode == 124
    assert remote.peers("tcp/8444", unmatched.payload) == []

    # action:passthrough reaches the remote host, which is what makes the above meaningful
    assert len(passed_peers) == 1


def test_up_refuses_when_already_up(paired_vps, netlane):
    with netlane.up("jailed"):
        res = netlane.run("up", "jailed")
        assert res.returncode != 0
        assert "Run 'down jailed' first" in (res.stdout + res.stderr)


def test_down_is_idempotent(paired_vps, netlane, vps_exec):
    # Ensure profile is down initially
    netlane.down("jailed")

    # Run down again
    res = netlane.down("jailed", check=False)
    assert res.returncode == 0

    _assert_vps_clean(vps_exec)


def test_lifecycle_hooks_executed(
    setup_vps, wireguard_config, tmp_path, vps_exec, create_netlane
):
    hook_cfg = tmp_path / "hooks_config.toml"
    hook_cfg.write_text(
        wireguard_config(
            "hooked",
            hooks="""
pre_up = "touch /tmp/hook_pre_up"
post_up = "touch /tmp/hook_post_up"
pre_down = "touch /tmp/hook_pre_down"
post_down = "touch /tmp/hook_post_down"
""",
            tunnels="test_port = 8085",
        )
    )

    runner = create_netlane(hook_cfg)
    vps_exec(
        "rm -f /tmp/hook_pre_up /tmp/hook_post_up /tmp/hook_pre_down /tmp/hook_post_down"
    )

    try:
        runner.pair("hooked", force=True)
        with runner.up("hooked"):
            # During up, pre_up and post_up should have run, but not pre_down
            assert vps_exec("test -f /tmp/hook_pre_up", check=False).returncode == 0
            assert vps_exec("test -f /tmp/hook_post_up", check=False).returncode == 0
            assert vps_exec("test -f /tmp/hook_pre_down", check=False).returncode != 0

        # After exiting up (teardown), pre_down and post_down should have run
        assert vps_exec("test -f /tmp/hook_pre_down", check=False).returncode == 0
        assert vps_exec("test -f /tmp/hook_post_down", check=False).returncode == 0
    finally:
        vps_exec(
            "rm -f /tmp/hook_pre_up /tmp/hook_post_up /tmp/hook_pre_down /tmp/hook_post_down"
        )


@pytest.mark.parametrize("hook", ["pre_up", "post_up"])
def test_failed_up_tears_down(
    setup_vps, wireguard_config, tmp_path, vps_exec, create_netlane, hook
):
    cfg = tmp_path / "failing_config.toml"
    cfg.write_text(
        wireguard_config(
            "failing",
            '{ name = "Default Route", target = "action:passthrough" },',
            # pre_up fails once WireGuard is up, post_up once it is trusted as well.
            f'{hook} = "exit 3"',
        )
    )
    runner = create_netlane(cfg)
    runner.pair("failing", force=True)

    try:
        res = runner.run("up", "failing")

        assert res.returncode != 0
        assert "Command failed with exit code 3" in (res.stdout + res.stderr)
        _assert_vps_clean(vps_exec)
    finally:
        runner.down("failing", check=False)


def test_closed_tunnel_tears_down(paired_vps, netlane, vps_exec):
    with netlane.up("jailed", check=False) as proc:
        assert "10.10.10.1:8080" in vps_exec("ss -tln").stdout

        # `up` leads its own process group, which the tunnel's ssh is part of.
        subprocess.run(["pkill", "-g", str(proc.pid), "-f", "ssh -N -R"], check=True)
        proc.wait(timeout=30)

        _assert_vps_clean(vps_exec)


# One rule per way of matching, to have the gateway's nft accept what the backend
# generates. Rules of every target are spread over them.
RULE_MATRIX = """
  { name = "Port set", protocol = ["tcp"], dport = [8001, 8002], target = "action:drop" },
  { name = "Source and destination port", protocol = ["udp"], sport = [5000], dport = [5001], target = "action:reject" },
  { name = "Ports of two protocols", protocol = ["tcp", "udp"], sport = [6000, 6001], dport = [53, 853], target = "action:passthrough" },
  { name = "Ports without protocol", sport = [7000], dport = [7001, 7002], target = "action:drop" },
  { name = "Protocol set", protocol = ["icmp", "ipv6-icmp"], target = "action:passthrough" },
  { name = "Protocol by number", protocol = ["47"], target = "action:reject" },
  { name = "Ports of another protocol", protocol = ["sctp"], dport = [9], target = "action:drop" },
  { name = "Single addresses", saddr = ["10.10.10.2"], daddr = ["192.0.2.1"], target = "action:passthrough" },
  { name = "Networks of both families", daddr = ["198.51.100.0/24", "203.0.113.7", "2001:db8::/32"], protocol = ["tcp"], dport = [22], target = "action:reject" },
  { name = "Source and destination of both families", saddr = ["10.10.10.0/24", "fd10:10:10::/64"], daddr = ["192.0.2.0/24", "2001:db8:1::1"], target = "action:passthrough" },
  { name = "Tunnel for IPv4 only", daddr = ["0.0.0.0/0"], protocol = ["tcp"], dport = [80], target = "tunnel:first" },
  { name = "Tunnel for both families", protocol = ["tcp"], dport = [443, 8443], target = "tunnel:second" },
  { name = "Punctuation (a, b): c/d+e-f_g.", protocol = ["udp"], target = "action:drop" },
  { name = "Catch all", target = "action:passthrough" },
"""


def test_rule_matrix_is_accepted_by_nft(
    setup_vps, wireguard_config, tmp_path, vps_exec, create_netlane
):
    cfg = tmp_path / "matrix_config.toml"
    cfg.write_text(
        wireguard_config("matrix", RULE_MATRIX, tunnels="first = 8080, second = 8081")
    )
    runner = create_netlane(cfg)
    runner.pair("matrix", force=True)

    with runner.up("matrix"):
        ruleset = vps_exec(f"nft list table inet {TABLE_NAME}").stdout

    for rule in load_config(cfg).profiles["matrix"].rules:
        assert f'comment "{rule.name}"' in ruleset
