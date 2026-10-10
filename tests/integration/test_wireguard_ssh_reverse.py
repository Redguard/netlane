from pathlib import Path

import pytest


@pytest.mark.integration
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


@pytest.mark.integration
def test_pair_refuses_without_force_when_already_paired(paired_vps, netlane):
    res = netlane.pair("jailed", force=False, check=False)
    assert res.returncode != 0
    assert "Use --force to replace its keys" in (res.stdout + res.stderr)


@pytest.mark.integration
def test_up_and_down_lifecycle(paired_vps, netlane, vps_exec):
    with netlane.up("jailed"):
        # 1. WireGuard interface wg0 exists with dual-stack IPs
        addr_res = vps_exec("ip -br addr show wg0")
        assert addr_res.returncode == 0
        assert "10.10.10.1/24" in addr_res.stdout
        assert "fd10:10:10::1/64" in addr_res.stdout

        # 2. nftables inet netlane table and chains exist with configured rules
        nft_res = vps_exec("nft list table inet netlane")
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

    # After exiting the context manager, netlane down has executed:
    # 1. wg0 interface no longer exists
    down_link = vps_exec("ip link show wg0", check=False)
    assert down_link.returncode != 0

    # 2. inet netlane nftables table is removed
    down_nft = vps_exec("nft list table inet netlane", check=False)
    assert down_nft.returncode != 0

    # 3. wg0 is removed from trusted_ifaces set
    down_trusted = vps_exec("nft list set inet base_filter trusted_ifaces")
    assert "wg0" not in down_trusted.stdout

    # 4. Kernel forwarding is disabled
    down_fwd4 = vps_exec("sysctl -n net.ipv4.ip_forward")
    assert down_fwd4.stdout.strip() == "0"
    down_fwd6 = vps_exec("sysctl -n net.ipv6.conf.all.forwarding")
    assert down_fwd6.stdout.strip() == "0"


@pytest.mark.integration
def test_up_refuses_when_already_up(paired_vps, netlane):
    with netlane.up("jailed"):
        res = netlane.run("up", "jailed")
        assert res.returncode != 0
        assert "Run 'down jailed' first" in (res.stdout + res.stderr)


@pytest.mark.integration
def test_down_is_idempotent(paired_vps, netlane, vps_exec):
    # Ensure profile is down initially
    netlane.down("jailed")

    # Run down again
    res = netlane.down("jailed", check=False)
    assert res.returncode == 0

    # Confirm VPS state is clean
    down_link = vps_exec("ip link show wg0", check=False)
    assert down_link.returncode != 0

    down_nft = vps_exec("nft list table inet netlane", check=False)
    assert down_nft.returncode != 0


@pytest.mark.integration
def test_lifecycle_hooks_executed(
    setup_vps, tmp_path, vps_server, vps_exec, create_netlane
):
    hook_cfg = tmp_path / "hooks_config.toml"
    hook_cfg.write_text(f"""[profiles.hooked]
mode = "wireguard_ssh_reverse"

[profiles.hooked.mode_opts]
ssh_host = "{vps_server['host']}"
ssh_user = "{vps_server['user']}"
elevation = "sudo"
tunnels = {{ test_port = 8085 }}

[profiles.hooked.hooks]
pre_up = "touch /tmp/hook_pre_up"
post_up = "touch /tmp/hook_post_up"
pre_down = "touch /tmp/hook_pre_down"
post_down = "touch /tmp/hook_post_down"
""")

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
