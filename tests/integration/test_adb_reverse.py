import pytest

HOOK_FILES = " ".join(
    f"/data/local/tmp/hook_{hook}"
    for hook in ("pre_up", "post_up", "pre_down", "post_down")
)


def _assert_device_clean(device_exec, adb_reverse_list):
    for ipt in ("iptables", "ip6tables"):
        # 1. Custom chains are removed from the filter table
        assert device_exec(f"{ipt} -w -S netlane", check=False).returncode != 0
        assert device_exec(f"{ipt} -w -S netlane_input", check=False).returncode != 0

        # 2. Hooks into the built-in chains are removed
        assert "netlane" not in device_exec(f"{ipt} -w -S OUTPUT").stdout
        assert "netlane" not in device_exec(f"{ipt} -w -S INPUT").stdout

    # 3. Custom chain and hook are removed from the nat table
    assert device_exec("iptables -w -t nat -S netlane", check=False).returncode != 0
    assert "netlane" not in device_exec("iptables -w -t nat -S OUTPUT").stdout

    # 4. Reverse tunnel is removed
    assert "tcp:8080" not in adb_reverse_list()


@pytest.mark.integration
def test_up_and_down_lifecycle(netlane_adb, device_exec, adb_reverse_list):
    with netlane_adb.up("rooted"):
        # 1. nat chain is hooked into OUTPUT and redirects to the tunnel port
        nat_output = device_exec("iptables -w -t nat -S OUTPUT")
        assert "-A OUTPUT -j netlane" in nat_output.stdout

        nat_res = device_exec("iptables -w -t nat -S netlane")
        assert "-A netlane -o lo -j RETURN" in nat_res.stdout
        assert "--dport 80 " in nat_res.stdout
        assert '--comment "Redirect HTTP"' in nat_res.stdout
        assert "-j DNAT --to-destination 127.0.0.1:8080" in nat_res.stdout

        # 2. filter chains exist for both address families and drop unmatched traffic
        for ipt in ("iptables", "ip6tables"):
            assert "-A OUTPUT -j netlane" in device_exec(f"{ipt} -w -S OUTPUT").stdout
            assert (
                "-A INPUT -j netlane_input" in device_exec(f"{ipt} -w -S INPUT").stdout
            )

            filter_res = device_exec(f"{ipt} -w -S netlane")
            assert "--ctstate DNAT -j RETURN" in filter_res.stdout
            assert '--comment "Default Route" -j RETURN' in filter_res.stdout
            assert filter_res.stdout.strip().endswith("-A netlane -j DROP")

            # 3. Tunnel port is only reachable from the device itself
            input_res = device_exec(f"{ipt} -w -S netlane_input")
            assert "--dport 8080 -j DROP" in input_res.stdout

        # 4. Connections opened before the rules are reset
        filter4_res = device_exec("iptables -w -S netlane")
        assert "-j REJECT --reject-with tcp-reset" in filter4_res.stdout

        # 5. Reverse ADB tunnel is active
        assert "tcp:8080 tcp:8080" in adb_reverse_list()

    # After exiting the context manager, netlane down has executed
    _assert_device_clean(device_exec, adb_reverse_list)


@pytest.mark.integration
def test_tunnel_redirects_traffic_to_local_port(
    netlane_adb, device_exec, local_listener
):
    with local_listener(8080) as received:
        with netlane_adb.up("rooted"):
            # 192.0.2.1 is unroutable (TEST-NET-1), only the DNAT rule can answer.
            # nc exits on stdin EOF, keep it open until the reply made it back.
            res = device_exec(
                "(echo ping; sleep 2) | nc -w 5 192.0.2.1 80", check=False
            )

    assert received == [b"ping\n"]
    assert "pong" in res.stdout


@pytest.mark.integration
def test_rule_targets_and_default_deny(
    adb_reverse_config, tmp_path, create_netlane, device_send, local_listener, remote
):
    cfg = tmp_path / "targets_config.toml"
    # The tunnel rule is restricted to IPv4, the container kernel may lack IPv6 NAT.
    cfg.write_text(adb_reverse_config("""
  { name = "Drop", protocol = ["tcp"], dport = [8443], target = "action:drop" },
  { name = "Reject", protocol = ["tcp"], dport = [443], target = "action:reject" },
  { name = "Redirect HTTP", daddr = ["0.0.0.0/0"], protocol = ["tcp"], dport = [80], target = "tunnel:proxy_main" },
  { name = "Pass DNS", protocol = ["udp"], dport = [53], target = "action:passthrough" },
"""))
    runner = create_netlane(cfg)
    runner.down("rooted", check=False)

    with local_listener(8080) as received, runner.up("rooted"):
        redirected = device_send(remote.address, 80, root=True)
        dropped = device_send(remote.address, 8443, root=True, timeout=3)
        rejected = device_send(remote.address, 443, root=True, timeout=3)
        unmatched = device_send(remote.address, 8444, root=True, timeout=3)
        passed = device_send(remote.address, 53, udp=True, root=True)
        passed_peers = remote.peers("udp/53", passed.payload, wait=5)

    # tunnel: ends up on the local port instead of the remote host
    assert received == [redirected.line]
    assert remote.peers("tcp/80", redirected.payload) == []

    # action:drop and action:reject never leave the device
    assert dropped.returncode != 0
    assert remote.peers("tcp/8443", dropped.payload) == []
    assert rejected.returncode != 0
    assert remote.peers("tcp/443", rejected.payload) == []

    # Traffic matching no rule is dropped
    assert unmatched.returncode != 0
    assert remote.peers("tcp/8444", unmatched.payload) == []

    # action:passthrough reaches the remote host, which is what makes the above meaningful
    assert len(passed_peers) == 1


@pytest.mark.integration
def test_up_refuses_when_already_up(netlane_adb):
    with netlane_adb.up("rooted"):
        res = netlane_adb.run("up", "rooted")
        assert res.returncode != 0
        assert "Run 'down rooted' first" in (res.stdout + res.stderr)


@pytest.mark.integration
def test_up_refuses_when_port_already_reversed(
    netlane_adb, adb_device, device_exec, adb_reverse_list
):
    serial = adb_device["serial"]
    netlane_adb._run_cmd(
        ["adb", "-s", serial, "reverse", "tcp:8080", "tcp:8080"], check=True
    )
    try:
        res = netlane_adb.run("up", "rooted")
        assert res.returncode != 0
        assert "Device port(s) 8080 already reversed" in (res.stdout + res.stderr)

        # Nothing was applied and the foreign tunnel is left untouched
        assert device_exec("iptables -w -S netlane", check=False).returncode != 0
        assert "tcp:8080 tcp:8080" in adb_reverse_list()
    finally:
        netlane_adb._run_cmd(["adb", "-s", serial, "reverse", "--remove", "tcp:8080"])


@pytest.mark.integration
def test_down_is_idempotent(netlane_adb, device_exec, adb_reverse_list):
    # Ensure profile is down initially
    netlane_adb.down("rooted")

    # Run down again
    res = netlane_adb.down("rooted", check=False)
    assert res.returncode == 0

    # Confirm device state is clean
    _assert_device_clean(device_exec, adb_reverse_list)


@pytest.mark.integration
def test_app_rule_resolves_package_uids(
    adb_reverse_config, tmp_path, device_exec, create_netlane
):
    app_cfg = tmp_path / "app_config.toml"
    app_cfg.write_text(adb_reverse_config("""
  { name = "Reject shell", app = ["com.android.shell"], target = "action:reject" },
  { name = "Default Route", target = "action:passthrough" },
"""))
    runner = create_netlane(app_cfg)

    # The shell package always runs as the fixed AID_SHELL uid
    packages = device_exec("cmd package list packages -U com.android.shell")
    assert "package:com.android.shell uid:2000" in packages.stdout

    with runner.up("rooted"):
        for ipt in ("iptables", "ip6tables"):
            filter_res = device_exec(f"{ipt} -w -S netlane")
            assert "-m owner --uid-owner 2000" in filter_res.stdout
            assert '--comment "Reject shell" -j REJECT' in filter_res.stdout


@pytest.mark.integration
def test_up_refuses_when_app_not_installed(
    adb_reverse_config, tmp_path, device_exec, create_netlane
):
    app_cfg = tmp_path / "missing_app_config.toml"
    app_cfg.write_text(adb_reverse_config("""
  { name = "Reject missing", app = ["com.netlane.not.installed"], target = "action:reject" },
"""))
    runner = create_netlane(app_cfg)

    res = runner.run("up", "rooted")
    assert res.returncode != 0
    assert "App 'com.netlane.not.installed' is not installed on the device." in (
        res.stdout + res.stderr
    )
    assert device_exec("iptables -w -S netlane", check=False).returncode != 0


@pytest.mark.integration
def test_lifecycle_hooks_executed(
    adb_reverse_config, tmp_path, device_exec, create_netlane
):
    hook_cfg = tmp_path / "hooks_config.toml"
    hook_cfg.write_text(adb_reverse_config(tunnels="test_port = 8085") + """
[profiles.rooted.hooks]
pre_up = "touch /data/local/tmp/hook_pre_up"
post_up = "touch /data/local/tmp/hook_post_up"
pre_down = "touch /data/local/tmp/hook_pre_down"
post_down = "touch /data/local/tmp/hook_post_down"
""")

    runner = create_netlane(hook_cfg)
    device_exec(f"rm -f {HOOK_FILES}")

    def hook_ran(hook: str) -> bool:
        res = device_exec(f"test -f /data/local/tmp/hook_{hook}", check=False)
        return res.returncode == 0

    try:
        with runner.up("rooted"):
            # During up, pre_up and post_up should have run, but not pre_down
            assert hook_ran("pre_up")
            assert hook_ran("post_up")
            assert not hook_ran("pre_down")

        # After exiting up (teardown), pre_down and post_down should have run
        assert hook_ran("pre_down")
        assert hook_ran("post_down")
    finally:
        device_exec(f"rm -f {HOOK_FILES}")
