"""The rooted profile of the repository's config.toml, with traffic of the Android device.

The profile's placeholder app is replaced by the ADB shell's package, so lines sent
by `device_send` are the app's traffic and those sent with `root=True` are not.
"""

from types import SimpleNamespace

import pytest

from netlane.config import load_config


@pytest.fixture(scope="module")
def rooted(shipped_config, adb_device, create_netlane, local_listener):
    """Brings the profile up for the whole module, with listeners on both of its tunnels."""
    runner = create_netlane(shipped_config)
    runner.down("rooted", check=False)
    try:
        with (
            local_listener(8080) as proxy,
            local_listener(8081) as telemetry,
            runner.up("rooted"),
        ):
            yield SimpleNamespace(proxy=proxy, telemetry=telemetry)
    finally:
        runner.down("rooted", check=False)


def _rejected_ipv6_packets(device_exec) -> int:
    """Packet counter of the profile's IPv6 reject rule."""
    listing = device_exec("ip6tables -w -nvxL netlane").stdout
    (rule,) = [line for line in listing.splitlines() if "Reject IPv6 traffic" in line]
    return int(rule.split()[0])


@pytest.mark.integration
def test_every_rule_is_installed(rooted, shipped_config, device_exec, adb_reverse_list):
    profile = load_config(shipped_config).profiles["rooted"]
    rules = device_exec("iptables -w -S netlane; ip6tables -w -S netlane").stdout

    assert [rule.name for rule in profile.rules] == [
        "Reject IPv6 traffic",
        "Reject QUIC to force tcp",
        "Redirect HTTP(S) for the app in scope",
        "Default Route",
    ]
    for rule in profile.rules:
        assert f'--comment "{rule.name}"' in rules

    # The app rule is bound to the uid of the app's package
    assert "-m owner --uid-owner 2000" in rules

    # Both of the profile's tunnels are open
    reverse_list = adb_reverse_list()
    assert "tcp:8080 tcp:8080" in reverse_list
    assert "tcp:8081 tcp:8081" in reverse_list


@pytest.mark.integration
@pytest.mark.parametrize("port", [80, 443])
def test_app_http_and_https_are_redirected_to_proxy(rooted, device_send, remote, port):
    sent = device_send(remote.address, port)

    assert "pong" in sent.reply
    assert sent.line in rooted.proxy
    # The connection ended at the proxy, the destination never saw it.
    assert remote.peers(f"tcp/{port}", sent.payload) == []


@pytest.mark.integration
@pytest.mark.parametrize("port", [80, 443])
def test_http_and_https_of_other_apps_pass_through(rooted, device_send, remote, port):
    sent = device_send(remote.address, port, root=True)

    assert "pong" in sent.reply
    assert len(remote.peers(f"tcp/{port}", sent.payload)) == 1
    assert sent.line not in rooted.proxy


@pytest.mark.integration
@pytest.mark.parametrize("root", [False, True], ids=["app", "other"])
def test_other_tcp_traffic_passes_through(rooted, device_send, remote, root):
    sent = device_send(remote.address, 8443, root=root)

    assert "pong" in sent.reply
    assert len(remote.peers("tcp/8443", sent.payload)) == 1
    assert sent.line not in rooted.proxy


@pytest.mark.integration
@pytest.mark.parametrize("root", [False, True], ids=["app", "other"])
def test_quic_is_rejected(rooted, device_send, remote, root):
    quic = device_send(remote.address, 443, udp=True, root=root, timeout=2)
    # Sent afterwards over the same path, so the QUIC datagram had its chance to arrive.
    other = device_send(remote.address, 53, udp=True, root=root, timeout=2)

    assert len(remote.peers("udp/53", other.payload, wait=5)) == 1
    assert remote.peers("udp/443", quic.payload) == []


@pytest.mark.integration
@pytest.mark.parametrize("root", [False, True], ids=["app", "other"])
def test_ipv6_is_rejected(rooted, device_send, device_exec, root):
    before = _rejected_ipv6_packets(device_exec)
    # The device has no IPv6 route beyond its link, so a neighbour on it is addressed.
    sent = device_send("fe80::1%eth0", 80, root=root, timeout=2)

    assert sent.returncode != 0
    assert _rejected_ipv6_packets(device_exec) > before
    assert sent.line not in rooted.proxy


@pytest.mark.integration
def test_telemetry_tunnel_reaches_its_local_port(rooted, device_send):
    # No rule of the profile targets this tunnel, the device addresses it directly.
    sent = device_send("127.0.0.1", 8081)

    assert "pong" in sent.reply
    assert sent.line in rooted.telemetry
    assert sent.line not in rooted.proxy
