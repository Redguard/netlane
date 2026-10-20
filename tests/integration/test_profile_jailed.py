"""The jailed profile of the repository's config.toml, with traffic of a WireGuard client."""

from types import SimpleNamespace

import pytest

from netlane.config import load_config
from netlane.modes.wireguard_ssh_reverse import TABLE_NAME

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def jailed(
    shipped_config,
    setup_vps,
    create_netlane,
    wg_client,
    local_listener,
    vps_exec,
    tmp_path_factory,
):
    """Brings the profile up for the whole module, with a paired client and the proxy's listeners."""
    runner = create_netlane(shipped_config)
    client_conf_path = tmp_path_factory.mktemp("jailed") / "client.conf"
    runner.pair("jailed", save_path=client_conf_path, force=True)
    addr_res = vps_exec("ip -4 -br addr show eth0")

    with (
        wg_client(client_conf_path.read_text()) as client,
        local_listener(8080) as proxy,
        local_listener(8080, host="::1") as proxy_v6,
        runner.up("jailed"),
    ):
        yield SimpleNamespace(
            client=client,
            proxy=proxy,
            proxy_v6=proxy_v6,
            # The address the gateway's own traffic leaves from.
            gateway_address=addr_res.stdout.split()[2].partition("/")[0],
        )


def test_every_rule_is_installed(jailed, shipped_config, vps_exec):
    profile = load_config(shipped_config).profiles["jailed"]
    ruleset = vps_exec(f"nft list table inet {TABLE_NAME}").stdout

    assert [rule.name for rule in profile.rules] == [
        "Reject IPv6 traffic",
        "Reject QUIC to force tcp",
        "Redirect HTTP(S)",
        "Default Route",
    ]
    for rule in profile.rules:
        assert f'comment "{rule.name}"' in ruleset


@pytest.mark.parametrize("port", [80, 443])
def test_http_and_https_are_redirected_to_proxy(jailed, remote, port):
    sent = jailed.client.send(remote.address, port)

    assert sent.reply == "pong\n"
    assert sent.line in jailed.proxy
    # The connection ended at the proxy, the destination never saw it.
    assert remote.peers(f"tcp/{port}", sent.payload) == []


def test_quic_is_rejected(jailed, remote):
    quic = jailed.client.send(remote.address, 443, udp=True)
    # Sent afterwards over the same path, so the QUIC datagram had its chance to arrive.
    other = jailed.client.send(remote.address, 53, udp=True)

    assert len(remote.peers("udp/53", other.payload, wait=5)) == 1
    assert remote.peers("udp/443", quic.payload) == []


def test_other_tcp_traffic_passes_through(jailed, remote):
    sent = jailed.client.send(remote.address, 8443)

    # The reply only finds its way back if the gateway masqueraded the client.
    assert sent.reply == "pong\n"
    assert remote.peers("tcp/8443", sent.payload) == [jailed.gateway_address]
    assert sent.line not in jailed.proxy


def test_other_udp_traffic_passes_through(jailed, remote):
    sent = jailed.client.send(remote.address, 53, udp=True)

    assert remote.peers("udp/53", sent.payload, wait=5) == [jailed.gateway_address]


@pytest.mark.parametrize("port", [80, 443])
def test_ipv6_is_rejected(jailed, port):
    # 2001:db8::1 is unroutable (documentation prefix). Without the reject rule,
    # the HTTP(S) rule would redirect these ports to the proxy.
    sent = jailed.client.send("2001:db8::1", port)

    # Rejected at once (1) instead of running into the timeout (124).
    assert sent.returncode == 1
    assert sent.line not in jailed.proxy_v6


def test_tunnel_port_is_not_directly_reachable(jailed):
    sent = jailed.client.send("10.10.10.1", 8080, timeout=3)

    assert sent.returncode == 124
    assert sent.line not in jailed.proxy
