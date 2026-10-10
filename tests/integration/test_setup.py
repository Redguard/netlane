import pytest


@pytest.mark.integration
def test_setup_installs_wireguard(setup_vps, vps_exec):
    res = vps_exec("which wg")
    assert res.returncode == 0
    assert "/wg" in res.stdout


@pytest.mark.integration
def test_setup_installs_conntrack(setup_vps, vps_exec):
    res = vps_exec("which conntrack")
    assert res.returncode == 0
    assert "/conntrack" in res.stdout


@pytest.mark.integration
def test_setup_enables_nftables(setup_vps, vps_exec):
    res = vps_exec("systemctl is-active nftables")
    assert res.stdout.strip() == "active"


@pytest.mark.integration
def test_setup_configures_nftables_rules(setup_vps, vps_exec):
    res = vps_exec("nft list table inet base_filter")
    assert res.returncode == 0
    assert "set trusted_ifaces" in res.stdout
    assert "chain input" in res.stdout
    assert "chain forward" in res.stdout


@pytest.mark.integration
def test_setup_configures_sshd_gatewayports(setup_vps, vps_exec):
    res = vps_exec("cat /etc/ssh/sshd_config.d/99-netlane-gatewayports.conf")
    assert res.returncode == 0
    assert "GatewayPorts clientspecified" in res.stdout


@pytest.mark.integration
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

    res_sshd = vps_exec("cat /etc/ssh/sshd_config.d/99-netlane-gatewayports.conf")
    assert res_sshd.returncode == 0
    assert "GatewayPorts clientspecified" in res_sshd.stdout
