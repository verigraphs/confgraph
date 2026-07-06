"""Tests for confgraph.utils.interface normalization."""

import pytest
from confgraph.utils.interface import normalize_interface_name, canonical_to_display


# ---------------------------------------------------------------------------
# normalize_interface_name
# ---------------------------------------------------------------------------

class TestNormalizeInterfaceName:

    # --- GigabitEthernet ---
    def test_gi_abbreviation(self):
        assert normalize_interface_name("Gi0/1") == "GigabitEthernet0/1"

    def test_gig_abbreviation(self):
        assert normalize_interface_name("Gig0/1") == "GigabitEthernet0/1"

    def test_gige_abbreviation(self):
        assert normalize_interface_name("GigE0/1") == "GigabitEthernet0/1"

    def test_ge_abbreviation(self):
        assert normalize_interface_name("GE0/1") == "GigabitEthernet0/1"

    def test_gigeth_abbreviation(self):
        assert normalize_interface_name("GigEth0/1") == "GigabitEthernet0/1"

    def test_full_gigabitethernet(self):
        assert normalize_interface_name("GigabitEthernet0/0/1") == "GigabitEthernet0/0/1"

    # --- TenGigabitEthernet ---
    def test_te_abbreviation(self):
        assert normalize_interface_name("Te1/0/1") == "TenGigabitEthernet1/0/1"

    def test_tengige_abbreviation(self):
        assert normalize_interface_name("TenGigE1/1") == "TenGigabitEthernet1/1"

    def test_ten_abbreviation(self):
        assert normalize_interface_name("Ten1/0/1") == "TenGigabitEthernet1/0/1"

    def test_tenge_abbreviation(self):
        assert normalize_interface_name("TenGE1/1") == "TenGigabitEthernet1/1"

    # --- HundredGigabitEthernet ---
    def test_hu_abbreviation(self):
        assert normalize_interface_name("Hu0/0/0/1") == "HundredGigabitEthernet0/0/0/1"

    def test_hundredgig_abbreviation(self):
        assert normalize_interface_name("HundredGig0/1") == "HundredGigabitEthernet0/1"

    def test_hundredge_abbreviation(self):
        assert normalize_interface_name("HundredGE0/1") == "HundredGigabitEthernet0/1"

    # --- FortyGigabitEthernet ---
    def test_fo_abbreviation(self):
        assert normalize_interface_name("Fo1/1") == "FortyGigabitEthernet1/1"

    def test_fortygig_abbreviation(self):
        assert normalize_interface_name("FortyGig1/1") == "FortyGigabitEthernet1/1"

    # --- TwentyFiveGigE ---
    def test_twe_abbreviation(self):
        assert normalize_interface_name("Twe1/0/1") == "TwentyFiveGigE1/0/1"

    def test_twentyfivegig_abbreviation(self):
        assert normalize_interface_name("TwentyFiveGig1/1") == "TwentyFiveGigE1/1"

    # --- FastEthernet ---
    def test_fa_abbreviation(self):
        assert normalize_interface_name("Fa0/1") == "FastEthernet0/1"

    def test_fasteth_abbreviation(self):
        assert normalize_interface_name("FastEth0/1") == "FastEthernet0/1"

    # --- Ethernet (EOS / NX-OS) ---
    def test_eth_abbreviation(self):
        assert normalize_interface_name("Eth1/1") == "Ethernet1/1"

    def test_full_ethernet(self):
        assert normalize_interface_name("Ethernet1/1") == "Ethernet1/1"

    # --- Port-channel / LAG ---
    def test_po_abbreviation(self):
        assert normalize_interface_name("Po1") == "Port-channel1"

    def test_port_channel_full(self):
        assert normalize_interface_name("Port-channel1") == "Port-channel1"

    def test_port_channel_capital_c(self):
        assert normalize_interface_name("Port-Channel1") == "Port-channel1"

    def test_bundle_ether_iosxr(self):
        assert normalize_interface_name("Bundle-Ether12") == "Port-channel12"

    def test_bundle_ether_lowercase(self):
        assert normalize_interface_name("Bundle-ether12") == "Port-channel12"

    # --- Loopback ---
    def test_lo_abbreviation(self):
        assert normalize_interface_name("Lo0") == "Loopback0"

    def test_loopback_full(self):
        assert normalize_interface_name("Loopback0") == "Loopback0"

    def test_loopback_lowercase(self):
        assert normalize_interface_name("loopback0") == "Loopback0"

    # --- Management ---
    def test_ma_abbreviation(self):
        assert normalize_interface_name("Ma0/0") == "Management0/0"

    def test_mgmt_abbreviation(self):
        assert normalize_interface_name("Mgmt0") == "Management0"

    def test_mgmteth_iosxr(self):
        assert normalize_interface_name("MgmtEth0/RP0/CPU0/0") == "Management0/RP0/CPU0/0"

    # --- Vlan / SVI ---
    def test_vl_abbreviation(self):
        assert normalize_interface_name("Vl10") == "Vlan10"

    def test_vlan_full(self):
        assert normalize_interface_name("Vlan100") == "Vlan100"

    def test_bvi_iosxr(self):
        assert normalize_interface_name("BVI10") == "Vlan10"

    # --- Tunnel ---
    def test_tu_abbreviation(self):
        assert normalize_interface_name("Tu0") == "Tunnel0"

    def test_tunnel_full(self):
        assert normalize_interface_name("Tunnel1") == "Tunnel1"

    # --- Serial ---
    def test_se_abbreviation(self):
        assert normalize_interface_name("Se0/0/0") == "Serial0/0/0"

    # --- Whitespace stripping ---
    def test_leading_trailing_whitespace(self):
        assert normalize_interface_name("  Gi0/1  ") == "GigabitEthernet0/1"

    def test_empty_string(self):
        assert normalize_interface_name("") == ""

    # --- Unrecognized — return as-is ---
    def test_unrecognized_prefix(self):
        assert normalize_interface_name("Xyz0/1") == "Xyz0/1"

    # --- JunOS — unchanged ---
    def test_junos_xe(self):
        assert normalize_interface_name("xe-0/0/1") == "xe-0/0/1"

    def test_junos_et(self):
        assert normalize_interface_name("et-0/0/0") == "et-0/0/0"

    def test_junos_ge(self):
        assert normalize_interface_name("ge-0/0/3") == "ge-0/0/3"

    def test_junos_ae(self):
        assert normalize_interface_name("ae0") == "ae0"

    def test_junos_loopback(self):
        assert normalize_interface_name("lo0") == "lo0"

    def test_junos_fxp(self):
        assert normalize_interface_name("fxp0") == "fxp0"

    def test_junos_irb(self):
        assert normalize_interface_name("irb.100") == "irb.100"

    def test_junos_reth(self):
        assert normalize_interface_name("reth0") == "reth0"


# ---------------------------------------------------------------------------
# canonical_to_display
# ---------------------------------------------------------------------------

class TestCanonicalToDisplay:

    def test_gigabitethernet(self):
        assert canonical_to_display("GigabitEthernet0/1") == "Gi0/1"

    def test_tengigabitethernet(self):
        assert canonical_to_display("TenGigabitEthernet1/0/1") == "Te1/0/1"

    def test_hundredgigabitethernet(self):
        assert canonical_to_display("HundredGigabitEthernet0/0/0/1") == "Hu0/0/0/1"

    def test_fortygigabitethernet(self):
        assert canonical_to_display("FortyGigabitEthernet1/1") == "Fo1/1"

    def test_twentyfivegige(self):
        assert canonical_to_display("TwentyFiveGigE1/1") == "Twe1/1"

    def test_fastethernet(self):
        assert canonical_to_display("FastEthernet0/1") == "Fa0/1"

    def test_ethernet(self):
        assert canonical_to_display("Ethernet1/1") == "Eth1/1"

    def test_port_channel(self):
        assert canonical_to_display("Port-channel1") == "Po1"

    def test_loopback(self):
        assert canonical_to_display("Loopback0") == "Lo0"

    def test_management(self):
        assert canonical_to_display("Management0/0") == "Ma0/0"

    def test_vlan(self):
        assert canonical_to_display("Vlan100") == "Vl100"

    def test_tunnel(self):
        assert canonical_to_display("Tunnel1") == "Tu1"

    def test_serial(self):
        assert canonical_to_display("Serial0/0/0") == "Se0/0/0"

    def test_junos_xe_unchanged(self):
        assert canonical_to_display("xe-0/0/1") == "xe-0/0/1"

    def test_junos_ae_unchanged(self):
        assert canonical_to_display("ae0") == "ae0"

    def test_whitespace_stripped(self):
        assert canonical_to_display("  GigabitEthernet0/1  ") == "Gi0/1"

    # Round-trip: normalize then display
    def test_roundtrip_gi(self):
        assert canonical_to_display(normalize_interface_name("Gi0/1")) == "Gi0/1"

    def test_roundtrip_te(self):
        assert canonical_to_display(normalize_interface_name("Te1/0/1")) == "Te1/0/1"

    def test_roundtrip_bundle_ether(self):
        assert canonical_to_display(normalize_interface_name("Bundle-Ether12")) == "Po12"


# ---------------------------------------------------------------------------
# infer_interface_type — shared name→type classification
# (CCR change_ir_proposal_operations.md Phase 1: the parsers delegate here and
# the Change-IR apply path reconstructs InterfaceConfig.interface_type from it)
# ---------------------------------------------------------------------------


class TestInferInterfaceType:
    def _infer(self, name, source_os=None):
        from confgraph.utils.interface import infer_interface_type

        return infer_interface_type(name, source_os)

    def test_ios_family_rules(self):
        from confgraph.models.interface import InterfaceType

        assert self._infer("Loopback0") is InterfaceType.LOOPBACK
        assert self._infer("Port-channel10") is InterfaceType.PORTCHANNEL
        assert self._infer("Po10") is InterfaceType.PORTCHANNEL
        assert self._infer("Vlan100") is InterfaceType.SVI
        assert self._infer("Tunnel5") is InterfaceType.TUNNEL
        assert self._infer("mgmt0") is InterfaceType.MANAGEMENT
        assert self._infer("Null0") is InterfaceType.NULL
        assert self._infer("GigabitEthernet0/1") is InterfaceType.PHYSICAL

    def test_junos_rules(self):
        from confgraph.models.interface import InterfaceType

        assert self._infer("lo0", "junos") is InterfaceType.LOOPBACK
        assert self._infer("fxp0", "junos") is InterfaceType.MANAGEMENT
        assert self._infer("ae0", "junos") is InterfaceType.PORTCHANNEL
        assert self._infer("irb", "junos") is InterfaceType.SVI
        assert self._infer("st0", "junos") is InterfaceType.TUNNEL
        assert self._infer("xe-0/0/1", "junos") is InterfaceType.PHYSICAL

    def test_parser_delegation_matches_util(self):
        """The IOS parser method and the util must be the same rule set."""
        from confgraph.parsers.ios_parser import IOSParser

        parser = IOSParser("")
        for name in ("Loopback7", "Port-channel2", "Vlan300", "Tunnel1",
                     "GigabitEthernet1/0/3", "Null0", "mgmt0"):
            assert parser._determine_interface_type(name) is self._infer(name)
