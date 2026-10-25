"""Tests for duplicate interface stanza coalescing.

IOS allows the same interface to appear in multiple stanzas — the CLI merges
them into one running-config interface.  The parser must coalesce these into a
single InterfaceConfig per interface name.

CCR: confgraph_duplicate_interface_stanza_coalescing.md
Repro fixture: demo_files/megacorp_enterprise/configs/branch-rtr-01.txt
"""

from collections import Counter

from confgraph.parsers.ios_parser import IOSParser
from tests._ccr0110_e_helpers import iface_nc
from confgraph.parsers.nxos_parser import NXOSParser


# ---------------------------------------------------------------------------
# IOS — basic coalescing
# ---------------------------------------------------------------------------


class TestIOSDuplicateInterfaceCoalescing:

    def test_duplicate_stanzas_produce_single_interface(self):
        """Two stanzas for the same interface must parse to one InterfaceConfig."""
        cfg = (
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            " no shutdown\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " service-policy output WAN-OUT\n"
        )
        pc = IOSParser(cfg).parse()
        names = [i.name for i in pc.interfaces]
        assert names.count("GigabitEthernet1") == 1, (
            f"Expected exactly one GigabitEthernet1, got {names.count('GigabitEthernet1')}"
        )

    def test_fields_from_all_stanzas_coalesced(self):
        """Fields from both stanzas must appear on the single coalesced object."""
        cfg = (
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            " bfd interval 300 min_rx 300 multiplier 3\n"
            " no shutdown\n"
            " ip nat outside\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " service-policy output WAN-OUT\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " mpls ip\n"
        )
        pc = IOSParser(cfg).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet1")

        # From first stanza
        assert gi1.ip_address is not None, "ip_address from first stanza must survive"
        assert gi1.bfd_interval == 300, "bfd_interval from first stanza must survive"
        assert gi1.nat_direction == "outside", "nat_direction from first stanza must survive"

        # From second stanza
        assert gi1.service_policy_output == "WAN-OUT", (
            "service_policy_output from second stanza must be coalesced"
        )

        # From third stanza
        assert gi1.mpls_ip is True, "mpls_ip from third stanza must be coalesced"

    def test_later_stanza_overrides_earlier_scalar(self):
        """When two stanzas set the same scalar, the later one wins (IOS merge semantics)."""
        cfg = (
            "interface GigabitEthernet1\n"
            " description ORIGINAL\n"
            " mtu 1500\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " description UPDATED\n"
        )
        pc = IOSParser(cfg).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet1")
        assert gi1.description == "UPDATED", "Later stanza must override earlier scalar"
        assert gi1.mtu == 1500, "mtu from first stanza must survive (not overridden)"

    def test_mtu_conflict_later_stanza_wins(self):
        """When both stanzas set mtu, the later value must win (last-match semantics)."""
        cfg = (
            "interface GigabitEthernet1\n"
            " mtu 1500\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " mtu 9000\n"
        )
        pc = IOSParser(cfg).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet1")
        assert gi1.mtu == 9000, (
            f"Later stanza mtu must win; got mtu={gi1.mtu}"
        )

    def test_ip_address_conflict_later_stanza_wins(self):
        """When both stanzas set ip address, the later value must win."""
        cfg = (
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " ip address 192.168.1.1 255.255.255.0\n"
        )
        pc = IOSParser(cfg).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet1")
        assert str(gi1.ip_address.ip) == "192.168.1.1", (
            f"Later stanza ip_address must win; got {gi1.ip_address}"
        )

    def test_three_stanzas_coalesced(self):
        """Three stanzas for the same interface coalesce to one."""
        cfg = (
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " service-policy output WAN-OUT\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " mpls ip\n"
        )
        pc = IOSParser(cfg).parse()
        counts = Counter(i.name for i in pc.interfaces)
        assert counts["GigabitEthernet1"] == 1

    def test_no_commands_concatenated(self):
        """no_commands from all stanzas must be concatenated."""
        cfg = (
            "interface GigabitEthernet1\n"
            " no description\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " no ip ospf cost\n"
        )
        pc = IOSParser(cfg).parse()
        # CCR-0110 Phase E: op-primary parsers no longer populate
        # ``InterfaceConfig.no_commands`` — the coalesced deletions are carried by
        # native ChangeOps and reconstructed by the golden-pinned shim codec.
        recon = iface_nc(pc, "GigabitEthernet1")
        assert any("description" in t for t in recon), (
            "description tombstone from first stanza must survive"
        )
        assert any("ospf_cost" in t for t in recon), (
            "ospf_cost tombstone from second stanza must survive"
        )

    def test_list_fields_concatenated(self):
        """List fields (e.g. helper_addresses, secondary_ips) should union across stanzas."""
        cfg = (
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            " ip helper-address 10.0.250.1\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " ip helper-address 10.0.250.2\n"
        )
        pc = IOSParser(cfg).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet1")
        from ipaddress import IPv4Address
        helpers = gi1.helper_addresses
        assert IPv4Address("10.0.250.1") in helpers, "helper from first stanza"
        assert IPv4Address("10.0.250.2") in helpers, "helper from second stanza"

    def test_shutdown_then_no_shutdown_results_in_enabled(self):
        """Later stanza re-enabling an interface must win (the blocking review finding)."""
        cfg = (
            "interface GigabitEthernet1\n"
            " shutdown\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " no shutdown\n"
        )
        pc = IOSParser(cfg).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet1")
        assert gi1.enabled is True, (
            f"no shutdown in later stanza must re-enable; got enabled={gi1.enabled}"
        )

    def test_no_shutdown_then_shutdown_results_in_disabled(self):
        """Later stanza disabling an interface must win."""
        cfg = (
            "interface GigabitEthernet1\n"
            " no shutdown\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " shutdown\n"
        )
        pc = IOSParser(cfg).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet1")
        assert gi1.enabled is False, (
            f"shutdown in later stanza must disable; got enabled={gi1.enabled}"
        )

    def test_non_duplicated_interfaces_unaffected(self):
        """Interfaces that appear only once must not be affected."""
        cfg = (
            "interface Loopback0\n"
            " ip address 10.255.0.1 255.255.255.255\n"
            "!\n"
            "interface GigabitEthernet1\n"
            " ip address 10.0.0.1 255.255.255.252\n"
            "!\n"
            "interface GigabitEthernet2\n"
            " ip address 10.0.0.5 255.255.255.252\n"
        )
        pc = IOSParser(cfg).parse()
        counts = Counter(i.name for i in pc.interfaces)
        assert all(v == 1 for v in counts.values()), (
            f"All interfaces should appear once: {counts}"
        )


# ---------------------------------------------------------------------------
# NX-OS inherits via super() — same behavior expected
# ---------------------------------------------------------------------------


class TestNXOSDuplicateInterfaceCoalescing:

    def test_nxos_inherits_coalescing(self):
        """NX-OS inherits IOSParser.parse_interfaces — coalescing must work."""
        cfg = (
            "interface Ethernet1/1\n"
            " ip address 10.0.0.1/30\n"
            " no shutdown\n"
            "!\n"
            "interface Ethernet1/1\n"
            " service-policy output QOS-OUT\n"
        )
        pc = NXOSParser(cfg).parse()
        names = [i.name for i in pc.interfaces]
        assert names.count("Ethernet1/1") == 1


# ---------------------------------------------------------------------------
# Real-world fixture: branch-rtr-01.txt
# ---------------------------------------------------------------------------


class TestRealWorldBranchConfig:

    # Abridged branch-rtr-01.txt — three GigabitEthernet1 stanzas at different
    # points in the config, exactly as IOS would present in running-config when
    # features are configured in different sessions.
    BRANCH_CFG = (
        "hostname branch-rtr-01\n"
        "interface Loopback0\n"
        " ip address 10.255.7.1 255.255.255.255\n"
        "interface GigabitEthernet1\n"
        " description to-wan-core-01\n"
        " ip address 10.0.0.186 255.255.255.252\n"
        " bfd interval 300 min_rx 300 multiplier 3\n"
        " no shutdown\n"
        " ip nat outside\n"
        "interface GigabitEthernet0/2\n"
        " description branch-LAN\n"
        " ip address 10.50.1.1 255.255.255.0\n"
        " no shutdown\n"
        "ip access-list extended NAT-ACL\n"
        " permit ip 10.50.1.0 0.0.0.255 any\n"
        "interface GigabitEthernet1\n"
        " service-policy output WAN-OUT\n"
        "router bgp 65501\n"
        " bgp router-id 10.255.7.1\n"
        "interface Loopback1\n"
        " ip address 10.255.7.5 255.255.255.255\n"
        "interface GigabitEthernet1\n"
        " mpls ip\n"
    )

    def test_three_stanzas_coalesce_to_one(self):
        """Three GigabitEthernet1 stanzas must produce exactly one InterfaceConfig."""
        pc = IOSParser(self.BRANCH_CFG).parse()
        counts = Counter(i.name for i in pc.interfaces)
        assert counts["GigabitEthernet1"] == 1, (
            f"Expected 1 GigabitEthernet1, got {counts['GigabitEthernet1']}"
        )

    def test_all_fields_present_after_coalescing(self):
        """The coalesced object must carry fields from all three stanzas."""
        pc = IOSParser(self.BRANCH_CFG).parse()
        gi1 = next(i for i in pc.interfaces if i.name == "GigabitEthernet1")

        assert gi1.description == "to-wan-core-01", "description from stanza 1"
        assert gi1.ip_address is not None, "ip_address from stanza 1"
        assert gi1.bfd_interval == 300, "bfd_interval from stanza 1"
        assert gi1.nat_direction == "outside", "nat_direction from stanza 1"
        assert gi1.service_policy_output == "WAN-OUT", "service_policy from stanza 2"
        assert gi1.mpls_ip is True, "mpls_ip from stanza 3"

    def test_other_interfaces_unaffected(self):
        """Non-duplicated interfaces must not be affected."""
        pc = IOSParser(self.BRANCH_CFG).parse()
        counts = Counter(i.name for i in pc.interfaces)
        duplicates = {name: n for name, n in counts.items() if n > 1}
        assert not duplicates, f"Duplicate interface names: {duplicates}"
