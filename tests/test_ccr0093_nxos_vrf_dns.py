"""CCR-0093 — NX-OS VRF-scoped DNS attribution.

`ip name-server` / `ip domain-name` / `ip domain-list` under a `vrf context NAME`
block must attribute to THAT VRF (VRFConfig.name_servers / domain_name /
domain_list) rather than being flattened into the global DNSConfig or dropped.
Global (top-level) DNS must keep landing in the global DNSConfig unchanged.

Device-verified emitted forms, Nexus 9000v NX-OS 10.5(5)
(syntax-corpus/nxos/dns-banner.yaml: global-dns-and-banner + vrf-scoped-dns,
both status verified-capture, emitted_form == typed form).
"""

from confgraph.parsers.nxos_parser import NXOSParser


def _parse(config: str):
    return NXOSParser(config).parse()


def _vrf(pc, name):
    return next((v for v in pc.vrfs if v.name == name), None)


# The exact device-verified snippet from the CCR / device fact.
_DEVICE_SNIPPET = (
    "ip domain-name example.com\n"
    "ip name-server 10.199.9.9 10.199.9.10\n"
    "vrf context management\n"
    "  ip domain-name mgmt.example.com\n"
    "  ip name-server 10.199.9.11\n"
)


class TestVRFScopedAttribution:
    """(a) VRF-scoped DNS lands on the VRF with the exact values."""

    def test_vrf_name_server_attributes_to_vrf(self):
        pc = _parse(_DEVICE_SNIPPET)
        vrf = _vrf(pc, "management")
        assert vrf is not None
        assert vrf.name_servers == ["10.199.9.11"]

    def test_vrf_domain_name_attributes_to_vrf(self):
        pc = _parse(_DEVICE_SNIPPET)
        vrf = _vrf(pc, "management")
        assert vrf is not None
        assert vrf.domain_name == "mgmt.example.com"

    def test_vrf_multiple_name_servers_on_one_line(self):
        pc = _parse(
            "vrf context CORP\n"
            "  ip name-server 10.50.0.1 10.50.0.2\n"
        )
        vrf = _vrf(pc, "CORP")
        assert vrf is not None
        assert vrf.name_servers == ["10.50.0.1", "10.50.0.2"]


class TestGlobalIsolation:
    """(b) Global DNS still lands in global DNSConfig and is NOT polluted by,
    nor does it steal, the VRF-scoped entries — isolation in both directions."""

    def test_global_dns_intact(self):
        pc = _parse(_DEVICE_SNIPPET)
        assert pc.dns is not None
        assert pc.dns.domain_name == "example.com"
        assert pc.dns.name_servers == ["10.199.9.9", "10.199.9.10"]

    def test_global_not_polluted_by_vrf_server(self):
        pc = _parse(_DEVICE_SNIPPET)
        assert pc.dns is not None
        assert "10.199.9.11" not in pc.dns.name_servers

    def test_global_domain_not_overwritten_by_vrf(self):
        pc = _parse(_DEVICE_SNIPPET)
        assert pc.dns is not None
        # global domain survives; the VRF domain does not leak up.
        assert pc.dns.domain_name == "example.com"

    def test_vrf_does_not_absorb_global_server(self):
        pc = _parse(_DEVICE_SNIPPET)
        vrf = _vrf(pc, "management")
        assert vrf is not None
        assert "10.199.9.9" not in vrf.name_servers
        assert "10.199.9.10" not in vrf.name_servers


class TestTwoVRFsKeepSeparateDNS:
    """(c) Two different VRFs keep independent DNS."""

    def test_two_vrfs_separate(self):
        pc = _parse(
            "vrf context management\n"
            "  ip domain-name mgmt.example.com\n"
            "  ip name-server 10.199.9.11\n"
            "vrf context CORP\n"
            "  ip domain-name corp.example.com\n"
            "  ip name-server 10.50.0.1 10.50.0.2\n"
        )
        mgmt = _vrf(pc, "management")
        corp = _vrf(pc, "CORP")
        assert mgmt is not None and corp is not None

        assert mgmt.domain_name == "mgmt.example.com"
        assert mgmt.name_servers == ["10.199.9.11"]

        assert corp.domain_name == "corp.example.com"
        assert corp.name_servers == ["10.50.0.1", "10.50.0.2"]

        # No cross-contamination between the two VRFs.
        assert "10.50.0.1" not in mgmt.name_servers
        assert "10.199.9.11" not in corp.name_servers
