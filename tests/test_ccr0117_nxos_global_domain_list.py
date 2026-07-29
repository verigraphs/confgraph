"""CCR-0117 — NX-OS global `ip domain-list` (hyphenated form) dropped.

NX-OS emits a global domain search-list as repeated hyphenated lines
`ip domain-list <domain>` (one per domain). The global DNS parser
`IOSParser.parse_dns` (inherited unchanged by `NXOSParser`) matched only the
spaced IOS spelling (`ip domain list`), so global NX-OS search-lists silently
dropped to `DNSConfig.domain_list == []`.

Fix (mirrors CCR-0093's VRF-scoped tolerance `ip\\s+domain(?:-|\\s+)list`):
broaden the GLOBAL match in `IOSParser.parse_dns` to accept hyphen OR space, so
both `ip domain-list <d>` (NX-OS) and `ip domain list <d>` (IOS) populate
`DNSConfig.domain_list` in config order. The IOS spaced form must parse
byte-identically (make-or-break regression guard), and the VRF path (CCR-0093)
must stay isolated.

Device-emitted forms:
  - hyphenated `ip domain-list <domain>`: syntax-corpus/nxos/dns-banner.yaml
    entry `domain-list` (status doc-only; emitted_form `ip domain-list <domain>`,
    one line per domain), consistent with CCR-0093's verified hyphenated VRF form.
  - spaced `ip domain list <domain>`: IOS form already exercised by the parser.
"""

from confgraph.parsers.nxos_parser import NXOSParser
from confgraph.parsers.ios_parser import IOSParser


class TestNXOSGlobalDomainListHyphenated:
    """(a) Global hyphenated `ip domain-list` populates DNSConfig.domain_list in
    config order — the exact CCR-0117 defect."""

    def test_global_hyphenated_domain_list_populated_in_order(self):
        pc = NXOSParser(
            "ip domain-list a.com\n"
            "ip domain-list b.com\n"
        ).parse()
        assert pc.dns is not None
        assert pc.dns.domain_list == ["a.com", "b.com"]

    def test_global_hyphenated_alongside_domain_name_and_server(self):
        pc = NXOSParser(
            "ip domain-name example.com\n"
            "ip domain-list a.com\n"
            "ip domain-list b.com\n"
            "ip name-server 8.8.8.8\n"
        ).parse()
        assert pc.dns is not None
        assert pc.dns.domain_name == "example.com"
        assert pc.dns.domain_list == ["a.com", "b.com"]
        assert pc.dns.name_servers == ["8.8.8.8"]


class TestIOSSpacedFormNotRegressed:
    """(b) The IOS spaced `ip domain list` form still parses — make-or-break
    regression guard for the shared IOS-family code."""

    def test_ios_spaced_domain_list_still_works(self):
        dns = IOSParser(
            "ip domain list x.com\n"
            "ip domain list y.com\n",
            os_type="ios",
        ).parse_dns()
        assert dns is not None
        assert dns.domain_list == ["x.com", "y.com"]

    def test_ios_full_dns_block_unchanged(self):
        # Spaced list + name + name-server + lookup-disable: the whole IOS DNS
        # vocabulary must survive the broadened list scan intact.
        dns = IOSParser(
            "ip domain name example.com\n"
            "ip domain list corp.example.com\n"
            "ip domain list eng.example.com\n"
            "ip name-server 8.8.8.8 8.8.4.4\n"
            "no ip domain lookup\n",
            os_type="ios",
        ).parse_dns()
        assert dns is not None
        assert dns.domain_name == "example.com"
        assert dns.domain_list == ["corp.example.com", "eng.example.com"]
        assert dns.name_servers == ["8.8.8.8", "8.8.4.4"]
        assert dns.lookup_enabled is False


class TestVRFAndGlobalIsolation:
    """(c) A VRF-scoped `ip domain-list` still attributes to the VRF (CCR-0093
    not regressed) and the global `DNSConfig.domain_list` stays clean."""

    _SNIPPET = (
        "ip domain-list global-a.com\n"
        "vrf context CORP\n"
        "  ip domain-list vrf-a.com\n"
        "  ip domain-list vrf-b.com\n"
    )

    def test_vrf_scoped_domain_list_attributes_to_vrf(self):
        pc = NXOSParser(self._SNIPPET).parse()
        vrf = next((v for v in pc.vrfs if v.name == "CORP"), None)
        assert vrf is not None
        assert vrf.domain_list == ["vrf-a.com", "vrf-b.com"]

    def test_global_domain_list_excludes_vrf_entries(self):
        pc = NXOSParser(self._SNIPPET).parse()
        assert pc.dns is not None
        assert pc.dns.domain_list == ["global-a.com"]
        assert "vrf-a.com" not in pc.dns.domain_list
        assert "vrf-b.com" not in pc.dns.domain_list
