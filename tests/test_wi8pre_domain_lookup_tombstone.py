"""WI-8-pre bug 3 — IOS ``no ip domain-lookup`` targeted tombstone.

CCR (platform): legacy_singleton_merge_bugs.md.

The IOS parser previously emitted the over-broad ``singleton:dns`` for
``no ip domain(-| )lookup``, wiping the ENTIRE DNS section (name servers,
domain name) when the command only disables lookups.  It now emits the
targeted action tombstone ``field:dns:lookup_disable``; the engine-side
accessor sets ``dns.lookup_enabled = False`` (NOT the model default True).

Run only these tests:
    uv run pytest tests/test_wi8pre_domain_lookup_tombstone.py
"""

from __future__ import annotations

from confgraph.parsers.ios_parser import IOSParser


class TestDomainLookupTombstone:
    def test_hyphen_form_emits_targeted_tombstone(self):
        pc = IOSParser("no ip domain-lookup\n").parse()
        assert "field:dns:lookup_disable" in pc.no_commands
        assert "singleton:dns" not in pc.no_commands

    def test_space_form_emits_targeted_tombstone(self):
        pc = IOSParser("no ip domain lookup\n").parse()
        assert "field:dns:lookup_disable" in pc.no_commands
        assert "singleton:dns" not in pc.no_commands

    def test_proposal_dns_model_also_carries_false(self):
        """The proposal-side DNSConfig carrier: parse_dns treats the line
        positively, so BOTH mechanisms (scalar merge + tombstone) agree."""
        pc = IOSParser("no ip domain-lookup\n").parse()
        assert pc.dns is not None
        assert pc.dns.lookup_enabled is False

    def test_baseline_parse_unaffected(self):
        """Full-config parsing never depended on the tombstone."""
        cfg = (
            "ip domain name corp.example.com\n"
            "ip name-server 8.8.8.8 8.8.4.4\n"
            "no ip domain-lookup\n"
        )
        pc = IOSParser(cfg).parse()
        assert pc.dns.lookup_enabled is False
        assert pc.dns.domain_name == "corp.example.com"
        assert pc.dns.name_servers == ["8.8.8.8", "8.8.4.4"]

    def test_entry_level_dns_tombstones_unchanged(self):
        pc = IOSParser(
            "no ip name-server 10.0.0.1\nno ip domain list corp.example\n"
        ).parse()
        assert "field:dns:name_server:10.0.0.1" in pc.no_commands
        assert "field:dns:domain:corp.example" in pc.no_commands


class TestChangeIRRoundTrip:
    def test_derive_ops_maps_to_unset_and_round_trips(self):
        """Ops mode consistency: the tombstone derives to an UNSET op via the
        generic ``field:<section>:<field>`` shape and encodes back
        byte-exact into no_commands."""
        from confgraph.change_ir import Verb, derive_ops, encode_legacy

        pc = IOSParser("no ip domain-lookup\n").parse()
        ops = derive_ops(pc)
        lookup_ops = [
            op for op in ops if op.path == ("field", "dns", "lookup_disable")
        ]
        assert len(lookup_ops) == 1
        assert lookup_ops[0].verb is Verb.UNSET

        artifacts = encode_legacy(ops)
        assert "field:dns:lookup_disable" in artifacts.no_commands
