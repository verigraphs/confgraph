"""CCR-0202 — three withdrawal deletion gaps that shipped silent-green (user-test F-12).

Each of the evaluator's probes produced a green "appears contained" with zero
tombstones, zero ops, zero unrecognized entries — and each gap lives in a
DIFFERENT mechanism (design-review round, 2026-09-19):

1. ``no redistribute static route-map RM-STATIC`` (IOS bgp af) — the nested
   rule existed but its $-anchored child_pattern rejected operand tails.
2. ``no network 10.30.1.0/24 area 0`` (EOS ospf) — family-6c grammar drift:
   the positive CIDR form was added to EOS without its removal twin.
3. ``no route-reflector-client`` (IOS-XR neighbor AF) — XR never wired the
   neighbor sub-mode negation hook, AND the AF-attach filter dropped any AF
   block whose only content is a boolean flag (an XR route reflector's client
   AF is exactly that), AND XR's ``parse_deletion_commands`` never traversed
   NESTED_DELETION_RULES at all (the fourth gap).

The negation surface is the native ``ChangeOp`` stream for (2) and (3)
(``ParsedConfig.native_change_ops``; no legacy twin) and the legacy
``field:`` tombstone channel for (1) (the registry's emission format).
"""

from __future__ import annotations

from confgraph.change_ir import Verb
from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.iosxr_parser import IOSXRParser


def _ops(pc, head):
    return [o for o in (pc.native_change_ops or []) if o.path and o.path[0] == head]


# ---------------------------------------------------------------------------
# Gap 1 — operand-tailed redistribute negation (nested-rule pattern)
# ---------------------------------------------------------------------------

class TestRedistributeOperandTails:
    def _tombstones(self, tail: str) -> list[str]:
        cfg = (
            "router bgp 65000\n"
            " address-family ipv4\n"
            f"  no redistribute {tail}\n"
        )
        return IOSParser(cfg, "ios").parse().no_commands

    def test_bare_form_unchanged(self):
        # The pre-CCR-0202 working form — byte-identical tombstone.
        assert self._tombstones("static") == [
            "field:bgp:65000:af:ipv4:redistribute:static:"
        ]

    def test_route_map_tail_emits_the_same_key(self):
        # The evaluator's exact probe. The tail never reaches the template,
        # so the operand-bearing form and its bare twin are one deletion.
        assert self._tombstones("static route-map RM-STATIC") == [
            "field:bgp:65000:af:ipv4:redistribute:static:"
        ]

    def test_parity_second_operand_kind_needs_no_new_code(self):
        # metric tail + pid-bearing protocol: same row, zero new code.
        assert self._tombstones("ospf 1 metric 100") == [
            "field:bgp:65000:af:ipv4:redistribute:ospf:1"
        ]
        assert self._tombstones("ospf 1 route-map RM metric 100") == [
            "field:bgp:65000:af:ipv4:redistribute:ospf:1"
        ]

    def test_unknown_tail_stays_blind(self):
        # The alternation is BOUNDED (CCR-0145 end-anchoring discipline): a
        # tail that is not route-map/metric does not match and stays blind —
        # never a mis-keyed tombstone.
        assert self._tombstones("static foo bar") == []


# ---------------------------------------------------------------------------
# Gap 2 — EOS CIDR-form OSPF network removal (family-6c grammar drift)
# ---------------------------------------------------------------------------

class TestEOSOspfCidrNetworkRemoval:
    def _parse(self, body: str):
        return EOSParser(f"router ospf 1\n{body}").parse()

    def test_cidr_removal_emits_the_family_6c_op(self):
        pc = self._parse("   no network 10.30.1.0/24 area 0\n")
        ops = [o for o in _ops(pc, "ospf_instance") if o.verb is Verb.LIST_REMOVE]
        assert [o.path for o in ops] == [
            ("ospf_instance", "1", "", "network", "10.30.1.0/24", "0")
        ]
        # Ops-only — no legacy twin, exactly like the IOS wildcard form.
        assert pc.no_commands == []

    def test_readd_later_suppresses_the_removal(self):
        # The WI-8 pattern the shared walk carries for BOTH grammars: a same
        # (cidr, area) positive AFTER the negation wins (refresh semantics).
        pc = self._parse(
            "   no network 10.30.1.0/24 area 0\n"
            "   network 10.30.1.0/24 area 0\n"
        )
        assert [o for o in _ops(pc, "ospf_instance") if o.verb is Verb.LIST_REMOVE] == []

    def test_parity_second_cidr_removal_needs_no_new_code(self):
        pc = self._parse(
            "   no network 10.30.1.0/24 area 0\n"
            "   no network 10.31.1.0/24 area 1\n"
        )
        removed = sorted(
            o.path[4:] for o in _ops(pc, "ospf_instance") if o.verb is Verb.LIST_REMOVE
        )
        assert removed == [("10.30.1.0/24", "0"), ("10.31.1.0/24", "1")]

    def test_ios_wildcard_form_is_byte_unchanged(self):
        # Regression pin for the extraction refactor: the IOS three-token walk
        # now runs through the shared helper and must emit the identical op.
        cfg = "router ospf 1\n no network 10.30.1.0 0.0.0.255 area 0\n"
        pc = IOSParser(cfg, "ios").parse()
        ops = [o for o in _ops(pc, "ospf_instance") if o.verb is Verb.LIST_REMOVE]
        assert [o.path for o in ops] == [
            ("ospf_instance", "1", "", "network", "10.30.1.0/24", "0")
        ]


# ---------------------------------------------------------------------------
# Gap 3 — IOS-XR neighbor negations (session + AF level) and the attach filter
# ---------------------------------------------------------------------------

_XR_RR_BASE = (
    "router bgp 65000\n"
    " bgp router-id 3.3.3.3\n"
    " address-family ipv4 unicast\n"
    " !\n"
    " neighbor 10.0.0.9\n"
    "  remote-as 65000\n"
    "  address-family ipv4 unicast\n"
    "   route-reflector-client\n"
    "  !\n"
    " !\n"
)


class TestXRNeighborNegations:
    def test_af_level_negation_emits_the_af_scoped_reset(self):
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.9\n"
            "  address-family ipv4 unicast\n"
            "   no route-reflector-client\n"
        )
        pc = IOSXRParser(cfg).parse()
        ops = [o for o in _ops(pc, "bgp_instance") if o.verb is Verb.UNSET]
        assert [o.path for o in ops] == [
            (
                "bgp_instance", "65000", "", "field", "neighbor", "10.0.0.9",
                "address_family", "ipv4", "unicast", "route_reflector_client",
            )
        ]

    def test_session_level_negation_flattens_like_every_other_dialect(self):
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.9\n"
            "  no next-hop-self\n"
        )
        pc = IOSXRParser(cfg).parse()
        ops = [o for o in _ops(pc, "bgp_instance") if o.verb is Verb.UNSET]
        assert [o.path for o in ops] == [
            ("bgp_instance", "65000", "", "field", "neighbor", "10.0.0.9",
             "next_hop_self")
        ]

    def test_parity_second_af_field_needs_no_new_code(self):
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.9\n"
            "  address-family ipv4 unicast\n"
            "   no next-hop-self\n"
        )
        pc = IOSXRParser(cfg).parse()
        ops = [o for o in _ops(pc, "bgp_instance") if o.verb is Verb.UNSET]
        assert [o.path[-1] for o in ops] == ["next_hop_self"]
        assert ops[0].path[6] == "address_family"


class TestXRPolicySpellingNegations:
    """Validation-round finding F2: XR's own policy spellings must not fall
    into the shared path's skip-silently tail — the positive parse maps
    route-policy→route_map_in/out and prefix-set→prefix_list_in/out, and the
    negation now mirrors it exactly."""

    def _af_unsets(self, body: str):
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.9\n"
            "  address-family ipv4 unicast\n"
            f"   {body}\n"
        )
        pc = IOSXRParser(cfg).parse()
        return [o.path for o in _ops(pc, "bgp_instance") if o.verb is Verb.UNSET]

    def test_no_route_policy_in_resets_the_af_route_map(self):
        assert self._af_unsets("no route-policy RP-IN in") == [
            ("bgp_instance", "65000", "", "field", "neighbor", "10.0.0.9",
             "address_family", "ipv4", "unicast", "route_map_in")
        ]

    def test_no_prefix_set_out_resets_the_af_prefix_list(self):
        assert self._af_unsets("no prefix-set PS-OUT out") == [
            ("bgp_instance", "65000", "", "field", "neighbor", "10.0.0.9",
             "address_family", "ipv4", "unicast", "prefix_list_out")
        ]


class TestAfScopedResetHasNoLegacyTwin:
    """Validation-round finding F1: encode_legacy must emit NOTHING for the
    AF-scoped field reset — a ``":".join`` fall-through minted a
    ``field:neighbor:…:address_family:…`` string in a vocabulary no consumer
    ever defined, entering OSS-published artifacts through the
    deprecation-window codec."""

    def test_shim_emits_nothing_for_the_af_scoped_reset(self):
        from confgraph.change_ir import derive_ops, encode_legacy_shim

        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.9\n"
            "  address-family ipv4 unicast\n"
            "   no route-reflector-client\n"
        )
        art = encode_legacy_shim(derive_ops(IOSXRParser(cfg).parse()))
        assert art.bgp_no_commands == {} or all(
            "address_family" not in t
            for ts in art.bgp_no_commands.values()
            for t in ts
        )
        assert all("address_family" not in t for t in art.no_commands)


class TestXRAfAttachFilter:
    def test_flag_only_af_block_now_attaches(self):
        # The latent drop the old value-shape heuristic caused: an XR route
        # reflector's client AF contains exactly ``route-reflector-client``,
        # and it vanished from the model — masking both baseline RR detection
        # and the CCR-0202 withdrawal.
        pc = IOSXRParser(_XR_RR_BASE).parse()
        nb = pc.bgp_instances[0].neighbors[0]
        assert [(af.afi, af.safi, af.route_reflector_client) for af in nb.address_families] == [
            ("ipv4", "unicast", True)
        ]

    def test_bare_activate_af_block_still_does_not_attach(self):
        # The CCR-0078 concern the old filter existed for — regression-pinned.
        cfg = (
            "router bgp 65000\n"
            " neighbor 10.0.0.9\n"
            "  remote-as 65000\n"
            "  address-family ipv4 unicast\n"
            "  !\n"
        )
        pc = IOSXRParser(cfg).parse()
        assert pc.bgp_instances[0].neighbors[0].address_families == []


class TestXRNestedRuleTraversal:
    def test_registry_rules_are_live_on_xr(self):
        # The fourth gap: XR's parse_deletion_commands never ran the registry.
        # An interface helper-address removal is a registry row on every other
        # OS; it must now emit on XR through the same shared traversal.
        cfg = (
            "interface GigabitEthernet0/0/0/1\n"
            " no ip helper-address 10.0.0.100\n"
        )
        pc = IOSXRParser(cfg).parse()
        removals = [
            o for o in (pc.native_change_ops or [])
            if o.verb is Verb.LIST_REMOVE and o.path[:2] == ("field", "interface")
        ]
        # Byte-identical to the IOS twin's op for the same negation — the
        # traversal is shared, so parity is by construction, and this pin
        # holds it (path head "field" comes from the registry's tombstone
        # spelling; the merger's field: channel dispatches on it).
        assert [o.path for o in removals] == [
            ("field", "interface", "GigabitEthernet0/0/0/1", "helper", "10.0.0.100")
        ]
