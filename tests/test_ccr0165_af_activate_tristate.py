"""CCR-0165 — ``BGPNeighborAF.activate`` is tri-state.

None = NOT STATED in the parsed text (EOS policy-only AF line in a snippet);
True = explicitly activated OR the OS convention where the AF block's presence
activates (NX-OS / IOS-XR / JunOS assert it themselves); False = explicitly
deactivated. The point of None: a partial-snippet restate must never merge as
a deactivation (the engine's merge convention skips proposal values equal to
the declared default).
"""

import tempfile
from pathlib import Path

import pytest

from confgraph.loader import load_and_parse
from confgraph.models.bgp import BGPNeighborAF


def _parse(text: str, os_type: str):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "dev.cfg"
        p.write_text(text, encoding="utf-8")
        res = load_and_parse(p, os_type=os_type)
        return res[0] if isinstance(res, tuple) else res


def _evpn_af(bgp_holder):
    return next(
        (a for a in bgp_holder.address_families
         if a.afi == "l2vpn" and a.safi == "evpn"),
        None,
    )


class TestModelDefault:
    def test_default_is_unstated(self):
        af = BGPNeighborAF(afi="l2vpn", safi="evpn")
        assert af.activate is None

    def test_bool_reads_unstated_as_not_activated(self):
        """Consumers read activation as bool(activate) — an unstated entry in
        a FULL config is not activated (EOS multi-agent device truth)."""
        assert bool(BGPNeighborAF(afi="l2vpn", safi="evpn").activate) is False


class TestEOSTriState:
    def test_policy_only_entry_is_unstated(self):
        """The CCR repro: a route-map attachment without an ``activate`` line
        parses activate=None, NOT False — so a merge cannot read it as a
        deactivation."""
        cfg = _parse(
            """hostname leaf2
router bgp 65102
   neighbor EVPN-OVERLAY peer group
   address-family evpn
      neighbor EVPN-OVERLAY route-map OOS-RM out
""",
            "eos",
        )
        pg = cfg.bgp_instances[0].peer_groups[0]
        af = _evpn_af(pg)
        assert af is not None
        assert af.route_map_out == "OOS-RM"
        assert af.activate is None

    def test_explicit_activate_is_true(self):
        cfg = _parse(
            """hostname leaf2
router bgp 65102
   neighbor EVPN-OVERLAY peer group
   address-family evpn
      neighbor EVPN-OVERLAY activate
""",
            "eos",
        )
        af = _evpn_af(cfg.bgp_instances[0].peer_groups[0])
        assert af.activate is True

    def test_activate_plus_policy_is_true(self):
        cfg = _parse(
            """hostname leaf2
router bgp 65102
   neighbor EVPN-OVERLAY peer group
   address-family evpn
      neighbor EVPN-OVERLAY activate
      neighbor EVPN-OVERLAY route-map OOS-RM out
""",
            "eos",
        )
        af = _evpn_af(cfg.bgp_instances[0].peer_groups[0])
        assert af.activate is True and af.route_map_out == "OOS-RM"


class TestBlockPresenceOSesAssertTrue:
    def test_nxos_af_block_presence_is_true(self):
        cfg = _parse(
            """hostname leaf1
feature bgp
router bgp 65001
  neighbor 10.1.1.2
    remote-as 65001
    address-family l2vpn evpn
      send-community extended
""",
            "nxos",
        )
        af = _evpn_af(cfg.bgp_instances[0].neighbors[0])
        assert af.activate is True

    def test_iosxr_af_block_presence_is_true(self):
        cfg = _parse(
            """hostname xr1
router bgp 65000
 neighbor 10.0.0.1
  remote-as 65001
  address-family ipv4 unicast
   route-policy RM-IN in
""",
            "iosxr",
        )
        nbr = cfg.bgp_instances[0].neighbors[0]
        af = next(a for a in nbr.address_families if a.afi == "ipv4")
        assert af.activate is True

    def test_ios_walk_distinguishes_stated_from_unstated(self):
        """Validation F1: the shared AF walk seeds UNSTATED (None); explicit
        lines state True/False. The per-OS device default (IOS ipv4
        default-on) is resolved at read time by the engine, NOT invented at
        parse time — inventing True made a policy-only proposal re-activate
        an explicitly deactivated AF."""
        cfg = _parse(
            """hostname r1
router bgp 65000
 neighbor 10.0.0.1 remote-as 65001
 neighbor 10.0.0.2 remote-as 65001
 neighbor 10.0.0.3 remote-as 65001
 address-family ipv4
  neighbor 10.0.0.1 route-map RM-IN in
  neighbor 10.0.0.2 activate
  no neighbor 10.0.0.3 activate
""",
            "ios",
        )
        by_ip = {str(n.peer_ip): n for n in cfg.bgp_instances[0].neighbors}

        def af_of(ip):
            return next((a for a in by_ip[ip].address_families
                         if a.afi == "ipv4"), None)

        policy_only = af_of("10.0.0.1")
        assert policy_only is not None               # entry must exist
        assert policy_only.activate is None          # unstated
        assert af_of("10.0.0.2").activate is True     # stated on
        assert af_of("10.0.0.3").activate is False    # stated off


class TestVocabularyInvisibleOnlyEntries:
    def test_policy_invisible_only_entry_is_not_emitted(self):
        """R2-2 (validation round 2, deliberate semantics): an AF-block peer
        whose ONLY lines are vocabulary-invisible (write no model field) no
        longer emits an empty BGPNeighborAF entry. Stricter than the old
        behavior and more truthful: on real IOS a non-default AF requires
        `neighbor X activate` before policy commands, so the dropped shapes
        are unreal configs; a real config's `activate` line keeps the entry."""
        cfg = _parse(
            """hostname r1
router bgp 65000
 neighbor 10.0.0.1 remote-as 65001
 address-family ipv6
  neighbor 10.0.0.1 soft-reconfiguration inbound
""",
            "ios",
        )
        nbr = cfg.bgp_instances[0].neighbors[0]
        assert not [a for a in nbr.address_families if a.afi == "ipv6"]

    def test_activate_alongside_keeps_the_entry(self):
        cfg = _parse(
            """hostname r1
router bgp 65000
 neighbor 10.0.0.1 remote-as 65001
 address-family ipv6
  neighbor 10.0.0.1 activate
  neighbor 10.0.0.1 soft-reconfiguration inbound
""",
            "ios",
        )
        nbr = cfg.bgp_instances[0].neighbors[0]
        af = next((a for a in nbr.address_families if a.afi == "ipv6"), None)
        assert af is not None and af.activate is True
