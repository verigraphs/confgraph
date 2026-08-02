"""CCR-0159 — NX-OS keeps remote-as-less neighbor blocks that carry content.

Proposal snippets are PARTIAL configs: an operator attaching a route-map (or
any per-AF setting) to an EXISTING neighbor legitimately omits ``remote-as``.
Before this fix the whole block silently vanished — "looks applied, isn't".
Kept blocks carry ``remote_as="inherited"``, the established stub the entrp
merge skips (non-clobbering) and topology treats as unresolved.  A truly
EMPTY bare ``neighbor <ip>`` stub is still dropped (pre-CCR behavior).
"""

import tempfile
from pathlib import Path

from confgraph.loader import load_and_parse


def _parse(text: str, os_type: str = "nxos"):
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "dev.cfg"
        p.write_text(text, encoding="utf-8")
        res = load_and_parse(p, os_type=os_type)
        return res[0] if isinstance(res, tuple) else res


class TestPolicyAttachSnippetSurvives:
    def test_af_policy_attach_without_remote_as(self):
        """THE CCR REPRO: the natural operator snippet — route-map onto an
        existing neighbor's AF, no remote-as restated."""
        pc = _parse(
            "router bgp 65001\n"
            "  neighbor 10.0.0.2\n"
            "    address-family l2vpn evpn\n"
            "      route-map RM-OUT out\n"
        )
        (nbr,) = pc.bgp_instances[0].neighbors
        assert str(nbr.peer_ip) == "10.0.0.2"
        assert nbr.remote_as == "inherited"
        af = next(a for a in nbr.address_families
                  if (a.afi, a.safi) == ("l2vpn", "evpn"))
        assert af.route_map_out == "RM-OUT"

    def test_session_level_attach_without_remote_as(self):
        """PARITY (second content kind, zero new code): a session-level
        attribute keeps the block too."""
        pc = _parse(
            "router bgp 65001\n"
            "  neighbor 10.0.0.2\n"
            "    description spine-uplink\n"
        )
        (nbr,) = pc.bgp_instances[0].neighbors
        assert nbr.remote_as == "inherited"
        assert nbr.description == "spine-uplink"

    def test_empty_stub_is_still_dropped(self):
        """NEGATIVE: a bare ``neighbor <ip>`` with no content at all keeps
        the pre-CCR drop."""
        pc = _parse(
            "router bgp 65001\n"
            "  neighbor 10.0.0.2\n"
        )
        assert pc.bgp_instances[0].neighbors == []

    def test_full_neighbor_unchanged(self):
        """REGRESSION: blocks with remote-as parse exactly as before."""
        pc = _parse(
            "router bgp 65001\n"
            "  neighbor 10.0.0.2\n"
            "    remote-as 65002\n"
            "    description spine\n"
        )
        (nbr,) = pc.bgp_instances[0].neighbors
        assert nbr.remote_as == 65002
        assert nbr.description == "spine"
