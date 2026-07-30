"""CCR-0139 — named IKE gateway + IKE crypto profile objects (PAN-OS).

Before this change the PAN-OS crypto parse threw away the names of two of the
tunnel chain's three referenced object kinds: an IKE gateway flattened into an
anonymous ``CryptoMapEntry`` (sequence number synthesized from walk order) and
an IKE crypto profile into a nameless ``IKEv1Policy`` (priority likewise
synthesized).  Only IPSec profiles kept a name.  So "the object this tunnel
depends on was deleted" was not expressible: there was no name to resolve a
reference against.

This suite pins the four things the fix has to get right:

  * the named objects exist, with the cross-references that make the chain
    walkable (gateway -> IKE crypto profile, gateway -> physical egress);
  * the anonymous forms are UNCHANGED — this is additive, their consumers were
    not part of the deal;
  * the COPY INVARIANT (CCR-0130 design review S4): a tunnel interface's
    ``tunnel_underlay_interface`` / ``tunnel_ike_crypto_profile`` are copies of
    the bound gateway's own fields, taken from that gateway object;
  * a dangling reference stays legible — the gateway keeps the profile NAME it
    points at even when no such profile object exists, which is the whole
    reason the named objects were needed.

XML shapes are the PAN-OS emitted forms recorded under ``syntax-corpus/panos``
(``ipsec.yaml``: ike-gateway, ike-gateway-local-address,
ike-gateway-peer-address, ike-gateway-ike-crypto-profile, ike-crypto-profile) —
doc-only provenance inherited from CCR-0116, SDK-cited, not device-captured.
"""

import pytest

from confgraph.models.crypto import CryptoConfig, IKECryptoProfile, IKEGateway
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.panos_parser import PANOSParser

# The CCR-0116 full-chain fixture itself (BGP -> tunnel.1 -> ipsec -> gw-branch
# -> ethernet1/1).  Imported rather than copied so an edit there is felt here.
from tests.test_ccr0116_panos_bgp_over_tunnel import FULL_CHAIN

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# FULL_CHAIN's gateway references the IKE crypto profile "default" but the
# fixture carries no crypto-profiles OBJECTS — that reference dangles (used
# below, deliberately).  This variant adds the objects so the gateway ->
# profile edge resolves.
_IKE_ANCHOR = "        <ike>\n"

_CRYPTO_PROFILES = """\
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="default">
                <encryption>
                  <member>aes-256-cbc</member>
                  <member>aes-128-cbc</member>
                </encryption>
                <hash><member>sha256</member></hash>
                <dh-group><member>group14</member></dh-group>
                <lifetime><hours>8</hours></lifetime>
              </entry>
            </ike-crypto-profiles>
            <ipsec-crypto-profiles>
              <entry name="default">
                <esp>
                  <encryption><member>aes-256-cbc</member></encryption>
                  <authentication><member>sha256</member></authentication>
                </esp>
              </entry>
            </ipsec-crypto-profiles>
          </crypto-profiles>
"""

assert FULL_CHAIN.count(_IKE_ANCHOR) == 1, "CCR-0116 fixture layout moved"
CHAIN_WITH_PROFILES = FULL_CHAIN.replace(_IKE_ANCHOR, _IKE_ANCHOR + _CRYPTO_PROFILES)

# Two gateways, one profile, no tunnels: the shape the resolver's namespace
# callables read.  gw-b's profile reference dangles; gw-b has no protocol block
# at all, so its version and profile are both absent.
GATEWAYS_ONLY = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="PROF-A">
                <encryption><member>aes-128-cbc</member></encryption>
                <hash><member>sha1</member></hash>
                <dh-group><member>group2</member></dh-group>
                <lifetime><hours>1</hours></lifetime>
              </entry>
            </ike-crypto-profiles>
          </crypto-profiles>
          <gateway>
            <entry name="gw-a">
              <local-address><interface>ethernet1/1</interface></local-address>
              <peer-address><ip>203.0.113.9</ip></peer-address>
              <protocol>
                <version>ikev2</version>
                <ikev2><ike-crypto-profile>PROF-A</ike-crypto-profile></ikev2>
              </protocol>
            </entry>
            <entry name="gw-b">
              <local-address><interface>ethernet1/2</interface></local-address>
              <peer-address><ip>203.0.113.10</ip></peer-address>
            </entry>
          </gateway>
        </ike>
      </network>
    </entry>
  </devices>
</config>
"""

# A nameless gateway entry and a nameless IKE crypto profile entry alongside
# named ones.  Not a shape a device emits (both objects are entry-keyed) — it is
# the defensive path, and what it must NOT do is invent an identity.
NAMELESS_ENTRIES = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="PROF-NAMED">
                <encryption><member>aes-128-cbc</member></encryption>
              </entry>
              <entry name="">
                <encryption><member>3des</member></encryption>
              </entry>
            </ike-crypto-profiles>
          </crypto-profiles>
          <gateway>
            <entry name="gw-named">
              <local-address><interface>ethernet1/1</interface></local-address>
            </entry>
            <entry name="">
              <local-address><interface>ethernet1/9</interface></local-address>
            </entry>
          </gateway>
        </ike>
      </network>
    </entry>
  </devices>
</config>
"""

IOS_CRYPTO = """\
hostname r1
crypto isakmp policy 10
 encryption aes
crypto ipsec transform-set TS esp-aes esp-sha-hmac
crypto map VPN 10 ipsec-isakmp
 set peer 203.0.113.9
 set transform-set TS
"""


def _crypto(xml: str) -> CryptoConfig:
    parsed = PANOSParser(xml).parse()
    assert parsed.crypto is not None, "expected a crypto section"
    return parsed.crypto


# ---------------------------------------------------------------------------
# The named objects and their cross-references
# ---------------------------------------------------------------------------

class TestNamedObjects:
    def test_gateway_is_named_with_its_egress_and_profile_reference(self):
        crypto = _crypto(CHAIN_WITH_PROFILES)

        assert [g.name for g in crypto.ike_gateways] == ["gw-branch"]
        gw = crypto.ike_gateways[0]
        assert gw.egress_interface == "ethernet1/1"
        assert gw.ike_crypto_profile == "default"
        assert gw.peer_address == "203.0.113.9"
        assert gw.ike_version == "ikev2"

    def test_ike_crypto_profile_is_named_with_its_parameters(self):
        crypto = _crypto(CHAIN_WITH_PROFILES)

        assert [p.name for p in crypto.ike_crypto_profiles] == ["default"]
        prof = crypto.ike_crypto_profiles[0]
        assert prof.encryption == "aes-256-cbc"  # first member as emitted
        assert prof.hash == "sha256"
        assert prof.group == 14  # 'group14'
        assert prof.lifetime == 8 * 3600

    def test_gateway_profile_reference_resolves_to_a_named_profile(self):
        """Edge 1 of the CCR-0130 chain: gateway -> IKE crypto profile."""
        crypto = _crypto(CHAIN_WITH_PROFILES)
        namespace = {p.name: p for p in crypto.ike_crypto_profiles}

        gw = crypto.ike_gateways[0]
        assert gw.ike_crypto_profile in namespace

    def test_gateway_egress_resolves_to_a_parsed_interface(self):
        """Edge 3 of the chain: gateway -> physical egress interface."""
        parsed = PANOSParser(CHAIN_WITH_PROFILES).parse()
        names = {i.name for i in parsed.interfaces}

        gw = parsed.crypto.ike_gateways[0]
        assert gw.egress_interface in names

    def test_two_gateways_are_both_named_and_keep_their_own_egress(self):
        crypto = _crypto(GATEWAYS_ONLY)

        by_name = {g.name: g for g in crypto.ike_gateways}
        assert set(by_name) == {"gw-a", "gw-b"}
        assert by_name["gw-a"].egress_interface == "ethernet1/1"
        assert by_name["gw-b"].egress_interface == "ethernet1/2"

    def test_gateway_without_a_protocol_block_is_still_named(self):
        """No <protocol> means no version and no profile — but the gateway
        object, its egress and its peer are all still there."""
        crypto = _crypto(GATEWAYS_ONLY)

        gw_b = next(g for g in crypto.ike_gateways if g.name == "gw-b")
        assert gw_b.ike_version is None
        assert gw_b.ike_crypto_profile is None
        assert gw_b.egress_interface == "ethernet1/2"
        assert gw_b.peer_address == "203.0.113.10"


# ---------------------------------------------------------------------------
# Dangling references — the reason the names were needed
# ---------------------------------------------------------------------------

class TestDanglingReferences:
    def test_profile_reference_survives_when_the_object_is_absent(self):
        """The CCR-0116 fixture references profile "default" and defines no
        crypto-profiles objects.  The gateway must still carry the NAME: that
        is what lets a resolver report DANGLING(default) instead of silently
        seeing nothing."""
        crypto = _crypto(FULL_CHAIN)

        assert crypto.ike_crypto_profiles == []
        gw = crypto.ike_gateways[0]
        assert gw.ike_crypto_profile == "default"
        assert gw.ike_crypto_profile not in {p.name for p in crypto.ike_crypto_profiles}

    def test_one_gateways_dangling_reference_does_not_affect_the_other(self):
        crypto = _crypto(GATEWAYS_ONLY)
        namespace = {p.name for p in crypto.ike_crypto_profiles}

        by_name = {g.name: g for g in crypto.ike_gateways}
        assert by_name["gw-a"].ike_crypto_profile in namespace
        assert by_name["gw-b"].ike_crypto_profile is None  # absent, not dangling


# ---------------------------------------------------------------------------
# Copy invariant (CCR-0130 design review S4)
# ---------------------------------------------------------------------------

class TestCopyInvariant:
    def test_interface_fields_equal_the_bound_gateways_own_fields(self):
        parsed = PANOSParser(CHAIN_WITH_PROFILES).parse()
        tun = next(i for i in parsed.interfaces if i.name == "tunnel.1")
        gw = {g.name: g for g in parsed.crypto.ike_gateways}[tun.tunnel_ike_gateway]

        assert tun.tunnel_underlay_interface == gw.egress_interface
        assert tun.tunnel_ike_crypto_profile == gw.ike_crypto_profile

    def test_invariant_holds_when_the_profile_reference_dangles(self):
        """The copies track the gateway's fields, not the resolution outcome —
        a dangling profile reference is copied verbatim, so "gateway deleted"
        (copies None, name kept) stays distinguishable from "gateway present,
        profile missing" (copies carry the missing name)."""
        parsed = PANOSParser(FULL_CHAIN).parse()
        tun = next(i for i in parsed.interfaces if i.name == "tunnel.1")
        gw = {g.name: g for g in parsed.crypto.ike_gateways}[tun.tunnel_ike_gateway]

        assert tun.tunnel_ike_crypto_profile == gw.ike_crypto_profile == "default"
        assert tun.tunnel_underlay_interface == gw.egress_interface == "ethernet1/1"


# ---------------------------------------------------------------------------
# Additive: the anonymous forms are untouched
# ---------------------------------------------------------------------------

class TestAnonymousFormsUnchanged:
    def test_flattened_gateway_row_is_unchanged(self):
        crypto = _crypto(CHAIN_WITH_PROFILES)

        assert [m.name for m in crypto.crypto_maps] == ["PANOS-IPSEC"]
        entries = crypto.crypto_maps[0].entries
        assert len(entries) == 1
        assert entries[0].sequence == 10
        assert str(entries[0].peer) == "203.0.113.9"
        assert entries[0].transform_sets == ["default"]

    def test_flattened_profile_row_is_unchanged(self):
        crypto = _crypto(CHAIN_WITH_PROFILES)

        assert len(crypto.isakmp_policies) == 1
        pol = crypto.isakmp_policies[0]
        assert pol.priority == 10  # synthesized walk-order ordinal, kept
        assert pol.encryption == "aes-256-cbc"
        assert pol.hash == "sha256"
        assert pol.group == 14
        assert pol.lifetime == 8 * 3600

    def test_ipsec_profiles_still_land_as_named_transform_sets(self):
        crypto = _crypto(CHAIN_WITH_PROFILES)

        assert [t.name for t in crypto.transform_sets] == ["default"]
        assert crypto.transform_sets[0].transforms == ["aes-256-cbc", "sha256"]

    def test_named_profile_mirrors_its_flattened_twin_field_for_field(self):
        """Both are built from one walk (design convention: one reader), so the
        four shared fields must be equal — a divergence here means the two reads
        drifted apart."""
        crypto = _crypto(CHAIN_WITH_PROFILES)
        named = crypto.ike_crypto_profiles[0]
        flat = crypto.isakmp_policies[0]

        assert (named.encryption, named.hash, named.group, named.lifetime) == (
            flat.encryption,
            flat.hash,
            flat.group,
            flat.lifetime,
        )

    def test_nameless_entries_keep_their_anonymous_rows_and_gain_no_identity(self):
        crypto = _crypto(NAMELESS_ENTRIES)

        # Both nameless entries still flatten (nothing was removed) ...
        assert len(crypto.isakmp_policies) == 2
        assert len(crypto.crypto_maps[0].entries) == 2
        # ... and neither appears among the named objects.
        assert [p.name for p in crypto.ike_crypto_profiles] == ["PROF-NAMED"]
        assert [g.name for g in crypto.ike_gateways] == ["gw-named"]


# ---------------------------------------------------------------------------
# Section-level behavior
# ---------------------------------------------------------------------------

class TestSectionBehavior:
    def test_named_objects_never_outlive_the_guard(self):
        """``parse_crypto`` returns None on "no crypto at all", tested on the
        three original lists only.  That stays correct exactly while a named
        object cannot exist without its anonymous twin — pin it here rather than
        leave it to a reader's inference."""
        for xml in (CHAIN_WITH_PROFILES, GATEWAYS_ONLY, NAMELESS_ENTRIES):
            crypto = _crypto(xml)
            if crypto.ike_gateways or crypto.ike_crypto_profiles:
                assert (
                    crypto.isakmp_policies
                    or crypto.transform_sets
                    or crypto.crypto_maps
                ), "named objects present but the guard's three lists are all empty"

    def test_a_config_with_no_crypto_at_all_still_returns_none(self):
        no_crypto = """\
<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3><ip><entry name="203.0.113.1/30"/></ip></layer3>
            </entry>
          </ethernet>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""
        assert PANOSParser(no_crypto).parse().crypto is None

    def test_non_panos_crypto_leaves_the_named_lists_empty(self):
        """The IOS family has no named IKE gateways or IKE crypto profiles (its
        ISAKMP policies are keyed by priority), so both lists stay empty and no
        IOS consumer sees a shape change."""
        parsed = IOSParser(IOS_CRYPTO).parse()

        assert parsed.crypto is not None
        assert parsed.crypto.ike_gateways == []
        assert parsed.crypto.ike_crypto_profiles == []
        # the IOS forms it does parse are untouched
        assert [p.priority for p in parsed.crypto.isakmp_policies] == [10]
        assert [t.name for t in parsed.crypto.transform_sets] == ["TS"]


# ---------------------------------------------------------------------------
# Model defaults
# ---------------------------------------------------------------------------

class TestModelDefaults:
    def test_gateway_defaults_are_all_absent(self):
        gw = IKEGateway(name="gw")
        assert (
            gw.egress_interface,
            gw.peer_address,
            gw.ike_version,
            gw.ike_crypto_profile,
        ) == (None, None, None, None)

    def test_profile_defaults_are_all_absent(self):
        prof = IKECryptoProfile(name="p")
        assert (prof.encryption, prof.hash, prof.group, prof.lifetime) == (
            None,
            None,
            None,
            None,
        )

    def test_name_is_required_on_both(self):
        for model in (IKEGateway, IKECryptoProfile):
            with pytest.raises(Exception):
                model()

    def test_crypto_config_defaults_the_new_lists_to_empty(self):
        crypto = CryptoConfig(object_id="crypto", source_os="panos")
        assert crypto.ike_gateways == []
        assert crypto.ike_crypto_profiles == []
