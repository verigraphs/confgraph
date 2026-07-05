"""Parser tombstone emission for IP SLA / object-track / EEM / banner removals.

CCR: confgraph_service_entity_removal_tombstones.md (Fable-5 review, WI-8).

``no ip sla <id>``, ``no track <id>``, ``no event manager applet <name>`` and
``no banner <type>`` previously emitted NO deletion tombstone — the entity
survived the merge and removal was a simulated no-op.  These tests pin the
new entry-level walks:

  - ``no ip sla <id>``                 → ``field:ip_sla_operations:<id>``
  - ``no track <id>``                  → ``field:object_tracks:<id>``
  - ``no event manager applet <name>`` → ``field:eem_applets:<name>``
  - ``no banner motd|login|exec|incoming``
        → ``field:banners:<motd|login|exec_banner|incoming>``

Path segments are the ParsedConfig field names (the ``field:vrfs:…``
precedent) so the engine classifier attributes each removal to its coverage
area with zero classifier changes.  NX-OS and EOS inherit the walks via
``super().parse_deletion_commands()`` — spot-checked below.
"""

from __future__ import annotations

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser
from confgraph.parsers.nxos_parser import NXOSParser


def _ios_tombstones(config: str) -> list[str]:
    return IOSParser(config).parse_deletion_commands()


def _nxos_tombstones(config: str) -> list[str]:
    return NXOSParser(config).parse_deletion_commands()


def _eos_tombstones(config: str) -> list[str]:
    return EOSParser(config).parse_deletion_commands()


# ---------------------------------------------------------------------------
# IOS — IP SLA
# ---------------------------------------------------------------------------

class TestIOSIpSlaRemoval:
    def test_no_ip_sla_emits_tombstone(self):
        assert "field:ip_sla_operations:10" in _ios_tombstones("no ip sla 10\n")

    def test_no_ip_sla_schedule_is_not_entity_removal(self):
        tombs = _ios_tombstones("no ip sla schedule 10 life forever\n")
        assert not any(t.startswith("field:ip_sla_operations:") for t in tombs)

    def test_no_ip_sla_responder_is_not_entity_removal(self):
        tombs = _ios_tombstones("no ip sla responder\n")
        assert not any(t.startswith("field:ip_sla_operations:") for t in tombs)

    def test_positive_ip_sla_block_emits_no_tombstone(self):
        config = "ip sla 10\n icmp-echo 198.51.100.99\n frequency 10\n"
        tombs = _ios_tombstones(config)
        assert not any(t.startswith("field:ip_sla_operations:") for t in tombs)


# ---------------------------------------------------------------------------
# IOS — object tracking
# ---------------------------------------------------------------------------

class TestIOSTrackRemoval:
    def test_no_track_emits_tombstone(self):
        assert "field:object_tracks:1" in _ios_tombstones("no track 1\n")

    def test_positive_track_line_emits_no_tombstone(self):
        tombs = _ios_tombstones("track 1 ip sla 10 reachability\n")
        assert not any(t.startswith("field:object_tracks:") for t in tombs)

    def test_no_track_with_trailing_spec_is_not_whole_entity_removal(self):
        tombs = _ios_tombstones("no track 1 ip sla 10 reachability\n")
        assert not any(t.startswith("field:object_tracks:") for t in tombs)


# ---------------------------------------------------------------------------
# IOS — EEM applet
# ---------------------------------------------------------------------------

class TestIOSEemAppletRemoval:
    def test_no_event_manager_applet_emits_tombstone(self):
        tombs = _ios_tombstones("no event manager applet WAN-WATCHDOG\n")
        assert "field:eem_applets:WAN-WATCHDOG" in tombs

    def test_positive_applet_block_emits_no_tombstone(self):
        config = (
            "event manager applet WAN-WATCHDOG\n"
            " event track 1 state down\n"
            " action 1.0 syslog msg WAN-DOWN\n"
        )
        tombs = _ios_tombstones(config)
        assert not any(t.startswith("field:eem_applets:") for t in tombs)


# ---------------------------------------------------------------------------
# IOS — banner
# ---------------------------------------------------------------------------

class TestIOSBannerRemoval:
    def test_no_banner_motd_emits_tombstone(self):
        assert "field:banners:motd" in _ios_tombstones("no banner motd\n")

    def test_no_banner_login_emits_tombstone(self):
        assert "field:banners:login" in _ios_tombstones("no banner login\n")

    def test_no_banner_exec_maps_to_model_field_name(self):
        assert "field:banners:exec_banner" in _ios_tombstones("no banner exec\n")

    def test_no_banner_incoming_emits_tombstone(self):
        assert "field:banners:incoming" in _ios_tombstones("no banner incoming\n")

    def test_positive_banner_emits_no_tombstone(self):
        tombs = _ios_tombstones("banner motd ^Authorized access only^\n")
        assert not any(t.startswith("field:banners:") for t in tombs)


# ---------------------------------------------------------------------------
# Delete + re-add in one script = replace (no tombstone)
# ---------------------------------------------------------------------------
# The canonical device-true retarget shape (``no ip sla 1`` followed by
# ``ip sla 1 …``) must NOT tombstone: deletions apply after the additive merge
# pass, so a tombstone would clobber the re-added entity.  The keyed replace
# merge already models the replacement.

class TestDeleteThenReaddSuppressesTombstone:
    def test_ip_sla_readd_suppresses(self):
        config = (
            "no ip sla 1\n"
            "ip sla 1\n"
            " icmp-echo 192.0.2.1 source-interface GigabitEthernet0/0\n"
            " frequency 5\n"
        )
        tombs = _ios_tombstones(config)
        assert not any(t.startswith("field:ip_sla_operations:") for t in tombs)

    def test_ip_sla_readd_of_other_id_still_tombstones(self):
        config = "no ip sla 1\nip sla 2\n icmp-echo 192.0.2.1\n"
        assert "field:ip_sla_operations:1" in _ios_tombstones(config)

    def test_track_readd_suppresses(self):
        config = "no track 1\ntrack 1 ip sla 20 reachability\n"
        tombs = _ios_tombstones(config)
        assert not any(t.startswith("field:object_tracks:") for t in tombs)

    def test_eem_readd_suppresses(self):
        config = (
            "no event manager applet WAN-WATCHDOG\n"
            "event manager applet WAN-WATCHDOG\n"
            " event track 1 state down\n"
            " action 1.0 syslog msg WAN-DOWN\n"
        )
        tombs = _ios_tombstones(config)
        assert not any(t.startswith("field:eem_applets:") for t in tombs)

    def test_banner_readd_suppresses(self):
        config = "no banner motd\nbanner motd ^New text^\n"
        tombs = _ios_tombstones(config)
        assert not any(t.startswith("field:banners:") for t in tombs)

    def test_removal_after_positive_still_tombstones(self):
        """Order matters: add first, delete last → the delete wins."""
        config = (
            "ip sla 1\n"
            " icmp-echo 192.0.2.1\n"
            "no ip sla 1\n"
        )
        assert "field:ip_sla_operations:1" in _ios_tombstones(config)


# ---------------------------------------------------------------------------
# NX-OS / EOS — inherited walks (identical syntax)
# ---------------------------------------------------------------------------

class TestInheritedOSParity:
    def test_nxos_inherits_ip_sla_and_track_walks(self):
        tombs = _nxos_tombstones("no ip sla 10\nno track 1\n")
        assert "field:ip_sla_operations:10" in tombs
        assert "field:object_tracks:1" in tombs

    def test_nxos_inherits_eem_and_banner_walks(self):
        tombs = _nxos_tombstones(
            "no event manager applet WAN-WATCHDOG\nno banner motd\n"
        )
        assert "field:eem_applets:WAN-WATCHDOG" in tombs
        assert "field:banners:motd" in tombs

    def test_eos_inherits_track_and_banner_walks(self):
        tombs = _eos_tombstones("no track 1\nno banner motd\n")
        assert "field:object_tracks:1" in tombs
        assert "field:banners:motd" in tombs
