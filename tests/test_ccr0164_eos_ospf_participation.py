"""CCR-0164 — EOS OSPF participation is engine-invisible.

Two confgraph-side defects made an EOS device's OSPF underlay form no
adjacency:

1. The prefix-form ``network <prefix> area <id>`` statement under
   ``router ospf`` was DROPPED — the inherited IOS walk matches only the
   three-token ``network <addr> <wildcard> area <id>`` form, and EOS emits a
   two-token CIDR form. It did not even surface in ``unrecognized_blocks``
   because ``network`` is a claimed child of ``router ospf``.
2. EOS's interface ``ip ospf area <id>`` carries no process id, so the
   interface's ``ospf_process_id`` stayed None and the engine's enrollment gate
   (which requires a process id) never enrolled it.

The fix parses the prefix form into the SAME ``OSPFConfig.network_statements``
shape the IOS wildcard form fills, and — when the config has EXACTLY ONE
``router ospf`` instance — binds that single process id onto participating
interfaces.

Syntax provenance: every EOS config line here is device-emitted, per
``syntax-corpus/eos/ospf.yaml`` — ``network-area`` and ``ip-ospf-area`` (both
status verified-capture, cEOS 4.36.1F). The CIDR prefix and dotted area-id
spellings are exactly the ``example_emitted`` forms. IPs/ids are this test's
own copy.
"""

from ipaddress import IPv4Network

from confgraph.parsers.eos_parser import EOSParser
from confgraph.parsers.ios_parser import IOSParser


# cEOS 4.36.1F: a single OSPF instance with two prefix-form network statements,
# plus a loopback and a transit interface bound via the interface-level
# `ip ospf area` (the modern EOS spelling with no process id).
EOS_SINGLE_INSTANCE = """router ospf 1
   router-id 1.1.1.1
   network 10.10.2.0/24 area 0.0.0.0
   network 10.10.3.0/24 area 0.0.0.1
!
interface Loopback0
   ip address 1.1.1.1/32
   ip ospf area 0.0.0.0
!
interface Ethernet1
   ip address 10.10.2.1/24
   ip ospf area 0.0.0.0
"""


def test_prefix_form_network_statements_parsed():
    """EOS `network <prefix> area <id>` populates network_statements."""
    ospf = EOSParser(EOS_SINGLE_INSTANCE).parse_ospf()
    assert len(ospf) == 1
    stmts = ospf[0].network_statements

    # Same shape as the IOS wildcard form: (IPv4Network, area-id str).
    assert (IPv4Network("10.10.2.0/24"), "0.0.0.0") in stmts
    assert (IPv4Network("10.10.3.0/24"), "0.0.0.1") in stmts
    # Both statements land — the second `network` line is not lost.
    assert len(stmts) == 2

    # Area id captured verbatim in the dotted spelling EOS emits.
    areas = {area for _, area in stmts}
    assert areas == {"0.0.0.0", "0.0.0.1"}


def test_single_instance_binds_ospf_process_id():
    """With exactly one `router ospf`, area-only interfaces get its process id."""
    intfs = EOSParser(EOS_SINGLE_INSTANCE).parse_interfaces()
    lo0 = next(i for i in intfs if i.name == "Loopback0")
    eth1 = next(i for i in intfs if i.name == "Ethernet1")

    # ospf_area already parsed by the existing handler...
    assert lo0.ospf_area == "0.0.0.0"
    assert eth1.ospf_area == "0.0.0.0"
    # ...and now the single instance's id is bound so enrollment can gate on it.
    assert lo0.ospf_process_id == 1
    assert eth1.ospf_process_id == 1


def test_multi_instance_leaves_process_id_none():
    """Two `router ospf` instances → interface process id stays None (guard)."""
    cfg = """router ospf 1
   router-id 1.1.1.1
!
router ospf 2 vrf CUSTOMER
   router-id 2.2.2.2
!
interface Ethernet1
   ip ospf area 0.0.0.0
"""
    intfs = EOSParser(cfg).parse_interfaces()
    eth1 = next(i for i in intfs if i.name == "Ethernet1")
    assert eth1.ospf_area == "0.0.0.0"
    assert eth1.ospf_process_id is None


def test_zero_instance_leaves_process_id_none():
    """`ip ospf area` with no `router ospf` → process id stays None (guard)."""
    cfg = """interface Ethernet1
   ip ospf area 0.0.0.0
"""
    intfs = EOSParser(cfg).parse_interfaces()
    eth1 = next(i for i in intfs if i.name == "Ethernet1")
    assert eth1.ospf_area == "0.0.0.0"
    assert eth1.ospf_process_id is None


def test_ios_wildcard_form_unaffected():
    """The inherited IOS three-token network walk still parses (no regression)."""
    cfg = """router ospf 10
   network 192.168.0.0 0.0.0.255 area 0
"""
    ospf = IOSParser(cfg).parse_ospf()
    assert ospf[0].network_statements == [(IPv4Network("192.168.0.0/24"), "0")]


def test_mixed_forms_coexist():
    """A block mixing the EOS prefix form and the IOS wildcard form keeps both."""
    cfg = """router ospf 1
   network 10.10.2.0/24 area 0.0.0.0
   network 192.168.0.0 0.0.0.255 area 0.0.0.1
"""
    ospf = EOSParser(cfg).parse_ospf()
    stmts = set(ospf[0].network_statements)
    assert (IPv4Network("10.10.2.0/24"), "0.0.0.0") in stmts
    assert (IPv4Network("192.168.0.0/24"), "0.0.0.1") in stmts
    assert len(stmts) == 2
