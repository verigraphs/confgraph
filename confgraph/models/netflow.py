"""NetFlow configuration models."""

from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class NetFlowDestination(BaseModel):
    """A single NetFlow export destination (collector)."""

    address: IPv4Address = Field(..., description="Collector IP address")
    port: int = Field(..., description="UDP port")


class NetFlowRecord(BaseModel):
    """A Flexible NetFlow ``flow record`` (NX-OS / IOS flow-record shape).

    Models::

        flow record <name>
          match ipv4 source address
          match ipv4 destination address
          collect counter bytes
          collect counter packets

    ``match`` fields are the flow key set, ``collect`` fields the non-key
    exported fields. Each is kept as the verbatim field spec with the
    leading keyword stripped (e.g. ``ipv4 source address``, ``counter
    bytes``) so the record's identity survives without inventing an enum.
    """

    name: str = Field(..., description="Flow record name")
    match_fields: list[str] = Field(
        default_factory=list,
        description="Flow key fields (the text after 'match '), in config order",
    )
    collect_fields: list[str] = Field(
        default_factory=list,
        description="Non-key collected fields (the text after 'collect '), in config order",
    )


class NetFlowExporter(BaseModel):
    """A Flexible NetFlow ``flow exporter`` (collector definition).

    Models::

        flow exporter <name>
          destination <ip> [use-vrf <vrf>]
          source <interface>
          version 9
    """

    name: str = Field(..., description="Flow exporter name")
    destination: str | None = Field(
        default=None, description="Collector destination address"
    )
    use_vrf: str | None = Field(
        default=None, description="VRF the destination is reached through (use-vrf <vrf>)"
    )
    source: str | None = Field(
        default=None, description="Source interface for exported packets"
    )
    version: int | None = Field(
        default=None, description="Export protocol version (e.g. 9)"
    )


class NetFlowMonitor(BaseModel):
    """A Flexible NetFlow ``flow monitor`` binding a record to an exporter.

    Models::

        flow monitor <name>
          record <record>
          exporter <exporter>

    The monitor is applied to an interface with ``ip flow monitor <name>
    input`` (see :class:`~confgraph.models.interface.InterfaceFlowMonitor`).
    """

    name: str = Field(..., description="Flow monitor name")
    record: str | None = Field(
        default=None, description="Bound flow record name"
    )
    exporter: str | None = Field(
        default=None, description="Bound flow exporter name"
    )


class NetFlowConfig(BaseConfigObject):
    """NetFlow export configuration (singleton per device).

    Covers classic IOS NetFlow ('ip flow-export') commands and the Flexible
    NetFlow ``flow record`` / ``flow exporter`` / ``flow monitor`` blocks
    used by NX-OS.
    """

    source_interface: str | None = Field(
        default=None,
        description="Interface used as source IP for flow export packets",
    )
    destinations: list[NetFlowDestination] = Field(
        default_factory=list,
        description="Flow export destinations (collector IP + UDP port)",
    )
    version: int | None = Field(
        default=None,
        description="NetFlow export version (5, 9, etc.)",
    )
    flow_records: list[NetFlowRecord] = Field(
        default_factory=list,
        description="Flexible NetFlow flow records (match/collect field sets)",
    )
    flow_exporters: list[NetFlowExporter] = Field(
        default_factory=list,
        description="Flexible NetFlow flow exporters (collector definitions)",
    )
    flow_monitors: list[NetFlowMonitor] = Field(
        default_factory=list,
        description="Flexible NetFlow flow monitors (record + exporter bindings)",
    )

    class Config:
        use_enum_values = True
