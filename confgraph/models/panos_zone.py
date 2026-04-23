"""PAN-OS Zone configuration model."""

from pydantic import Field
from confgraph.models.base import BaseConfigObject


class PANOSZoneConfig(BaseConfigObject):
    """PAN-OS security zone configuration.

    Zones are the fundamental security segmentation unit in PAN-OS.
    Interfaces are assigned to zones; security and NAT policies
    reference zones for match criteria.
    """

    name: str = Field(..., description="Zone name (e.g. 'trust', 'untrust')")
    vsys: str = Field(default="vsys1", description="Virtual system this zone belongs to")
    zone_type: str = Field(default="layer3", description="Zone type (layer3, layer2, tap, virtual-wire, tunnel)")
    interfaces: list[str] = Field(default_factory=list, description="Interface names assigned to this zone")
    zone_protection_profile: str | None = Field(default=None, description="Zone protection profile name")
    log_setting: str | None = Field(default=None, description="Log forwarding profile name")
    description: str | None = Field(default=None, description="Zone description")
