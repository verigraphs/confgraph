"""Object-group configuration models (NX-OS / IOS-family named groups).

An object-group is a reusable, named set of addresses or ports that ACEs
reference by name (``permit ip addrgroup OG_HOSTS any``).  On NX-OS the
device emits::

    object-group ip address OG_HOSTS
      10 host 10.199.1.1
      20 10.199.2.0/24
    object-group ip port OG_PORTS
      10 eq 443

These definitions (and the members inside them) were previously dropped
entirely — ``ParsedConfig`` had no place to keep them (CCR-0086).
"""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class ObjectGroupMember(BaseModel):
    """One member line inside an object-group block."""

    sequence: int | None = Field(
        default=None,
        description="Sequence number of the member line (device-assigned)",
    )
    value: str = Field(
        ...,
        description=(
            "Member payload as emitted, sequence stripped "
            "(e.g. 'host 10.199.1.1', '10.199.2.0/24', 'eq 443')"
        ),
    )


class ObjectGroup(BaseConfigObject):
    """A named object-group and its members.

    ``group_type`` is the family/kind as emitted between ``object-group`` and
    the name (e.g. ``ip address``, ``ip port``, ``ipv6 address``).
    """

    name: str = Field(
        ...,
        description="Object-group name",
    )
    group_type: str = Field(
        ...,
        description="Group kind as emitted (e.g. 'ip address', 'ip port', 'ipv6 address')",
    )
    members: list[ObjectGroupMember] = Field(
        default_factory=list,
        description="Member entries in the group block",
    )
