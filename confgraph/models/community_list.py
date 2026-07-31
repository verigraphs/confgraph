"""BGP community-list, extended-community list, and AS-path list configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class CommunityListEntry(BaseModel):
    """Community-list entry."""

    action: str = Field(
        ...,
        description="Action ('permit' or 'deny')",
    )
    communities: list[str] = Field(
        default_factory=list,
        description="Community values (e.g., '65000:100', 'internet', 'no-export', 'local-AS')",
    )


class CommunityListConfig(BaseConfigObject):
    """BGP community-list configuration.

    Community-lists are used to match BGP communities in route-maps
    for filtering and policy decisions.
    """

    name: str = Field(
        ...,
        description="Community-list name or number",
    )
    list_type: str = Field(
        ...,
        description="List type ('standard', 'expanded')",
    )
    entries: list[CommunityListEntry] = Field(
        default_factory=list,
        description="Community-list entries",
    )


class ExtCommunityListEntry(BaseModel):
    """Extended-community list entry.

    A single ``permit``/``deny`` line of an ``ip extcommunity-list``.
    Standard lists carry typed extended-community VALUES (route-target /
    site-of-origin, plus NX-OS ``4byteas-generic`` and ``rmac`` forms);
    expanded lists carry a REGULAR EXPRESSION.  Each PARSED STATEMENT
    populates exactly one of ``values`` / ``regex``, decided by the
    statement's own dialect — on device-valid configs this always agrees
    with the parent list's ``list_type``, but the invariant is per-entry,
    not enforced across the parent (a device-invalid same-name-both-types
    config yields a parent holding entries of both kinds, parsed honestly).

    ``seq`` numbers (NX-OS emits them, e.g. ``seq 5``) are ACCEPTED but NOT
    STORED — deliberate data-loss disclosure: entries carry file order,
    which equals seq order in device-emitted running-config; the original
    line survives in ``raw_lines``. Matches the CommunityListEntry family
    posture.
    """

    action: str = Field(
        ...,
        description="Action ('permit' or 'deny')",
    )
    values: list[str] = Field(
        default_factory=list,
        description=(
            "Standard-list typed value specs, one per extended-community on "
            "the statement (logical AND across multiple), e.g. "
            "['rt 65001:10010', 'soo 65400:20', '4byteas-generic transitive "
            "65001:100', 'rmac 00aa.bbcc.ddee']. Empty for expanded lists."
        ),
    )
    regex: str | None = Field(
        default=None,
        description=(
            "Expanded-list regular expression matched against the "
            "extended-community string. None for standard lists."
        ),
    )


class ExtCommunityListConfig(BaseConfigObject):
    """BGP extended-community list (``ip extcommunity-list``) configuration.

    Extended-community lists match BGP extended communities (route-target /
    site-of-origin, EVPN router-MAC, generic 4-byte-AS) in route-maps
    (``match extcommunity <name>``) for filtering and policy decisions —
    the definition side of a ``match extcommunity`` clause.

    Per-OS identifier rules differ: Cisco IOS/IOS-XE lists are NUMBERED
    (standard 1-99, expanded 100-500) OR NAMED; NX-OS lists are NAMED ONLY.
    The ``standard``/``expanded`` keyword is always present on both, so
    ``list_type`` is taken from it rather than inferred from a number range.
    """

    name: str = Field(
        ...,
        description="Extended-community list name or number",
    )
    list_type: str = Field(
        ...,
        description="List type ('standard' = typed values, 'expanded' = regex)",
    )
    entries: list[ExtCommunityListEntry] = Field(
        default_factory=list,
        description="Extended-community list entries",
    )


class ASPathListEntry(BaseModel):
    """AS-path access-list entry."""

    action: str = Field(
        ...,
        description="Action ('permit' or 'deny')",
    )
    regex: str = Field(
        ...,
        description="AS-path regular expression",
    )


class ASPathListConfig(BaseConfigObject):
    """BGP AS-path access-list configuration.

    AS-path lists use regular expressions to match AS paths
    in BGP routes for filtering.
    """

    name: str = Field(
        ...,
        description="AS-path list name or number",
    )
    entries: list[ASPathListEntry] = Field(
        default_factory=list,
        description="AS-path list entries",
    )
