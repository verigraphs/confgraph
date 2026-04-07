"""BGP community-list and AS-path list configuration models."""

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
