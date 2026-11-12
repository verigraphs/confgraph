"""Route-map configuration models."""

from pydantic import BaseModel, Field
from confgraph.models.base import BaseConfigObject


class RouteMapMatch(BaseModel):
    """Route-map match clause."""

    match_type: str = Field(
        ...,
        description="Match type (e.g., 'ip address', 'ip address prefix-list', 'as-path', 'community', 'metric', 'tag')",
    )
    values: list[str] = Field(
        default_factory=list,
        description="Match values (can reference prefix-list, ACL, community-list, AS-path list)",
    )


class RouteMapSet(BaseModel):
    """Route-map set clause."""

    set_type: str = Field(
        ...,
        description="Set type (e.g., 'local-preference', 'metric', 'metric-type', 'community', 'as-path', 'next-hop', 'origin', 'weight', 'tag')",
    )
    values: list[str] = Field(
        default_factory=list,
        description="Set values",
    )


class RouteMapSequence(BaseModel):
    """Route-map sequence (entry)."""

    sequence: int = Field(..., description="Sequence number")
    action: str = Field(
        ..., description="Action ('permit' or 'deny')"
    )
    match_clauses: list[RouteMapMatch] = Field(
        default_factory=list,
        description="Match clauses (AND operation within sequence)",
    )
    set_clauses: list[RouteMapSet] = Field(
        default_factory=list,
        description="Set clauses",
    )
    continue_sequence: int | None = Field(
        default=None,
        description="Continue to sequence number after processing this entry",
    )
    continuation: str | None = Field(
        default=None,
        description=(
            "Non-terminal flow control (IOS-XR RPL). None = TERMINAL: this entry's "
            "'action' is the policy's verdict and evaluation stops — the behavior every "
            "classic route-map entry has. 'pass' = the route is marked as PASSING and "
            "evaluation CONTINUES to the next entry (RPL 'pass'). 'fallthrough' = "
            "evaluation continues with NO verdict recorded (an RPL 'if' body that ends "
            "without pass/drop/done). 'action' keeps its permit/deny meaning in every "
            "case, so a consumer that reads 'action' alone sees exactly the values it "
            "saw before this field existed and cannot misread a 'pass' as a deny."
        ),
    )
    exclusive_group: int | None = Field(
        default=None,
        description=(
            "Entries sharing a non-null value are ALTERNATIVES: at most one of them "
            "executes, and once one matches the rest of its group is skipped. Set by "
            "the IOS-XR converter for the arms of one if/elseif/else chain, whose "
            "mutual exclusivity flat first-match-wins entries cannot otherwise express "
            "once an entry is non-terminal. None = the entry stands alone."
        ),
    )
    description: str | None = Field(
        default=None,
        description="Route-map sequence description",
    )


class RouteMapConfig(BaseConfigObject):
    """Route-map configuration.

    Route-maps are used for:
    - BGP route filtering and attribute manipulation
    - OSPF redistribution filtering
    - PBR (Policy-Based Routing)
    - VRF import/export policies
    """

    name: str = Field(..., description="Route-map name")
    sequences: list[RouteMapSequence] = Field(
        default_factory=list,
        description="Route-map sequences (entries)",
    )
    untranslated_constructs: list[str] = Field(
        default_factory=list,
        description=(
            "Constructs this policy contains that the parser recognised as PRESENT but "
            "could not translate into sequences, NAMED ('apply', 'set weight', "
            "'destination in A and B'), not merely counted — a consumer's disclosure is "
            "only useful if it can say what was lost. WHITELIST semantics: the "
            "converter enumerates what it understands and everything else lands here, "
            "so an EMPTY list is a positive claim that the whole policy is represented "
            "by 'sequences'. A consumer must not let a policy with a non-empty list "
            "deny a route — the sequences are an incomplete reading of it."
        ),
    )
