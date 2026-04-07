"""Banner configuration models."""

from pydantic import Field
from confgraph.models.base import BaseConfigObject


class BannerConfig(BaseConfigObject):
    """Device banner configuration (singleton per device)."""

    motd: str | None = Field(default=None, description="Message-of-the-day banner text")
    login: str | None = Field(default=None, description="Login banner text")
    exec_banner: str | None = Field(default=None, description="Exec banner text")
    incoming: str | None = Field(default=None, description="Incoming connection banner text")

    class Config:
        use_enum_values = True
