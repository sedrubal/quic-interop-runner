"""Some enums."""

from enum import Enum, IntFlag
from typing import Literal, Union


class PlotMode(Enum):
    """The plot type."""

    OFFSET_NUMBER = "offset-number"
    PACKET_NUMBER = "packet-number"
    FILE_SIZE = "file-size"
    PACKET_SIZE = "packet-size"
    DATA_RATE = "data-rate"
    #  SIZE_HIST = "size-hist"
    #  RTT = "rtt"


class CacheMode(Enum):
    """The mode of caching."""

    NONE = "none"
    LOAD = "load"
    STORE = "store"
    BOTH = "both"

    @property
    def load(self) -> bool:
        """Is loading enabled?"""

        return self in (CacheMode.LOAD, CacheMode.BOTH)

    @property
    def store(self) -> bool:
        """Is storing enabled?"""

        return self in (CacheMode.STORE, CacheMode.BOTH)


class Direction(Enum):
    """Packet flow direction."""

    TO_CLIENT = "to_client"
    TO_SERVER = "to_server"

    def is_opposite(self, other) -> bool:
        """Return True if the direction is the other direction than this."""

        return (self == Direction.TO_CLIENT and other == Direction.TO_SERVER) or (
            self == Direction.TO_SERVER and other == Direction.TO_CLIENT
        )


class Side(Enum):
    """The side of a trace (left=client / right=server)."""

    LEFT = "left"
    RIGHT = "right"


class PostProcessingMode(IntFlag):
    """The mode of post processing."""

    INJECT_SECRETS = 0b01
    RENAME_QLOGS = 0b10
    ALL = 0b11
    NONE = 0b00

    @classmethod
    def from_str(cls, value: str) -> "PostProcessingMode":
        """Parse from string."""
        lookup: dict[str, PostProcessingMode] = {
            flag.name.lower(): flag for flag in PostProcessingMode
        }

        return lookup[value.lower()]
