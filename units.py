"""Some Units."""

from typing import ClassVar


class FileSize:
    KiB: ClassVar[int] = 1 << 10
    MiB: ClassVar[int] = 1 << 20


class DataRate:
    KBPS: ClassVar[int] = 10 ** 3
    MBPS: ClassVar[int] = 10 ** 6
    GBPS: ClassVar[int] = 10 ** 9

    @classmethod
    def from_str(cls, value: str) -> int:
        """Return DataRate unit from string."""
        mapping = {
            "KBPS": cls.KBPS,
            "MBPS": cls.MBPS,
            "GBPS": cls.GBPS,
        }
        return mapping[value.upper()]


class Time:
    S: ClassVar[int] = 1
    MS: ClassVar[float] = 10 ** -3
