"""Some Units."""

from typing import ClassVar


class FileSize:
    KiB: ClassVar[int] = 1 << 10
    MiB: ClassVar[int] = 1 << 20


class DataRate:
    KBPS: ClassVar[int] = 10 ** 3
    MBPS: ClassVar[int] = 10 ** 6
    GBPS: ClassVar[int] = 10 ** 9


class Time:
    S: ClassVar[int] = 1
    MS: ClassVar[float] = 10 ** -3
