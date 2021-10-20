"""Some utils."""
import argparse
import logging
import os
import random
import statistics
import string
import sys
import typing
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, NamedTuple, Optional, TypeVar, Union

import humanize
import requests
import termcolor
from dateutil.parser import parse as parse_date
from matplotlib import pyplot as plt
from termcolor import colored, cprint
from urllib3.util.url import Url, parse_url
from yaspin import yaspin

if typing.TYPE_CHECKING:
    from collections.abc import Iterable


#: monkey patch termcolor:
termcolor.ATTRIBUTES["italic"] = 3

T = TypeVar("T")

def random_string(length: int):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase

    return "".join(random.choice(letters) for i in range(length))


class Statistics(NamedTuple):
    """Statistics for a dataset."""

    #: The average
    avg: float
    #: The median
    med: Union[int, float]
    #: The variance
    var: float
    #: The standard deviation
    std: float
    #: The amount of values
    num: int
    #: The sum of all values
    sum: Union[int, float]
    #: The maximum
    max: Union[int, float]
    #: The minimum
    min: Union[int, float]

    def mpl_label_short(
        self,
        formatter: Callable[[Union[float, int]], str] = str,
    ) -> str:
        """:Return: A short label for matplotlib."""

        return "\n".join(
            (
                fr"$\mu = {formatter(self.avg)} \left(\pm {formatter(self.std)}\right)$",
                fr"Range: {formatter(self.min)}..{formatter(self.max)}",
            )
        )

    def mpl_label(
        self,
        formatter: Callable[[Union[float, int]], str] = str,
    ) -> str:
        """:Return: A short label for matplotlib."""

        return "\n".join(
            (
                fr"$\mu = {formatter(self.avg)}$",
                fr"$\mathrm{{median}} = {formatter(self.med)}$",
                fr"$\sigma = {formatter(self.std)}$",
                fr"Range: {formatter(self.min)}..{formatter(self.max)}",
            )
        )

    @classmethod
    def calc(cls, data: list[Union[int, float]]) -> "Statistics":
        """Calculate statistics for data."""

        return cls(
            avg=statistics.mean(data),
            med=statistics.median(data),
            var=statistics.variance(data),
            std=statistics.stdev(data),
            sum=sum(data),
            num=len(data),
            max=max(data),
            min=min(data),
        )


def map2d(func: Callable[["Iterable[T]"], T], arrays: "Iterable[Iterable[T]]") -> T:
    """Map func to arrays and to each entry of arrays."""

    return func(map(func, arrays))


def map3d(
    func: Callable[["Iterable[T]"], T],
    arrays: "Iterable[Iterable[Iterable[T]]]",
) -> T:
    def inner_func(arr):
        return map2d(func, arr)

    return func(map(inner_func, arrays))


class YaspinWrapper:
    def __init__(self, debug: bool, text: str, color: str):
        self.debug = debug
        self._text = text
        self.color = color
        self._result_set = False

        if not debug:
            self.yaspin = yaspin(text=text, color=color)

    def __enter__(self):
        if self.debug:
            self._update()
        else:
            self.yaspin.__enter__()

        return self

    def __exit__(self, err, args, traceback):
        if not self._result_set:
            if err:
                self.fail("⨯")
            else:
                self.ok("✔")

        if not self.debug:
            self.yaspin.__exit__(err, args, traceback)

    @property
    def text(self) -> str:
        if self.debug:
            return self._text
        else:
            return self.yaspin.text

    @text.setter
    def text(self, value: str):
        if self.debug:
            self._text = value
            self._update()
        else:
            self.yaspin.text = value

    def hidden(self):
        if self.debug:
            return self
        else:
            return self.yaspin.hidden()

    def _update(self):
        if self.debug:
            cprint(f"⚒ {self.text}", color=self.color, end="\r", flush=True)

    def ok(self, text: str):
        self._result_set = True

        if self.debug:
            print(text)
        else:
            self.yaspin.ok(text)

    def fail(self, text: str):
        self._result_set = True

        if self.debug:
            print(text, file=sys.stderr)
        else:
            self.yaspin.fail(text)

    def write(self, text: str):
        if self.debug:
            print(text)
            self._update()
        else:
            self.yaspin.write(text)


class HideCursor:
    def __enter__(self, *args, **kwargs):
        """hide cursor"""
        print("\x1b[?25l")

    def __exit__(self, *args, **kwargs):
        """show cursor"""
        print("\x1b[?25h")


def clear_line(**kwargs):
    """Clear current line."""
    print("\033[1K", end="\r", **kwargs)


def create_relpath(path1: Path, path2: Optional[Path] = None) -> Path:
    """Create a relative path for path1 relative to path2. TODO this is broken."""

    if not path2:
        path2 = Path(".")

    path1 = path1.absolute()
    path2 = path2.absolute()

    common_prefix = Path(os.path.commonprefix((path1, path2)))

    return Path(os.path.relpath(path1, common_prefix))


def existing_dir_path(value: str, allow_none=False) -> Optional[Path]:
    if not value or value.lower() == "none":
        if allow_none:
            return None
        else:
            raise argparse.ArgumentTypeError("`none` is not allowed here.")

    path = Path(value)

    if path.is_file():
        raise argparse.ArgumentTypeError(f"{value} is a file. A directory is required.")

    elif not path.is_dir():
        raise argparse.ArgumentTypeError(f"{value} does not exist.")

    return path


def existing_file_path(value: str, allow_none=False) -> Optional[Path]:
    if not value or value.lower() == "none":
        if allow_none:
            return None
        else:
            raise argparse.ArgumentTypeError("`none` is not allowed here.")

    path = Path(value)

    if path.is_dir():
        raise argparse.ArgumentTypeError(f"{value} is a directory. A file is required.")

    elif not path.is_file():
        raise argparse.ArgumentTypeError(f"{value} does not exist.")

    return path


class UrlOrPath:
    def __init__(self, src: Union[str, Path, Url, "UrlOrPath"]):
        if isinstance(src, UrlOrPath):
            self.src: Union[Url, Path] = src.src
        elif isinstance(src, Url):
            self.src = src
        elif isinstance(src, Path):
            self.src = src
        else:
            url = parse_url(src)

            if not url.host or not url.scheme:
                self.src = Path(src)
            else:
                self.src = url

    def __str__(self):
        return str(self.src)

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.src)})"

    @property
    def is_path(self):
        return isinstance(self.src, Path)

    def read(self, mode="r"):
        if isinstance(self.src, Path):
            with self.path.open(mode) as file:
                return file.read()
        else:
            resp = requests.get(self.src)
            resp.raise_for_status()

            return resp.text

    @property
    def scheme(self):
        return self.src.scheme if isinstance(self.src, Url) else None

    @property
    def auth(self):
        return self.src.auth if isinstance(self.src, Url) else None

    @property
    def host(self):
        return self.src.host if isinstance(self.src, Url) else None

    @property
    def port(self):
        return self.src.port if isinstance(self.src, Url) else None

    @property
    def path(self) -> Path:
        return Path(self.src.path) if isinstance(self.src, Url) else self.src

    @property
    def url(self) -> Url:
        return Url(
            scheme=self.scheme,
            auth=self.auth,
            host=self.host,
            port=self.port,
            path=str(self.path),
        )

    @property
    def parent(self) -> "UrlOrPath":
        if isinstance(self.src, Path):
            return UrlOrPath(self.path.parent)
        else:
            return UrlOrPath(
                Url(
                    scheme=self.scheme,
                    auth=self.auth,
                    host=self.host,
                    port=self.port,
                    path=str(self.path.parent),
                )
            )

    def __truediv__(self, other: Union[str, Path]) -> "UrlOrPath":
        if isinstance(self.src, Path):
            return UrlOrPath(self.path / other)
        else:
            return UrlOrPath(
                Url(
                    scheme=self.scheme,
                    auth=self.auth,
                    host=self.host,
                    port=self.port,
                    path=str(self.path / other),
                )
            )

    def __rtruediv__(self, other: Union[str, Path]) -> "UrlOrPath":
        if isinstance(self.src, Path):
            return UrlOrPath(Path(other) / self.path)
        else:
            return UrlOrPath(
                Url(
                    scheme=self.scheme,
                    auth=self.auth,
                    host=self.host,
                    port=self.port,
                    path=str(other / self.path),
                )
            )

    def is_dir(self) -> bool:
        return self.path.is_dir()

    def is_absolute(self) -> bool:
        return self.path.is_absolute()

    @property
    def name(self):
        return self.path.name

    @property
    def mtime(self) -> datetime:
        """The modification date"""

        if isinstance(self.src, Path):
            return datetime.fromtimestamp(self.path.stat().st_mtime)
        else:
            resp = requests.head(self.src)
            resp.raise_for_status()

            return parse_date(resp.headers["Last-Modified"])

    @mtime.setter
    def mtime(self, value: datetime):
        self._mtime = value


@dataclass
class TraceTriple:
    left_pcap_path: Path
    right_pcap_path: Path
    keylog_path: Optional[Path] = None

    @classmethod
    def from_str(cls, value: str) -> "TraceTriple":
        parts = value.split(":")

        if len(parts) not in (2, 3):
            raise argparse.ArgumentTypeError(
                f"{value} is not a valid triple or tuple of paths separated by :"
            )

        path0 = Path(parts[0])
        path1 = Path(parts[1])
        path2 = Path(parts[2]) if len(parts) == 3 else None

        for path in (path0, path1, path2):
            if path:
                if path.is_dir():
                    raise argparse.ArgumentTypeError(
                        f"{path} is a directory. A file is required."
                    )
                elif not path.is_file():
                    raise argparse.ArgumentTypeError(f"{path} does not exist.")

        return cls(left_pcap_path=path0, right_pcap_path=path1, keylog_path=path2)


class Subplot:
    fig: plt.Figure
    ax: plt.Axes

    def __init__(self, *args, **kwargs):
        self.fig, self.ax = plt.subplots(*args, **kwargs)

    def __enter__(self):
        return self.fig, self.ax

    def __exit__(self, *args, **kwargs):
        plt.close(fig=self.fig)


def natural_data_rate(value: int) -> str:
    """Convert a value in bps to a natural string."""
    replace_units = {
        "Bytes": "bit/s",
        "kB": "kbit/s",
        "MB": "Mbit/s",
        "GB": "Gbit/s",
        "TB": "Tbit/s",
    }
    natural_file_size = humanize.naturalsize(value, binary=False)
    natural_value, file_size_unit = natural_file_size.split(" ", 1)
    replaced_unit = replace_units[file_size_unit]

    return f"{natural_value} {replaced_unit}"


class TerminalFormatter(logging.Formatter):
    """logging formatter with colors."""

    colors = {
        logging.DEBUG: "grey",
        logging.INFO: "cyan",
        logging.WARNING: "yellow",
        logging.ERROR: "red",
        logging.CRITICAL: "red",
    }
    attrs = {
        logging.CRITICAL: ["bold"],
    }

    def __init__(self, fmt="%(asctime)s | %(message)s"):
        super().__init__(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record):
        return colored(
            super().format(record),
            color=self.colors[record.levelno],
            attrs=self.attrs.get(record.levelno),
        )
