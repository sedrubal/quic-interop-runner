#!/usr/bin/env python3

"""Plot time packet-number plots and more."""

import argparse
import json
import sys
from collections import deque
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Sequence, Union

import numpy as np
import prettytable
import seaborn as sns
from humanize.filesize import naturalsize
from matplotlib import pyplot as plt
from termcolor import colored

from enums import CacheMode, PlotMode, Side
from tango_colors import Tango
from trace_analyzer2 import ParsingError, Trace
from units import DataRate, FileSize
from utils import (
    LOGGER,
    Statistics,
    Subplot,
    TraceTriple,
    YaspinWrapper,
    create_relpath,
    natural_data_rate,
)

DEFAULT_TITLES = {
    PlotMode.OFFSET_NUMBER: "Offset vs. Time",
    PlotMode.PACKET_NUMBER: "Time vs. Packet Number",
    PlotMode.FILE_SIZE: "Transmitted Data Size vs. Time",
    PlotMode.PACKET_SIZE: "Packet Size vs. Time",
    PlotMode.DATA_RATE: "Data Rate vs. Time",
    PlotMode.RETURN_PATH: "Return Path Data Rate vs. Time",
    #  PlotMode.SIZE_HIST: "Size Histogram",
    #  PlotMode.RTT: "RTT vs. Time",
}


def parse_args():
    """Parse command line args."""
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument(
        "trace_triples",
        metavar="trace_triple",
        action="store",
        nargs="+",
        type=TraceTriple.from_str,
        help="':'-separated triples or tuples of the left pcap(ng) traces, right pcap(ng) traces and optional a keylog file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        action="store",
        type=Path,
        help="The output file.",
    )
    parser.add_argument(
        "-t",
        "--title",
        action="store",
        default=None,
        type=str,
        help="The title for the diagram.",
    )
    parser.add_argument(
        "--no-annotation",
        action="store_true",
        help="Hide TTFB, TTLB, ... markers.",
    )
    parser.add_argument(
        "--mode",
        action="store",
        choices=PlotMode,
        type=PlotMode,
        default=PlotMode.OFFSET_NUMBER,
        help="The mode of plotting (time vs. packet-number or time vs. file-size",
    )
    parser.add_argument(
        "--cache",
        action="store",
        choices=CacheMode,
        type=CacheMode,
        default=CacheMode.LOAD,
        help="Cache parsed trace (store: create caches, load: load existing caches, both: load and store caches)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode.",
    )
    parser.add_argument(
        "--ideal",
        action="store_true",
        help="Plot an ideal trace (only supported in offset vs time)",
    )
    parser.add_argument(
        "--no-shadow",
        action="store_true",
        help="Omit shadow traces",
    )

    args = parser.parse_args()

    return args


@dataclass
class TraceAnalyzeResult:
    """The result of analyzing for one trace pair."""

    __FORMAT_VERSION__ = 0

    # the extended facts of each trace (pair)
    extended_facts: dict[str, Any] = field(default_factory=dict)

    # the offset numbers of each request packet
    request_offsets: list[Optional[int]] = field(default_factory=list[Optional[int]])
    # the offset numbers of each response packet that is transmitted the first time
    response_first_offsets: list[Optional[int]] = field(
        default_factory=list[Optional[int]]
    )
    # the offset numbers of each response packet that is a retransmission
    response_retrans_offsets: list[Optional[int]] = field(
        default_factory=list[Optional[int]]
    )

    # The maximum offset value (offset + payload size).
    max_offset: int = field(default=0)

    # The timestamps of packets in `trace.request_stream_packets`
    request_stream_packet_timestamps: list[float] = field(default_factory=list[float])
    # The timestamps of packets in `trace.response_stream_packets`
    response_stream_packet_timestamps: list[float] = field(default_factory=list[float])
    # The timestamps of packets in `trace.response_stream_packets_first_tx`
    response_stream_layers_first_timestamps: list[float] = field(
        default_factory=list[float]
    )
    # The timestamps of packets in `trace.response_stream_packets_retrans`
    response_stream_layers_retrans_timestamps: list[float] = field(
        default_factory=list[float]
    )
    # The timestamps of packets in `trace.server_client_packets`
    server_client_packet_timestamps: list[float] = field(default_factory=list[float])

    # the timestamps of data rate lists
    data_rate_timestamps: Sequence[float] = field(default_factory=list[float])
    # the goodput data rates by trace
    forward_goodput_data_rates: list[float] = field(default_factory=list[float])
    # the transmission data rates by trace
    forward_tx_data_rates: list[float] = field(default_factory=list[float])
    # the return path data rates
    return_data_rates: list[float] = field(default_factory=list[float])

    # the packet numbers of packets in the return direction
    request_packet_numbers: list[int] = field(default_factory=list[int])
    # the packet numbers of packets in the forward direction
    response_packet_numbers: list[int] = field(default_factory=list[int])

    # The payload sizes of the transmitted packets in response direction
    response_transmitted_file_sizes: list[int] = field(default_factory=list[int])
    # The accumulated payload size of the transmitted packets in response direction
    response_accumulated_transmitted_file_sizes: list[int] = field(
        default_factory=list[int]
    )

    # The packet sizes of the packets in response direction
    response_packet_sizes: list[int] = field(default_factory=list[int])
    # The overhead (headers) sizes of the packets in response direction
    response_overhead_sizes: list[int] = field(default_factory=list[int])
    # TODO
    response_stream_data_sizes: list[int] = field(default_factory=list[int])

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TraceAnalyzeResult":
        format_version = data.pop("__FORMAT_VERSION__")
        assert cls.__FORMAT_VERSION__ == format_version
        ret = cls()
        ret.__dict__ = data
        return ret

    def to_json(self) -> dict[str, Any]:
        return self.__dict__

    @cached_property
    def min_timestamp(self) -> float:
        """The minimal packet timestamp we have ever seen."""
        return 0

    @cached_property
    def max_timestamp(self) -> float:
        """The maximum packet timestamp we have ever seen."""
        assert self.extended_facts
        ttlb = self.extended_facts["ttlb"] or 0
        timestamp_series = [
            self.request_stream_packet_timestamps,
            self.response_stream_packet_timestamps,
            self.response_stream_layers_first_timestamps,
            self.response_stream_layers_retrans_timestamps,
            self.server_client_packet_timestamps,
        ]

        return max(ttlb, *(ts[-1] for ts in timestamp_series if ts))

    @cached_property
    def max_forward_data_rate(self) -> float:
        """The maximum forward path data rate."""
        values = (0, *self.forward_tx_data_rates, *self.forward_goodput_data_rates)
        return max(values)

    @cached_property
    def max_return_data_rate(self) -> float:
        """The maximum return path data rate."""
        values = (0, *self.return_data_rates)
        return max(values)

    @cached_property
    def min_packet_number(self) -> int:
        """The minimum packet number."""
        return min(*self.request_packet_numbers, *self.response_packet_numbers)

    @cached_property
    def max_packet_number(self) -> int:
        """The maximum packet number."""
        return max(*self.request_packet_numbers, *self.response_packet_numbers)

    @cached_property
    def min_response_acc_file_size(self) -> int:
        """The minimum data size."""
        return min(self.response_accumulated_transmitted_file_sizes)

    @cached_property
    def max_response_acc_file_size(self) -> int:
        """The maximum data size."""
        return max(self.response_accumulated_transmitted_file_sizes)

    @cached_property
    def response_packet_stats(self) -> Statistics:
        """Some stats about response packets."""
        return Statistics.calc(self.response_packet_sizes)

    @cached_property
    def response_overhead_stats(self) -> Statistics:
        """Some stats about overhead data."""
        return Statistics.calc(self.response_overhead_sizes)

    @cached_property
    def response_stream_data_stats(self) -> Statistics:
        """Some stats about stream data."""
        return Statistics.calc(self.response_stream_data_sizes)


class PlotCli:
    """Cli for plotting."""

    def __init__(
        self,
        trace_triples: list[TraceTriple],
        title: Union[str, None] = None,
        output_file: Optional[Path] = None,
        annotate=True,
        mode: PlotMode = PlotMode.OFFSET_NUMBER,
        cache=CacheMode.BOTH,
        debug: bool = False,
        add_ideal: bool = False,
        no_shadow: bool = False,
    ):
        self.output_file: Optional[Path] = output_file
        self.title = title if title else DEFAULT_TITLES[mode] if mode else None
        self.annotate = annotate
        self.mode = mode
        self.debug = debug
        self._markersize = 1
        self.set_params(
            title=title,
            output_file=output_file,
            annotate=annotate,
            mode=mode,
        )
        self._colors = Tango(model="HTML")

        self.traces = list[Trace]()

        for trace_triple in trace_triples:
            left_trace = Trace(
                file=trace_triple.left_pcap_path,
                keylog_file=trace_triple.keylog_path,
                side=Side.LEFT,
                cache=cache,
                debug=self.debug,
            )
            right_trace = Trace(
                file=trace_triple.right_pcap_path,
                keylog_file=trace_triple.keylog_path,
                side=Side.RIGHT,
                cache=cache,
                debug=self.debug,
            )
            right_trace.pair_trace = left_trace
            self.traces.append(right_trace)

        self.print_trace_table()

        self._analyze_results = list[TraceAnalyzeResult]()
        self._median_duration_index: int = 0
        self._add_ideal = add_ideal
        self._no_shadow = no_shadow

    def analyze_traces(self):
        """Analyze the traces."""
        if self._analyze_results:
            # LOGGER.debug("already analyzed")
            return

        if not self.traces:
            breakpoint()

        last_error: Optional[ParsingError] = None
        while True:
            try:
                trace = self.traces.pop()
            except IndexError:
                break

            try:
                result = self.analyze_trace(trace)
            except ParsingError as err:
                last_error = err
                LOGGER.error(
                    "Trace %s raised an error: %s. Skipping this trace.",
                    str(trace),
                    err,
                )
                del trace
                continue

            self._analyze_results.append(result)
            # free memory
            del trace

        if not self._analyze_results and last_error:
            LOGGER.error("Every trace contains errors. We can't plot anything.")
            raise last_error

        # find index of trace with median plt
        plts = sorted(
            (r.max_timestamp - r.min_timestamp, i)
            for i, r in enumerate(self._analyze_results)
        )
        median_pos = len(plts) // 2
        _med_time_to_completion, self._median_duration_index = plts[median_pos]

    def analyze_trace(self, trace: Trace):

        cache_file = (
            trace.input_file.parent / f".{trace.input_file.stem}_analyze_cache.json"
        )
        if cache_file.is_file() and cache_file.stat().st_size > 0:
            LOGGER.debug("⚒ Loading cache from %s", cache_file)
            with cache_file.open() as file:
                try:
                    data = json.load(file)
                    return TraceAnalyzeResult.from_json(data)
                except json.JSONDecodeError as err:
                    LOGGER.error("Could not load cache: %s", err)

        assert trace.pair_trace
        trace.parse()
        trace.pair_trace.parse()

        DATA_RATE_WINDOW = 1  # 1s

        @dataclass
        class DataRateBufEntry:
            timestamp: float
            raw_data: int
            _successful_stream_data: Optional[int] = None

            @property
            def successful_stream_data(self) -> int:
                assert self._successful_stream_data is not None
                return self._successful_stream_data

        result = TraceAnalyzeResult()

        result.extended_facts = trace.extended_facts

        data_rate_timestamps = np.arange(0, trace.extended_facts["ttlb"], 0.1).tolist()
        result.data_rate_timestamps = data_rate_timestamps

        # -- offset number --

        for layer in trace.request_stream_packets:
            result.request_stream_packet_timestamps.append(layer.norm_time)

            # packet numbers
            packet_number = int(layer.packet_number)
            result.request_packet_numbers.append(packet_number)

            # offset numbers
            offset = trace.get_stream_offset(layer)
            result.request_offsets.append(offset)

            if offset is not None:
                result.max_offset = max(
                    result.max_offset, offset + trace.get_stream_length(layer)
                )

        for layer in trace.response_stream_packets:
            result.response_stream_packet_timestamps.append(layer.norm_time)

            # packet number

            packet_number = int(layer.packet_number)
            result.response_packet_numbers.append(packet_number)

            # packet sizes (only in direction of response)

            packet_size = int(layer.packet_length)
            result.response_packet_sizes.append(packet_size)
            stream_data_size = trace.get_stream_length(layer)
            result.response_stream_data_sizes.append(stream_data_size)
            result.response_overhead_sizes.append(packet_size - stream_data_size)

        for layer in trace.response_stream_packets_first_tx:
            result.response_stream_layers_first_timestamps.append(layer.norm_time)

            # offset number

            offset = trace.get_stream_offset(layer)
            result.response_first_offsets.append(offset)

            if offset is not None:
                result.max_offset = max(
                    result.max_offset, offset + trace.get_stream_length(layer)
                )

        for layer in trace.response_stream_packets_retrans:
            result.response_stream_layers_retrans_timestamps.append(layer.norm_time)

            # offset number

            offset = trace.get_stream_offset(layer)
            result.response_retrans_offsets.append(offset)
            # Do not calculate result.max_offsets in assertion that retransmitted packets are
            # not larger than previously transmitted packets

        def calc_data_rates(
            data_rate_buf: Sequence[DataRateBufEntry],
            data_rate_timestamps: Sequence[float],
            calc_goodput: bool = True,
        ):
            """Calculate data rates for data_rate_buf."""

            # rate of transmitted data
            tx_data_rates = list[float]()
            # rate of goodput data
            goodput_data_rates = list[float]()

            # marker_start is inclusive, marker_end is exclusive
            marker_start = marker_end = 0

            for timestamp in data_rate_timestamps:
                while data_rate_buf[marker_end].timestamp < timestamp:
                    if marker_end == len(data_rate_buf) - 1:
                        break
                    marker_end += 1

                while (
                    data_rate_buf[marker_start].timestamp < timestamp - DATA_RATE_WINDOW
                ):
                    if marker_start == len(data_rate_buf) - 1:
                        break
                    marker_start += 1

                buf_slice = list(data_rate_buf)[marker_start:marker_end]
                tx_data_rate = (
                    sum(entry.raw_data for entry in buf_slice) / DATA_RATE_WINDOW
                )
                tx_data_rates.append(tx_data_rate)

                if calc_goodput:
                    goodput_data_rate = (
                        sum(entry.successful_stream_data for entry in buf_slice)
                        / DATA_RATE_WINDOW
                    )
                    goodput_data_rates.append(goodput_data_rate)

            return tx_data_rates, goodput_data_rates

        # -- forward data rate --

        data_rate_buf = deque[DataRateBufEntry]()

        for packet in trace.server_client_packets:
            result.server_client_packet_timestamps.append(packet.norm_time)

            # data size (only in response direction)
            file_size = trace.get_quic_payload_size(packet)
            result.response_transmitted_file_sizes.append(file_size)
            acc_file_size = sum(result.response_transmitted_file_sizes)
            result.response_accumulated_transmitted_file_sizes.append(acc_file_size)

            # data rates

            raw_data_len = len(packet.udp.payload.binary_value)
            # goodput
            right_packet = trace.get_pair_packet(packet)

            if not right_packet:
                stream_data_len = 0
            else:
                stream_data_len = trace.pair_trace.get_quic_payload_size(right_packet)

            # *8: convert from byte to bit
            data_rate_buf.append(
                DataRateBufEntry(
                    timestamp=packet.norm_time,
                    raw_data=raw_data_len * 8,
                    _successful_stream_data=stream_data_len * 8,
                )
            )

        (
            result.forward_tx_data_rates,
            result.forward_goodput_data_rates,
        ) = calc_data_rates(data_rate_buf, data_rate_timestamps)

        # -- return path data rates --

        data_rate_buf = deque[DataRateBufEntry]()

        for packet in trace.pair_trace.client_server_packets:
            raw_data_len = len(packet.udp.payload.binary_value)

            # *8: convert from byte to bit
            data_rate_buf.append(
                DataRateBufEntry(
                    timestamp=packet.norm_time,
                    raw_data=raw_data_len * 8,
                )
            )

        # calculate data rates in direction of return path
        result.return_data_rates, _return_goodput_rates = calc_data_rates(
            data_rate_buf,
            data_rate_timestamps,
            calc_goodput=False,
        )

        LOGGER.debug("⚒ Saving cache file %s", cache_file)
        with cache_file.open("w") as file:
            json.dump(
                {
                    **result.__dict__,
                    "__FORMAT_VERSION__": result.__FORMAT_VERSION__,
                },
                file,
            )

        return result

    def set_params(
        self,
        title: Union[str, None] = None,
        output_file: Optional[Path] = None,
        annotate: Optional[bool] = None,
        mode: Optional[PlotMode] = None,
    ):
        self.output_file = output_file

        if mode is not None:
            self.title = title or DEFAULT_TITLES[mode]

        if annotate is not None:
            self.annotate = annotate

        if mode is not None:
            self.mode = mode

    @property
    def _main_analyze_result(self) -> TraceAnalyzeResult:
        """Return the analyze result with median duration (max timestamp - min timestamp)."""

        return self._analyze_results[self._median_duration_index]

    @property
    def _shadow_analyze_results(self) -> list[TraceAnalyzeResult]:
        """Return a list of analyze results that does not include `_main_analyze_result`."""

        return [
            r
            for i, r in enumerate(self._analyze_results)
            if i != self._median_duration_index
        ]

    def _vline_annotate(
        self,
        ax,
        x: Union[float, int],
        y: Union[float, int],
        text: str,
        label_side="right",
    ):
        """Annotate with vline."""
        ax.axvline(x=x, color=self._colors.ScarletRed, alpha=0.75)  # , linestyle="--"
        xoffset = 10 if label_side == "right" else -20
        ax.annotate(
            text,
            xy=(x, y),
            xytext=(xoffset, 0),
            textcoords="offset points",
            va="top",
            arrowprops=dict(
                arrowstyle="-",
                color="red",
                alpha=0.75,
            ),
            rotation=90,
            color=self._colors.ScarletRed,
            alpha=0.75,
        )

    def _vdim_annotate(
        self,
        ax,
        left: Union[int, float],
        right: Union[int, float],
        y: Union[int, float],
        text: str,
    ):
        """Add a vertical dimension."""
        ax.annotate(
            "",
            xy=(left, y),
            xytext=(right, y),
            textcoords=ax.transData,
            arrowprops=dict(
                arrowstyle="<->",
                color=self._colors.ScarletRed,
                alpha=0.75,
            ),
            color=self._colors.ScarletRed,
            alpha=0.75,
        )
        ax.annotate(
            "",
            xy=(left, y),
            xytext=(right, y),
            textcoords=ax.transData,
            arrowprops=dict(
                arrowstyle="|-|",
                color=self._colors.ScarletRed,
                alpha=0.75,
            ),
            color=self._colors.ScarletRed,
            alpha=0.75,
        )
        ax.text(
            (right + left) / 2,
            y,
            text,
            ha="center",
            va="center",
            rotation=90,
            color=self._colors.ScarletRed,
            alpha=0.75,
            bbox=dict(fc="white", ec="none"),
        )

    def _annotate_time_plot(
        self,
        ax: plt.Axes,
        height: Union[float, int],
    ):
        if not self.annotate:
            return

        if not self._main_analyze_result.extended_facts["is_http09"]:
            LOGGER.warning(
                "⨯ Can't annotate plot, because HTTP could not be parsed.",
            )

            return

        ttfb = self._main_analyze_result.extended_facts["ttfb"]
        req_start = self._main_analyze_result.extended_facts["request_start"]
        ttlb = self._main_analyze_result.extended_facts["ttlb"]
        resp_delay = self._main_analyze_result.extended_facts["response_delay"]
        first_resp_tx_time = self._main_analyze_result.extended_facts[
            "first_response_send_time"
        ]
        last_resp_tx_time = self._main_analyze_result.extended_facts[
            "last_response_send_time"
        ]

        for text, value, label_side in (
            (
                "Req. Start = {value:.3f} s",
                req_start,
                "left",
            ),
            (
                "TTFB = {value:.3f} s",
                ttfb,
                "right",
            ),
            (
                "Last Resp. TX = {value:.3f} s",
                last_resp_tx_time,
                "left",
            ),
            (
                "TTLB = {value:.3f} s",
                ttlb,
                "right",
            ),
        ):
            if value is None:
                # value was not calculated
                continue
            text = text.format(value=value)
            self._vline_annotate(
                ax=ax,
                x=value,
                y=height / 2,
                text=text,
                label_side=label_side,
            )

        ax.annotate(  # type: ignore
            f"1st Resp. TX = {first_resp_tx_time:.3f} s",
            xy=(first_resp_tx_time, 0),
            xytext=(-30, -20),
            textcoords="offset points",
            va="top",
            arrowprops=dict(
                arrowstyle="->",
                color="red",
                alpha=0.5,
            ),
            color=self._colors.ScarletRed,
            alpha=0.75,
        )

        if req_start is not None and ttfb is not None and resp_delay is not None:
            self._vdim_annotate(
                ax=ax,
                left=req_start,
                right=ttfb,
                y=height * 3 / 4,
                text=f"{resp_delay * 1000:.0f} ms",
            )
        if last_resp_tx_time is not None and ttlb is not None:
            end_ts = ttlb - last_resp_tx_time
            self._vdim_annotate(
                ax=ax,
                left=last_resp_tx_time,
                right=ttlb,
                y=height * 3 / 4,
                text=f"{end_ts * 1000:.0f} ms",
            )

    def plot_offset_number(self, fig, ax):
        """Plot the offset number diagram."""

        sns.set_theme(style="whitegrid")
        ax.grid(True)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Offset")
        assert self.title
        ax.set_title(self.title)
        ax.yaxis.set_major_formatter(lambda val, _pos: naturalsize(val, binary=True))

        min_offset: int = 0
        max_offset: int = max(r.max_offset for r in self._analyze_results)

        ax.set_xlim(
            left=min(0, *(r.min_timestamp for r in self._analyze_results)),
            right=max(r.max_timestamp for r in self._analyze_results),
        )
        ax.set_ylim(bottom=min_offset, top=max_offset * 1.01)
        ax.set_yticks(np.arange(0, max_offset * 1.1, 1 * FileSize.MiB))

        # plot shadow traces (request and response separated)

        if not self._no_shadow:
            for trace_timestamps, trace_offsets in zip(
                (
                    r.request_stream_packet_timestamps
                    for r in self._shadow_analyze_results
                ),
                (r.request_offsets for r in self._shadow_analyze_results),
            ):
                sns.scatterplot(
                    x=trace_timestamps,
                    y=trace_offsets,
                    ax=ax,
                    marker=".",
                    # linestyle="",
                    color=self._colors.aluminium4,
                    size=self._markersize,
                    edgecolor="none",
                    legend=None,
                )

            for (
                trace_first_timestamps,
                trace_first_offsets,
                trace_retrans_timestamps,
                trace_retrans_offsets,
            ) in zip(
                (
                    r.response_stream_layers_first_timestamps
                    for r in self._shadow_analyze_results
                ),
                (r.response_first_offsets for r in self._shadow_analyze_results),
                (
                    r.response_stream_layers_retrans_timestamps
                    for r in self._shadow_analyze_results
                ),
                (r.response_retrans_offsets for r in self._shadow_analyze_results),
            ):
                sns.scatterplot(
                    x=(*trace_first_timestamps, *trace_retrans_timestamps),
                    y=(*trace_first_offsets, *trace_retrans_offsets),
                    ax=ax,
                    marker=".",
                    # linestyle="",
                    color=self._colors.aluminium4,
                    size=self._markersize,
                    edgecolor="none",
                    legend=None,
                )

        # plot main trace (request and response separated)

        sns.scatterplot(
            x=self._main_analyze_result.request_stream_packet_timestamps,
            y=self._main_analyze_result.request_offsets,
            ax=ax,
            marker="o",
            # linestyle="",
            color=self._colors.Chameleon,
            size=self._markersize,
            edgecolor="none",
            legend=None,
        )
        sns.scatterplot(
            x=self._main_analyze_result.response_stream_layers_first_timestamps,
            y=self._main_analyze_result.response_first_offsets,
            ax=ax,
            marker="o",
            # linestyle="",
            color=self._colors.SkyBlue,
            size=self._markersize,
            edgecolor="none",
            legend=None,
        )
        sns.scatterplot(
            x=self._main_analyze_result.response_stream_layers_retrans_timestamps,
            y=self._main_analyze_result.response_retrans_offsets,
            ax=ax,
            marker="o",
            # linestyle="",
            color=self._colors.Orange,
            size=self._markersize * 2,
            edgecolor="none",
            legend=None,
        )

        if self._add_ideal:
            # plot an ideal trace
            ideal_start = self._main_analyze_result.extended_facts[
                "first_response_send_time"
            ]
            LOGGER.info("Assuming file size = 10 MiB, data rate = 20 mbps")
            file_size_byte = self._main_analyze_result.max_offset
            # file_size_byte = 10 * FileSize.MiB
            file_size_bit = file_size_byte * 8
            max_data_rate = 20 * DataRate.MBPS
            ideal_last_tx = ideal_start + file_size_bit / max_data_rate
            ideal_ttlb = ideal_last_tx + self._main_analyze_result.extended_facts.get(
                "rtt", 300
            )
            sns.lineplot(
                x=[ideal_start, ideal_last_tx],
                y=[0, file_size_byte],
                ax=ax,
                color=self._colors.DarkChameleon,
                # linestyle="--",
                label="ideal trace",
            )
            ax.axvline(
                x=ideal_last_tx,
                color=self._colors.DarkChameleon,
                alpha=0.75,
                linestyle="dotted",
            )
            ax.axvline(
                x=ideal_ttlb,
                color=self._colors.DarkChameleon,
                alpha=0.75,
                linestyle="dotted",
            )
            ax.annotate(
                f"ideal TTLB = {ideal_ttlb:.3f} s",
                xy=(ideal_ttlb, file_size_byte),
                xytext=(12, 0),
                textcoords="offset points",
                va="top",
                arrowprops=dict(
                    arrowstyle="-",
                    color=self._colors.DarkChameleon,
                    alpha=0.75,
                ),
                rotation=90,
                color=self._colors.DarkChameleon,
                alpha=0.75,
            )

        self._annotate_time_plot(ax, height=max_offset)

    def plot_data_rate(self, fig, ax):
        """Plot the data rate plot."""

        sns.set_theme(style="whitegrid")
        ax.grid(True)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Data Rate")
        assert self.title
        ax.set_title(self.title)
        ax.yaxis.set_major_formatter(lambda val, _pos: natural_data_rate(val))

        max_forward_data_rate = max(
            r.max_forward_data_rate for r in self._analyze_results
        )

        ax.set_xlim(
            left=min(0, *(r.min_timestamp for r in self._analyze_results)),
            right=max(r.max_timestamp for r in self._analyze_results),
        )
        ax.set_ylim(bottom=0, top=max_forward_data_rate)
        #  ax.set_yticks(np.arange(0, max_offset * 1.1, 1 * FileSize.MiB))

        # plot shadow traces (request and response separated)

        for trace_timestamps, trace_goodput in zip(
            (r.data_rate_timestamps for r in self._shadow_analyze_results),
            (r.forward_goodput_data_rates for r in self._shadow_analyze_results),
        ):
            sns.lineplot(
                x=trace_timestamps,
                y=trace_goodput,
                ax=ax,
                # marker="o",
                linestyle="--",
                color=self._colors.aluminium4,
                size=self._markersize,
                legend=None,
            )

        # plot main trace

        sns.lineplot(
            x=self._main_analyze_result.data_rate_timestamps,
            y=self._main_analyze_result.forward_goodput_data_rates,
            ax=ax,
            label=r"Goodput (recv'd payload rate delayed by $\frac{-RTT}{2}$)",
            #  marker="o",
            linestyle="--",
            color=self._colors.orange1,
            size=self._markersize,
            legend=None,
        )
        sns.lineplot(
            x=self._main_analyze_result.data_rate_timestamps,
            y=self._main_analyze_result.forward_tx_data_rates,
            ax=ax,
            label="Data Rate of Transmitted Packets",
            #  marker="o",
            linestyle="--",
            color=self._colors.orange3,
            size=self._markersize,
            legend=None,
        )
        ax.legend(fontsize=8)
        # ax.legend(loc="upper left", fontsize=8)

        self._annotate_time_plot(ax, height=max_forward_data_rate)

    def plot_return_path(self, fig, ax):
        """Plot the return path utilization."""

        ax.grid(True)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Data Rate (Return Path)")
        assert self.title
        ax.set_title(self.title)
        ax.yaxis.set_major_formatter(lambda val, _pos: natural_data_rate(val))
        ax.set_xlim(
            left=min(0, *(r.min_timestamp for r in self._analyze_results)),
            right=max(r.max_timestamp for r in self._analyze_results),
        )
        max_return_data_rate = max(
            r.max_return_data_rate for r in self._analyze_results
        )
        ax.set_ylim(bottom=0, top=max_return_data_rate)
        # ax.set_yticks(np.arange(0, max_return_data_rate * 1.1, 1 * FileSize.MiB))

        # plot shadow traces (request and response separated)

        if not self._no_shadow:
            for trace_timestamps, trace_goodput in zip(
                (r.data_rate_timestamps for r in self._shadow_analyze_results),
                (r.return_data_rates for r in self._shadow_analyze_results),
            ):
                ax.plot(
                    trace_timestamps,
                    trace_goodput,
                    #  marker="o",
                    linestyle="--",
                    color=self._colors.aluminium4,
                    markersize=self._markersize,
                )

        # plot main trace

        ax.plot(
            self._main_analyze_result.data_rate_timestamps,
            self._main_analyze_result.return_data_rates,
            label=r"Data Rate in Return Path",
            #  marker="o",
            linestyle="--",
            color=self._colors.orange1,
            markersize=self._markersize,
        )

        self._annotate_time_plot(ax, height=max_return_data_rate)

    def plot_packet_number(self, fig, ax):
        """Plot the packet number diagram."""
        ax.grid(True)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Packet Number")
        assert self.title
        ax.set_title(self.title)

        min_packet_number = min(r.min_packet_number for r in self._analyze_results)
        max_packet_number = max(r.max_packet_number for r in self._analyze_results)

        ax.set_xlim(
            left=min(0, *(r.min_timestamp for r in self._analyze_results)),
            right=max(r.max_timestamp for r in self._analyze_results),
        )
        ax.set_ylim(bottom=min(0, min_packet_number), top=max_packet_number)

        # plot shadow traces (request and response separated)

        if not self._no_shadow:
            for trace_timestamps, trace_packet_numbers in zip(
                (
                    r.request_stream_packet_timestamps
                    for r in self._shadow_analyze_results
                ),
                (r.request_packet_numbers for r in self._shadow_analyze_results),
            ):
                ax.plot(
                    trace_timestamps,
                    trace_packet_numbers,
                    marker=".",
                    linestyle="",
                    color=self._colors.aluminium4,
                    markersize=self._markersize,
                )

            for trace_timestamps, trace_packet_numbers in zip(
                (
                    r.response_stream_packet_timestamps
                    for r in self._shadow_analyze_results
                ),
                (r.response_packet_numbers for r in self._shadow_analyze_results),
            ):
                ax.plot(
                    trace_timestamps,
                    trace_packet_numbers,
                    marker=".",
                    linestyle="",
                    color=self._colors.aluminium4,
                    markersize=self._markersize,
                )

        # plot main trace (request and response separated)

        ax.plot(
            self._main_analyze_result.request_stream_packet_timestamps,
            self._main_analyze_result.request_packet_numbers,
            marker="o",
            linestyle="",
            color=self._colors.Plum,
            markersize=self._markersize,
        )
        ax.plot(
            self._main_analyze_result.response_stream_packet_timestamps,
            self._main_analyze_result.response_packet_numbers,
            marker="o",
            linestyle="",
            color=self._colors.SkyBlue,
            markersize=self._markersize,
        )

        self._annotate_time_plot(ax, height=max_packet_number)
        # spinner.write(f"rtt: {self._main_analyze_result.extended_facts.get('rtt')}")

    def plot_data_size(self, fig, ax):
        """Plot the data size diagram."""

        sns.set_theme(style="whitegrid")
        ax.grid(True)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Transmitted Data Size")
        assert self.title
        ax.set_title(self.title)
        ax.yaxis.set_major_formatter(lambda val, _pos: naturalsize(val, binary=True))

        min_response_acc_file_size = min(
            r.min_response_acc_file_size for r in self._analyze_results
        )
        max_response_acc_file_size = max(
            r.max_response_acc_file_size for r in self._analyze_results
        )

        ax.set_xlim(
            left=min(0, *(r.min_timestamp for r in self._analyze_results)),
            right=max(r.max_timestamp for r in self._analyze_results),
        )
        ax.set_ylim(
            bottom=min(0, min_response_acc_file_size),
            top=max_response_acc_file_size,
        )
        ax.set_yticks(np.arange(0, max_response_acc_file_size * 1.1, 1 * FileSize.MiB))

        # plot shadow traces

        if not self._no_shadow:
            for trace_timestamps, trace_file_sizes in zip(
                (
                    r.server_client_packet_timestamps
                    for r in self._shadow_analyze_results
                ),
                (
                    r.response_accumulated_transmitted_file_sizes
                    for r in self._shadow_analyze_results
                ),
            ):
                sns.scatterplot(
                    x=trace_timestamps,
                    y=trace_file_sizes,
                    ax=ax,
                    marker=".",
                    # linestyle="",
                    color=self._colors.aluminium4,
                    size=self._markersize,
                    edgecolor="none",
                    legend=None,
                )

        # plot main trace

        sns.scatterplot(
            x=self._main_analyze_result.server_client_packet_timestamps,
            y=self._main_analyze_result.response_accumulated_transmitted_file_sizes,
            ax=ax,
            marker="o",
            # linestyle="",
            color=self._colors.SkyBlue,
            size=self._markersize,
            edgecolor="none",
            legend=None,
        )

        self._annotate_time_plot(ax, height=max_response_acc_file_size)

    def plot_packet_size(self, fig, ax):
        """Plot the packet size diagram."""
        ax.grid(True)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Packet Size")
        assert self.title
        ax.set_title(self.title)
        ax.yaxis.set_major_formatter(lambda val, _pos: naturalsize(val, binary=True))

        min_timestamp = min(self._main_analyze_result.response_stream_packet_timestamps)
        max_timestamp = max(self._main_analyze_result.response_stream_packet_timestamps)

        ax.set_xlim(left=min(0, min_timestamp), right=max_timestamp)
        #  ax.set_ylim(bottom=0, top=packet_stats.max)
        #  ax.set_yticks(np.arange(0, packet_stats.max * 1.1, 1024))

        # no shadow traces here
        # plot main trace
        ax.stackplot(
            self._main_analyze_result.response_stream_packet_timestamps,
            (
                self._main_analyze_result.response_stream_data_sizes,
                self._main_analyze_result.response_overhead_sizes,
            ),
            colors=(
                self._colors.skyblue1,
                self._colors.plum1,
            ),
            edgecolor=(
                self._colors.skyblue3,
                self._colors.plum3,
            ),
            labels=(
                "Stream Data Size",
                "Overhead Size",
            ),
            baseline="zero",
            step="pre",
        )
        ax.legend(loc="upper left")

        assert self._main_analyze_result.response_packet_stats
        assert self._main_analyze_result.response_stream_data_stats
        assert self._main_analyze_result.response_overhead_stats

        ax.text(
            0.95,
            0.05,
            "\n".join(
                (
                    "Packet Statistics",
                    self._main_analyze_result.response_packet_stats.mpl_label_short(
                        naturalsize
                    ),
                    "\n Stream Data Statistics",
                    self._main_analyze_result.response_stream_data_stats.mpl_label_short(
                        naturalsize
                    ),
                    "\n Overhead Statistics",
                    self._main_analyze_result.response_overhead_stats.mpl_label_short(
                        naturalsize
                    ),
                )
            ),
            transform=ax.transAxes,
            fontsize=12,
            verticalalignment="bottom",
            horizontalalignment="right",
            bbox=dict(
                boxstyle="round",
                facecolor=self._colors.chocolate1,
                edgecolor=self._colors.chocolate3,
                alpha=0.75,
            ),
        )

        self._annotate_time_plot(
            ax,
            height=self._main_analyze_result.response_packet_stats.max,
        )

    #  def plot_packet_hist(self, output_file: Optional[Path]):
    #      """Plot the packet size histogram."""
    #      with Subplot(ncols=3) as (fig, axs):
    #          assert self.title
    #
    #          for ax in axs:
    #              ax.grid(True)
    #              ax.set_xlabel("Size")
    #              ax.set_ylabel("Amount of Packets")
    #              ax.xaxis.set_major_formatter(
    #                  lambda val, _pos: naturalsize(val, binary=True)
    #              )
    #
    #          with YaspinWrapper(
    #              debug=self.debug, text="processing...", color="cyan"
    #          ) as spinner:
    #              (
    #                  packet_sizes,
    #                  overhead_sizes,
    #                  stream_data_sizes,
    #                  _timestamps,
    #                  _max_timestamp,
    #                  _min_timestamp,
    #                  packet_stats,
    #                  overhead_stats,
    #                  stream_data_stats,
    #              ) = self._process_packet_sizes()
    #
    #          with YaspinWrapper(
    #              debug=self.debug, text="plotting...", color="cyan"
    #          ) as spinner:
    #              fig.suptitle(f"{self.title}\n{packet_stats.num} Packets")
    #              n_bins = 100
    #
    #              axs[0].set_title("Overall Packet Size")
    #              axs[0].hist(
    #                  packet_sizes,
    #                  bins=n_bins,
    #                  color=self._colors.Plum,
    #              )
    #              axs[0].text(
    #                  0.5,
    #                  0.5,
    #                  packet_stats.mpl_label(naturalsize),
    #                  transform=axs[0].transAxes,
    #                  fontsize=10,
    #                  verticalalignment="center",
    #                  horizontalalignment="center",
    #                  bbox=dict(
    #                      boxstyle="round",
    #                      facecolor=self._colors.chocolate1,
    #                      edgecolor=self._colors.chocolate3,
    #                      alpha=0.75,
    #                  ),
    #              )
    #
    #              axs[1].set_title("Overhead Size")
    #              axs[1].hist(
    #                  overhead_sizes,
    #                  bins=n_bins,
    #                  color=self._colors.ScarletRed,
    #              )
    #              axs[1].text(
    #                  0.5,
    #                  0.5,
    #                  stream_data_stats.mpl_label(naturalsize),
    #                  transform=axs[1].transAxes,
    #                  fontsize=10,
    #                  verticalalignment="center",
    #                  horizontalalignment="center",
    #                  bbox=dict(
    #                      boxstyle="round",
    #                      facecolor=self._colors.chocolate1,
    #                      edgecolor=self._colors.chocolate3,
    #                      alpha=0.75,
    #                  ),
    #              )
    #
    #              axs[2].set_title("Stream Data Size")
    #              axs[2].hist(
    #                  stream_data_sizes,
    #                  bins=n_bins,
    #                  color=self._colors.Chameleon,
    #              )
    #              axs[2].text(
    #                  0.5,
    #                  0.5,
    #                  overhead_stats.mpl_label(naturalsize),
    #                  transform=axs[2].transAxes,
    #                  fontsize=10,
    #                  verticalalignment="center",
    #                  horizontalalignment="center",
    #                  bbox=dict(
    #                      boxstyle="round",
    #                      facecolor=self._colors.chocolate1,
    #                      edgecolor=self._colors.chocolate3,
    #                      alpha=0.75,
    #                  ),
    #              )
    #
    #              self._save(fig, output_file)
    #
    #  def plot_rtt(self, output_file: Optional[Path]):
    #      """Plot the rtt diagram."""
    #      with Subplot() as (fig, ax):
    #          ax.grid(True)
    #          ax.set_xlabel("Time (s)")
    #          ax.set_ylabel("estimated RTT")
    #          assert self.title
    #          ax.set_title(self.title)
    #          ax.yaxis.set_major_formatter(lambda val, _pos: f"{val:.1f} ms")
    #
    #          with YaspinWrapper(
    #              debug=self.debug, text="processing...", color="cyan"
    #          ) as spinner:
    #
    #              for trace in self.traces:
    #                  trace.parse()
    #
    #              self._request_timestamps = [
    #                  [packet.norm_time for packet in trace.request_stream_packets]
    #                  for trace in self.traces
    #              ]
    #              response_timestamps = [
    #                  [packet.norm_time for packet in trace.response_stream_packets]
    #                  for trace in self.traces
    #              ]
    #              request_spin_bits = [
    #                  [
    #                      packet.quic.spin_bit.int_value
    #                      if "spin_bit" in packet.quic.field_names
    #                      else None
    #                      for packet in trace.packets
    #                      if getattr(packet, "direction", None) == Direction.TO_SERVER
    #                  ]
    #                  for trace in self.traces
    #              ]
    #              response_spin_bits = [
    #                  [
    #                      packet.quic.spin_bit.int_value
    #                      if "spin_bit" in packet.quic.field_names
    #                      else None
    #                      for packet in trace.packets
    #                      if getattr(packet, "direction", None) == Direction.TO_CLIENT
    #                  ]
    #                  for trace in self.traces
    #              ]
    #              min_timestamp: float = map3d(
    #                  min, [self._request_timestamps, response_timestamps]
    #              )
    #              max_timestamp: float = max(
    #                  trace.extended_facts["ttlb"] for trace in self.traces
    #              )
    #
    #              self._request_timestamps = list[list[float]]()
    #              response_timestamps = list[list[float]]()
    #              request_spin_bits = list[list[int]]()
    #              response_spin_bits = list[list[int]]()
    #              min_timestamp = float("inf")
    #              max_timestamp = -float("inf")
    #
    #              for trace in self.traces:
    #                  self._request_timestamps.append(list[float]())
    #                  response_timestamps.append(list[float]())
    #                  request_spin_bits.append(list[int]())
    #                  response_spin_bits.append(list[int]())
    #
    #                  for packet in trace.packets:
    #                      packet_direction = getattr(packet, "direction", None)
    #
    #                      if "spin_bit" not in packet.quic.field_names:
    #                          continue
    #                      spin_bit = packet.quic.spin_bit.int_value
    #                      timestamp = packet.norm_time
    #                      min_timestamp = min(min_timestamp, timestamp)
    #                      max_timestamp = max(max_timestamp, timestamp)
    #
    #                      if packet_direction == Direction.TO_SERVER:
    #                          request_spin_bits[-1].append(spin_bit)
    #                          self._request_timestamps[-1].append(timestamp)
    #                      else:
    #                          response_spin_bits[-1].append(spin_bit)
    #                          response_timestamps[-1].append(timestamp)
    #
    #              ax.set_xlim(left=min(0, min_timestamp), right=max_timestamp)
    #
    #          with YaspinWrapper(
    #              debug=self.debug, text="plotting...", color="cyan"
    #          ) as spinner:
    #              for (
    #                  self._trace_request_timestamps,
    #                  trace_response_timestamps,
    #                  trace_request_spin_bits,
    #                  trace_response_spin_bits,
    #              ) in zip(
    #                  self._request_timestamps[1:],
    #                  response_timestamps[1:],
    #                  request_spin_bits[1:],
    #                  response_spin_bits[1:],
    #              ):
    #                  ax.plot(
    #                      (*self._trace_request_timestamps, *trace_response_timestamps),
    #                      (*trace_request_spin_bits, *trace_response_spin_bits),
    #                      marker="o",
    #                      linestyle="",
    #                      color=self._colors.aluminium4,
    #                      markersize=self._markersize,
    #                  )
    #
    #              # plot main trace (request and response separated)
    #              ax.plot(
    #                  self._request_timestamps[0],
    #                  request_spin_bits[0],
    #                  marker="o",
    #                  linestyle="",
    #                  color=self._colors.Chameleon,
    #                  markersize=self._markersize,
    #              )
    #              ax.plot(
    #                  response_timestamps[0],
    #                  response_spin_bits[0],
    #                  marker="o",
    #                  linestyle="",
    #                  color=self._colors.SkyBlue,
    #                  markersize=self._markersize,
    #              )
    #
    #              self._annotate_time_plot(ax, height=1)
    #
    #              self._save(fig, output_file)

    def _save(self, figure: plt.Figure, output_file: Optional[Path]):
        """Save or show the plot."""

        if output_file:
            figure.savefig(
                output_file,
                dpi=300,
                #  transparent=True,
                bbox_inches="tight",
            )
            LOGGER.info("%s written", output_file)
        else:
            LOGGER.info("✔ Showing plot")
            plt.show()

    def print_trace_table(self):
        table = prettytable.PrettyTable()
        table.hrules = prettytable.FRAME
        table.vrules = prettytable.ALL
        table.field_names = [
            colored("left traces", color="cyan", attrs=["bold"]),
            colored("right traces", color="cyan", attrs=["bold"]),
            colored("keylog file", color="cyan", attrs=["bold"]),
        ]

        for i, right_trace in enumerate(self.traces):
            assert right_trace.pair_trace
            table.add_row(
                [
                    create_relpath(right_trace.pair_trace.input_file),
                    create_relpath(right_trace.input_file),
                    create_relpath(right_trace.keylog_file)
                    if right_trace.keylog_file
                    else colored("-", color="grey"),
                ]
            )

        print(table)

    def run(self):
        """Run command line interface."""

        LOGGER.info("Plotting %d traces", len(self.traces))

        mapping = {
            PlotMode.OFFSET_NUMBER: {
                "callback": self.plot_offset_number,
            },
            PlotMode.PACKET_NUMBER: {
                "callback": self.plot_packet_number,
            },
            PlotMode.FILE_SIZE: {
                "callback": self.plot_data_size,
            },
            PlotMode.PACKET_SIZE: {
                "callback": self.plot_packet_size,
                "single": True,
            },
            PlotMode.DATA_RATE: {
                "callback": self.plot_data_rate,
            },
            PlotMode.RETURN_PATH: {
                "callback": self.plot_return_path,
            },
            #  PlotMode.SIZE_HIST: {
            #      "callback": self.plot_packet_hist,
            #      "single": True,
            #  },
            #  PlotMode.RTT: {
            #      "callback": self.plot_rtt,
            #  },
        }

        cfg = mapping[self.mode]
        # single: Optional[bool] = cfg.get("single")
        callback = cfg["callback"]
        desc = DEFAULT_TITLES[self.mode]
        # num_traces = 1 if single else len(self.traces)

        self.analyze_traces()

        LOGGER.info("⚒ Plotting into a %s plot...", desc)

        with Subplot() as (fig, ax):
            callback(fig, ax)
            self._save(fig, self.output_file)


def main():
    """docstring for main"""
    try:
        args = parse_args()
    except argparse.ArgumentError as err:
        sys.exit(err)

    cli = PlotCli(
        trace_triples=args.trace_triples,
        output_file=args.output_file,
        title=args.title,
        annotate=not args.no_annotation,
        mode=args.mode,
        cache=args.cache,
        debug=args.debug,
        add_ideal=args.ideal,
        no_shadow=args.no_shadow,
    )
    try:
        cli.run()
    except ParsingError as err:
        sys.exit(colored(str(err), color="red"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nQuit")
