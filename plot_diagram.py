#!/usr/bin/env python3

"""Plot time packet-number plots and more."""

import argparse
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

import numpy as np
import prettytable
from humanize.filesize import naturalsize
from matplotlib import colors
from matplotlib import pyplot as plt
from termcolor import colored, cprint

from enums import CacheMode, Direction, PlotMode, Side
from tango_colors import Tango
from trace_analyzer2 import ParsingError, Trace
from utils import (Statistics, Subplot, TraceTriple, YaspinWrapper,
                   create_relpath, map2d, map3d, natural_data_rate)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pyshark.packet.packet import Packet


DEFAULT_TITLES = {
    PlotMode.OFFSET_NUMBER: "Time vs. Offset-Number",
    PlotMode.PACKET_NUMBER: "Time vs. Packet-Number",
    PlotMode.FILE_SIZE: "Time vs. Transmitted File Size",
    PlotMode.PACKET_SIZE: "Time vs. Packet Size",
    PlotMode.DATA_RATE: "Time vs. Data Rate",
    #  PlotMode.SIZE_HIST: "Size Histogram",
    #  PlotMode.RTT: "Time vs. RTT",
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
        help="Hide TTFB, PLT, ... markers.",
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

    args = parser.parse_args()

    return args


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
        debug=False,
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
        self, ax: plt.Axes, height: Union[float, int], spinner: YaspinWrapper
    ):
        if not self.annotate:
            return

        if not self.traces[0].extended_facts["is_http09"]:
            spinner.write(
                colored(
                    f"⨯ Can't annotate plot, because facts are missing.", color="red"
                )
            )

            return

        ttfb = self.traces[0].extended_facts["ttfb"]
        req_start = self.traces[0].extended_facts["request_start"]
        pglt = self.traces[0].extended_facts["plt"]
        resp_delay = self.traces[0].extended_facts["response_delay"]
        first_resp_tx_time = self.traces[0].extended_facts["first_response_send_time"]
        last_resp_tx_time = self.traces[0].extended_facts["last_response_send_time"]

        for label, value, label_side in (
            (
                f"Req. Start = {req_start:.3f} s",
                req_start,
                "left",
            ),
            (
                f"TTFB = {ttfb:.3f} s",
                ttfb,
                "right",
            ),
            (
                f"Last Resp. TX = {last_resp_tx_time:.3f} s",
                last_resp_tx_time,
                "left",
            ),
            (
                f"PLT = {pglt:.3f} s",
                pglt,
                "right",
            ),
        ):
            self._vline_annotate(
                ax=ax,
                x=value,
                y=height / 2,
                text=label,
                label_side=label_side,
            )

        ax.annotate(
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

        self._vdim_annotate(
            ax=ax,
            left=self.traces[0].extended_facts["request_start"],
            right=self.traces[0].extended_facts["ttfb"],
            y=height * 3 / 4,
            text=f"{resp_delay * 1000:.0f} ms",
        )
        end_ts = pglt - last_resp_tx_time
        self._vdim_annotate(
            ax=ax,
            left=last_resp_tx_time,
            right=pglt,
            y=height * 3 / 4,
            text=f"{end_ts * 1000:.0f} ms",
        )

    def plot_offset_number(self, output_file: Optional[Path]):
        """Plot the offset number diagram."""
        with Subplot(nrows=1, ncols=1) as (fig, ax):
            ax.grid(True)
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Offset")
            assert self.title
            ax.set_title(self.title)
            ax.yaxis.set_major_formatter(
                lambda val, _pos: naturalsize(val, binary=True)
            )

            assert self.traces[0].pair_trace

            with YaspinWrapper(
                debug=self.debug, text="processing...", color="cyan"
            ) as spinner:
                request_offsets = list[list[int]]()
                response_first_offsets = list[list[int]]()
                response_retrans_offsets = list[list[int]]()
                request_timestamps = list[list[float]]()
                response_first_timestamps = list[list[float]]()
                response_retrans_timestamps = list[list[float]]()
                max_offsets = list[int]()

                for trace in self.traces:

                    request_offsets.append(list[int]())
                    response_first_offsets.append(list[int]())
                    response_retrans_offsets.append(list[int]())
                    request_timestamps.append(list[float]())
                    response_first_timestamps.append(list[float]())
                    response_retrans_timestamps.append(list[float]())
                    max_offsets.append(0)

                    for layer in trace.request_stream_packets:
                        offset = trace.get_stream_offset(layer)

                        if offset is None:
                            continue

                        request_offsets[-1].append(offset)
                        request_timestamps[-1].append(layer.norm_time)

                        if offset > max_offsets[-1]:
                            # assert that we transmit without overlapping
                            max_offsets[-1] = offset + trace.get_stream_length(layer)

                    for layer in trace.response_stream_packets_first_tx:
                        offset = trace.get_stream_offset(layer)

                        if offset is None:
                            continue
                        response_first_offsets[-1].append(offset)
                        response_first_timestamps[-1].append(layer.norm_time)

                        if offset > max_offsets[-1]:
                            # assert that we transmit without overlapping
                            max_offsets[-1] = offset + trace.get_stream_length(layer)

                    for layer in trace.response_stream_packets_retrans:
                        offset = trace.get_stream_offset(layer)

                        if offset is None:
                            continue
                        response_retrans_offsets[-1].append(offset)
                        response_retrans_timestamps[-1].append(layer.norm_time)
                        # Do not calculate max_offsets in assertion that retransmitted packets are
                        # not larger than previously transmitted packets

                all_offsets = (
                    *request_offsets,
                    *response_first_offsets,
                    *(lst for lst in response_retrans_offsets if lst),
                )
                min_offset: int = map2d(min, all_offsets)
                max_offset: int = max(max_offsets)
                all_timestamps = (
                    *request_timestamps,
                    *response_first_timestamps,
                    *(lst for lst in response_retrans_timestamps if lst),
                )
                min_timestamp: float = map2d(min, all_timestamps)
                max_timestamp: float = max(
                    trace.extended_facts["plt"] for trace in self.traces
                )

                ax.set_xlim(left=min(0, min_timestamp), right=max_timestamp)
                ax.set_ylim(bottom=min(0, min_offset), top=max_offset)
                ax.set_yticks(np.arange(0, max_offset * 1.1, 1024 * 1024))

            with YaspinWrapper(
                debug=self.debug, text="plotting...", color="cyan"
            ) as spinner:
                # plot shadow traces (request and response separated)

                for trace_timestamps, trace_offsets in zip(
                    request_timestamps[1:], request_offsets[1:]
                ):
                    ax.plot(
                        trace_timestamps,
                        trace_offsets,
                        marker="o",
                        linestyle="",
                        color=self._colors.aluminium4,
                        markersize=self._markersize,
                    )

                for (
                    trace_first_timestamps,
                    trace_first_offsets,
                    trace_retrans_timestamps,
                    trace_retrans_offsets,
                ) in zip(
                    response_first_timestamps[1:],
                    response_first_offsets[1:],
                    response_retrans_timestamps[1:],
                    response_retrans_offsets[1:],
                ):
                    ax.plot(
                        (*trace_first_timestamps, *trace_retrans_timestamps),
                        (*trace_first_offsets, *trace_retrans_offsets),
                        marker="o",
                        linestyle="",
                        color=self._colors.aluminium4,
                        markersize=self._markersize,
                    )

                # plot main trace (request and response separated)

                ax.plot(
                    request_timestamps[0],
                    request_offsets[0],
                    marker="o",
                    linestyle="",
                    color=self._colors.Chameleon,
                    markersize=self._markersize,
                )
                ax.plot(
                    response_first_timestamps[0],
                    response_first_offsets[0],
                    marker="o",
                    linestyle="",
                    color=self._colors.SkyBlue,
                    markersize=self._markersize,
                )
                ax.plot(
                    response_retrans_timestamps[0],
                    response_retrans_offsets[0],
                    marker="o",
                    linestyle="",
                    color=self._colors.Orange,
                    markersize=self._markersize,
                )

                self._annotate_time_plot(ax, height=max_offset, spinner=spinner)
                self._save(fig, output_file, spinner)

    def plot_data_rate(self, output_file: Optional[Path]):
        """Plot the data rate plot."""

        with Subplot(nrows=1, ncols=1) as (fig, ax):
            ax.grid(True)
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Data Rate")
            assert self.title
            ax.set_title(self.title)
            ax.yaxis.set_major_formatter(lambda val, _pos: natural_data_rate(val))
            DATA_RATE_WINDOW = 1  # 1s

            with YaspinWrapper(
                debug=self.debug, text="processing...", color="cyan"
            ) as spinner:
                timestamps = []
                goodput_data_rates = list[list[float]]()
                tx_data_rates = list[list[float]]()
                min_timestamp: float = 0
                max_timestamp: float = 0

                @dataclass
                class DataRateBufEntry:
                    timestamp: float
                    raw_data: int
                    successful_stream_data: int

                for trace in self.traces:

                    goodput_data_rates.append(list[float]())
                    tx_data_rates.append(list[float]())
                    trace_max_timestamp = trace.extended_facts["plt"]
                    trace_timestamps = np.arange(
                        min_timestamp, trace_max_timestamp, 0.1
                    )
                    timestamps.append(trace_timestamps)
                    max_timestamp = max(max_timestamp, trace_max_timestamp)

                    data_rate_buf = deque[DataRateBufEntry]()

                    assert trace.pair_trace
                    with spinner.hidden():
                        trace.pair_trace.parse()

                    for packet in trace.server_client_packets:
                        raw_data_len = len(packet.udp.payload.binary_value)
                        # goodput
                        right_packet = trace.get_pair_packet(packet)

                        if not right_packet:
                            stream_data_len = 0
                        else:
                            stream_data_len = trace.pair_trace.get_quic_payload_size(
                                right_packet
                            )

                        # *8: convert from byte to bit
                        data_rate_buf.append(
                            DataRateBufEntry(
                                timestamp=packet.norm_time,
                                raw_data=raw_data_len * 8,
                                successful_stream_data=stream_data_len * 8,
                            )
                        )

                    # calculate data rates

                    # marker_start is inclusive, marker_end is exclusive
                    marker_start = marker_end = 0

                    for timestamp in trace_timestamps:
                        while data_rate_buf[marker_end].timestamp < timestamp:
                            if marker_end == len(data_rate_buf) - 1:
                                break
                            marker_end += 1

                        while (
                            data_rate_buf[marker_start].timestamp
                            < timestamp - DATA_RATE_WINDOW
                        ):
                            if marker_start == len(data_rate_buf) - 1:
                                break
                            marker_start += 1

                        buf_slice = list(data_rate_buf)[marker_start:marker_end]
                        tx_data_rates[-1].append(
                            sum(entry.raw_data for entry in buf_slice)
                            / DATA_RATE_WINDOW
                        )
                        goodput_data_rates[-1].append(
                            sum(entry.successful_stream_data for entry in buf_slice)
                            / DATA_RATE_WINDOW
                        )

                max_data_rate: float = map3d(max, (tx_data_rates, goodput_data_rates))

                ax.set_xlim(left=min(0, min_timestamp), right=max_timestamp)
                ax.set_ylim(bottom=0, top=max_data_rate)
                #  ax.set_yticks(np.arange(0, max_offset * 1.1, 1024 * 1024))

            with YaspinWrapper(
                debug=self.debug, text="plotting...", color="cyan"
            ) as spinner:
                # plot shadow traces (request and response separated)

                for trace_timestamps, trace_goodput in zip(
                    timestamps[1:], goodput_data_rates[1:]
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
                    timestamps[0],
                    goodput_data_rates[0],
                    label=r"Goodput (recv'd payload rate delayed by $\frac{-RTT}{2}$)",
                    #  marker="o",
                    linestyle="--",
                    color=self._colors.orange1,
                    markersize=self._markersize,
                )
                ax.plot(
                    timestamps[0],
                    tx_data_rates[0],
                    label="Data Rate of Transmitted Packets",
                    #  marker="o",
                    linestyle="--",
                    color=self._colors.orange3,
                    markersize=self._markersize,
                )
                ax.legend(loc="upper left", fontsize=8)

                self._annotate_time_plot(ax, height=max_data_rate, spinner=spinner)
                self._save(fig, output_file, spinner)

    def plot_packet_number(self, output_file: Optional[Path]):
        """Plot the packet number diagram."""
        with Subplot(nrows=1, ncols=1) as (fig, ax):
            ax.grid(True)
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Packet Number")
            assert self.title
            ax.set_title(self.title)

            with YaspinWrapper(
                debug=self.debug, text="processing...", color="cyan"
            ) as spinner:
                request_timestamps = [
                    [layer.norm_time for layer in trace.request_stream_packets]

                    for trace in self.traces
                ]
                response_timestamps = [
                    [layer.norm_time for layer in trace.response_stream_packets]

                    for trace in self.traces
                ]
                request_packet_numbers = [
                    [int(layer.packet_number) for layer in trace.request_stream_packets]

                    for trace in self.traces
                ]
                response_packet_numbers = [
                    [
                        int(layer.packet_number)

                        for layer in trace.response_stream_packets
                    ]

                    for trace in self.traces
                ]
                all_packet_numbers = [request_packet_numbers, response_packet_numbers]
                min_packet_number: int = map3d(min, all_packet_numbers)
                max_packet_number: int = map3d(max, all_packet_numbers)
                all_timestamps = [request_timestamps, response_timestamps]
                min_timestamp: float = map3d(min, all_timestamps)
                max_timestamp: float = max(
                    trace.extended_facts["plt"] for trace in self.traces
                )

                ax.set_xlim(left=min(0, min_timestamp), right=max_timestamp)
                ax.set_ylim(bottom=min(0, min_packet_number), top=max_packet_number)

            with YaspinWrapper(
                debug=self.debug, text="plotting...", color="cyan"
            ) as spinner:
                # plot shadow traces (request and response separated)

                for trace_timestamps, trace_packet_numbers in zip(
                    request_timestamps[1:], request_packet_numbers[1:]
                ):
                    ax.plot(
                        trace_timestamps,
                        trace_packet_numbers,
                        marker="o",
                        linestyle="",
                        color=self._colors.aluminium4,
                        markersize=self._markersize,
                    )

                for trace_timestamps, trace_packet_numbers in zip(
                    response_timestamps[1:], response_packet_numbers[1:]
                ):
                    ax.plot(
                        trace_timestamps,
                        trace_packet_numbers,
                        marker="o",
                        linestyle="",
                        color=self._colors.aluminium4,
                        markersize=self._markersize,
                    )

                # plot main trace (request and response separated)

                ax.plot(
                    request_timestamps[0],
                    request_packet_numbers[0],
                    marker="o",
                    linestyle="",
                    color=self._colors.Plum,
                    markersize=self._markersize,
                )
                ax.plot(
                    response_timestamps[0],
                    response_packet_numbers[0],
                    marker="o",
                    linestyle="",
                    color=self._colors.SkyBlue,
                    markersize=self._markersize,
                )

                self._annotate_time_plot(ax, height=max_packet_number, spinner=spinner)
                spinner.write(f"rtt: {self.traces[0].extended_facts.get('rtt')}")
                self._save(fig, output_file, spinner)

    def plot_file_size(self, output_file: Optional[Path]):
        """Plot the file size diagram."""
        with Subplot() as (fig, ax):
            ax.grid(True)
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Transmitted File Size")
            assert self.title
            ax.set_title(self.title)
            ax.yaxis.set_major_formatter(
                lambda val, _pos: naturalsize(val, binary=True)
            )

            with YaspinWrapper(
                debug=self.debug, text="processing...", color="cyan"
            ) as spinner:
                # only response
                timestamps = [
                    np.array(
                        [packet.norm_time for packet in trace.server_client_packets]
                    )

                    for trace in self.traces
                ]
                file_sizes = [
                    np.array(
                        [
                            trace.get_quic_payload_size(packet)

                            for packet in trace.server_client_packets
                        ]
                    )

                    for trace in self.traces
                ]
                accumulated_transmitted_file_size = [
                    np.cumsum(trace_file_sizes) for trace_file_sizes in file_sizes
                ]
                min_file_size: int = map2d(min, accumulated_transmitted_file_size)
                max_file_size: int = map2d(max, accumulated_transmitted_file_size)
                min_timestamp = map2d(min, timestamps)
                max_timestamp = max(
                    trace.extended_facts["plt"] for trace in self.traces
                )

                ax.set_xlim(left=min(0, min_timestamp), right=max_timestamp)
                ax.set_ylim(bottom=min(0, min_file_size), top=max_file_size)
                ax.set_yticks(np.arange(0, max_file_size * 1.1, 1024 * 1024))

            with YaspinWrapper(
                debug=self.debug, text="plotting...", color="cyan"
            ) as spinner:
                # plot shadow traces

                for trace_timestamps, trace_file_sizes in zip(
                    timestamps[1:], accumulated_transmitted_file_size[1:]
                ):
                    ax.plot(
                        trace_timestamps,
                        trace_file_sizes,
                        marker="o",
                        linestyle="",
                        color=self._colors.aluminium4,
                        markersize=self._markersize,
                    )

                # plot main trace

                ax.plot(
                    timestamps[0],
                    accumulated_transmitted_file_size[0],
                    marker="o",
                    linestyle="",
                    color=self._colors.SkyBlue,
                    markersize=self._markersize,
                )

                self._annotate_time_plot(ax, height=max_file_size, spinner=spinner)
                self._save(fig, output_file, spinner)

    def _process_packet_sizes(self):
        """Helper function."""
        # only response
        # only the first trace
        packet_sizes = list[int]()
        overhead_sizes = list[int]()
        stream_data_sizes = list[int]()
        timestamps = list[float]()
        min_timestamp = float("inf")

        for packet in self.traces[0].response_stream_packets:
            packet_size = int(packet.packet_length)
            packet_sizes.append(packet_size)
            stream_data_size = self.traces[0].get_stream_length(packet)
            stream_data_sizes.append(stream_data_size)
            overhead_sizes.append(packet_size - stream_data_size)
            timestamps.append(packet.norm_time)
            min_timestamp = max(min_timestamp, packet.norm_time)

        max_timestamp: float = self.traces[0].extended_facts["plt"]

        packet_stats = Statistics.calc(packet_sizes)
        overhead_stats = Statistics.calc(overhead_sizes)
        stream_data_stats = Statistics.calc(stream_data_sizes)

        return (
            packet_sizes,
            overhead_sizes,
            stream_data_sizes,
            timestamps,
            max_timestamp,
            min_timestamp,
            packet_stats,
            overhead_stats,
            stream_data_stats,
        )

    def plot_packet_size(self, output_file: Optional[Path]):
        """Plot the packet size diagram."""
        with Subplot() as (fig, ax):
            ax.grid(True)
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Packet Size")
            assert self.title
            ax.set_title(self.title)
            ax.yaxis.set_major_formatter(
                lambda val, _pos: naturalsize(val, binary=True)
            )

            with YaspinWrapper(
                debug=self.debug, text="processing...", color="cyan"
            ) as spinner:
                (
                    _packet_sizes,
                    overhead_sizes,
                    stream_data_sizes,
                    timestamps,
                    max_timestamp,
                    min_timestamp,
                    packet_stats,
                    overhead_stats,
                    stream_data_stats,
                ) = self._process_packet_sizes()

                ax.set_xlim(left=min(0, min_timestamp), right=max_timestamp)
                #  ax.set_ylim(bottom=0, top=packet_stats.max)
                #  ax.set_yticks(np.arange(0, packet_stats.max * 1.1, 1024))

            with YaspinWrapper(
                debug=self.debug, text="plotting...", color="cyan"
            ) as spinner:
                # no shadow traces here
                # plot main trace
                ax.stackplot(
                    timestamps,
                    (
                        stream_data_sizes,
                        overhead_sizes,
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

                ax.text(
                    0.95,
                    0.05,
                    "\n".join(
                        (
                            "Packet Statistics",
                            packet_stats.mpl_label_short(naturalsize),
                            "\n Stream Data Statistics",
                            stream_data_stats.mpl_label_short(naturalsize),
                            "\n Overhead Statistics",
                            overhead_stats.mpl_label_short(naturalsize),
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

                self._annotate_time_plot(ax, height=packet_stats.max, spinner=spinner)

                self._save(fig, output_file, spinner)

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
    #              self._save(fig, output_file, spinner)
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
    #              request_timestamps = [
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
    #                  min, [request_timestamps, response_timestamps]
    #              )
    #              max_timestamp: float = max(
    #                  trace.extended_facts["plt"] for trace in self.traces
    #              )
    #
    #              request_timestamps = list[list[float]]()
    #              response_timestamps = list[list[float]]()
    #              request_spin_bits = list[list[int]]()
    #              response_spin_bits = list[list[int]]()
    #              min_timestamp = float("inf")
    #              max_timestamp = -float("inf")
    #
    #              for trace in self.traces:
    #                  request_timestamps.append(list[float]())
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
    #                          request_timestamps[-1].append(timestamp)
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
    #                  trace_request_timestamps,
    #                  trace_response_timestamps,
    #                  trace_request_spin_bits,
    #                  trace_response_spin_bits,
    #              ) in zip(
    #                  request_timestamps[1:],
    #                  response_timestamps[1:],
    #                  request_spin_bits[1:],
    #                  response_spin_bits[1:],
    #              ):
    #                  ax.plot(
    #                      (*trace_request_timestamps, *trace_response_timestamps),
    #                      (*trace_request_spin_bits, *trace_response_spin_bits),
    #                      marker="o",
    #                      linestyle="",
    #                      color=self._colors.aluminium4,
    #                      markersize=self._markersize,
    #                  )
    #
    #              # plot main trace (request and response separated)
    #              ax.plot(
    #                  request_timestamps[0],
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
    #              self._annotate_time_plot(ax, height=1, spinner=spinner)
    #
    #              self._save(fig, output_file, spinner)

    def _save(
        self, figure: plt.Figure, output_file: Optional[Path], spinner: YaspinWrapper
    ):
        """Save or show the plot."""

        if output_file:
            figure.savefig(
                output_file,
                dpi=300,
                #  transparent=True,
                bbox_inches="tight",
            )
            spinner.text = colored(
                f"{create_relpath(output_file)} written.", color="green"
            )
        else:
            spinner.write(f"✔ {spinner.text}")
            spinner.text = "Showing plot"
            spinner.ok("✔")
            plt.show()

    def run(self):
        """Run command line interface."""

        cprint(f"Plotting {len(self.traces)} traces", color="cyan", attrs=["bold"])
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
                    colored(
                        str(create_relpath(right_trace.pair_trace.input_file)),
                        attrs=["bold"] if i == 0 else None,
                    ),
                    colored(
                        str(create_relpath(right_trace.input_file)),
                        attrs=["bold"] if i == 0 else None,
                    ),
                    create_relpath(right_trace.keylog_file)

                    if right_trace.keylog_file
                    else colored("-", color="grey"),
                ]
            )

        print(table)

        mapping = {
            PlotMode.OFFSET_NUMBER: {
                "callback": self.plot_offset_number,
            },
            PlotMode.PACKET_NUMBER: {
                "callback": self.plot_packet_number,
            },
            PlotMode.FILE_SIZE: {
                "callback": self.plot_file_size,
            },
            PlotMode.PACKET_SIZE: {
                "callback": self.plot_packet_size,
                "single": True,
            },
            PlotMode.DATA_RATE: {
                "callback": self.plot_data_rate,
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
        single: Optional[bool] = cfg.get("single")
        callback = cfg["callback"]
        desc = DEFAULT_TITLES[self.mode]
        num_traces = 1 if single else len(self.traces)

        # avoid lazy result parsing:

        if single:
            self.traces[0].parse()
        else:
            for trace in self.traces:
                trace.parse()

        cprint(f"⚒ Plotting {num_traces} traces into a {desc} plot...", color="cyan")
        callback(self.output_file)


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
