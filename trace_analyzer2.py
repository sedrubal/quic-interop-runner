#!/usr/bin/env python3
"""Handle pcap traces."""

# pylint: disable=protected-access

import argparse
import json
import pickle
import subprocess
import sys
import typing
from functools import cached_property
from pathlib import Path
from typing import Any, Iterator, Optional, TypedDict

import nest_asyncio
import pyshark  # type: ignore
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import ProgressBar
from termcolor import colored, cprint

from conf import CONFIG
from enums import CacheMode, Direction, Side
from utils import LOGGER, TraceTriple, YaspinWrapper, clear_line, create_relpath

if typing.TYPE_CHECKING:
    from pyshark.packet.packet import Packet  # type: ignore


# https://github.com/KimiNewt/pyshark/issues/434#issuecomment-691706873
nest_asyncio.apply()

QuicStreamPacket = Any


class ParsingError(Exception):
    """Exception that will be thrown when we can't parse the trace."""

    def __init__(self, msg: str, trace: "Trace"):
        super().__init__(msg)
        self.msg = msg
        self.trace = trace

    def __str__(self):
        return f"{self.trace.input_file}: {self.msg}"


class FinError(ParsingError):
    """Error with closing streams detected."""


class HTTP09Error(ParsingError):
    """Error with HTTP/0.9 detected."""


class CryptoError(ParsingError):
    """Error with crypto detected."""


#  def get_frame_prop_from_all_frames(
#      packet: "Packet",
#      prop_name: str,
#      include_none: bool = False,
#      callback: Optional[Callable[[Any], Any]] = None,
#  ) -> Any:
#      ret = list[Any]()
#
#      for quic_layer in iter_stream_packets(packet):
#          if not hasattr(quic_layer, prop_name):
#              if include_none:
#                  ret.append(None)
#          else:
#              raw_value = getattr(quic_layer, prop_name)
#
#              if callback:
#                  ret.append(callback(raw_value))
#              else:
#                  ret.append(raw_value)
#
#      return ret


class Trace:
    """A pcap trace."""

    def __init__(
        self,
        file: Path,
        side: Side,
        keylog_file: Optional[Path] = None,
        cache=CacheMode.LOAD,
        debug=False,
        display_filter="(quic && !icmp)",
        port=443,
    ):
        self.side = side
        self.debug = debug
        self._display_filter = display_filter
        self._keylog_file = keylog_file
        override_prefs = {}

        file = file.resolve()

        if keylog_file is not None:
            override_prefs["tls.keylog_file"] = keylog_file

        if cache:
            self._cache_file: Optional[Path] = file.parent / f".{file.stem}.pickle"
            self._cache_mode = cache
        else:
            self._cache_file = None
            self._cache_mode = CacheMode.NONE

        if file.suffix not in (".pcap", ".pcapng"):
            cprint(
                f"⨯ Warning! Are you sure, that {file} is a pcap/pcapng file?",
                color="yellow",
            )

        self._cap = pyshark.FileCapture(
            str(file.absolute()),
            display_filter=display_filter,
            override_prefs=override_prefs,
            # see https://github.com/marten-seemann/quic-interop-runner/pull/179/
            disable_protocol="http3",
            decode_as={f"udp.port=={port}": "quic"},
            tshark_path=CONFIG.tshark_bin,
        )

        if CONFIG.pyshark_debug:
            self._cap.set_debug()
        self._facts = dict[str, Any]()
        self._extended_facts: Optional[dict[str, Any]] = None
        self._response_stream_packets_first_tx = list[QuicStreamPacket]()
        self._response_stream_packets_retrans = list[QuicStreamPacket]()
        self._client_server_packets = list["Packet"]()
        self._server_client_packets = list["Packet"]()
        self._request_stream_packets = list[QuicStreamPacket]()
        self._response_stream_packets = list[QuicStreamPacket]()
        self._parsed = False
        self._error_cfg = {
            HTTP09Error: "warning",
            FinError: "warning",
        }
        self._packets = list["Packet"]()
        self._packets_by_fpr = dict[int, "Packet"]()
        self._pair_trace: Optional[
            "Trace"
        ] = None  # Trace for the other side (left / right)

    @property
    def input_file(self) -> Path:
        return Path(self._cap.input_filename)

    @property
    def keylog_file(self) -> Optional[Path]:
        keylog_file = self._cap._override_prefs.get("tls.keylog_file")

        if keylog_file:
            return Path(keylog_file)

        else:
            return None

    def __str__(self):
        trace_file_name = self.input_file.name

        if self._keylog_file:
            return f'<Trace {trace_file_name} "{self._display_filter}" ({self._keylog_file})>'
        else:
            return f'<Trace {trace_file_name} "{self._display_filter}">'

    def __repr__(self):
        return str(self)

    @cached_property
    def num_packets(self) -> int:
        """Return the number of packets."""

        if self._packets:
            # alternatively: if self._cap.loaded:
            # 1. if already loaded -> use loaded packets

            return len(self._packets)
        else:
            # 2. use cmd tool to determine the cap length
            output = subprocess.check_output(
                ("capinfos", "-r", "-B", "-T", "-c", self.input_file),
                text=True,
            ).strip()

            return int(output.split()[1])

    def get_packet_by_fpr(self, fpr: int, partial=True) -> Optional["Packet"]:
        """
        Get a packet by it's packet fingerprint. Assuming that we need one of the first packets.
        """

        packets_by_fpr = dict[int, "Packet"]()

        if not partial and not self._packets_by_fpr:
            # 1. if not partial and not yet sorted: parse all packets

            for packet in self.packet_iter():
                packet_fpr = self._packet_fingerprint(packet)
                packets_by_fpr[packet_fpr] = packet

            self._packets_by_fpr = packets_by_fpr

        if self._packets_by_fpr:
            # 2. if already fingerprinted -> use dict lookup

            return self._packets_by_fpr.get(fpr, None)

        # 3. load and iterate over packets and check fingerprint

        for packet in self.packet_iter():
            packet_fpr = self._packet_fingerprint(packet)

            if packet_fpr == fpr:
                return packet

            packets_by_fpr[packet_fpr] = packet

        self._packets_by_fpr = packets_by_fpr

        return None

    def get_pair_packet(self, packet: "Packet", partial=False) -> Optional["Packet"]:
        """Get the packet of the pair trace that belong to this packet."""
        assert self.pair_trace

        return self.pair_trace.get_packet_by_fpr(
            self._packet_fingerprint(packet),
            partial=partial,
        )

    def get_pair_stream_packet(
        self,
        stream_packet: QuicStreamPacket,
        partial=False,
    ) -> Optional[QuicStreamPacket]:
        """Get the quic stream packet of the pair trace that belongs to this packet."""
        assert self.pair_trace

        pair_packet = self.get_pair_packet(
            stream_packet.packet,
            partial=partial,
        )

        if not pair_packet:
            return None

        for pair_stream_packet in self.pair_trace.iter_stream_packets(pair_packet):
            if pair_stream_packet.packet_number == stream_packet.packet_number:
                return pair_stream_packet

        return None

    @property
    def packets(self) -> list["Packet"]:
        """Parse packets of this trace."""

        if self._packets:
            # 1. if already loaded -> return loaded packets

            return self._packets

        input_file_rel_path = create_relpath(self.input_file)
        with YaspinWrapper(
            debug=self.debug,
            text=f"Loading {input_file_rel_path}",
            color="green",
        ) as spinner:
            if (
                self._cache_mode.load
                and self._cache_file
                and self._cache_file.is_file()
                and self._cache_file.stat().st_size
            ):
                # 2. Load all packets from cache
                with self._cache_file.open("rb") as cache_file:
                    spinner.write(
                        colored(
                            f"⚒ Using cache from {create_relpath(self._cache_file)}",
                            color="grey",
                        )
                    )
                    try:
                        cached_packets = pickle.load(cache_file)

                        self._packets = cached_packets

                        return cached_packets
                    except Exception as exc:
                        spinner.write(
                            colored(
                                f"⚒ Could not load cache: {exc}",
                                color="red",
                            )
                        )

            # 3. Load all packets from pcap
            with spinner.hidden():
                with ProgressBar() as prog_bar:
                    _packet: "Packet"

                    for _packet in prog_bar(
                        self.packet_iter(),  # type: ignore
                        label=HTML("<cyan>⚒ Parsing packets</cyan>"),
                        total=self.num_packets,
                    ):
                        # nothing to do as packet_iter stores packets
                        pass

            if self._cache_mode.store and self._cache_file:
                with self._cache_file.open("wb") as cache_file:
                    spinner.write(
                        colored(
                            f"⚒ Saving parsed packets to {create_relpath(self._cache_file)}",
                            color="grey",
                        )
                    )
                    pickle.dump(obj=self._packets, file=cache_file)

        return self._packets

    def packet_iter(self) -> Iterator["Packet"]:
        """Load and iterate over packets from file."""

        if self._packets:
            # 1. if already loaded: Use loaded packets
            yield from self._packets

            return

        # 2. load and yield packets from cap
        packets = list["Packet"]()
        packet: "Packet"
        first_packet_sniff_timestamp = float("-inf")

        for packet in self._cap:
            if (
                not hasattr(packet, "udp")
                or not hasattr(packet, "ip")
                or not hasattr(packet, "quic")
            ):
                clear_line(file=sys.stderr)
                cprint(
                    f"⨯ Skipping packet #{packet.number} without UDP or IP?!? ({packet.frame_info.protocols})",
                    color="red",
                    file=sys.stderr,
                )

                continue

            # calculate norm_time
            # norm_time should be the same as udp.time_relative

            if first_packet_sniff_timestamp < 0:
                first_packet_sniff_timestamp = float(packet.sniff_timestamp)
            packet.norm_time = (
                float(packet.sniff_timestamp) - first_packet_sniff_timestamp
            )
            assert packet.norm_time >= 0

            # set packet direction, when facts have already been loaded from facts cache
            if self._facts:
                self._set_packet_direction(
                    packet,
                    client_ip=self._facts["client_ip"],
                    client_port=self._facts["client_port"],
                    server_ip=self._facts["server_ip"],
                    server_port=self._facts["server_port"],
                )

            yield packet

            packets.append(packet)

        # https://github.com/KimiNewt/pyshark/issues/366#issuecomment-524746268
        self._cap.close()
        self._packets = packets

    #  def get_prop_of_any_quic_packet(self, packet: "Packet", prop: str) -> Any:
    #      empty = object()
    #      value: Any = empty
    #
    #      for layer in packet.get_multiple_layers("quic"):
    #          if hasattr(layer, prop):
    #              new_value = getattr(layer, prop)
    #
    #              if value is not empty and value != new_value:
    #                  raise ValueError(
    #                      f"Single QUIC packets of packet #{packet.number} has different values "
    #                      f"for property {prop}: {value} != {new_value}"
    #                  )
    #              value = new_value
    #
    #      if value is not empty:
    #          return value
    #      else:
    #          breakpoint()
    #          raise ParsingError(
    #              trace=self,
    #              msg=f"No QUIC packet in packet #{packet.number} has a value for property {prop}",
    #          )

    @staticmethod
    def _packet_fingerprint(packet: "Packet"):
        """Generate a fingerprint for packets."""
        #  layers = packet.get_multiple_layers("quic")
        props = frozenset(
            (
                packet.ip.src,
                packet.ip.dst,
                packet.udp.srcport,
                packet.udp.dstport,
                packet.udp.payload.binary_value,
                #  len(layers),
                #  *(
                #      frozenset(
                #          (
                #              layer.packet_number,
                #              layer.get_field("scid").binary_value,
                #              layer.get_field("dcid").binary_value,
                #          )
                #      )
                #      for layer in layers
                #  ),
            )
        )

        return hash(props)

    @property
    def client_server_packets(self) -> list["Packet"]:
        """Packets from client to server."""
        self.parse()

        return self._client_server_packets

    @property
    def server_client_packets(self) -> list["Packet"]:
        """Packets from server to client."""
        self.parse()

        return self._server_client_packets

    @property
    def request_stream_packets(self) -> list[QuicStreamPacket]:
        """Packets with stream frames from client to server."""
        self.parse()

        return self._request_stream_packets

    @property
    def response_stream_packets(self) -> list[QuicStreamPacket]:
        """Packets with stream frames from server to client."""
        self.parse()

        return self._response_stream_packets

    @property
    def facts(self) -> dict[str, Any]:
        """Return a dict of findings / facts / infos."""

        if not self._facts:
            self._load_facts_cache_if_exists(extended=False)

        if not self._facts:
            self.parse()

        self._store_facts_to_cache()

        return self._facts

    def analyse_response_retrans(self):
        """Check which stream packets have been retransmitted in response stream."""

        if (
            not self._response_stream_packets_first_tx
            and not self._response_stream_packets_retrans
        ):
            response_stream_packets_first_tx = list[QuicStreamPacket]()
            response_stream_packets_retrans = list[QuicStreamPacket]()
            sent_offsets = set[int]()

            for packet in self.response_stream_packets:
                offset = self.get_stream_offset(packet)
                assert offset is not None

                if offset not in sent_offsets:
                    sent_offsets.add(offset)
                    response_stream_packets_first_tx.append(packet)
                else:
                    response_stream_packets_retrans.append(packet)

            # "thread safe"
            self._response_stream_packets_first_tx = response_stream_packets_first_tx
            self._response_stream_packets_retrans = response_stream_packets_retrans

            if not self._response_stream_packets_first_tx:
                raise ParsingError(
                    "No packets have been sent the first time. This should not happen.",
                    trace=self,
                )

    @property
    def response_stream_packets_first_tx(self) -> list[QuicStreamPacket]:
        """
        Packets with stream frames from server to client, that have not been resent but are the first try.
        """
        self.analyse_response_retrans()

        return self._response_stream_packets_first_tx

    @property
    def response_stream_packets_retrans(self) -> list[QuicStreamPacket]:
        """
        Packets with stream frames from server to client, that carry offset ranges, that already have been sent.
        """
        self.analyse_response_retrans()

        return self._response_stream_packets_retrans

    def _set_packet_direction(
        self, packet: "Packet", client_ip, client_port, server_ip, server_port
    ):
        client_tuple = (client_ip, client_port)
        server_tuple = (server_ip, server_port)

        src_port = packet.udp.srcport
        dst_port = packet.udp.dstport
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        src_tuple = (src_ip, src_port)
        dst_tuple = (dst_ip, dst_port)

        if src_tuple == client_tuple and dst_tuple == server_tuple:
            packet.direction = Direction.TO_SERVER

        elif src_tuple == server_tuple and dst_tuple == client_tuple:
            packet.direction = Direction.TO_CLIENT
        else:
            raise ParsingError(
                (
                    f"Packet #{packet.quic.packet_number} has unknown source or destination: "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                ),
                trace=self,
            )

    def parse(self) -> None:
        """
        Analyze the packets and return a "fact" dict containing:
        - is_http
        - client/server IP/port
        - packet number of stream.fin == 1
        """

        if self._parsed:
            return

        if len(self.packets) < 2:
            raise ParsingError(
                (
                    "There are less than 2 quic stream packets in this trace. "
                    "Did you provide the SSLKEYLOG?"
                ),
                trace=self,
            )

        # TODO check if pacing was used?
        self._facts = dict[str, Any]()

        first_packet = self.packets[0]

        # get client and server IP addresses and UDP ports
        server_ip = first_packet.ip.dst
        client_ip = first_packet.ip.src
        self._facts["client_ip"] = client_ip
        self._facts["server_ip"] = server_ip
        server_port = first_packet.udp.dstport
        client_port = first_packet.udp.srcport
        self._facts["client_port"] = client_port
        self._facts["server_port"] = server_port

        client_server_packets = list["Packet"]()
        server_client_packets = list["Packet"]()
        request_stream_packets = list[QuicStreamPacket]()
        response_stream_packets = list[QuicStreamPacket]()

        for packet in self.packets:
            self._set_packet_direction(
                packet,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
            )
            if packet.direction == Direction.TO_CLIENT:
                server_client_packets.append(packet)

                for inner_packet in self.iter_stream_packets(packet):
                    response_stream_packets.append(inner_packet)
            elif packet.direction == Direction.TO_SERVER:
                client_server_packets.append(packet)

                for inner_packet in self.iter_stream_packets(packet):
                    request_stream_packets.append(inner_packet)

        self._client_server_packets = client_server_packets
        self._server_client_packets = server_client_packets
        self._request_stream_packets = request_stream_packets
        self._response_stream_packets = response_stream_packets

        # check if first packet is an HTTP (0.9) request

        if not self._request_stream_packets:
            raise ParsingError(
                "No request packets with stream frames found!?",
                trace=self,
            )

        if not self._response_stream_packets:
            raise ParsingError(
                "No response packets with stream frames found!?",
                trace=self,
            )

        try:
            self._facts["request_stream_fin_pkns"] = self.get_stream_fin_packet_number(
                self._request_stream_packets
            )
        except FinError as err:
            if self._error_cfg[FinError] == "error":
                raise err
            else:
                cprint(f"⨯ Validation error: {err}", file=sys.stderr, color="red")

        try:
            request_raw = self.follow_stream(self._request_stream_packets)
            try:
                request = request_raw.decode("utf-8")
            except UnicodeDecodeError as err:
                raise HTTP09Error(
                    (
                        "Request seems not to be a HTTP/0.9 GET request. Maybe it is HTTP/3? "
                        f"{request_raw[:16]!r}"
                    ),
                    trace=self,
                ) from err

            if not request.startswith("GET /"):
                raise HTTP09Error(
                    "First packet is not a HTTP/0.9 GET request.",
                    trace=self,
                )

            self._facts["request"] = request
            self._facts["is_http09"] = True

            # check if all other packets are in direction from server to client:

            if float(self._request_stream_packets[-1].norm_time) >= float(
                self._response_stream_packets[0].norm_time
            ):
                raise HTTP09Error(
                    "Request packets appear after first response packet. Is this really HTTP/0.9?",
                    trace=self,
                )

            self._facts["first_response_send_time"] = self._response_stream_packets[
                0
            ].norm_time
            self._facts["last_response_send_time"] = self._response_stream_packets[
                -1
            ].norm_time
        except HTTP09Error as err:
            if self._error_cfg[HTTP09Error] == "error":
                raise err
            else:
                self._facts["is_http09"] = False
                cprint(f"⨯ Validation error: {err}", file=sys.stderr, color="red")

        try:
            # check fin bit
            self._facts["response_stream_fin_pkns"] = self.get_stream_fin_packet_number(
                self._response_stream_packets
            )
        except FinError as err:
            if self._error_cfg[FinError] == "error":
                raise err
            else:
                cprint(f"⨯ Validation error: {err}", file=sys.stderr, color="red")

        self._parsed = True

    @property
    def pair_trace(self) -> Optional["Trace"]:
        """Return the other trace, that belongs to this trace."""

        return self._pair_trace

    @pair_trace.setter
    def pair_trace(self, value: "Trace"):
        assert (
            not self._pair_trace and not value._pair_trace and value.side != self.side
        )
        value._pair_trace = self
        self._pair_trace = value

    @cached_property
    def _facts_cache_file(self) -> Path:
        return self.input_file.parent / f"facts.json"

    def _load_facts_cache_if_exists(
        self, extended: bool = False
    ) -> Optional[dict[str, Any]]:
        """Load facts or extended facts if cache file exists and cache loading is enabled."""
        if (
            not self._cache_mode.load
            or not self._facts_cache_file.is_file()
            or not self._facts_cache_file.stat().st_size > 0
        ):
            return None

        with self._facts_cache_file.open("r") as file:
            cached_facts = json.load(file)
        is_extended = cached_facts.pop("_extended", False)
        self._facts = cached_facts
        if is_extended:
            self._extended_facts = cached_facts

        if extended:
            if is_extended:
                return self._extended_facts
            else:
                return None
        return self._facts

    def _store_facts_to_cache(self):
        """Write facts file (always - even if cache mode != store)."""
        # prefer extended facts (do not overwrite cache, when extended facts are already parsed but we want to store only `facts`)
        if self._extended_facts:
            facts_to_cache = self._extended_facts
            is_extended = True
        else:
            facts_to_cache = self._facts
            is_extended = False
        assert facts_to_cache
        with self._facts_cache_file.open("w") as file:
            json.dump(
                {
                    **facts_to_cache,
                    "_extended": is_extended,
                },
                fp=file,
            )

    @property
    def extended_facts(self) -> dict[str, Any]:
        """Return the extended facts, that use information of the left trace."""
        if not self.pair_trace:
            raise AssertionError("Left trace was not yet set.")

        if self.side != Side.RIGHT or self.pair_trace.side != Side.LEFT:
            raise AssertionError(
                f"Asserted that this is a right side trace (was {self.side.value}) "
                f"and the other trace is a left side trace (was {self.pair_trace.side.value})."
            )

        if self._extended_facts:
            return self._extended_facts

        if self._load_facts_cache_if_exists(extended=True):
            assert self._extended_facts
            return self._extended_facts

        self.parse()
        facts = self.facts

        # calculate times
        rtt = self._get_rtt()
        if rtt is None:
            req_start = None
            ttfb = None
            pglt = None
            resp_delay = None
        else:
            req_start = self._request_stream_packets[0].norm_time - rtt / 2
            ttfb = self._response_stream_packets[0].norm_time + rtt / 2
            pglt = self._response_stream_packets[-1].norm_time + rtt / 2
            resp_delay = ttfb - req_start

        facts["request_start"] = req_start
        facts["ttfb"] = ttfb
        facts["response_delay"] = resp_delay
        facts["plt"] = pglt
        facts["rtt"] = rtt
        self._extended_facts = facts

        self._store_facts_to_cache()

        return self._extended_facts

    def _get_rtt(self) -> Optional[float]:
        def calc_rtt(
            direction: Direction, left_trace: "Trace", right_trace: "Trace"
        ) -> Optional[float]:
            # a packet in direction ``direction`` from the right trace
            last_in_dir_packet_right: Optional["Packet"] = None
            # a packet in direction ``direction`` from the left trace
            last_in_dir_packet_left: Optional["Packet"] = None
            # the first packet in the other direction after the last packet in the direction from the right trace
            first_opp_dir_packet_right: Optional["Packet"] = None
            # the first packet in the other direction after the last packet in the direction from the left trace
            first_opp_dir_packet_left: Optional["Packet"] = None

            # search for packets
            for packet in right_trace.packets:
                if packet.direction == direction:
                    last_in_dir_packet_left = left_trace.get_packet_by_fpr(
                        right_trace._packet_fingerprint(packet)
                    )

                    if not last_in_dir_packet_left:
                        # maybe the packet never arrived on left side -> search for a new one
                        last_in_dir_packet_left = None
                        last_in_dir_packet_right = None
                        first_opp_dir_packet_left = None
                        first_opp_dir_packet_right = None
                        continue

                    elif (
                        direction == Direction.TO_SERVER
                        and last_in_dir_packet_left.norm_time > packet.norm_time
                    ) or (
                        direction == Direction.TO_CLIENT
                        and last_in_dir_packet_left.norm_time < packet.norm_time
                    ):
                        # this should not happen
                        last_in_dir_packet_left = None
                        last_in_dir_packet_right = None
                        first_opp_dir_packet_left = None
                        first_opp_dir_packet_right = None

                        continue

                    last_in_dir_packet_right = packet
                    first_opp_dir_packet_right = None

                elif packet.direction.is_opposite(direction):
                    first_opp_dir_packet_left = left_trace.get_packet_by_fpr(
                        right_trace._packet_fingerprint(packet)
                    )

                    if not first_opp_dir_packet_left:
                        # maybe the packet never arrived on left side -> search for a new one
                        last_in_dir_packet_left = None
                        last_in_dir_packet_right = None
                        first_opp_dir_packet_left = None
                        first_opp_dir_packet_right = None
                        continue

                    elif (
                        direction == Direction.TO_SERVER
                        and first_opp_dir_packet_left.norm_time < packet.norm_time
                    ) or (
                        direction == Direction.TO_CLIENT
                        and first_opp_dir_packet_left.norm_time > packet.norm_time
                    ):
                        # tihs should not happen...
                        last_in_dir_packet_left = None
                        last_in_dir_packet_right = None
                        first_opp_dir_packet_left = None
                        first_opp_dir_packet_right = None

                        continue

                    first_opp_dir_packet_right = packet

                else:
                    assert False, f"Unexpected packet direction {packet.direction}"

                if (
                    last_in_dir_packet_right
                    and last_in_dir_packet_left
                    and first_opp_dir_packet_right
                    and first_opp_dir_packet_left
                ):
                    # we found all packets we need
                    break

            if not first_opp_dir_packet_right or not last_in_dir_packet_right:
                # we did not find the packets
                LOGGER.warning(
                    "No suitable packets found for RTT calculation."
                    "Maybe normalization of capture time failed or clock drift in left and right trace is too large."
                )
                return None

            assert (
                first_opp_dir_packet_right.norm_time
                > last_in_dir_packet_right.norm_time
            )

            if (
                not last_in_dir_packet_right
                or not last_in_dir_packet_left
                or not first_opp_dir_packet_right
                or not first_opp_dir_packet_left
            ):
                raise ParsingError(
                    (
                        "Did not find suitable packets for RTT determination in "
                        f"{direction.value}-direction. Do the traces really belong together?"
                    ),
                    trace=left_trace,
                )

            in_dir_delay = (
                last_in_dir_packet_right.norm_time - last_in_dir_packet_left.norm_time
            )

            if direction == Direction.TO_CLIENT:
                in_dir_delay *= -1
            #  proc_delay = (
            #      first_opp_dir_packet.packet_right.norm_time
            #      - last_in_dir_packet.packet_right.norm_time
            #  )
            opp_dir_delay = (
                first_opp_dir_packet_left.norm_time
                - first_opp_dir_packet_right.norm_time
            )

            if direction == Direction.TO_CLIENT:
                opp_dir_delay *= -1

            assert (
                in_dir_delay >= -0.1 and opp_dir_delay >= -0.1
            ), "The delays should be positive!"

            if direction == Direction.TO_SERVER:
                assert (
                    in_dir_delay < 0.001
                ), "The delay in direction to the server should be very small, because of norm time."
            else:
                assert (
                    opp_dir_delay < 0.001
                ), "The delay in direction to the server should be very small, because of norm_time"

            return in_dir_delay + opp_dir_delay

        assert self.pair_trace
        left_trace = self.pair_trace if self.side == Side.RIGHT else self
        right_trace = self if self.side == Side.RIGHT else self.pair_trace

        rtt_ret = calc_rtt(Direction.TO_SERVER, left_trace, right_trace)
        rtt_fwd = calc_rtt(Direction.TO_CLIENT, left_trace, right_trace)

        if rtt_fwd is not None and rtt_ret is not None:
            assert (
                abs(rtt_fwd / rtt_ret - 1) <= 0.02 or abs(rtt_fwd - rtt_ret) <= 0.005
            ), f"RTTs vary by more than 2 % or 5ms: {rtt_fwd * 1000:.1f} ms vs. {rtt_ret * 1000:.1f} ms"

            return (rtt_fwd + rtt_ret) / 2
        elif rtt_ret is not None:
            return rtt_ret
        elif rtt_fwd is not None:
            return rtt_fwd
        elif rtt_ret is None and rtt_fwd is None:
            return None

    def iter_stream_packets(self, packet: "Packet") -> Iterator[QuicStreamPacket]:
        for quic_packet in packet.get_multiple_layers("quic"):
            if hasattr(quic_packet, "decryption_failed"):
                raise CryptoError(
                    f"Decryption of QUIC crypto failed: {quic_packet.decryption_failed}",
                    trace=self,
                )

            if hasattr(quic_packet, "stream_stream_id"):
                # add fields from parent
                quic_packet.norm_time = packet.norm_time
                quic_packet.packet = packet
                yield quic_packet

    def get_stream_length(self, quic_layer: QuicStreamPacket) -> int:
        """:Return: The length of the stream data."""
        stream_data = quic_layer.stream_data

        if stream_data.raw_value is None:
            stream_data_len = 0
        else:
            stream_data_len = len(quic_layer.stream_data.binary_value)

        if quic_layer.get("stream_len") == "1":
            stream_length = int(quic_layer.stream_length)

            if stream_length != stream_data_len:
                raise ParsingError(
                    f"Stream length (={stream_length} b) of packet "
                    f"#{quic_layer.packet_number} missmatches the actual length "
                    f"(={stream_data_len} b).",
                    trace=self,
                )

        return stream_data_len

    def get_quic_payload_size(self, packet: "Packet") -> int:
        """:Return: The stream_data payload size of this packet."""

        return sum(
            self.get_stream_length(quic_layer)
            for quic_layer in self.iter_stream_packets(packet)
        )

    def follow_stream(self, stream_packets: list[QuicStreamPacket]) -> bytes:
        """Reconstruct the content of a series of packets with stream frames."""
        buf = list[Optional[int]]()

        for packet in stream_packets:
            offset = self.get_stream_offset(packet)
            assert offset is not None
            extend_buf = offset - len(buf)

            if extend_buf > 0:
                buf += [None] * extend_buf

            buf[offset:] = packet.stream_data.binary_value

        if not all(byte is not None for byte in buf):
            cprint(
                "⨯ Warning! Did not receive all bytes in follow_stream.",
                color="yellow",
            )

        return bytes([byte or 0 for byte in buf])

    @staticmethod
    def get_stream_offset(quic_layer: QuicStreamPacket) -> Optional[int]:
        """Get the offset number of a stream frame."""

        if not hasattr(quic_layer, "stream_off"):
            # not a stream_frame

            return None

        if quic_layer.stream_off.int_value:
            return int(quic_layer.stream_offset)
        else:
            return 0

    #  def get_stream_offsets(packet: "Packet") -> list[int]:
    #      offsets = [
    #          get_stream_offset(quic_layer) for quic_layer in iter_stream_packets(packet)
    #      ]
    #
    #      return [off for off in offsets if off is not None]

    def get_stream_fin_packet_number(
        self,
        packets: list[QuicStreamPacket],
        warn_only=False,
    ) -> list[int]:
        """
        Check if the last packet and only the last packet of this stream ends the stream.

        :Return: A list of packet numbers, in which this stream was closed.
        This may be multiple packets, if the fin packet was re-sent.
        All other cases should be validated and an error should be raised.
        """

        class StreamFinEntry(TypedDict):
            """Types for a helper dict."""

            packet_number: int
            stream_id: int
            offset: int

        stream_fins = list[StreamFinEntry]()
        # packets may be out of order:
        max_offset = float("-inf")
        pkn_with_max_offset = float("-inf")

        for quic_packet in packets:
            layer_offset = self.get_stream_offset(quic_packet)
            assert layer_offset is not None

            if layer_offset is not None and layer_offset > max_offset:
                max_offset = layer_offset
                pkn_with_max_offset = int(quic_packet.packet_number)

            if hasattr(quic_packet, "stream_fin") and quic_packet.stream_fin.int_value:
                stream_fins.append(
                    {
                        "packet_number": int(quic_packet.packet_number),
                        "stream_id": int(quic_packet.stream_stream_id, base=16),
                        "offset": layer_offset,
                    }
                )

        if not stream_fins:
            msg = "Last packet that contains a stream frame does not close stream."

            if warn_only:
                cprint(f"⨯ {msg}", color="red", file=sys.stderr)

                return []
            else:
                raise FinError(msg, trace=self)
        elif len(stream_fins) == 1:
            fin_pkn: int = stream_fins[0]["packet_number"]

            if pkn_with_max_offset < 0 or fin_pkn == pkn_with_max_offset:
                return [fin_pkn]
            else:
                msg = (
                    f"Stream {stream_fins[0]['stream_id']} was closed before "
                    "the last packet was sent. "
                    f"(closed with #{fin_pkn}, max offset in #{pkn_with_max_offset})"
                )

                if warn_only:
                    cprint(f"⨯ {msg}", color="red", file=sys.stderr)

                    return []
                else:
                    raise FinError(
                        msg,
                        trace=self,
                    )
        else:
            # this may happen if the packet was re-sent
            # -> all must have same stream_id (check) and same offset

            if not all(
                fin_pkg["stream_id"] == stream_fins[0]["stream_id"]
                for fin_pkg in stream_fins
            ):
                msg = "There are multiple stream ids in this list. Is it HTTP/3?"

                if warn_only:
                    cprint(f"⨯ {msg}", color="red", file=sys.stderr)

                    return []
                else:
                    raise FinError(msg, trace=self)

            if not all(
                fin_pkg["offset"] == stream_fins[0]["offset"] for fin_pkg in stream_fins
            ):
                msg = "Stream was closed multiple times."

                if warn_only:
                    cprint(f"⨯ {msg}", color="red", file=sys.stderr)

                    return []
                else:
                    raise FinError(msg, trace=self)

            assert max_offset == stream_fins[0]["offset"]

            return [fin_pkg["packet_number"] for fin_pkg in stream_fins]


# --- for debugging ---


def parse_args():
    """Load command line args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "trace_triple",
        action="store",
        type=TraceTriple.from_str,
        help="':'-separated triples or tuples of the left pcap(ng) traces, right pcap(ng) traces and optional a keylog file.",
    )

    return parser.parse_args()


def main():
    """Interactive repl."""
    args = parse_args()

    left_trace = Trace(
        file=args.trace_triple.left_pcap_path,
        keylog_file=args.trace_triple.keylog_path,
        side=Side.LEFT,
    )
    right_trace = Trace(
        file=args.trace_triple.right_pcap_path,
        keylog_file=args.trace_triple.keylog_path,
        side=Side.RIGHT,
    )
    right_trace.pair_trace = left_trace

    cprint(
        f"Trace {Side.LEFT}: {left_trace.num_packets} packets.",
        color="green",
        attrs=["bold"],
    )
    cprint(
        f"Trace {Side.RIGHT}: {right_trace.num_packets} packets.",
        color="green",
        attrs=["bold"],
    )

    from ipdb import pm  # pylint: disable=import-outside-toplevel
    from IPython import embed  # pylint: disable=import-outside-toplevel
    from IPython import get_ipython

    # TODO launching ipdb on exception does not work, because ipython overwrites exception hook
    # -> configure ipython to launch ipdb
    embed(banner="Use pm() on exception")

    print("Done")
    sys.exit(0)


if __name__ == "__main__":
    main()
