#!/usr/bin/env python3
import datetime
import subprocess
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

import pyshark

from conf import CONFIG
from exceptions import ErrorCode, TestFailed
from utils import LOGGER

#  IP4_CLIENT = "193.167.0.100"
#  IP4_SERVER = "193.167.100.100"
#  IP6_CLIENT = "fd00:cafe:cafe:0::100"
#  IP6_SERVER = "fd00:cafe:cafe:100::100"


QUIC_V1 = hex(0x6b3343cf)


class Direction(Enum):
    ALL = 0
    FROM_CLIENT = 1
    FROM_SERVER = 2
    INVALID = 3


class PacketType(Enum):
    INITIAL = 1
    HANDSHAKE = 2
    ZERORTT = 3
    RETRY = 4
    ONERTT = 5
    VERSIONNEGOTIATION = 6
    INVALID = 7


WIRESHARK_PACKET_TYPES = {
    PacketType.INITIAL: "0",
    PacketType.ZERORTT: "1",
    PacketType.HANDSHAKE: "2",
    PacketType.RETRY: "3",
}


WIRESHARK_PACKET_TYPES_V2 = {
    PacketType.INITIAL: "1",
    PacketType.ZERORTT: "2",
    PacketType.HANDSHAKE: "3",
    PacketType.RETRY: "0",
}


def get_packet_type(p) -> PacketType:
    if p.quic.header_form == "0":
        return PacketType.ONERTT

    if p.quic.version == "0x00000000":
        return PacketType.VERSIONNEGOTIATION

    if p.quic.version == QUIC_V1:
        for t, num in WIRESHARK_PACKET_TYPES_V2.items():
            if p.quic.long_packet_type_v2 == num:
                return t

        return PacketType.INVALID

    for t, num in WIRESHARK_PACKET_TYPES.items():
        if p.quic.long_packet_type == num:
            return t

    return PacketType.INVALID


class TraceAnalyzer:
    def __init__(
        self,
        pcap_path: Path,
        ip4_client: Optional[str],
        ip6_client: Optional[str],
        ip4_server: Optional[str],
        ip6_server: Optional[str],
        keylog_file: Optional[Path] = None,
    ):
        self._pcap_path = pcap_path
        self._keylog_file = keylog_file
        self._ip4_client = ip4_client
        self._ip6_client = ip6_client
        self._ip4_server = ip4_server
        self._ip6_server = ip6_server

    def validate_pcap(self):
        """Validate that the pcap can be parsed."""
        cmd = [
            CONFIG.tshark_bin or "tshark",
            "-n",
            "-Y",
            "!quic && quic",
            # "-d",
            # "udp.port==443,quic",
            "--disable-protocol",
            "http3",
            "-r",
            self._pcap_path,
        ]

        if self._keylog_file:
            cmd.extend(
                [
                    "-o",
                    f"tls.keylog_file:{self._keylog_file}",
                ]
            )
        try:
            subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as err:
            msg = err.stderr.split(":", 1)[1].strip()
            raise TestFailed(msg, ErrorCode.BROKEN_PCAP) from err

    def get_direction(self, packet) -> Direction:
        """Return the direction of a packet."""

        if (
            hasattr(packet, "ip")
            and self._ip4_client
            and packet.ip.src == self._ip4_client
        ) or (
            hasattr(packet, "ipv6")
            and self._ip6_client
            and packet.ipv6.src == self._ip6_client
        ):
            return Direction.FROM_CLIENT

        if (
            hasattr(packet, "ip")
            and self._ip4_server
            and packet.ip.src == self._ip4_server
        ) or (
            hasattr(packet, "ipv6")
            and self._ip6_server
            and packet.ipv6.src == self._ip6_server
        ):
            return Direction.FROM_SERVER

        return Direction.INVALID

    def _get_direction_filter(self, direction: Direction) -> str:
        display_filter = "(quic && !icmp) && "

        def create_ip_filter(
            ip4_addr,
            ip6_addr,
        ) -> str:
            ip4_filter = f"ip.src=={ip4_addr}" if ip4_addr else None
            ip6_filter = f"ipv6.src=={ip6_addr}" if ip6_addr else None
            assert ip4_filter or ip6_filter

            if ip4_filter and ip6_filter:
                # use "or" connection to connect both ip filters

                return f"{display_filter} ({ip4_filter} || {ip6_filter}) && "
            else:
                ip_filter = ip4_filter or ip6_filter

                return f"{display_filter} {ip_filter} && "

        if direction == Direction.FROM_CLIENT:
            return create_ip_filter(self._ip4_client, self._ip6_client)
        elif direction == Direction.FROM_SERVER:
            return create_ip_filter(self._ip4_server, self._ip6_server)
        else:
            return display_filter

    def _get_packets(self, display_filter: str) -> List:
        override_prefs = {}

        if self._keylog_file is not None:
            override_prefs["tls.keylog_file"] = str(self._keylog_file)
        cap = pyshark.FileCapture(
            str(self._pcap_path),
            display_filter=display_filter,
            override_prefs=override_prefs,
            disable_protocol="http3",  # see https://github.com/marten-seemann/quic-interop-runner/pull/179/
            # decode_as={"udp.port==443": "quic"},
            tshark_path=CONFIG.tshark_bin,
        )

        if CONFIG.pyshark_debug:
            cap.set_debug()
        packets = []
        # If the pcap has been cut short in the middle of the packet, pyshark will crash.
        # See https://github.com/KimiNewt/pyshark/issues/390.
        try:
            for packet in cap:
                packets.append(packet)
            cap.close()
        except pyshark.capture.capture.TSharkCrashException as exc:
            LOGGER.error(exc)

        if self._keylog_file is not None:
            for packet in packets:
                if hasattr(packet["quic"], "decryption_failed"):
                    LOGGER.info("At least one QUIC packet could not be decrypted")
                    LOGGER.debug(packet)

                    break

        return packets

    def get_raw_packets(self, direction: Direction = Direction.ALL) -> List:
        packets = []

        for packet in self._get_packets(self._get_direction_filter(direction) + "quic"):
            packets.append(packet)

        return packets

    def get_1rtt(self, direction: Direction = Direction.ALL) -> List:
        """Get all QUIC packets, one or both directions."""
        packets, _, _ = self.get_1rtt_sniff_times(direction)

        return packets

    def get_1rtt_sniff_times(
        self, direction: Direction = Direction.ALL
    ) -> Tuple[List, datetime.datetime, datetime.datetime]:
        """Get all QUIC packets, one or both directions, and first and last sniff times."""
        packets = []
        first, last = 0, 0

        for packet in self._get_packets(
            self._get_direction_filter(direction) + "quic.header_form==0"
        ):
            for layer in packet.layers:
                if (
                    layer.layer_name == "quic"
                    and not hasattr(layer, "long_packet_type")
                    and not hasattr(layer, "long_packet_type_v2")
                ):
                    if first == 0:
                        first = packet.sniff_time
                    last = packet.sniff_time
                    packets.append(layer)

        return packets, first, last

    def get_vnp(self, direction: Direction = Direction.ALL) -> List:
        return self._get_packets(
            self._get_direction_filter(direction) + "quic.version==0"
        )

    def _get_long_header_packets(
        self, packet_type: PacketType, direction: Direction
    ) -> List:
        packets = []

        for packet in self._get_packets(
            self._get_direction_filter(direction)
            + "(quic.long.packet_type || quic.long.packet_type_v2)"
        ):
            for layer in packet.layers:
                if layer.layer_name == "quic" and (
                    (
                        hasattr(layer, "long_packet_type")
                        and layer.long_packet_type
                        == WIRESHARK_PACKET_TYPES[packet_type]
                    )
                    or (
                        hasattr(layer, "long_packet_type_v2")
                        and layer.long_packet_type_v2
                        == WIRESHARK_PACKET_TYPES_V2[packet_type]
                    )
                ):
                    packets.append(layer)

        return packets

    def get_initial(self, direction: Direction = Direction.ALL) -> List:
        """Get all Initial packets."""

        return self._get_long_header_packets(PacketType.INITIAL, direction)

    def get_retry(self, direction: Direction = Direction.ALL) -> List:
        """Get all Retry packets."""

        return self._get_long_header_packets(PacketType.RETRY, direction)

    def get_handshake(self, direction: Direction = Direction.ALL) -> List:
        """Get all Handshake packets."""

        return self._get_long_header_packets(PacketType.HANDSHAKE, direction)

    def get_0rtt(self) -> List:
        """Get all 0-RTT packets."""

        return self._get_long_header_packets(PacketType.ZERORTT, Direction.FROM_CLIENT)


# --- for debugging ---


def parse_args():
    """Load command line args."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "pcap",
        action="store",
        type=Path,
        help="The pcap file to load",
    )
    parser.add_argument(
        "--keylog",
        action="store",
        type=Path,
        default=None,
        help="The keylog file to load",
    )
    parser.add_argument(
        "--ip4-client",
        action="store",
        default="193.167.0.100",
    )
    parser.add_argument(
        "--ip4-server",
        action="store",
        default="193.167.100.100",
    )
    parser.add_argument(
        "--ip6-client",
        action="store",
        default=None,
    )
    parser.add_argument(
        "--ip6-server",
        action="store",
        default=None,
    )

    return parser.parse_args()


def main():
    """Interactive repl."""
    args = parse_args()

    trace = TraceAnalyzer(
        pcap_path=args.pcap,
        ip4_client=args.ip4_client,
        ip6_client=args.ip6_client,
        ip4_server=args.ip4_server,
        ip6_server=args.ip6_server,
        keylog_file=args.keylog,
    )

    from ipdb import pm  # pylint: disable=import-outside-toplevel
    from IPython import embed, get_ipython  # pylint: disable=import-outside-toplevel

    # TODO launching ipdb on exception does not work, because ipython overwrites exception hook
    # -> configure ipython to launch ipdb
    embed(banner="Use pm() on exception")

    print("Done")


if __name__ == "__main__":
    main()
