"""Test case definitions."""
import abc
import filecmp
import logging
import os
import re
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import ClassVar, Optional, Type, Union

from Crypto.Cipher import AES  # type: ignore

from custom_types import IPAddress
from enums import ECN, Perspective
from exceptions import TestFailed, TestUnsupported
from result_parser import MeasurementDescription, TestDescription
from trace_analyzer import Direction, PacketType, TraceAnalyzer, get_packet_type
from units import DataRate, FileSize, Time
from utils import random_string

LOGGER = logging.getLogger(name="quic-interop-runner")


QUIC_DRAFT = 34  # draft-34
QUIC_VERSION = hex(0x1)


def generate_cert_chain(directory: Union[str, Path], length: int = 1):
    LOGGER.debug("Generating cert chain into directory %s...", directory)
    try:
        stdout = subprocess.check_output(
            f"./certs.sh {directory} {length}",
            shell=True,
            stderr=subprocess.STDOUT,
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        LOGGER.info("Unable to create certificates")
        sys.exit(1)

    if stdout:
        LOGGER.debug("%s", stdout)


class TestCase(abc.ABC):
    data_rate: ClassVar[int] = 10 * DataRate.MBPS
    rtt = 30 * Time.MS

    def __init__(
        self,
        sim_log_dir: Path,
        client_keylog_file: Path,
        server_keylog_file: Path,
    ):
        self._server_keylog_file = server_keylog_file
        self._client_keylog_file = client_keylog_file
        self._files = list[str]()
        self._sim_log_dir = sim_log_dir
        self._www_dir: Optional[tempfile.TemporaryDirectory] = None
        self._download_dir: Optional[tempfile.TemporaryDirectory] = None
        self._cert_dir: Optional[tempfile.TemporaryDirectory] = None
        self._client_client_addrs = set[IPAddress]()
        self._client_server_addrs = set[IPAddress]()
        self._server_client_addrs = set[IPAddress]()
        self._server_server_addrs = set[IPAddress]()
        self._server_trace: Optional[TraceAnalyzer] = None
        self._client_trace: Optional[TraceAnalyzer] = None

    def set_ip_addrs(
        self,
        client_client_addrs: set[IPAddress],
        client_server_addrs: set[IPAddress],
        server_client_addrs: set[IPAddress],
        server_server_addrs: set[IPAddress],
    ):
        """
        Set the IP addresses as set of the current deployment for the current execution of the testcase.
        """
        self._client_client_addrs = client_client_addrs
        self._client_server_addrs = client_server_addrs
        self._server_client_addrs = server_client_addrs
        self._server_server_addrs = server_server_addrs

    @classmethod
    @property
    @abc.abstractmethod
    def name(cls) -> str:
        """A long string for this test."""

    @classmethod
    @property
    @abc.abstractmethod
    def abbreviation(cls) -> str:
        """A short string for this test."""

    @classmethod
    @property
    @abc.abstractmethod
    def desc(cls) -> str:
        pass

    def __str__(self):
        return self.name

    @classmethod
    def testname(cls, perspective: Perspective):
        """The name of testcase presented to the endpoint Docker images"""

        return cls.name

    @classmethod
    @property
    def scenario(cls) -> str:
        """Scenario for the ns3 simulator."""

        return " ".join(
            (
                "simple-p2p",
                f"--delay={cls.rtt / Time.MS / 2:.0f}ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                "--queue=25",
            )
        )

    @classmethod
    @property
    def timeout(cls) -> int:
        """timeout in s"""

        return 60

    @classmethod
    def to_desc(cls) -> TestDescription:
        return TestDescription(
            name=cls.name,
            abbr=cls.abbreviation,
            desc=cls.desc,
            timeout=cls.timeout,
        )

    @classmethod
    def urlprefix(cls) -> str:
        """URL prefix"""

        return "https://server4:443/"

    @classmethod
    def additional_envs(cls) -> dict[str, Union[str, int, float]]:
        """Additional environment variables."""

        return {}

    @classmethod
    @property
    def additional_containers(cls) -> list[str]:
        return []

    @property
    def www_dir(self) -> Path:
        if not self._www_dir:
            self._www_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="www_")

        return Path(self._www_dir.name)

    @property
    def download_dir(self) -> Path:
        if not self._download_dir:
            self._download_dir = tempfile.TemporaryDirectory(
                dir="/tmp", prefix="download_"
            )

        return Path(self._download_dir.name)

    @property
    def certs_dir(self) -> Path:
        if not self._cert_dir:
            self._cert_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="certs_")
            generate_cert_chain(self._cert_dir.name)

        return Path(self._cert_dir.name)

    def _is_valid_keylog(self, filename) -> bool:
        if not os.path.isfile(filename) or os.path.getsize(filename) == 0:
            return False
        with open(filename, "r") as file:
            if not re.search(
                r"^SERVER_HANDSHAKE_TRAFFIC_SECRET", file.read(), re.MULTILINE
            ):
                LOGGER.info("Key log file %s is using incorrect format.", filename)

                return False

        return True

    @property
    def _keylog_file(self) -> Optional[Path]:
        if self._is_valid_keylog(self._client_keylog_file):
            LOGGER.debug("Using the client's key log file.")

            return self._client_keylog_file
        elif self._is_valid_keylog(self._server_keylog_file):
            LOGGER.debug("Using the server's key log file.")

            return self._server_keylog_file

        LOGGER.debug("No key log file found.")

        return None

    @property
    def client_trace(self) -> TraceAnalyzer:
        if not self._client_trace:
            ipv4_client: Optional[str] = None
            ipv6_client: Optional[str] = None
            ipv4_server: Optional[str] = None
            ipv6_server: Optional[str] = None

            for ip_addr in self._client_client_addrs:
                if ip_addr.version == 4:
                    ipv4_client = ip_addr.exploded
                elif ip_addr.version == 6:
                    ipv6_client = ip_addr.exploded

            for ip_addr in self._client_server_addrs:
                if ip_addr.version == 4:
                    ipv4_server = ip_addr.exploded
                elif ip_addr.version == 6:
                    ipv6_server = ip_addr.exploded

            assert (ipv4_client or ipv6_client) and (ipv4_server or ipv6_server)

            self._client_trace = TraceAnalyzer(
                pcap_path=self._sim_log_dir / "trace_node_left.pcap",
                keylog_file=self._keylog_file,
                ip4_client=ipv4_client,
                ip6_client=ipv6_client,
                ip4_server=ipv4_server,
                ip6_server=ipv6_server,
            )

        return self._client_trace

    @property
    def server_trace(self) -> TraceAnalyzer:
        if not self._server_trace:
            ipv4_client: Optional[str] = None
            ipv6_client: Optional[str] = None
            ipv4_server: Optional[str] = None
            ipv6_server: Optional[str] = None

            for ip_addr in self._server_client_addrs:
                if ip_addr.version == 4:
                    ipv4_client = ip_addr.exploded
                elif ip_addr.version == 6:
                    ipv6_client = ip_addr.exploded

            for ip_addr in self._server_server_addrs:
                if ip_addr.version == 4:
                    ipv4_server = ip_addr.exploded
                elif ip_addr.version == 6:
                    ipv6_server = ip_addr.exploded

            assert (ipv4_client or ipv6_client) and (ipv4_server or ipv6_server)

            self._server_trace = TraceAnalyzer(
                pcap_path=self._sim_log_dir / "trace_node_right.pcap",
                keylog_file=self._keylog_file,
                ip4_client=ipv4_client,
                ip6_client=ipv6_client,
                ip4_server=ipv4_server,
                ip6_server=ipv6_server,
            )

        return self._server_trace

    def _generate_random_file(self, size: int, filename_len=10) -> str:
        """See https://www.stefanocappellini.it/generate-pseudorandom-bytes-with-python/ for benchmarks"""
        filename = random_string(filename_len)
        enc = AES.new(os.urandom(32), AES.MODE_OFB, b"a" * 16)
        with (self.www_dir / filename).open("wb") as file:
            file.write(enc.encrypt(b" " * size))
        LOGGER.debug("Generated random file: %s of size: %d", filename, size)

        return filename

    def _retry_sent(self) -> bool:
        return len(self.client_trace.get_retry()) > 0

    def _check_version_and_files(self):
        versions = [hex(int(v, 0)) for v in self._get_versions()]

        if len(versions) != 1:
            raise TestFailed(f"Expected exactly one version. Got {versions}")

        if QUIC_VERSION not in versions:
            raise TestFailed(f"Wrong version. Expected {QUIC_VERSION}, got {versions}")

        if len(self._files) == 0:
            raise AssertionError("No test files generated.")

        files = [
            n.name
            for n in self.download_dir.iterdir()
            if (self.download_dir / n).is_file()
        ]
        too_many = [f for f in files if f not in self._files]

        if len(too_many) != 0:
            raise TestFailed(f"Found unexpected downloaded files: {too_many}")

        too_few = [f for f in self._files if f not in files]

        if len(too_few) != 0:
            raise TestFailed(f"Missing files: {too_few}")

        for file_name in self._files:
            file_path = self.download_dir / file_name

            if not os.path.isfile(file_path):
                raise TestFailed(f"File {file_path} does not exist.")

            try:
                size = (self.www_dir / file_name).stat().st_size
                downloaded_size = os.path.getsize(file_path)

                if size != downloaded_size:
                    raise TestFailed(
                        f"File size of {file_path} doesn't match. "
                        f"Original: {size} bytes, downloaded: {downloaded_size} bytes.",
                    )

                if not filecmp.cmp(self.www_dir / file_name, file_path, shallow=False):
                    raise TestFailed(f"File contents of {file_path} do not match.")

            except Exception as exception:
                raise TestFailed(
                    f"Could not compare files {self.www_dir / file_name} and {file_path}: {exception}",
                ) from exception

        LOGGER.debug("Check of downloaded files succeeded.")

    def _check_handshakes(self, expected_num):
        """Count the number of QUIC handshakes and check if it equals the expected amount."""
        # Determine the number of handshakes by looking at Initial packets.
        # This is easier, since the SCID of Initial packets doesn't changes.

        num_handshakes = len(
            {
                packet.scid
                for packet in self.server_trace.get_initial(Direction.FROM_SERVER)
            }
        )

        if num_handshakes != expected_num:
            raise TestFailed(
                f"Expected exactly {expected_num} handshake{'' if expected_num == 1 else 's'}."
                f" Got: {num_handshakes}"
            )

    def _get_versions(self) -> set:
        """Get the QUIC versions"""

        return {
            packet.version
            for packet in self.server_trace.get_initial(Direction.FROM_SERVER)
        }

    def _payload_size(self, packets: list) -> int:
        """Get the sum of the payload sizes of all packets"""
        size = 0

        for packet in packets:
            if hasattr(packet, "long_packet_type"):
                if hasattr(packet, "payload"):  # when keys are available
                    size += len(packet.payload.split(":"))
                else:
                    size += len(packet.remaining_payload.split(":"))
            else:
                if hasattr(packet, "protected_payload"):
                    size += len(packet.protected_payload.split(":"))

        return size

    def _check_traces(self):
        self.server_trace.validate_pcap()
        self.client_trace.validate_pcap()

    def _check_keylog(self):
        if not self._keylog_file:
            raise TestUnsupported("Can't check test result. SSLKEYLOG required.")

    def cleanup(self):
        if self._www_dir:
            self._www_dir.cleanup()
            self._www_dir = None

        if self._download_dir:
            self._download_dir.cleanup()
            self._download_dir = None

        # clear traces
        del self._server_trace
        self._server_trace = None
        del self._client_trace
        self._client_trace = None

    def __del__(self):
        self.cleanup()

    @abc.abstractmethod
    def get_paths(self) -> list[str]:
        pass

    @abc.abstractmethod
    def check(self):
        pass


class Measurement(TestCase):
    _result: Optional[float] = None

    @property
    def result(self) -> Optional[float]:
        return self._result

    @classmethod
    @property
    @abc.abstractmethod
    def theoretical_max_value(cls) -> Union[float, int]:
        """Return the maximum value, that could be reached theoretically in ``unit``."""

    @classmethod
    @property
    @abc.abstractmethod
    def unit(cls) -> str:
        pass

    @classmethod
    @property
    @abc.abstractmethod
    def repetitions(cls) -> int:
        pass

    @classmethod
    def to_desc(cls) -> MeasurementDescription:
        return MeasurementDescription(
            name=cls.name,
            abbr=cls.abbreviation,
            desc=cls.desc,
            timeout=cls.timeout,
            theoretical_max_value=cls.theoretical_max_value,
            repetitions=cls.repetitions,
        )


class TestCaseVersionNegotiation(TestCase):
    @classmethod
    @property
    def name(cls):
        """A longer human and machine readable name. Used e.g. in path names."""

        return "versionnegotiation"

    @classmethod
    @property
    def abbreviation(cls):
        return "V"

    @classmethod
    @property
    def desc(cls):
        return "A version negotiation packet is elicited and acted on."

    def get_paths(self):
        return [""]

    def check(self):
        self._check_traces()
        initials = self.client_trace.get_initial(Direction.FROM_CLIENT)
        dcid = ""

        for packet in initials:
            dcid = packet.dcid

            break

        if dcid == "":
            raise TestFailed("Didn't find an Initial / a DCID.")

        vnps = self.client_trace.get_vnp()

        for packet in vnps:
            if packet.scid == dcid:
                return

        raise TestFailed("Didn't find a Version Negotiation Packet with matching SCID.")


class TestCaseHandshake(TestCase):
    @classmethod
    @property
    def name(cls):
        return "handshake"

    @classmethod
    @property
    def abbreviation(cls):
        return "H"

    @classmethod
    @property
    def desc(cls):
        return "Handshake completes successfully."

    def get_paths(self):
        self._files = [self._generate_random_file(1 * FileSize.KiB)]

        return self._files

    def check(self):
        self._check_traces()
        self._check_version_and_files()

        if self._retry_sent():
            raise TestFailed("Didn't expect a Retry to be sent.")

        self._check_handshakes(1)


class TestCaseLongRTT(TestCaseHandshake):
    rtt = 1500 * Time.MS
    data_rate = 10 * DataRate.MBPS
    queue_size = 25

    @classmethod
    @property
    def abbreviation(cls):
        return "LR"

    @classmethod
    @property
    def name(cls):
        return "longrtt"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "handshake"

    @classmethod
    @property
    def desc(cls):
        return f"Handshake completes when RTT is very high ({cls.rtt / Time.S:.1f} s)."

    @classmethod
    @property
    def scenario(cls) -> str:
        return " ".join(
            (
                "simple-p2p",
                f"--delay={cls.rtt / Time.MS / 2:.0f}ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                f"--queue={cls.queue_size}",
            )
        )

    def check(self):
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()

        num_ch = 0

        for packet in self.client_trace.get_initial(Direction.FROM_CLIENT):
            if hasattr(packet, "tls_handshake_type"):
                if packet.tls_handshake_type == "1":
                    num_ch += 1

        if num_ch < 2:
            raise TestFailed(f"Expected at least 2 ClientHellos. Got: {num_ch}")


class TestCaseTransfer(TestCase):
    @classmethod
    @property
    def name(cls):
        return "transfer"

    @classmethod
    @property
    def abbreviation(cls):
        return "DC"

    @classmethod
    @property
    def desc(cls):
        return "Stream data is being sent and received correctly. Connection close completes with a zero error code."

    def get_paths(self):
        self._files = [
            self._generate_random_file(2 * FileSize.MiB),
            self._generate_random_file(3 * FileSize.MiB),
            self._generate_random_file(5 * FileSize.MiB),
        ]

        return self._files

    def check(self):
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()


class TestCaseChaCha20(TestCase):
    @classmethod
    @property
    def name(cls):
        return "chacha20"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "chacha20"

    @classmethod
    @property
    def abbreviation(cls):
        return "C20"

    @classmethod
    @property
    def desc(cls):
        return "Handshake completes using ChaCha20."

    def get_paths(self):
        self._files = [self._generate_random_file(3 * FileSize.MiB)]

        return self._files

    def check(self):
        self._check_traces()
        self._check_handshakes(1)

        ciphersuites = set()

        for packet in self.client_trace.get_initial(Direction.FROM_CLIENT):
            if hasattr(packet, "tls_handshake_ciphersuite"):
                ciphersuites.add(packet.tls_handshake_ciphersuite)

        if len(ciphersuites) != 1 or "4867" not in ciphersuites:
            raise TestFailed(
                f"Expected only ChaCha20 cipher suite to be offered. Got: {ciphersuites}"
            )

        self._check_version_and_files()


class TestCaseMultiplexing(TestCase):
    @classmethod
    @property
    def name(cls):
        return "multiplexing"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "transfer"

    @classmethod
    @property
    def abbreviation(cls):
        return "M"

    @classmethod
    @property
    def desc(cls):
        return "Thousands of files are transferred over a single connection, and server increased stream limits to accomodate client requests."

    def get_paths(self):
        for _ in range(1, 2000):
            self._files.append(self._generate_random_file(32))

        return self._files

    def check(self):
        self._check_keylog()
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()

        # Check that the server set a bidirectional stream limit <= 1000
        checked_stream_limit = False

        for packet in self.client_trace.get_handshake(Direction.FROM_SERVER):
            if hasattr(packet, "tls.quic.parameter.initial_max_streams_bidi"):
                checked_stream_limit = True
                stream_limit = int(
                    getattr(packet, "tls.quic.parameter.initial_max_streams_bidi")
                )
                LOGGER.debug("Server set bidirectional stream limit: %d", stream_limit)

                if stream_limit > 1000:
                    raise TestFailed("Server set a stream limit > 1000.")

        if not checked_stream_limit:
            raise TestFailed("Couldn't check stream limit.")


class TestCaseRetry(TestCase):
    @classmethod
    @property
    def name(cls):
        return "retry"

    @classmethod
    @property
    def abbreviation(cls):
        return "S"

    @classmethod
    @property
    def desc(cls):
        return "Server sends a Retry, and a subsequent connection using the Retry token completes successfully."

    def get_paths(self):
        self._files = [
            self._generate_random_file(10 * FileSize.KiB),
        ]

        return self._files

    def _check_trace(self):
        """Check that (at least) one Retry packet was actually sent."""
        tokens = []
        retries = self.client_trace.get_retry(Direction.FROM_SERVER)

        for packet in retries:
            if not hasattr(packet, "retry_token"):
                raise TestFailed(f"Retry packet doesn't have a retry_token: {packet}")

            tokens += [packet.retry_token.replace(":", "")]

        if len(tokens) == 0:
            raise TestFailed("Didn't find any Retry packets.")

        # check that an Initial packet uses a token sent in the Retry packet(s)
        highest_pn_before_retry = -1

        for packet in self.client_trace.get_initial(Direction.FROM_CLIENT):
            packet_number = int(packet.packet_number)

            if packet.token_length == "0":
                highest_pn_before_retry = max(highest_pn_before_retry, packet_number)

                continue

            if packet_number <= highest_pn_before_retry:
                raise TestFailed(
                    f"Client reset the packet number. Check failed for PN {packet_number}"
                )

            token = packet.token.replace(":", "")

            if token in tokens:
                LOGGER.debug("Check of Retry succeeded. Token used: %s", token)

                return True

        raise TestFailed("Didn't find any Initial packet using a Retry token.")

    def check(self):
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()
        self._check_trace()


class TestCaseResumption(TestCase):
    @classmethod
    @property
    def name(cls):
        return "resumption"

    @classmethod
    @property
    def abbreviation(cls):
        return "R"

    @classmethod
    @property
    def desc(cls):
        return "Connection is established using TLS Session Resumption."

    def get_paths(self):
        self._files = [
            self._generate_random_file(5 * FileSize.KiB),
            self._generate_random_file(10 * FileSize.KiB),
        ]

        return self._files

    def check(self):
        self._check_keylog()
        self._check_traces()
        self._check_handshakes(2)

        handshake_packets = self.client_trace.get_handshake(Direction.FROM_SERVER)
        cids = [p.scid for p in handshake_packets]
        first_handshake_has_cert = False

        for packet in handshake_packets:
            if packet.scid == cids[0]:
                if hasattr(packet, "tls_handshake_certificates_length"):
                    first_handshake_has_cert = True
            elif packet.scid == cids[len(cids) - 1]:  # second handshake
                if hasattr(packet, "tls_handshake_certificates_length"):
                    raise TestFailed(
                        "Server sent a Certificate message in the second handshake."
                    )

            else:
                raise TestFailed(
                    "Found handshake packet that neither belongs to the first nor the second handshake."
                )

        if not first_handshake_has_cert:
            raise TestFailed(
                "Didn't find a Certificate message in the first handshake. That's weird."
            )

        self._check_version_and_files()


class TestCaseZeroRTT(TestCase):
    NUM_FILES = 40
    FILESIZE = 32  # in bytes
    FILENAMELEN = 250

    @classmethod
    @property
    def name(cls):
        return "zerortt"

    @classmethod
    @property
    def abbreviation(cls):
        return "Z"

    @classmethod
    @property
    def desc(cls):
        return "0-RTT data is being sent and acted on."

    def get_paths(self):
        for _ in range(self.NUM_FILES):
            self._files.append(
                self._generate_random_file(self.FILESIZE, self.FILENAMELEN)
            )

        return self._files

    def check(self):
        self._check_traces()
        self._check_handshakes(2)
        self._check_version_and_files()

        zero_rtt_size = self._payload_size(self.client_trace.get_0rtt())
        one_rtt_size = self._payload_size(
            self.client_trace.get_1rtt(Direction.FROM_CLIENT)
        )
        LOGGER.debug("0-RTT size: %d", zero_rtt_size)
        LOGGER.debug("1-RTT size: %d", one_rtt_size)

        if zero_rtt_size == 0:
            raise TestFailed("Client didn't send any 0-RTT data.")

        if one_rtt_size > 0.5 * self.FILENAMELEN * self.NUM_FILES:
            raise TestFailed("Client sent too much data in 1-RTT packets.")


class TestCaseHTTP3(TestCase):
    @classmethod
    @property
    def name(cls):
        return "http3"

    @classmethod
    @property
    def abbreviation(cls):
        return "3"

    @classmethod
    @property
    def desc(cls):
        return "An H3 transaction succeeded."

    def get_paths(self):
        self._files = [
            self._generate_random_file(5 * FileSize.KiB),
            self._generate_random_file(10 * FileSize.KiB),
            self._generate_random_file(500 * FileSize.KiB),
        ]

        return self._files

    def check(self):
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()


class TestCaseAmplificationLimit(TestCase):
    @classmethod
    @property
    def name(cls):
        return "amplificationlimit"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "transfer"

    @classmethod
    @property
    def abbreviation(cls):
        return "A"

    @classmethod
    @property
    def desc(cls):
        return "The server obeys the 3x amplification limit."

    @property
    def certs_dir(self):
        if not self._cert_dir:
            self._cert_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="certs_")
            generate_cert_chain(self._cert_dir.name, 9)

        return Path(self._cert_dir.name)

    @classmethod
    @property
    def scenario(cls) -> str:
        # Let the ClientHello pass, but drop a bunch of retransmissions afterwards.

        return " ".join(
            (
                "droplist",
                "--delay=15ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                "--queue=25",
                "--drops_to_server=2,3,4,5,6,7",
            )
        )

    def get_paths(self):
        self._files = [self._generate_random_file(5 * FileSize.KiB)]

        return self._files

    def check(self):
        self._check_keylog()
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()

        # Check the highest offset of CRYPTO frames sent by the server.
        # This way we can make sure that it actually used the provided cert chain.
        max_handshake_offset = 0

        for packet in self.server_trace.get_handshake(Direction.FROM_SERVER):
            if hasattr(packet, "crypto_offset"):
                max_handshake_offset = max(
                    max_handshake_offset,
                    int(packet.crypto_offset) + int(packet.crypto_length),
                )

        if max_handshake_offset < 7500:
            raise TestFailed(
                f"Server sent too little Handshake CRYPTO data ({max_handshake_offset} bytes)."
                " Not using the provided cert chain?",
            )

        LOGGER.debug(
            "Server sent %d bytes in Handshake CRYPTO frames.", max_handshake_offset
        )

        # Check that the server didn't send more than 3-4x what the client sent.
        allowed = 0
        allowed_with_tolerance = 0
        client_sent, server_sent = 0, 0  # only for debug messages
        failed = True
        log_output = []

        for packet in self.server_trace.get_raw_packets():
            direction = self.server_trace.get_direction(packet)
            packet_type = get_packet_type(packet)

            if packet_type == PacketType.VERSIONNEGOTIATION:
                raise TestFailed("Didn't expect a Version Negotiation packet.")

            packet_size = int(packet.udp.length) - 8  # subtract the UDP header length

            if packet_type == PacketType.INVALID:
                raise TestFailed("Couldn't determine packet type.")

            if direction == Direction.FROM_CLIENT:
                if packet_type is PacketType.HANDSHAKE:
                    failed = False

                if packet_type is PacketType.INITIAL:
                    client_sent += packet_size
                    allowed += 3 * packet_size
                    allowed_with_tolerance += 4 * packet_size
                    log_output.append(
                        f"Received a {packet_size} byte Initial packet from the client."
                        f" Amplification limit: {3 * client_sent}"
                    )
            elif direction == Direction.FROM_SERVER:
                server_sent += packet_size
                log_output.append(
                    f"Received a {packet_size} byte Handshake packet from the server."
                    f" Total: {server_sent}"
                )

                if packet_size >= allowed_with_tolerance:
                    log_output.append("Server violated the amplification limit.")

                    break

                if packet_size > allowed:
                    log_output.append(
                        "Server violated the amplification limit, but stayed within 3-4x amplification. Letting it slide."
                    )
                allowed_with_tolerance -= packet_size
                allowed -= packet_size
            else:
                raise TestFailed("Couldn't determine sender of packet.")

        if failed:
            raise TestFailed("\n".join(log_output))
        else:
            for msg in log_output:
                LOGGER.debug(msg)


class TestCaseBlackhole(TestCase):
    @classmethod
    @property
    def name(cls):
        return "blackhole"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "transfer"

    @classmethod
    @property
    def abbreviation(cls):
        return "B"

    @classmethod
    @property
    def desc(cls):
        return "Transfer succeeds despite underlying network blacking out for a few seconds."

    @classmethod
    @property
    def scenario(cls) -> str:
        return " ".join(
            (
                "blackhole",
                "--delay=15ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                "--queue=25",
                "--on=5s",
                "--off=2s",
            )
        )

    def get_paths(self):
        self._files = [self._generate_random_file(10 * FileSize.MiB)]

        return self._files

    def check(self):
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()


class TestCaseKeyUpdate(TestCaseHandshake):
    @classmethod
    @property
    def name(cls):
        return "keyupdate"

    @classmethod
    def testname(cls, perspective: Perspective):
        if perspective is Perspective.CLIENT:
            return "keyupdate"

        return "transfer"

    @classmethod
    @property
    def abbreviation(cls):
        return "U"

    @classmethod
    @property
    def desc(cls):
        return "One of the two endpoints updates keys and the peer responds correctly."

    def get_paths(self):
        self._files = [self._generate_random_file(3 * FileSize.MiB)]

        return self._files

    def check(self):
        self._check_keylog()
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()

        client = {0: 0, 1: 0}
        server = {0: 0, 1: 0}
        try:
            for packet in self.client_trace.get_1rtt(Direction.FROM_CLIENT):
                client[int(packet.key_phase)] += 1

            for packet in self.server_trace.get_1rtt(Direction.FROM_SERVER):
                server[int(packet.key_phase)] += 1
        except Exception as exc:
            raise TestFailed(
                "Failed to read key phase bits. Potentially incorrect SSLKEYLOG?"
            ) from exc

        succeeded = client[1] * server[1] > 0

        log_level = logging.INFO

        if succeeded:
            log_level = logging.DEBUG

        LOGGER.log(
            log_level,
            "Client sent %d key phase 0 and %d key phase 1 packets.",
            client[0],
            client[1],
        )
        LOGGER.log(
            log_level,
            "Server sent %d key phase 0 and %d key phase 1 packets.",
            server[0],
            server[1],
        )

        if not succeeded:
            raise TestFailed(
                "Expected to see packets sent with key phase 1 from both client and server."
            )


class TestCaseHandshakeLoss(TestCase):
    _num_runs = 50

    @classmethod
    @property
    def name(cls):
        return "handshakeloss"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "multiconnect"

    @classmethod
    @property
    def abbreviation(cls):
        return "L1"

    @classmethod
    @property
    def desc(cls):
        return "Handshake completes under extreme packet loss."

    @classmethod
    @property
    def timeout(cls) -> int:
        return 300

    @classmethod
    @property
    def scenario(cls) -> str:
        return " ".join(
            (
                "drop-rate",
                "--delay=15ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                "--queue=25",
                "--rate_to_server=30",
                "--rate_to_client=30",
            )
        )

    def get_paths(self):
        for _ in range(self._num_runs):
            self._files.append(self._generate_random_file(1 * FileSize.KiB))

        return self._files

    def check(self):
        self._check_traces()
        self._check_handshakes(self._num_runs)
        self._check_version_and_files()


class TestCaseTransferLoss(TestCase):
    @classmethod
    @property
    def name(cls):
        return "transferloss"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "transfer"

    @classmethod
    @property
    def abbreviation(cls):
        return "L2"

    @classmethod
    @property
    def desc(cls):
        return "Transfer completes under moderate packet loss."

    @classmethod
    @property
    def scenario(cls) -> str:
        return " ".join(
            (
                "drop-rate",
                "--delay=15ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                "--queue=25",
                "--rate_to_server=2",
                "--rate_to_client=2",
            )
        )

    def get_paths(self):
        # At a packet loss rate of 2% and a MTU of 1500 bytes, we can expect 27 dropped packets.
        self._files = [self._generate_random_file(2 * FileSize.MiB)]

        return self._files

    def check(self):
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()


class TestCaseHandshakeCorruption(TestCaseHandshakeLoss):
    @classmethod
    @property
    def name(cls):
        return "handshakecorruption"

    @classmethod
    @property
    def abbreviation(cls):
        return "C1"

    @classmethod
    @property
    def desc(cls):
        return "Handshake completes under extreme packet corruption."

    @classmethod
    @property
    def scenario(cls) -> str:
        return " ".join(
            (
                "corrupt-rate",
                "--delay=15ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                "--queue=25",
                "--rate_to_server=30",
                "--rate_to_client=30",
            )
        )


class TestCaseTransferCorruption(TestCaseTransferLoss):
    @classmethod
    @property
    def name(cls):
        return "transfercorruption"

    @classmethod
    @property
    def abbreviation(cls):
        return "C2"

    @classmethod
    @property
    def desc(cls):
        return "Transfer completes under moderate packet corruption."

    @classmethod
    @property
    def scenario(cls) -> str:
        return " ".join(
            (
                "corrupt-rate",
                "--delay=15ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                "--queue=25",
                "--rate_to_server=2",
                "--rate_to_client=2",
            )
        )


class TestCaseECN(TestCaseHandshake):
    @classmethod
    @property
    def name(cls):
        return "ecn"

    @classmethod
    @property
    def abbreviation(cls):
        return "E"

    def _count_ecn(self, trace):
        ecn = [0] * (max(ECN) + 1)

        for packet in trace:
            e = int(getattr(packet["ip"], "dsfield.ecn"))
            ecn[e] += 1

        for e in ECN:
            LOGGER.debug("%s %d", e, ecn[e])

        return ecn

    def _check_ecn_any(self, e) -> bool:
        return e[ECN.ECT0] != 0 or e[ECN.ECT1] != 0

    def _check_ecn_marks(self, e) -> bool:
        return (
            e[ECN.NONE] == 0
            and e[ECN.CE] == 0
            and ((e[ECN.ECT0] == 0) != (e[ECN.ECT1] == 0))
        )

    def _check_ack_ecn(self, tr) -> bool:
        # NOTE: We only check whether the trace contains any ACK-ECN information, not whether it is valid

        for p in tr:
            if hasattr(p["quic"], "ack.ect0_count"):
                return True

        return False

    def check(self):
        self._check_keylog()
        self._check_traces()

        super(TestCaseECN, self).check()

        tr_client = self.client_trace._get_packets(
            self.client_trace._get_direction_filter(Direction.FROM_CLIENT) + " quic"
        )
        ecn = self._count_ecn(tr_client)
        ecn_client_any_marked = self._check_ecn_any(ecn)
        ecn_client_all_ok = self._check_ecn_marks(ecn)
        ack_ecn_client_ok = self._check_ack_ecn(tr_client)

        tr_server = self.server_trace._get_packets(
            self.server_trace._get_direction_filter(Direction.FROM_SERVER) + " quic"
        )
        ecn = self._count_ecn(tr_server)
        ecn_server_any_marked = self._check_ecn_any(ecn)
        ecn_server_all_ok = self._check_ecn_marks(ecn)
        ack_ecn_server_ok = self._check_ack_ecn(tr_server)

        msgs = list[str]()

        if ecn_client_any_marked is False:
            msgs.append("Client did not mark any packets ECT(0) or ECT(1)")
        else:
            if ack_ecn_server_ok is False:
                msgs.append("Server did not send any ACK-ECN frames")
            elif ecn_client_all_ok is False:
                msgs.append(
                    "Not all client packets were consistently marked with ECT(0) or ECT(1)"
                )

        if ecn_server_any_marked is False:
            msgs.append("Server did not mark any packets ECT(0) or ECT(1)")
        else:
            if ack_ecn_client_ok is False:
                msgs.append("Client did not send any ACK-ECN frames")
            elif ecn_server_all_ok is False:
                msgs.append(
                    "Not all server packets were consistently marked with ECT(0) or ECT(1)"
                )

        if (
            ecn_client_all_ok
            and ecn_server_all_ok
            and ack_ecn_client_ok
            and ack_ecn_server_ok
        ):
            return

        raise TestFailed("\n".join(msgs))


class TestCasePortRebinding(TestCaseTransfer):
    @classmethod
    @property
    def name(cls):
        return "rebind-port"

    @classmethod
    @property
    def abbreviation(cls):
        return "BP"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "transfer"

    @classmethod
    @property
    def desc(cls):
        return "Transfer completes under frequent port rebindings on the client side."

    def get_paths(self):
        self._files = [
            self._generate_random_file(10 * FileSize.MiB),
        ]

        return self._files

    @classmethod
    @property
    def scenario(cls) -> str:
        return " ".join(
            (
                "rebind",
                "--delay=15ms",
                f"--bandwidth={cls.data_rate // DataRate.MBPS}Mbps",
                "--queue=25",
                "--first-rebind=1s",
                "--rebind-freq=5s",
            )
        )

    def check(self):
        self._check_keylog()
        self._check_traces()
        super(TestCasePortRebinding, self).check()

        tr_server = self.server_trace._get_packets(
            self.server_trace._get_direction_filter(Direction.FROM_SERVER) + " quic"
        )

        ports = list(set(getattr(p["udp"], "dstport") for p in tr_server))

        LOGGER.info("Server saw these client ports: %s", ports)

        if len(ports) <= 1:
            raise TestFailed(
                "Server saw only a single client port in use; test broken?"
            )

        last = None
        num_migrations = 0

        for p in tr_server:
            cur = (
                getattr(p["ipv6"], "dst")
                if "IPV6" in str(p.layers)
                else getattr(p["ip"], "dst"),
                int(getattr(p["udp"], "dstport")),
            )

            if last is None:
                last = cur

                continue

            if last != cur:
                last = cur
                num_migrations += 1
                # packet to different IP/port, should have a PATH_CHALLENGE frame

                if hasattr(p["quic"], "path_challenge.data") is False:
                    raise TestFailed(
                        f"First server packet to new client destination {cur} did not contain"
                        f" a PATH_CHALLENGE frame.\n"
                        f"{p['quic']}",
                    )

        tr_client = self.client_trace._get_packets(
            self.client_trace._get_direction_filter(Direction.FROM_CLIENT) + " quic"
        )

        challenges = list(
            set(
                getattr(p["quic"], "path_challenge.data")
                for p in tr_server
                if hasattr(p["quic"], "path_challenge.data")
            )
        )

        if len(challenges) < num_migrations:
            raise TestFailed(
                f"Saw {len(challenges)} migrations, "
                f"but only {num_migrations} unique PATH_CHALLENGE frames",
            )

        responses = list(
            set(
                getattr(p["quic"], "path_response.data")
                for p in tr_client
                if hasattr(p["quic"], "path_response.data")
            )
        )

        unresponded = [c for c in challenges if c not in responses]

        if unresponded:
            raise TestFailed(f"PATH_CHALLENGE without a PATH_RESPONSE: {unresponded}")


class TestCaseAddressRebinding(TestCasePortRebinding):
    @classmethod
    @property
    def name(cls):
        return "rebind-addr"

    @classmethod
    @property
    def abbreviation(cls):
        return "BA"

    @classmethod
    @property
    def desc(cls):
        return "Transfer completes under frequent IP address and port rebindings on the client side."

    @classmethod
    @property
    def scenario(cls) -> str:
        """Scenario for the ns3 simulator"""

        return (
            super(TestCaseAddressRebinding, TestCaseAddressRebinding).scenario
            + " --rebind-addr"
        )

    def check(self):
        self._check_keylog()
        self._check_traces()

        tr_server = self.server_trace._get_packets(
            self.server_trace._get_direction_filter(Direction.FROM_SERVER) + " quic"
        )

        ips = set()

        for p in tr_server:
            ip_vers = "ip"

            if "IPV6" in str(p.layers):
                ip_vers = "ipv6"
            ips.add(getattr(p[ip_vers], "dst"))

        LOGGER.info("Server saw these client addresses: %s", ips)

        if len(ips) <= 1:
            raise TestFailed(
                "Server saw only a single client IP address in use; test broken?"
            )

        super(TestCaseAddressRebinding, self).check()


class TestCaseIPv6(TestCaseTransfer):
    @classmethod
    @property
    def name(cls):
        return "ipv6"

    @classmethod
    @property
    def abbreviation(cls):
        return "6"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "transfer"

    @staticmethod
    def urlprefix() -> str:
        return "https://server6:443/"

    @classmethod
    @property
    def desc(cls):
        return "A transfer across an IPv6-only network succeeded."

    def get_paths(self):
        self._files = [
            self._generate_random_file(5 * FileSize.KiB),
            self._generate_random_file(10 * FileSize.KiB),
        ]

        return self._files

    def check(self):
        super().check()

        tr_server = self.server_trace._get_packets(
            self.server_trace._get_direction_filter(Direction.FROM_SERVER)
            + " quic && ip"
        )

        if tr_server:
            raise TestFailed(f"Packet trace contains {len(tr_server)} IPv4 packets.")


class TestCaseConnectionMigration(TestCaseAddressRebinding):
    @classmethod
    @property
    def name(cls):
        return "connectionmigration"

    @classmethod
    @property
    def abbreviation(cls):
        return "CM"

    @classmethod
    def testname(cls, perspective: Perspective):
        if perspective is Perspective.CLIENT:
            return "connectionmigration"

        return "transfer"

    @classmethod
    @property
    def desc(cls):
        return "A transfer succeeded during which the client performed an active migration."

    @classmethod
    @property
    def scenario(cls) -> str:
        return super(TestCaseTransfer, TestCaseTransfer).scenario

    def get_paths(self):
        self._files = [
            self._generate_random_file(2 * FileSize.MiB),
        ]

        return self._files

    def check(self):
        # The parent check() method ensures that the client changed addresses
        # and that PATH_CHALLENGE/RESPONSE frames were sent and received
        super().check()

        tr_client = self.client_trace._get_packets(
            self.client_trace._get_direction_filter(Direction.FROM_CLIENT) + " quic"
        )

        last = None
        dcid = None

        for p in tr_client:
            cur = (
                getattr(p["ipv6"], "src")
                if "IPV6" in str(p.layers)
                else getattr(p["ip"], "src"),
                int(getattr(p["udp"], "srcport")),
            )

            if last is None:
                last = cur
                dcid = getattr(p["quic"], "dcid")

                continue

            if last != cur:
                last = cur
                # packet to different IP/port, should have a new DCID

                if dcid == getattr(p["quic"], "dcid"):
                    raise TestFailed(
                        f"First client packet during active migration to {cur}"
                        f" used previous DCID {dcid}.\n"
                        f"{p['quic']}"
                    )

                dcid = getattr(p["quic"], "dcid")
                LOGGER.info(
                    "DCID changed to %s during active migration to %s", dcid, cur
                )


class MeasurementGoodput(Measurement):
    FILESIZE = 10 * FileSize.MiB

    @classmethod
    @property
    def name(cls):
        return "goodput"

    @classmethod
    @property
    def unit(cls) -> str:
        return "kbps"

    @classmethod
    def testname(cls, perspective: Perspective):
        return "transfer"

    @classmethod
    @property
    def abbreviation(cls):
        return "G"

    @classmethod
    @property
    def desc(cls):
        return "Measures connection goodput over a 10Mbps link."

    @classmethod
    @property
    def theoretical_max_value(cls):
        return cls.data_rate / DataRate.KBPS
        # return 1 / ((1 / cls.data_rate) + (cls.rtt / cls.FILESIZE)) / DataRate.KBPS

    @classmethod
    @property
    def repetitions(cls) -> int:
        return 2

    def get_paths(self):
        self._files = [self._generate_random_file(self.FILESIZE)]

        return self._files

    def check(self):
        self._check_traces()
        self._check_handshakes(1)
        self._check_version_and_files()

        packets = self.client_trace.get_1rtt(Direction.FROM_SERVER)
        packet_times: list[timedelta] = [packet.sniff_time for packet in packets]
        first = min(packet_times)
        last = max(packet_times)
        time = last - first

        if not time:
            raise TestFailed("No time difference between first an last packet.")

        time_ms = time.total_seconds() * 1000
        goodput_kbps = (8 * self.FILESIZE) / time_ms
        LOGGER.debug(
            "Transferring %d MiB took %d ms. Goodput: %d kbps",
            self.FILESIZE / FileSize.MiB,
            time_ms,
            goodput_kbps,
        )
        self._result = goodput_kbps


class MeasurementCrossTraffic(MeasurementGoodput):
    FILESIZE = 25 * FileSize.MiB

    @classmethod
    @property
    def name(cls):
        return "crosstraffic"

    @classmethod
    @property
    def abbreviation(cls):
        return "C"

    @classmethod
    @property
    def desc(cls):
        return "Measures goodput over a 10Mbps link when competing with a TCP (cubic) connection."

    @classmethod
    @property
    def timeout(cls) -> int:
        return 180

    @staticmethod
    def additional_envs() -> dict[str, Union[str, int, float]]:
        return {"IPERF_CONGESTION": "cubic"}

    @classmethod
    @property
    def additional_containers(cls) -> list[str]:
        return ["iperf_server", "iperf_client"]


class MeasurementSatellite(MeasurementGoodput):
    FILESIZE = 10 * FileSize.MiB
    rtt = 600 * Time.MS
    forward_data_rate = 20 * DataRate.MBPS
    return_data_rate = 2 * DataRate.MBPS
    queue_size = 25

    @classmethod
    @property
    def name(cls):
        return "sat"

    @classmethod
    @property
    def abbreviation(cls):
        return "SAT"

    @classmethod
    @property
    def desc(cls):
        return (
            "Measures connection goodput over a satellite link. "
            f"File: {int(cls.FILESIZE / FileSize.MiB)} MiB; "
            f"RTT: {cls.rtt / Time.MS:.0f} ms; "
            f"Data Rate: {cls.forward_data_rate // DataRate.MBPS}/{cls.return_data_rate // DataRate.MBPS} Mbps; "
        )

    @classmethod
    @property
    def theoretical_max_value(cls):
        return cls.forward_data_rate / DataRate.KBPS

    @classmethod
    @property
    def repetitions(cls) -> int:
        #  return 3

        return 2

    @classmethod
    @property
    def scenario(cls) -> str:
        return (
            "asymmetric-p2p "
            f"--delay={cls.rtt / Time.MS // 2}ms "
            f"--forward-data-rate={cls.forward_data_rate // DataRate.MBPS}Mbps "
            f"--return-data-rate={cls.return_data_rate // DataRate.MBPS}Mbps "
            f"--forward-queue={cls.queue_size} "
            f"--return-queue={cls.queue_size}"
        )

    @classmethod
    @property
    def timeout(cls) -> int:
        """timeout in s"""

        return 120


class MeasurementSatelliteLoss(MeasurementSatellite):

    drop_rate_percent: ClassVar[int] = 1

    @classmethod
    @property
    def name(cls):
        return "satloss"

    @classmethod
    @property
    def abbreviation(cls):
        return "SATL"

    @classmethod
    @property
    def desc(cls):
        return (
            "Measures connection goodput over a lossy satellite link. "
            f"File: {int(cls.FILESIZE / FileSize.MiB)} MiB; "
            f"RTT: {cls.rtt / Time.MS:.0f} ms; "
            f"Data Rate: {cls.forward_data_rate // DataRate.MBPS}/{cls.return_data_rate // DataRate.MBPS} Mbps; "
            f"Loss Rate: {cls.drop_rate_percent} %"
        )

    #  @classmethod
    #  @property
    #  def theoretical_max_value(cls):
    #      return cls.forward_data_rate * (1 - cls.drop_rate_percent / 100) / DataRate.KBPS

    @classmethod
    @property
    def scenario(cls) -> str:
        return (
            f"{super().scenario} "
            f"--drop-rate-to-server={cls.drop_rate_percent} "
            f"--drop-rate-to-client={cls.drop_rate_percent} "
        )

    @classmethod
    @property
    def timeout(cls) -> int:
        """timeout in s"""

        return super().timeout * 3


class MeasurementRealLink(MeasurementGoodput):
    forward_data_rate: int
    return_data_rate: int

    @classmethod
    @property
    def name(cls):
        return "realLink"

    @classmethod
    @property
    def abbreviation(cls):
        return "LNK"

    @classmethod
    @property
    def desc(cls):
        return (
            "Measures connection goodput over a real network link. "
            f"File: {int(cls.FILESIZE / FileSize.MiB)} MiB; "
        )

    @classmethod
    @property
    def theoretical_max_value(cls):
        return cls.forward_data_rate / DataRate.KBPS

    @classmethod
    @property
    def client_docker_host(cls) -> str:
        """The Docker URL to the remote host, where the client should be deployed."""

        return "remote_client"

    @classmethod
    @property
    def server_docker_host(cls) -> str:
        """The Docker URL to the remote host, where the server should be deployed."""

        return "remote_server"

    @classmethod
    @property
    def timeout(cls) -> int:
        """timeout in s"""

        return 120


class MeasurementStarlink(MeasurementRealLink):
    """Measurement over a starlink connection."""

    # https://www.starlink.com/faq : 50..150 Mbit/s
    forward_data_rate = 150 * DataRate.MBPS
    return_data_rate = 150 * DataRate.MBPS

    @classmethod
    @property
    def name(cls):
        return "starlink"

    @classmethod
    @property
    def abbreviation(cls):
        return "SL"

    @classmethod
    @property
    def desc(cls):
        return (
            "Measures connection goodput over a starlink network link (LEO). "
            f"File: {int(cls.FILESIZE / FileSize.MiB)} MiB; "
        )

    @classmethod
    @property
    def client_docker_host(cls) -> str:
        return "starlink_client"


class MeasurementAstra(MeasurementRealLink):
    forward_data_rate = 20 * DataRate.MBPS
    return_data_rate = 2 * DataRate.MBPS

    @classmethod
    @property
    def name(cls):
        return "astra"

    @classmethod
    @property
    def abbreviation(cls):
        return "AST"

    @classmethod
    @property
    def desc(cls):
        return (
            "Measures connection goodput over an astra network link (GEO). "
            f"File: {int(cls.FILESIZE / FileSize.MiB)} MiB; "
            f"Data Rate: 20/2 MiB"
        )

    @classmethod
    @property
    def client_docker_host(cls) -> str:
        return "astra_client"


class MeasurementEutelsat(MeasurementRealLink):
    forward_data_rate = 50 * DataRate.MBPS
    return_data_rate = 5 * DataRate.MBPS

    @classmethod
    @property
    def name(cls):
        return "eutelsat"

    @classmethod
    @property
    def abbreviation(cls):
        return "EUT"

    @classmethod
    @property
    def desc(cls):
        return (
            "Measures connection goodput over a eutelsat network link (GEO). "
            f"File: {int(cls.FILESIZE / FileSize.MiB)} MiB; "
            f"Data Rate: 50/5 MiB"
        )

    @classmethod
    @property
    def client_docker_host(cls) -> str:
        return "eutelsat_client"


TESTCASES: list[Type[TestCase]] = [
    TestCaseHandshake,
    TestCaseTransfer,
    TestCaseLongRTT,
    TestCaseChaCha20,
    TestCaseMultiplexing,
    TestCaseRetry,
    TestCaseResumption,
    TestCaseZeroRTT,
    TestCaseHTTP3,
    TestCaseBlackhole,
    TestCaseKeyUpdate,
    TestCaseECN,
    TestCaseAmplificationLimit,
    TestCaseHandshakeLoss,
    TestCaseTransferLoss,
    TestCaseHandshakeCorruption,
    TestCaseTransferCorruption,
    TestCaseIPv6,
    # The next three tests are disabled due to Wireshark not being able
    # to decrypt packets sent on the new path.
    # TestCasePortRebinding,
    # TestCaseAddressRebinding,
    # TestCaseConnectionMigration,
]

MEASUREMENTS: list[Type[Measurement]] = [
    MeasurementGoodput,
    MeasurementCrossTraffic,
    MeasurementSatellite,
    MeasurementSatelliteLoss,
    MeasurementRealLink,
    MeasurementStarlink,
    MeasurementAstra,
    MeasurementEutelsat,
]
