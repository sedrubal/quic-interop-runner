import abc
import filecmp
import logging
import os
import random
import re
import string
import subprocess
import sys
import tempfile
from datetime import timedelta
from enum import Enum, IntEnum
from functools import cached_property
from pathlib import Path
from typing import ClassVar, Optional, Type, Union

from Crypto.Cipher import AES

from custom_types import IPAddress
from result import TestResult
from trace_analyzer import Direction, PacketType, TraceAnalyzer, get_packet_type

LOGGER = logging.getLogger(name="quic-interop-runner")


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


QUIC_DRAFT = 34  # draft-34
QUIC_VERSION = hex(0x1)


class Perspective(Enum):
    SERVER = "server"
    CLIENT = "client"


class ECN(IntEnum):
    NONE = 0
    ECT1 = 1
    ECT0 = 2
    CE = 3


def random_string(length: int):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase

    return "".join(random.choice(letters) for i in range(length))


def generate_cert_chain(directory: str, length: int = 1):
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
        pass

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
    def to_json(cls) -> dict:
        return {
            "name": cls.name,
            "desc": cls.desc,
        }

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

    @cached_property
    def _client_trace(self):
        ipv4_client: Optional[str] = None
        ipv6_client: Optional[str] = None
        ipv4_server: Optional[str] = None
        ipv6_server: Optional[str] = None

        for ip_addr in self._client_client_addrs:
            if ip_addr.version == 4:
                ipv4_client = ip_addr.exploded
            elif ip_addr.version == 6:
                ipv4_client = ip_addr.exploded

        for ip_addr in self._client_server_addrs:
            if ip_addr.version == 4:
                ipv4_server = ip_addr.exploded
            elif ip_addr.version == 6:
                ipv4_server = ip_addr.exploded

        assert (ipv4_client or ipv6_client) and (ipv4_server or ipv6_server)

        return TraceAnalyzer(
            pcap_path=self._sim_log_dir / "trace_node_left.pcap",
            keylog_file=self._keylog_file,
            ip4_client=ipv4_client,
            ip6_client=ipv6_client,
            ip4_server=ipv4_server,
            ip6_server=ipv6_server,
        )

    @cached_property
    def _server_trace(self):
        ipv4_client: Optional[str] = None
        ipv6_client: Optional[str] = None
        ipv4_server: Optional[str] = None
        ipv6_server: Optional[str] = None

        for ip_addr in self._server_client_addrs:
            if ip_addr.version == 4:
                ipv4_client = ip_addr.exploded
            elif ip_addr.version == 6:
                ipv4_client = ip_addr.exploded

        for ip_addr in self._server_server_addrs:
            if ip_addr.version == 4:
                ipv4_server = ip_addr.exploded
            elif ip_addr.version == 6:
                ipv4_server = ip_addr.exploded

        assert (ipv4_client or ipv6_client) and (ipv4_server or ipv6_server)

        return TraceAnalyzer(
            pcap_path=self._sim_log_dir / "trace_node_right.pcap",
            keylog_file=self._keylog_file,
            ip4_client=ipv4_client,
            ip6_client=ipv6_client,
            ip4_server=ipv4_server,
            ip6_server=ipv6_server,
        )

    def _generate_random_file(self, size: int, filename_len=10) -> str:
        """See https://www.stefanocappellini.it/generate-pseudorandom-bytes-with-python/ for benchmarks"""
        filename = random_string(filename_len)
        enc = AES.new(os.urandom(32), AES.MODE_OFB, b"a" * 16)
        with (self.www_dir / filename).open("wb") as file:
            file.write(enc.encrypt(b" " * size))
        LOGGER.debug("Generated random file: %s of size: %d", filename, size)

        return filename

    def _retry_sent(self) -> bool:
        return len(self._client_trace.get_retry()) > 0

    def _check_version_and_files(self) -> bool:
        versions = [hex(int(v, 0)) for v in self._get_versions()]

        if len(versions) != 1:
            LOGGER.info("Expected exactly one version. Got %s", versions)

            return False

        if QUIC_VERSION not in versions:
            LOGGER.info("Wrong version. Expected %s, got %s", QUIC_VERSION, versions)

            return False

        if len(self._files) == 0:
            raise Exception("No test files generated.")
        files = [
            n.name
            for n in self.download_dir.iterdir()
            if (self.download_dir / n).is_file()
        ]
        too_many = [f for f in files if f not in self._files]

        if len(too_many) != 0:
            LOGGER.info("Found unexpected downloaded files: %s", too_many)
        too_few = [f for f in self._files if f not in files]

        if len(too_few) != 0:
            LOGGER.info("Missing files: %s", too_few)

        if len(too_many) != 0 or len(too_few) != 0:
            return False

        for file_name in self._files:
            file_path = self.download_dir / file_name

            if not os.path.isfile(file_path):
                LOGGER.info("File %s does not exist.", file_path)

                return False
            try:
                size = (self.www_dir / file_name).stat().st_size
                downloaded_size = os.path.getsize(file_path)

                if size != downloaded_size:
                    LOGGER.info(
                        "File size of %s doesn't match. Original: %d bytes, downloaded: %d bytes.",
                        file_path,
                        size,
                        downloaded_size,
                    )

                    return False

                if not filecmp.cmp(self.www_dir / file_name, file_path, shallow=False):
                    LOGGER.info("File contents of %s do not match.", file_path)

                    return False
            except Exception as exception:
                LOGGER.info(
                    "Could not compare files %s and %s: %s",
                    self.www_dir / file_name,
                    file_path,
                    exception,
                )

                return False
        LOGGER.debug("Check of downloaded files succeeded.")

        return True

    def _count_handshakes(self) -> int:
        """Count the number of QUIC handshakes"""
        # Determine the number of handshakes by looking at Initial packets.
        # This is easier, since the SCID of Initial packets doesn't changes.

        return len(
            {
                packet.scid
                for packet in self._server_trace.get_initial(Direction.FROM_SERVER)
            }
        )

    def _get_versions(self) -> set:
        """Get the QUIC versions"""

        return {
            packet.version
            for packet in self._server_trace.get_initial(Direction.FROM_SERVER)
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

    def cleanup(self):
        if self._www_dir:
            self._www_dir.cleanup()
            self._www_dir = None

        if self._download_dir:
            self._download_dir.cleanup()
            self._download_dir = None

    @abc.abstractmethod
    def get_paths(self) -> list[str]:
        pass

    @abc.abstractmethod
    def check(self) -> TestResult:
        pass


class Measurement(TestCase):
    _result = 0.0

    @property
    def result(self) -> float:
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
    def to_json(cls) -> dict:
        return {
            **super().to_json(),
            **{
                "theoretical_max_value": cls.theoretical_max_value,
                "repetitions": cls.repetitions,
            },
        }


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

    def check(self) -> TestResult:
        initials = self._client_trace.get_initial(Direction.FROM_CLIENT)
        dcid = ""

        for packet in initials:
            dcid = packet.dcid

            break

        if dcid == "":
            LOGGER.info("Didn't find an Initial / a DCID.")

            return TestResult.FAILED

        vnps = self._client_trace.trace.get_vnp()

        for packet in vnps:
            if packet.scid == dcid:
                return TestResult.SUCCEEDED

        LOGGER.info("Didn't find a Version Negotiation Packet with matching SCID.")

        return TestResult.FAILED


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

    def check(self) -> TestResult:
        if not self._check_version_and_files():
            return TestResult.FAILED

        if self._retry_sent():
            LOGGER.info("Didn't expect a Retry to be sent.")

            return TestResult.FAILED
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED
        num_ch = 0

        for packet in self._client_trace.get_initial(Direction.FROM_CLIENT):
            if hasattr(packet, "tls_handshake_type"):
                if packet.tls_handshake_type == "1":
                    num_ch += 1

        if num_ch < 2:
            LOGGER.info("Expected at least 2 ClientHellos. Got: %d", num_ch)

            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        ciphersuites = set()

        for packet in self._client_trace.get_initial(Direction.FROM_CLIENT):
            if hasattr(packet, "tls_handshake_ciphersuite"):
                ciphersuites.add(packet.tls_handshake_ciphersuite)

        if len(ciphersuites) != 1 or "4867" not in ciphersuites:
            LOGGER.info(
                "Expected only ChaCha20 cipher suite to be offered. Got: %s",
                ciphersuites,
            )

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        if not self._keylog_file:
            LOGGER.info("Can't check test result. SSLKEYLOG required.")

            return TestResult.UNSUPPORTED
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED
        # Check that the server set a bidirectional stream limit <= 1000
        checked_stream_limit = False

        for packet in self._client_trace.get_handshake(Direction.FROM_SERVER):
            if hasattr(packet, "tls.quic.parameter.initial_max_streams_bidi"):
                checked_stream_limit = True
                stream_limit = int(
                    getattr(packet, "tls.quic.parameter.initial_max_streams_bidi")
                )
                LOGGER.debug("Server set bidirectional stream limit: %d", stream_limit)

                if stream_limit > 1000:
                    LOGGER.info("Server set a stream limit > 1000.")

                    return TestResult.FAILED

        if not checked_stream_limit:
            LOGGER.info("Couldn't check stream limit.")

            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def _check_trace(self) -> bool:
        # check that (at least) one Retry packet was actually sent
        tokens = []
        retries = self._client_trace.get_retry(Direction.FROM_SERVER)

        for packet in retries:
            if not hasattr(packet, "retry_token"):
                LOGGER.info("Retry packet doesn't have a retry_token")
                LOGGER.info(packet)

                return False
            tokens += [packet.retry_token.replace(":", "")]

        if len(tokens) == 0:
            LOGGER.info("Didn't find any Retry packets.")

            return False

        # check that an Initial packet uses a token sent in the Retry packet(s)
        highest_pn_before_retry = -1

        for packet in self._client_trace.get_initial(Direction.FROM_CLIENT):
            pn = int(packet.packet_number)

            if packet.token_length == "0":
                highest_pn_before_retry = max(highest_pn_before_retry, pn)

                continue

            if pn <= highest_pn_before_retry:
                LOGGER.debug(
                    "Client reset the packet number. Check failed for PN %d", pn
                )

                return False

            token = packet.token.replace(":", "")

            if token in tokens:
                LOGGER.debug("Check of Retry succeeded. Token used: %s", token)

                return True
        LOGGER.info("Didn't find any Initial packet using a Retry token.")

        return False

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        if not self._check_trace():
            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        if not self._keylog_file:
            LOGGER.info("Can't check test result. SSLKEYLOG required.")

            return TestResult.UNSUPPORTED
        num_handshakes = self._count_handshakes()

        if num_handshakes != 2:
            LOGGER.info("Expected exactly 2 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        handshake_packets = self._client_trace.get_handshake(Direction.FROM_SERVER)
        cids = [p.scid for p in handshake_packets]
        first_handshake_has_cert = False

        for packet in handshake_packets:
            if packet.scid == cids[0]:
                if hasattr(packet, "tls_handshake_certificates_length"):
                    first_handshake_has_cert = True
            elif packet.scid == cids[len(cids) - 1]:  # second handshake
                if hasattr(packet, "tls_handshake_certificates_length"):
                    LOGGER.info(
                        "Server sent a Certificate message in the second handshake."
                    )

                    return TestResult.FAILED
            else:
                LOGGER.info(
                    "Found handshake packet that neither belongs to the first nor the second handshake."
                )

                return TestResult.FAILED

        if not first_handshake_has_cert:
            LOGGER.info(
                "Didn't find a Certificate message in the first handshake. That's weird."
            )

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 2:
            LOGGER.info("Expected exactly 2 handshakes. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        zeroRTTSize = self._payload_size(self._client_trace.get_0rtt())
        oneRTTSize = self._payload_size(
            self._client_trace.get_1rtt(Direction.FROM_CLIENT)
        )
        LOGGER.debug("0-RTT size: %d", zeroRTTSize)
        LOGGER.debug("1-RTT size: %d", oneRTTSize)

        if zeroRTTSize == 0:
            LOGGER.info("Client didn't send any 0-RTT data.")

            return TestResult.FAILED

        if oneRTTSize > 0.5 * self.FILENAMELEN * self.NUM_FILES:
            LOGGER.info("Client sent too much data in 1-RTT packets.")

            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        if not self._keylog_file:
            LOGGER.info("Can't check test result. SSLKEYLOG required.")

            return TestResult.UNSUPPORTED
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED
        # Check the highest offset of CRYPTO frames sent by the server.
        # This way we can make sure that it actually used the provided cert chain.
        max_handshake_offset = 0

        for packet in self._server_trace.get_handshake(Direction.FROM_SERVER):
            if hasattr(packet, "crypto_offset"):
                max_handshake_offset = max(
                    max_handshake_offset,
                    int(packet.crypto_offset) + int(packet.crypto_length),
                )

        if max_handshake_offset < 7500:
            LOGGER.info(
                "Server sent too little Handshake CRYPTO data (%d bytes). Not using the provided cert chain?",
                max_handshake_offset,
            )

            return TestResult.FAILED
        LOGGER.debug(
            "Server sent %d bytes in Handshake CRYPTO frames.", max_handshake_offset
        )

        # Check that the server didn't send more than 3-4x what the client sent.
        allowed = 0
        allowed_with_tolerance = 0
        client_sent, server_sent = 0, 0  # only for debug messages
        res = TestResult.FAILED
        log_output = []

        for packet in self._server_trace.get_raw_packets():
            direction = self._server_trace.get_direction(packet)
            packet_type = get_packet_type(packet)

            if packet_type == PacketType.VERSIONNEGOTIATION:
                LOGGER.info("Didn't expect a Version Negotiation packet.")

                return TestResult.FAILED
            packet_size = int(packet.udp.length) - 8  # subtract the UDP header length

            if packet_type == PacketType.INVALID:
                LOGGER.debug("Couldn't determine packet type.")

                return TestResult.FAILED

            if direction == Direction.FROM_CLIENT:
                if packet_type is PacketType.HANDSHAKE:
                    res = TestResult.SUCCEEDED

                    break

                if packet_type is PacketType.INITIAL:
                    client_sent += packet_size
                    allowed += 3 * packet_size
                    allowed_with_tolerance += 4 * packet_size
                    log_output.append(
                        "Received a {} byte Initial packet from the client. Amplification limit: {}".format(
                            packet_size, 3 * client_sent
                        )
                    )
            elif direction == Direction.FROM_SERVER:
                server_sent += packet_size
                log_output.append(
                    "Received a {} byte Handshake packet from the server. Total: {}".format(
                        packet_size, server_sent
                    )
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
                LOGGER.debug("Couldn't determine sender of packet.")

                return TestResult.FAILED

        log_level = logging.DEBUG

        if res == TestResult.FAILED:
            log_level = logging.INFO

        for msg in log_output:
            LOGGER.log(log_level, msg)

        return res


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

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        return TestResult.SUCCEEDED


class TestCaseKeyUpdate(TestCaseHandshake):
    @classmethod
    @property
    def name(cls):
        return "keyupdate"

    @classmethod
    def testname(cls, perspective: Perspective):
        if p is Perspective.CLIENT:
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

    def check(self) -> TestResult:
        if not self._keylog_file:
            LOGGER.info("Can't check test result. SSLKEYLOG required.")

            return TestResult.UNSUPPORTED

        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        client = {0: 0, 1: 0}
        server = {0: 0, 1: 0}
        try:
            for packet in self._client_trace.get_1rtt(Direction.FROM_CLIENT):
                client[int(packet.key_phase)] += 1

            for packet in self._server_trace.get_1rtt(Direction.FROM_SERVER):
                server[int(packet.key_phase)] += 1
        except Exception:
            LOGGER.info(
                "Failed to read key phase bits. Potentially incorrect SSLKEYLOG?"
            )

            return TestResult.FAILED

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
            LOGGER.info(
                "Expected to see packets sent with key phase 1 from both client and server."
            )

            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != self._num_runs:
            LOGGER.info(
                "Expected %d handshakes. Got: %d", self._num_runs, num_handshakes
            )

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def _count_ecn(self, tr):
        ecn = [0] * (max(ECN) + 1)

        for p in tr:
            e = int(getattr(p["ip"], "dsfield.ecn"))
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

    def check(self) -> TestResult:
        if not self._keylog_file:
            LOGGER.info("Can't check test result. SSLKEYLOG required.")

            return TestResult.UNSUPPORTED

        result = super(TestCaseECN, self).check()

        if result != TestResult.SUCCEEDED:
            return result

        tr_client = self._client_trace._get_packets(
            self._client_trace._get_direction_filter(Direction.FROM_CLIENT) + " quic"
        )
        ecn = self._count_ecn(tr_client)
        ecn_client_any_marked = self._check_ecn_any(ecn)
        ecn_client_all_ok = self._check_ecn_marks(ecn)
        ack_ecn_client_ok = self._check_ack_ecn(tr_client)

        tr_server = self._server_trace._get_packets(
            self._server_trace._get_direction_filter(Direction.FROM_SERVER) + " quic"
        )
        ecn = self._count_ecn(tr_server)
        ecn_server_any_marked = self._check_ecn_any(ecn)
        ecn_server_all_ok = self._check_ecn_marks(ecn)
        ack_ecn_server_ok = self._check_ack_ecn(tr_server)

        if ecn_client_any_marked is False:
            LOGGER.info("Client did not mark any packets ECT(0) or ECT(1)")
        else:
            if ack_ecn_server_ok is False:
                LOGGER.info("Server did not send any ACK-ECN frames")
            elif ecn_client_all_ok is False:
                LOGGER.info(
                    "Not all client packets were consistently marked with ECT(0) or ECT(1)"
                )

        if ecn_server_any_marked is False:
            LOGGER.info("Server did not mark any packets ECT(0) or ECT(1)")
        else:
            if ack_ecn_client_ok is False:
                LOGGER.info("Client did not send any ACK-ECN frames")
            elif ecn_server_all_ok is False:
                LOGGER.info(
                    "Not all server packets were consistently marked with ECT(0) or ECT(1)"
                )

        if (
            ecn_client_all_ok
            and ecn_server_all_ok
            and ack_ecn_client_ok
            and ack_ecn_server_ok
        ):
            return TestResult.SUCCEEDED

        return TestResult.FAILED


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

    def check(self) -> TestResult:
        if not self._keylog_file:
            LOGGER.info("Can't check test result. SSLKEYLOG required.")

            return TestResult.UNSUPPORTED

        result = super(TestCasePortRebinding, self).check()

        if result != TestResult.SUCCEEDED:
            return result

        tr_server = self._server_trace._get_packets(
            self._server_trace._get_direction_filter(Direction.FROM_SERVER) + " quic"
        )

        ports = list(set(getattr(p["udp"], "dstport") for p in tr_server))

        LOGGER.info("Server saw these client ports: %s", ports)

        if len(ports) <= 1:
            LOGGER.info("Server saw only a single client port in use; test broken?")

            return TestResult.FAILED

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
                    LOGGER.info(
                        "First server packet to new client destination %s did not contain a PATH_CHALLENGE frame",
                        cur,
                    )
                    LOGGER.info(p["quic"])

                    return TestResult.FAILED

        tr_client = self._client_trace._get_packets(
            self._client_trace._get_direction_filter(Direction.FROM_CLIENT) + " quic"
        )

        challenges = list(
            set(
                getattr(p["quic"], "path_challenge.data")
                for p in tr_server
                if hasattr(p["quic"], "path_challenge.data")
            )
        )

        if len(challenges) < num_migrations:
            LOGGER.info(
                "Saw %d migrations, but only %d unique PATH_CHALLENGE frames",
                len(challenges),
                num_migrations,
            )

            return TestResult.FAILED

        responses = list(
            set(
                getattr(p["quic"], "path_response.data")
                for p in tr_client
                if hasattr(p["quic"], "path_response.data")
            )
        )

        unresponded = [c for c in challenges if c not in responses]

        if unresponded != []:
            LOGGER.info("PATH_CHALLENGE without a PATH_RESPONSE: %s", unresponded)

            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        if not self._keylog_file:
            LOGGER.info("Can't check test result. SSLKEYLOG required.")

            return TestResult.UNSUPPORTED

        tr_server = self._server_trace._get_packets(
            self._server_trace._get_direction_filter(Direction.FROM_SERVER) + " quic"
        )

        ips = set()

        for p in tr_server:
            ip_vers = "ip"

            if "IPV6" in str(p.layers):
                ip_vers = "ipv6"
            ips.add(getattr(p[ip_vers], "dst"))

        LOGGER.info("Server saw these client addresses: %s", ips)

        if len(ips) <= 1:
            LOGGER.info(
                "Server saw only a single client IP address in use; test broken?"
            )

            return TestResult.FAILED

        result = super(TestCaseAddressRebinding, self).check()

        if result != TestResult.SUCCEEDED:
            return result

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        result = super(TestCaseIPv6, self).check()

        if result != TestResult.SUCCEEDED:
            return result

        tr_server = self._server_trace._get_packets(
            self._server_trace._get_direction_filter(Direction.FROM_SERVER)
            + " quic && ip"
        )

        if tr_server:
            LOGGER.info("Packet trace contains %s IPv4 packets.", len(tr_server))

            return TestResult.FAILED

        return TestResult.SUCCEEDED


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

    def check(self) -> TestResult:
        # The parent check() method ensures that the client changed addresses
        # and that PATH_CHALLENGE/RESPONSE frames were sent and received
        result = super(TestCaseConnectionMigration, self).check()

        if result != TestResult.SUCCEEDED:
            return result

        tr_client = self._client_trace._get_packets(
            self._client_trace._get_direction_filter(Direction.FROM_CLIENT) + " quic"
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
                    LOGGER.info(
                        "First client packet during active migration to %s used previous DCID %s",
                        cur,
                        dcid,
                    )
                    LOGGER.info(p["quic"])

                    return TestResult.FAILED
                dcid = getattr(p["quic"], "dcid")
                LOGGER.info(
                    "DCID changed to %s during active migration to %s", dcid, cur
                )

        return TestResult.SUCCEEDED


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

    #  @classmethod
    #  @property
    #  def theoretical_max_value(cls):
    #      return 1 / ((1 / cls.data_rate) + (cls.rtt / cls.FILESIZE)) / DataRate.KBPS

    @classmethod
    @property
    def repetitions(cls) -> int:
        return 2

    def get_paths(self):
        self._files = [self._generate_random_file(self.FILESIZE)]

        return self._files

    def check(self) -> TestResult:
        num_handshakes = self._count_handshakes()

        if num_handshakes != 1:
            LOGGER.info("Expected exactly 1 handshake. Got: %d", num_handshakes)

            return TestResult.FAILED

        if not self._check_version_and_files():
            return TestResult.FAILED

        packets = self._client_trace.get_1rtt(Direction.FROM_SERVER)
        packet_times: list[timedelta] = [packet.sniff_time for packet in packets]
        first = min(packet_times)
        last = max(packet_times)
        time = last - first

        if not time:
            return TestResult.FAILED

        time_ms = time.total_seconds() * 1000
        goodput_kbps = (8 * self.FILESIZE) / time_ms
        LOGGER.debug(
            "Transferring %d MiB took %d ms. Goodput: %d kbps",
            self.FILESIZE / FileSize.MiB,
            time_ms,
            goodput_kbps,
        )
        self._result = goodput_kbps

        return TestResult.SUCCEEDED


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
    _result = 0.0

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

    # TODO
    #  @classmethod
    #  @property
    #  def theoretical_max_value(cls):
    #      return cls.forward_data_rate / DataRate.KBPS

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


class MeasurementAstra(MeasurementRealLink):
    ...


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
]
