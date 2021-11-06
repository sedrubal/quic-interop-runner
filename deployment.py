#!/usr/bin/env python3
"""Deployment using Docker and SSH (for remote hosts)."""

import concurrent.futures
import ipaddress
import logging
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

import docker
import paramiko
from termcolor import colored

from conf import CONFIG
from custom_types import IPAddress
from docker_utils import (
    Container,
    Network,
    copy_file_from_container,
    copy_file_to_container,
    copy_tree_from_container,
    copy_tree_to_container,
    force_same_img_version,
    get_client_ips,
    negotiate_server_ip,
    remove_containers,
)
from enums import ImplementationRole as Role
from implementations import IMPLEMENTATIONS, Implementation
from testcases import MeasurementRealLink, Perspective, TestCase
from utils import TerminalFormatter, random_string

MEMLOCK_ULIMIT = docker.types.Ulimit(name="memlock", hard=67108864, soft=67108864)
IPERF_ENDPOINT_IMG = "martenseemann/quic-interop-iperf-endpoint"
SIM_IMG = "therealsedrubal/quic-network-simulator"
TCPDUMP_IMG = "therealsedrubal/tcpdump:main"

VOID_NETWORK = "none"

# Pathes inside the containers
DOWNLOADS_PATH = Path("/downloads")
CERTS_PATH = Path("/certs")
WWW_PATH = Path("/www")
LOGS_PATH = Path("/logs")
SSLKEYLOG_FILE = LOGS_PATH / "keys.log"
QLOG_DIR = LOGS_PATH / "qlog/"
TRACE_PATH = Path("/trace.pcap")


REAL_LINK_SETUP_SCRIPT = Path(__file__).parent / "real_link_setup.sh"

LOGGER = logging.getLogger(name="quic-interop-runner")


class ContainerStatus(Enum):
    CREATED = "created"
    RUNNING = "running"
    EXITED = "exited"


class IPVersion(Enum):
    V4 = 4
    V6 = 6


class Stage(Enum):
    PRE = 0
    SERVER_PRE = 10
    SERVER = 20
    SERVER_POST = 30
    CLIENT_PRE = 40
    CLIENT = 50
    CLIENT_POST = 60
    POST = 70


@dataclass
class NetworkSpec:
    name: str
    subnet_v4: ipaddress.IPv4Network
    subnet_v6: ipaddress.IPv6Network

    def get_subnet(self, version: IPVersion):
        return self.subnet_v4 if version == IPVersion.V4 else self.subnet_v6


NETWORKS: dict[Role, NetworkSpec] = {
    Role.CLIENT: NetworkSpec(
        name="leftnet",
        subnet_v4=ipaddress.IPv4Network("193.167.0.0/24"),
        subnet_v6=ipaddress.IPv6Network("fd00:cafe:cafe:0::/64"),
    ),
    Role.SERVER: NetworkSpec(
        name="rightnet",
        subnet_v4=ipaddress.IPv4Network("193.167.100.0/24"),
        subnet_v6=ipaddress.IPv6Network("fd00:cafe:cafe:100::/64"),
    ),
}


def get_container_name(container: Container) -> str:
    return container.labels.get("de.sedrubal.interop.service", container.name)


def get_container_status(container: Container) -> ContainerStatus:
    container.reload()

    return ContainerStatus(container.status)


@dataclass
class LogLine:
    container: Container
    line: str
    color_index: int
    max_container_name_len: int

    COLORS = [
        "green",
        "yellow",
        "blue",
        "magenta",
        "cyan",
        "red",
    ]

    @property
    def container_name(self) -> str:
        return get_container_name(self.container)

    @property
    def ljusted_container_name(self) -> str:
        return self.container_name.ljust(self.max_container_name_len)

    @property
    def color(self):
        return self.COLORS[self.color_index]

    @property
    def colored_container_name(self):
        return colored(self.ljusted_container_name, color=self.color)

    def formatted(self):
        return f"{self.colored_container_name} | {self.line}"

    def __str__(self):
        return self.formatted()


Log = list[LogLine]


@dataclass
class ExecResult:
    log: Log
    timed_out: bool
    failed: bool
    exit_codes: dict[str, int]
    ip_addrs: dict[str, set[IPAddress]]

    def __str__(self):
        log_str = f"log: {len(self.log)} lines"

        if self.timed_out:
            return f"<Result: Timeout; {log_str}>"

        exit_codes_str = " ".join(
            f"{container}: {code}" for container, code in self.exit_codes.items()
        )

        return f"<Result: {exit_codes_str}; {log_str}>"


def container_monitor_thread(
    container: Container,
    log_callback: Callable[[Container, str, bool], None],
    end_callback: Callable[[], None],
    status_changed_callback: Callable[[Container, ContainerStatus], None],
):
    status = get_container_status(container)
    assert status == ContainerStatus.CREATED
    log_callback(container, "Starting...", False)
    try:
        container.start()
    except docker.errors.APIError as err:
        log_callback(container, str(err), False)
        status_changed_callback(container, status)
        end_callback()

        return

    while True:
        new_status = get_container_status(container)

        if new_status != status:
            status = new_status
            log_callback(container, status.value, False)
            status_changed_callback(container, status)

            break

    for chunk in container.logs(stream=True):
        try:
            chunk_str = chunk.decode("utf-8")
        except UnicodeDecodeError:
            chunk_str = str(chunk)

        log_callback(container, chunk_str, True)

    # container stopped

    new_status = get_container_status(container)

    if new_status != status:
        status = new_status
        log_callback(container, status.value, False)

    try:
        result = container.wait()
    except paramiko.ssh_exception.ChannelException as exc:
        LOGGER.error(str(exc))

        return

    error = result.pop("Error", None)
    exit_code = result.pop("StatusCode", None)

    if error:
        raise Exception(error)

    if exit_code is not None:
        log_callback(container, f"exit status {exit_code}", False)

    if result:
        LOGGER.warning("Unknown contianer result: %s", str(result))

    new_status = get_container_status(container)

    if new_status != status:
        status = new_status
        log_callback(container, status.value, False)

    # stop all containers when one container exits
    end_callback()


class Deployment:

    project_name = "quic-interop-runner"

    def __init__(self):
        self._networks: dict[Role, Optional[Network]] = {
            Role.SERVER: None,
            Role.CLIENT: None,
        }
        self._docker_clis = dict[str, docker.DockerClient]()
        self._stage_status_cv = threading.Condition()
        self.docker_host_urls = CONFIG.docker_host_urls

    def get_docker_cli(self, name="default"):
        if name not in self._docker_clis.keys():
            self._docker_clis[name] = docker.DockerClient(self.docker_host_urls[name])

        return self._docker_clis[name]

    def run_and_wait(
        self,
        containers: list[Container],
        timeout: int,
        hooks: dict[Stage, list[Callable[[], None]]] = {},
    ) -> ExecResult:
        """Return logs and timed_out."""
        containers_by_stage = defaultdict[Stage, list[Container]](list[Container])

        for container in containers:
            containers_by_stage[
                Stage(int(container.labels["de.sedrubal.interop.stage"]))
            ].append(container)

        max_container_name_len = max(
            len(get_container_name(container)) for container in containers
        )
        logs = list[LogLine]()

        def log_buf(container: Container):
            line = data_structure[container].log_buf

            if not line:
                return
            data_structure[container].log_buf = ""
            log_line = LogLine(
                container=container,
                line=line,
                color_index=containers.index(container) % len(LogLine.COLORS),
                max_container_name_len=max_container_name_len,
            )
            LOGGER.debug(log_line.formatted())
            logs.append(log_line)

        def log_callback(container: Container, msg: str, is_chunk=False):
            for char in msg:
                if char == "\n":
                    log_buf(container)
                else:
                    data_structure[container].log_buf += char

            if not is_chunk:
                log_buf(container)

        def status_changed_callback(container: Container, status: ContainerStatus):
            with self._stage_status_cv:
                data_structure[container].status = status
                self._stage_status_cv.notify()

                if status == ContainerStatus.RUNNING:
                    # save IP address of container
                    data_structure[container].ip_addrs = {
                        ipaddress.ip_address(network["IPAddress"])
                        for network in container.attrs["NetworkSettings"][
                            "Networks"
                        ].values()
                    }

        def end_callback(force=False):
            for container in reversed(containers):

                if get_container_status(container) in (ContainerStatus.RUNNING,):
                    if force:
                        log_callback(container, "Killing container...")
                        container.kill()
                    else:
                        log_callback(container, "Stopping container...")
                        container.stop()
                #  else:
                #      log_callback(container, f"status={container.status}")

                log_buf(container)

        @dataclass
        class DataStructureEntry:
            monitor_thread: threading.Thread
            status: ContainerStatus
            log_buf: str = ""
            ip_addrs = set[IPAddress]()

        data_structure: dict[Container, DataStructureEntry] = {
            container: DataStructureEntry(
                monitor_thread=threading.Thread(
                    target=container_monitor_thread,
                    args=[
                        container,
                        log_callback,
                        end_callback,
                        status_changed_callback,
                    ],
                ),
                status=get_container_status(container),
            )
            for container in containers
        }

        # start containers in the order of their stage

        timed_out = False
        failed = False

        start = time.time()

        for stage in Stage:
            containers_in_stage = containers_by_stage[stage]

            with self._stage_status_cv:
                if containers_in_stage:
                    LOGGER.debug(
                        "Starting containers in stage %s(%i)", stage.name, stage.value
                    )

                    # check that all containers are in created state (in parallel)

                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        statuses = executor.map(
                            get_container_status, containers_in_stage
                        )

                        for container, status in zip(containers_in_stage, statuses):
                            assert status == ContainerStatus.CREATED
                            data_structure[container].status = status

                    # start containers and their monitor threads

                    for container in containers_in_stage:
                        data_structure[container].monitor_thread.start()

                    # wait until all containers are in started state (cv will be signaled)

                    timed_out = False

                    while any(
                        data_structure[container].status == ContainerStatus.CREATED
                        for container in containers_in_stage
                    ):
                        timed_out = not self._stage_status_cv.wait(
                            timeout=max(0, timeout - (time.time() - start))
                        )

                        if timed_out:
                            LOGGER.error(
                                "Timeout after %i seconds. Could not even start all containers.",
                                timeout,
                            )

                            break

                    # check if any container did not start

                    containers_not_running = [
                        container
                        for container in containers_in_stage
                        if data_structure[container].status != ContainerStatus.RUNNING
                    ]

                    if containers_not_running:
                        different_status_str = ", ".join(
                            f"{container.name}: {data_structure[container].status.value}"
                            for container in containers_not_running
                        )
                        LOGGER.error(
                            "Some containers did not start successfully. Exiting."
                        )
                        LOGGER.error(different_status_str)
                        timeout = 0
                        end_callback()
                        failed = True

                        # don't start next stage

                        break

                # call hooks as we successfully started this staget

                for hook in hooks.get(stage, []):
                    hook()

        # exit

        for container, container_data_structure in data_structure.items():
            thread: threading.Thread = container_data_structure.monitor_thread
            thread_timeout = max(0, timeout - (time.time() - start))
            try:
                if thread._started.is_set():  # noqa
                    thread.join(timeout=thread_timeout)
            except KeyboardInterrupt:
                print(end="\r", file=sys.stderr)
                LOGGER.warning("Stopping containers")
                end_callback(force=True)
                thread.join(timeout=1)
                sys.exit(1)

            if thread.is_alive():
                # timeout
                timed_out = True
                LOGGER.error("Timeout after %i seconds", timeout)
                end_callback()
                thread.join(timeout=1)

                if thread.is_alive():
                    end_callback(force=True)
                    thread.join()

        for container in containers:
            status = get_container_status(container)

            if status != ContainerStatus.EXITED:
                LOGGER.error(
                    "Container %s did not exit, but is in %s state.",
                    container.name,
                    status.value,
                )
                failed = True

                break

        self.disconnect_all_containers()

        if failed:
            LOGGER.error("Starting containers failed.")

        return ExecResult(
            log=logs,
            timed_out=timed_out,
            failed=failed,
            exit_codes={
                get_container_name(container): container.wait().pop("StatusCode")
                for container in containers
            },
            ip_addrs={
                get_container_name(container): data_structure[container].ip_addrs
                for container in containers
            },
        )

    def run_compliance_check(
        self,
        implementation: Implementation,
        role: Role,
        local_certs_path: Path,
        local_www_path: Path,
        local_downloads_path: Path,
        version,
    ) -> ExecResult:
        LOGGER.info("Checking compliance of %s %s", implementation.name, role.value)
        testcase_name = random_string(6)
        # check client
        containers = list[Container]()

        if role == Role.CLIENT:
            containers.append(
                self._create_sim(
                    scenario="simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25",
                )
            )
        containers.append(
            self._create_implementation_sim(
                image=implementation.image,
                role=role,
                local_certs_path=local_certs_path,
                testcase=testcase_name,
                version=version,
                request_urls="https://server4:443/",
                local_www_path=local_www_path if role == Role.SERVER else None,
                local_download_path=local_downloads_path
                if role == Role.CLIENT
                else None,
            )
        )
        # wait

        result = self.run_and_wait(containers, timeout=30)

        remove_containers(containers)

        return result

    def run_debug_setup(
        self,
        client: Implementation = IMPLEMENTATIONS["quic-go"],
        server: Implementation = IMPLEMENTATIONS["quic-go"],
    ):
        timeout = 60 * 60 * 1  # 1h
        version = 0x1
        testcase = "transfer"
        LOGGER.debug("Creating sim container")
        sim_container = self._create_sim(
            waitforserver=False,
            scenario="debug-scenario",
            entrypoint=["sleep", str(timeout)],
        )
        LOGGER.debug("Creating server container")
        server_container = self._create_implementation_sim(
            image=server.image,
            role=Role.SERVER,
            local_certs_path=Path("/dev/null"),
            testcase=testcase,
            version=version,
            local_www_path=Path("/dev/null"),
            entrypoint=["sleep", str(timeout)],
        )
        LOGGER.debug("Creating client container")
        client_container = self._create_implementation_sim(
            image=client.image,
            role=Role.CLIENT,
            local_certs_path=Path("/dev/null"),
            testcase=testcase,
            version=version,
            request_urls="debug-request-url",
            local_download_path=Path("/dev/null"),
            entrypoint=["sleep", str(timeout)],
        )
        containers = [sim_container, client_container, server_container]
        # wait
        LOGGER.debug("Starting containers")
        result = self.run_and_wait(containers, timeout=timeout)

        remove_containers(containers)

        return result

    def run_testcase(
        self,
        log_path: Path,
        timeout: int,
        testcase: TestCase,
        local_certs_path: Path,
        local_www_path: Path,
        local_downloads_path: Path,
        client: Implementation,
        server: Implementation,
        request_urls: str,
        version: str,
    ) -> ExecResult:
        if testcase.additional_containers:
            # TODO extra containers
            raise NotImplementedError(
                "Additional containers are currently not supported"
            )

        if isinstance(testcase, MeasurementRealLink):
            LOGGER.debug("Using a real link for this testcase.")

            return self._run_testcase_with_remote_client(
                log_path=log_path,
                timeout=timeout,
                testcase=testcase,
                local_certs_path=local_certs_path,
                local_www_path=local_www_path,
                local_downloads_path=local_downloads_path,
                client=client,
                server=server,
                request_urls=request_urls,
                version=version,
            )
        else:
            LOGGER.debug("Using an emulated link for this testcase.")

            return self._run_testcase_with_sim(
                log_path=log_path,
                timeout=timeout,
                testcase=testcase,
                local_certs_path=local_certs_path,
                local_www_path=local_www_path,
                local_downloads_path=local_downloads_path,
                client=client,
                server=server,
                request_urls=request_urls,
                version=version,
            )

        self.cleanup()

    def _run_testcase_with_sim(
        self,
        log_path: Path,
        timeout: int,
        testcase: TestCase,
        local_certs_path: Path,
        local_www_path: Path,
        local_downloads_path: Path,
        client: Implementation,
        server: Implementation,
        request_urls: str,
        version: str,
    ) -> ExecResult:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            create_sim_t = executor.submit(
                lambda: self._create_sim(
                    waitforserver=True,
                    scenario=testcase.scenario,
                )
            )
            create_server_t = executor.submit(
                lambda: self._create_implementation_sim(
                    image=server.image,
                    role=Role.SERVER,
                    local_certs_path=local_certs_path,
                    testcase=testcase.testname(Perspective.SERVER),
                    version=version,
                    request_urls=request_urls,
                    local_www_path=local_www_path,
                )
            )
            create_client_t = executor.submit(
                lambda: self._create_implementation_sim(
                    image=client.image,
                    role=Role.CLIENT,
                    local_certs_path=local_certs_path,
                    testcase=testcase.testname(Perspective.CLIENT),
                    version=version,
                    request_urls=request_urls,
                    local_download_path=local_downloads_path,
                )
            )
            sim_container = create_sim_t.result()
            server_container = create_server_t.result()
            client_container = create_client_t.result()

        containers = [sim_container, client_container, server_container]
        # wait
        result = self.run_and_wait(containers, timeout=timeout)
        # set IP addresses
        testcase.set_ip_addrs(
            client_client_addrs={
                self.get_container_ipv4(Role.CLIENT),
                self.get_container_ipv6(Role.CLIENT),
            },
            client_server_addrs={
                self.get_container_ipv4(Role.SERVER),
                self.get_container_ipv6(Role.SERVER),
            },
            server_client_addrs={
                self.get_container_ipv4(Role.CLIENT),
                self.get_container_ipv6(Role.CLIENT),
            },
            server_server_addrs={
                self.get_container_ipv4(Role.SERVER),
                self.get_container_ipv6(Role.SERVER),
            },
        )
        # copy logs
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(
                lambda: copy_tree_from_container(
                    server_container, LOGS_PATH, log_path / "server"
                ),
            )
            executor.submit(
                lambda: copy_tree_from_container(
                    client_container, LOGS_PATH, log_path / "client"
                ),
            )
            executor.submit(
                lambda: copy_tree_from_container(
                    sim_container, LOGS_PATH, log_path / "sim"
                ),
            )

        remove_containers(containers)

        return result

    def _run_testcase_with_remote_client(
        self,
        log_path: Path,
        timeout: int,
        testcase: MeasurementRealLink,
        local_certs_path: Path,
        local_www_path: Path,
        local_downloads_path: Path,
        client: Implementation,
        server: Implementation,
        request_urls: str,
        version: str,
    ) -> ExecResult:
        client_cli = self.get_docker_cli(testcase.client_docker_host)
        server_cli = self.get_docker_cli(testcase.server_docker_host)

        # ensure image version is the same
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(lambda: force_same_img_version(client, client_cli))
            executor.submit(lambda: force_same_img_version(server, server_cli))

        self._remove_existing_container(f"{self.project_name}_server", server_cli)
        server_port = 443
        server_ip = negotiate_server_ip(server_cli, client_cli, port=server_port)
        server_ip4 = server_ip if server_ip.version == 4 else None
        server_ip6 = server_ip if server_ip.version == 6 else None
        LOGGER.debug(
            "Server IPs: IPv4: %s IPv6: %s (Port: %i)",
            server_ip4,
            server_ip6,
            server_port,
        )
        client_ip4, client_ip6 = get_client_ips(client_cli)
        LOGGER.debug("Client IPs: IPv4: %s IPv6: %s", client_ip4, client_ip6)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            create_server_t = executor.submit(
                self._create_implementation_real,
                cli=server_cli,
                image=server.image,
                role=Role.SERVER,
                server_port=server_port,
                server_ip=server_ip,
                local_certs_path=local_certs_path,
                testcase=testcase.testname(Perspective.SERVER),
                version=version,
                request_urls=request_urls,
                local_www_path=local_www_path,
            )
            create_client_t = executor.submit(
                self._create_implementation_real,
                cli=client_cli,
                image=client.image,
                role=Role.CLIENT,
                server_port=server_port,
                server_ip=server_ip,
                local_certs_path=local_certs_path,
                testcase=testcase.testname(Perspective.CLIENT),
                version=version,
                request_urls=request_urls,
                local_www_path=local_www_path,
            )

            server_container = create_server_t.result()
            client_container = create_client_t.result()

            create_right_tcpdump_t = executor.submit(
                self._create_container,
                cli=server_cli,
                image=TCPDUMP_IMG,
                service_name="right_tcpdump",
                stage=Stage.SERVER_POST,
                entrypoint=[
                    "tcpdump",
                    "-q",
                    "-w",
                    str(TRACE_PATH),
                    "udp",
                    "port",
                    str(server_port),
                ],
                #  extra_hosts: Optional[dict[str, str]] = None,
                network=f"container:{server_container.name}",
                #  volumes: Optional[dict] = None,
            )
            create_left_tcpdump_t = executor.submit(
                self._create_container,
                cli=client_cli,
                image=TCPDUMP_IMG,
                service_name="left_tcpdump",
                stage=Stage.CLIENT_POST,
                entrypoint=[
                    "tcpdump",
                    "-q",
                    "-w",
                    str(TRACE_PATH),
                    "udp",
                    "port",
                    str(server_port),
                ],
                #  extra_hosts: Optional[dict[str, str]] = None,
                network=f"container:{client_container.name}",
                #  volumes: Optional[dict] = None,
            )

            left_tcpdump_container = create_left_tcpdump_t.result()
            right_tcpdump_container = create_right_tcpdump_t.result()

        containers = [
            server_container,
            right_tcpdump_container,
            client_container,
            left_tcpdump_container,
        ]

        def after_left_trace_start_hook():
            LOGGER.debug("Signal client to start...")
            ret = client_container.exec_run("sh -c 'echo 1 > /tmp/wait_for_sim'")
            assert ret.exit_code == 0
            output = ret.output.decode("utf-8").strip()

            if output:
                LOGGER.debug("Exec command output: %s", output)

        # wait
        result = self.run_and_wait(
            containers,
            timeout=timeout,
            hooks={Stage.CLIENT_POST: [after_left_trace_start_hook]},
        )

        testcase.set_ip_addrs(
            client_client_addrs=result.ip_addrs["client"],
            client_server_addrs={ip for ip in (server_ip4, server_ip6) if ip},
            server_client_addrs={ip for ip in (client_ip4, client_ip6) if ip},
            server_server_addrs=result.ip_addrs["server"],
        )

        with concurrent.futures.ThreadPoolExecutor() as executor:
            # copy downloads
            executor.submit(
                lambda: copy_tree_from_container(
                    client_container, DOWNLOADS_PATH, local_downloads_path
                )
            )
            # copy logs
            executor.submit(
                lambda: copy_tree_from_container(
                    server_container, LOGS_PATH, log_path / "server"
                )
            )
            executor.submit(
                lambda: copy_tree_from_container(
                    client_container, LOGS_PATH, log_path / "client"
                )
            )

            # copy traces
            executor.submit(
                lambda: copy_file_from_container(
                    right_tcpdump_container,
                    TRACE_PATH,
                    log_path / "sim" / "trace_node_right.pcap",
                )
            )
            executor.submit(
                lambda: copy_file_from_container(
                    left_tcpdump_container,
                    TRACE_PATH,
                    log_path / "sim" / "trace_node_left.pcap",
                )
            )

        remove_containers(containers)

        return result

    def create_networks(self):
        """Create sim networks."""

        for role in (Role.CLIENT, Role.SERVER):
            network_name = self.get_network_name(role)

            try:
                network: Optional[Network] = self.get_docker_cli().networks.get(
                    network_name
                )
            except docker.errors.NotFound:
                network = None

            if network:
                self._networks[role] = network

                continue

            self._networks[role] = self.get_docker_cli().networks.create(
                name=network_name,
                driver="bridge",
                options={
                    "com.docker.network.bridge.enable_ip_masquerade": "false",
                },
                ipam=docker.types.IPAMConfig(
                    pool_configs=[
                        docker.types.IPAMPool(
                            subnet=NETWORKS[role].get_subnet(ip_version).exploded,
                            gateway=(
                                NETWORKS[role].get_subnet(ip_version).network_address
                                + 1
                            ).exploded,
                        )
                        for ip_version in IPVersion
                    ],
                ),
                check_duplicate=True,
                labels={
                    "de.sedrubal.interop.network": NETWORKS[role].name,
                    "de.sedrubal.interop.project": self.project_name,
                },
                enable_ipv6=True,
                attachable=True,
                scope="local",
                ingress=False,
            )

    def get_network(self, role: Role) -> Network:
        if not self._networks[role]:
            self.create_networks()

        network = self._networks[role]
        assert network

        return network

    def get_network_name(self, role: Role) -> str:
        return f"{self.project_name}_{NETWORKS[role].name}"

    def disconnect_container_from_void(self, container: Container):
        container.client.networks.get(VOID_NETWORK).disconnect(container)

    def disconnect_all_containers(self):
        """Disconnect all containers from our networks."""

        for network in self._networks.values():
            if not network:
                continue

            try:
                for container in network.containers:
                    try:
                        network.disconnect(container)
                    except docker.errors.NotFound:
                        LOGGER.debug(
                            "Could not disconnect %s from %s as it was not found(?!?)",
                            container.name,
                            network.name,
                        )
            except docker.errors.NotFound:
                LOGGER.debug(
                    "Network %s not found(?!?)",
                    network.name,
                )

    def get_container_ipv4(self, role: Role) -> ipaddress.IPv4Address:
        return NETWORKS[role].subnet_v4.network_address + 100

    def get_container_ipv6(self, role: Role) -> ipaddress.IPv6Address:
        return NETWORKS[role].subnet_v6.network_address + 0x100

    def get_iperf_ipv4(self, role: Role) -> ipaddress.IPv4Address:
        offset = 110 if role == Role.SERVER else 90

        return NETWORKS[role].subnet_v4.network_address + offset

    def get_iperf_ipv6(self, role: Role) -> ipaddress.IPv6Address:
        offset = 0x110 if role == Role.SERVER else 0x90

        return NETWORKS[role].subnet_v6.network_address + offset

    def get_sim_ipv4(self, perspective: Role) -> ipaddress.IPv4Address:
        return NETWORKS[perspective].subnet_v4.network_address + 2

    def get_sim_ipv6(self, perspective: Role) -> ipaddress.IPv6Address:
        return NETWORKS[perspective].subnet_v6.network_address + 0x2

    def get_extra_hosts(self, role: Role, iperf=False) -> dict[str, str]:
        other_role = Role.CLIENT if role == Role.SERVER else Role.SERVER
        other_ipv4 = (
            self.get_iperf_ipv4(other_role)
            if iperf
            else self.get_container_ipv4(other_role)
        )
        other_ipv6 = (
            self.get_iperf_ipv6(other_role)
            if iperf
            else self.get_container_ipv6(other_role)
        )

        return {
            f"{other_role.value}": other_ipv4.exploded,
            f"{other_role.value}4": other_ipv4.exploded,
            f"{other_role.value}6": other_ipv6.exploded,
            f"{other_role.value}46": other_ipv4.exploded,
            f"{other_role.value}46 ": other_ipv6.exploded,
            "sim": self.get_sim_ipv4(role).exploded,
            "sim4": self.get_sim_ipv4(role).exploded,
            "sim6": self.get_sim_ipv6(role).exploded,
            "sim46": self.get_sim_ipv4(role).exploded,
            "sim46 ": self.get_sim_ipv6(role).exploded,
        }

    def _create_sim(
        self,
        scenario: str,
        waitforserver: bool = False,
        entrypoint: Optional[list[str]] = None,
    ):
        environment = {
            "SCENARIO": scenario,
        }

        if waitforserver:
            environment["WAITFORSERVER"] = "server:443"

        container = self._create_container(
            cli=self.get_docker_cli(),
            image=SIM_IMG,
            entrypoint=entrypoint,
            environment=environment,
            extra_hosts={
                "server": self.get_container_ipv4(Role.SERVER).exploded,
                "server4": self.get_container_ipv4(Role.SERVER).exploded,
                "server6": self.get_container_ipv6(Role.SERVER).exploded,
                "server46": self.get_container_ipv4(Role.SERVER).exploded,
                "server46 ": self.get_container_ipv6(Role.SERVER).exploded,
                "client": self.get_container_ipv4(Role.CLIENT).exploded,
                "client4": self.get_container_ipv4(Role.CLIENT).exploded,
                "client6": self.get_container_ipv6(Role.CLIENT).exploded,
                "client46": self.get_container_ipv4(Role.CLIENT).exploded,
                "client46 ": self.get_container_ipv6(Role.CLIENT).exploded,
            },
            service_name="sim",
            stage=Stage.PRE,
            # connect to dummy network to avoid connecting to host
            network=VOID_NETWORK,
        )

        # connect to desired networks
        self.disconnect_container_from_void(container)

        for role in (Role.CLIENT, Role.SERVER):
            network = self.get_network(role)
            network.connect(
                container,
                ipv4_address=self.get_sim_ipv4(perspective=role).exploded,
                ipv6_address=self.get_sim_ipv6(perspective=role).exploded,
            )

        return container

    #  def _create_iperf(
    #      self,
    #      role: Role,
    #      iperf_congestion="cubic",
    #      entrypoint: Optional[list[str]] = None,
    #  ) -> Container:
    #      env = {
    #          "ROLE": role.value,
    #          "IPERF_CONGESTION": iperf_congestion,
    #      }
    #
    #      if role == Role.SERVER:
    #          env["CLIENT"] = "client4"
    #
    #      return self._create_sim_endpoint(
    #          cli=self.get_docker_cli(),
    #          image=IPERF_ENDPOINT_IMG,
    #          role=role,
    #          name=f"iperf_{role.value}",
    #          ipv4_address=self.get_iperf_ipv4(role),
    #          ipv6_address=self.get_iperf_ipv6(role),
    #          extra_hosts=self.get_extra_hosts(role, iperf=True),
    #          env=env,
    #          entrypoint=entrypoint,
    #      )

    def _create_implementation_sim(
        self,
        image: str,
        role: Role,
        local_certs_path: Path,
        testcase: str,
        version,
        request_urls: Optional[str] = None,
        local_www_path: Optional[Path] = None,
        local_download_path: Optional[Path] = None,
        entrypoint: Optional[list[str]] = None,
    ) -> Container:
        volumes = {
            local_certs_path: {"bind": CERTS_PATH, "mode": "ro"},
        }
        env = {
            "ROLE": role.value,
            "TESTCASE": testcase,
            "VERSION": version,
            "SSLKEYLOGFILE": SSLKEYLOG_FILE,
            "QLOGDIR": QLOG_DIR,
        }

        if role == Role.CLIENT:
            assert request_urls is not None
            env["REQUESTS"] = request_urls
            assert local_www_path is None
            assert local_download_path
            volumes[local_download_path] = {"bind": DOWNLOADS_PATH, "mode": "delegated"}
        else:
            # server
            assert local_download_path is None
            assert local_www_path
            volumes[local_www_path] = {"bind": WWW_PATH, "mode": "ro"}

        return self._create_sim_endpoint(
            image=image,
            role=role,
            name=role.value,
            entrypoint=entrypoint,
            env=env,
            extra_hosts=self.get_extra_hosts(role),
            ipv4_address=self.get_container_ipv4(role),
            ipv6_address=self.get_container_ipv6(role),
            volumes=volumes,
        )

    def _create_implementation_real(
        self,
        cli: docker.DockerClient,
        image: str,
        role: Role,
        local_certs_path: Path,
        testcase: str,
        version,
        server_ip: IPAddress,
        server_port: int,
        request_urls: Optional[str] = None,
        local_www_path: Optional[Path] = None,
        entrypoint: Optional[list[str]] = None,
    ) -> Container:
        ports: Optional[dict] = None
        env = {
            "ROLE": role.value,
            "TESTCASE": testcase,
            "VERSION": version,
            "SSLKEYLOGFILE": SSLKEYLOG_FILE,
            "QLOGDIR": QLOG_DIR,
        }

        if role == Role.CLIENT:
            assert request_urls is not None
            env["REQUESTS"] = request_urls
        else:
            # server
            ports = {
                #  "443/tcp": (server_ip.exploded, server_port),
                "443/udp": (server_ip.exploded, server_port),
            }

        if role == Role.SERVER:
            extra_hosts: Optional[dict[str, str]] = None
        else:
            if server_ip.version == 4:
                extra_hosts = {
                    "server4": server_ip.exploded,
                    #  "server46": other_ipv4.exploded,
                }
            else:
                extra_hosts = {
                    "server6": server_ip.exploded,
                    #  "server46": other_ipv4.exploded,
                }

        container = self._create_container(
            cli=cli,
            entrypoint=entrypoint,
            environment=env,
            extra_hosts=extra_hosts,
            image=image,
            ports=ports,
            service_name=role.value,
            stage=Stage.SERVER if role == Role.SERVER else Stage.CLIENT,
        )

        # monkey patch setup.sh
        copy_file_to_container(REAL_LINK_SETUP_SCRIPT, container, "/setup.sh")

        # avoid volumes

        if role == Role.CLIENT:
            copy_tree_to_container(local_certs_path, container, CERTS_PATH)
        elif role == Role.SERVER:
            assert local_www_path
            copy_tree_to_container(local_certs_path, container, CERTS_PATH)
            copy_tree_to_container(local_www_path, container, WWW_PATH)
        else:
            assert False

        return container

    def _remove_existing_container(
        self, container_name: str, cli: Optional[docker.DockerClient] = None
    ):
        if not cli:
            cli = self.get_docker_cli()
            assert cli
        try:
            container = cli.containers.get(container_name)
            LOGGER.debug("Removing existing container %s", container.name)
            container.stop()
            container.remove()
        except docker.errors.NotFound:
            pass

    def _create_sim_endpoint(
        self,
        image: str,
        role: Role,
        name: str,
        ipv4_address: ipaddress.IPv4Address,
        ipv6_address: ipaddress.IPv6Address,
        volumes: Optional[dict] = None,
        extra_hosts: Optional[dict[str, str]] = None,
        env: Optional[dict] = None,
        entrypoint: Optional[list[str]] = None,
    ):
        """Create an endpoint container."""
        assert role != Role.BOTH

        container = self._create_container(
            cli=self.get_docker_cli(),
            entrypoint=entrypoint,
            environment=env,
            extra_hosts=extra_hosts,
            image=image,
            # connect to dummy network to avoid connecting to host
            network=VOID_NETWORK,
            service_name=name,
            stage=Stage.SERVER if role == Role.SERVER else Stage.CLIENT,
            volumes=volumes,
        )

        self.disconnect_container_from_void(container)
        network = self.get_network(role)
        network.connect(
            container,
            ipv4_address=ipv4_address.exploded,
            ipv6_address=ipv6_address.exploded,
        )

        return container

    def _create_container(
        self,
        image: str,
        service_name: str,
        stage: Stage,
        cli: docker.DockerClient,
        entrypoint: Optional[list[str]] = None,
        environment: Optional[dict] = None,
        extra_hosts: Optional[dict[str, str]] = None,
        network: Optional[str] = None,
        ports: Optional[dict] = None,
        volumes: Optional[dict] = None,
    ):
        container_name = f"{self.project_name}_{service_name}"

        self._remove_existing_container(container_name=container_name, cli=cli)

        hostname = (
            None if network and network.startswith("container:") else service_name
        )

        try:
            # ensure the image is pulled
            image_instance = cli.images.get(image)
        except docker.errors.NotFound:
            image_instance = cli.images.pull(image)

        return cli.containers.create(
            image=image_instance,
            cap_add="NET_ADMIN",
            detach=True,
            entrypoint=entrypoint,
            environment=environment,
            extra_hosts=extra_hosts,
            hostname=hostname,
            labels={
                "de.sedrubal.interop.service": service_name,
                "de.sedrubal.interop.project": self.project_name,
                "de.sedrubal.interop.working_dir": str(Path().absolute()),
                "de.sedrubal.interop.stage": str(stage.value),
            },
            name=container_name,
            # connect to dummy network to avoid connecting to host
            network=network,
            ports=ports,
            stdin_open=True,
            tty=True,
            ulimits=[MEMLOCK_ULIMIT],
            volumes=(
                {
                    str(local): {"bind": str(cfg.pop("bind")), **cfg}
                    for local, cfg in volumes.items()
                }
                if volumes
                else None
            ),
        )

    def cleanup(self):
        """Cleanup things. Can be called between testcases."""

        for docker_cli in self._docker_clis.values():
            docker_cli.close()


def main():
    LOGGER.setLevel(logging.DEBUG)
    CONSOLE_LOG_HANDLER = logging.StreamHandler(stream=sys.stderr)
    CONSOLE_LOG_HANDLER.setFormatter(TerminalFormatter())
    LOGGER.addHandler(CONSOLE_LOG_HANDLER)
    deployment = Deployment()
    LOGGER.info(
        "Starting dev setup. "
        "Use docker exec to execute a shell inside the containers as soon as they are running."
    )
    result = deployment.run_debug_setup()
    logging.info(str(result))


if __name__ == "__main__":
    main()
