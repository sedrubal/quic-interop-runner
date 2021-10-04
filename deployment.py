"""Deployment using Docker and SSH (for remote hosts)."""

import ipaddress
import logging
import tarfile
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional, Type, Union

import docker
from termcolor import colored

from implementations import Implementation, Role
from testcases import Perspective, TestCase
from utils import random_string

DEFAULT_DOCKER_SOCK = "unix:///var/run/docker.sock"
MEMLOCK_ULIMIT = docker.types.Ulimit(name="memlock", hard=67108864, soft=0)
IPERF_ENDPOINT_IMG = "martenseemann/quic-interop-iperf-endpoint"
SIM_IMG = "therealsedrubal/quic-network-simulator"

Container = Type[docker.models.containers.Container]
Network = Type[docker.models.networks.Network]

LOGGER = logging.getLogger(name="quic-interop-runner")


class IPVersion(Enum):
    V4 = 4
    V6 = 6


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
    exit_codes: dict[str, int]


class Deployment:

    project_name = "quic-interop-runner"

    def __init__(
        self,
        server_host: str = DEFAULT_DOCKER_SOCK,
        client_host: str = DEFAULT_DOCKER_SOCK,
    ):
        self.docker_clis = {
            Role.SERVER: docker.DockerClient(server_host),
            Role.CLIENT: docker.DockerClient(client_host),
        }
        self._networks: dict[Role, Optional[Network]] = {
            Role.SERVER: None,
            Role.CLIENT: None,
        }
        self._stage_pending = 0
        self._stage_pending_cv = threading.Condition()

    def _thread_monitor_container(
        self,
        container: Container,
        log_callback: Callable[[Container, str, bool], None],
        end_callback: Callable[[], None],
        running_callback: Callable[[], None],
    ):
        status: str = container.status
        assert status == "created"
        log_callback(container, "Starting...", False)
        try:
            container.start()
        except docker.errors.APIError as err:
            log_callback(container, str(err), False)
            end_callback()

            return

        while True:
            container.reload()

            if container.status != status:
                status = container.status
                log_callback(container, status, False)
                assert status == "running"
                running_callback()

                break

        for chunk in container.logs(stream=True):
            try:
                chunk_str = chunk.decode("utf-8")
            except UnicodeDecodeError:
                chunk_str = str(chunk)

            log_callback(container, chunk_str, True)

        container.reload()

        if container.status != status:
            status = container.status
            log_callback(container, status, False)

        result = container.wait()
        error = result.pop("Error", None)
        exit_code = result.pop("StatusCode", None)

        if error:
            raise Exception(error)

        if exit_code is not None:
            log_callback(container, f"exit status {exit_code}", False)

        if result:
            LOGGER.warning("Unknown contianer result: %s", str(result))

        container.reload()

        if container.status != status:
            status = container.status
            log_callback(container, status, False)

        # stop all containers when one container exits
        end_callback()

    def run_and_wait(self, containers: list[Container], timeout: int) -> ExecResult:
        """Return logs and timed_out."""
        containers_by_stage = defaultdict[int, list[Container]](list[Container])

        for container in containers:
            containers_by_stage[
                int(container.labels["de.sedrubal.interop.stage"])
            ].append(container)

        start = time.time()

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

        def running_callback():
            with self._stage_pending_cv:
                self._stage_pending -= 1
                self._stage_pending_cv.notify()

        def end_callback(force=False):
            for container in reversed(containers):
                container.reload()

                if container.status in ("running",):
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
            log_buf: str = ""

        data_structure: dict[Container, DataStructureEntry] = {
            container: DataStructureEntry(
                monitor_thread=threading.Thread(
                    target=self._thread_monitor_container,
                    args=[container, log_callback, end_callback, running_callback],
                )
            )
            for container in containers
        }

        # start according to stage

        timed_out = False

        for stage in sorted(containers_by_stage.keys()):
            LOGGER.debug("Starting containers in stage %i", stage)

            assert self._stage_pending == 0
            with self._stage_pending_cv:
                self._stage_pending = len(containers_by_stage[stage])

                for container in containers_by_stage[stage]:
                    data_structure[container].monitor_thread.start()

                timed_out = not self._stage_pending_cv.wait(
                    timeout=max(0, timeout - (time.time() - start))
                )

        for container, container_data_structure in data_structure.items():
            thread: threading.Thread = container_data_structure.monitor_thread
            thread_timeout = max(0, timeout - (time.time() - start))
            thread.join(timeout=thread_timeout)

            if thread.is_alive():
                # timeout
                timed_out = True
                end_callback()
                thread.join(timeout=1)

                if thread.is_alive():
                    end_callback(force=True)
                    thread.join()

        for container in containers:
            container.reload()

            if container.status != "exited":
                breakpoint()
            assert container.status == "exited"

        for network in self._networks.values():
            assert network

            for container in network.containers:
                network.disconnect(container)

        return ExecResult(
            log=logs,
            timed_out=timed_out,
            exit_codes={
                get_container_name(container): container.wait().pop("StatusCode")
                for container in containers
            },
        )

    def _copy_logs(self, container: Container, dst: Path):
        src = Path("/logs")
        target_archive = dst.parent / f"{dst.name}.tar"
        with target_archive.open("wb") as file:
            bits, _stat = container.get_archive(src)
            # TODO progress bar with stat["size"]

            for chunk in bits:
                file.write(chunk)

        if not target_archive.is_file():
            logging.error("Failed to copy %s:%s to %s", container.name, src, dst)

            return

        with tarfile.open(target_archive) as archive:
            archive.extractall()

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
            self._create_implementation(
                image=implementation.image,
                role=role,
                local_certs_path=local_certs_path,
                testcase=testcase_name,
                version=version,
                request_urls="https://server4:443/",
                local_www_path=local_www_path,
                local_download_path=local_downloads_path,
            )
        )
        # wait

        result = self.run_and_wait(containers, timeout=10)

        for container in containers:
            container.remove()

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
        # gather information
        client.gather_infos_from_docker(docker_cli=self.docker_clis[Role.CLIENT])
        server.gather_infos_from_docker(docker_cli=self.docker_clis[Role.SERVER])

        # TODO extra containers
        sim_container = self._create_sim(
            waitforserver=True,
            scenario=testcase.scenario,
        )
        server_container = self._create_implementation(
            image=server.image,
            role=Role.SERVER,
            local_certs_path=local_certs_path,
            testcase=testcase.testname(Perspective.SERVER),
            version=version,
            request_urls=request_urls,
            local_www_path=local_www_path,
            local_download_path=local_downloads_path,
        )
        client_container = self._create_implementation(
            image=client.image,
            role=Role.CLIENT,
            local_certs_path=local_certs_path,
            testcase=testcase.testname(Perspective.CLIENT),
            version=version,
            request_urls=request_urls,
            local_www_path=local_www_path,
            local_download_path=local_downloads_path,
        )
        containers = [sim_container, client_container, server_container]
        # wait
        result = self.run_and_wait(containers, timeout=timeout)
        # copy logs
        self._copy_logs(server_container, log_path / "server")
        self._copy_logs(client_container, log_path / "client")
        self._copy_logs(sim_container, log_path / "sim")

        for container in containers:
            container.remove()

        return result

    def create_networks(self):
        for role in (Role.CLIENT, Role.SERVER):
            network_name = self.get_network_name(role)

            try:
                network: Optional[Network] = self.docker_clis[role].networks.get(
                    network_name
                )
            except docker.errors.NotFound:
                network = None

            if network:
                self._networks[role] = network

                continue

            self._networks[role] = self.docker_clis[role].networks.create(
                name=network_name,
                driver="bridge",
                options={
                    "com.docker.network.bridge.enable_ip_masquerade": "false",
                },
                ipam=docker.types.IPAMConfig(
                    pool_configs=[
                        docker.types.IPAMPool(
                            subnet=str(NETWORKS[role].get_subnet(ip_version)),
                            gateway=str(
                                NETWORKS[role].get_subnet(ip_version).network_address
                                + 1
                            ),
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

        assert self._networks[role]

        return self._networks[role]

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

    def get_network_name(self, role: Role) -> str:
        return f"{self.project_name}_{NETWORKS[role].name}"

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
            f"{other_role.value}4": str(other_ipv4),
            f"{other_role.value}6": str(other_ipv6),
            f"{other_role.value}46": str(other_ipv4),
            f"{other_role.value}46 ": str(other_ipv6),
        }

    def _create_sim(self, scenario: str, waitforserver: bool = False):
        # TODO on which host?
        environment = {
            "SCENARIO": scenario,
        }

        if waitforserver:
            environment["WAITFORSERVER"] = "server:443"

        name = "sim"
        container_name = f"{self.project_name}_{name}"

        self._remove_existing_container(role=Role.CLIENT, container_name=container_name)

        container = self.docker_clis[Role.CLIENT].containers.create(
            image=SIM_IMG,
            cap_add="NET_ADMIN",
            detach=True,
            environment=environment,
            extra_hosts={
                "server": self.get_container_ipv4(Role.SERVER),
            },
            hostname=name,
            labels={
                "de.sedrubal.interop.service": name,
                "de.sedrubal.interop.project": self.project_name,
                "de.sedrubal.interop.working_dir": str(Path().absolute()),
                "de.sedrubal.interop.stage": "0",
            },
            name=container_name,
            network=self.get_network_name(Role.CLIENT),
            stdin_open=True,
            tty=True,
        )
        # TODO - why and how?
        #  expose:
        #    - "57832"

        for role in (Role.CLIENT, Role.SERVER):
            network = self.get_network(role)
            network.connect(
                container,
                ipv4_address=str(NETWORKS[role].subnet_v4.network_address + 2),
                ipv6_address=str(NETWORKS[role].subnet_v6.network_address + 0x2),
            )

        return container

    def _create_iperf(self, role: Role, iperf_congestion="cubic") -> Container:
        env = {
            "ROLE": role.value,
            "IPERF_CONGESTION": iperf_congestion,
        }

        if role == Role.SERVER:
            env["CLIENT"] = "client4"

        return self._create_endpoint(
            image=IPERF_ENDPOINT_IMG,
            role=role,
            name=f"iperf_{role.value}",
            ipv4_address=self.get_iperf_ipv4(role),
            ipv6_address=self.get_iperf_ipv6(role),
            extra_hosts=self.get_extra_hosts(role, iperf=True),
            env=env,
        )

    def _create_implementation(
        self,
        image: str,
        role: Role,
        local_certs_path: Path,
        testcase: str,
        version,
        request_urls: Optional[str] = None,
        local_www_path: Optional[Path] = None,
        local_download_path: Optional[Path] = None,
    ) -> Container:
        volumes = {
            local_certs_path: {"bind": "/certs", "mode": "ro"},
        }
        env = {
            "ROLE": role.value,
            "TESTCASE": testcase,
            "VERSION": version,
            "SSLKEYLOGFILE": "/logs/keys.log",
            "QLOGDIR": "/logs/qlog/",
        }

        if role == Role.CLIENT:
            assert request_urls is not None
            env["REQUESTS"] = request_urls
            assert local_download_path
            volumes[local_download_path] = {"bind": "/downloads", "mode": "delegated"}
        else:
            # server
            assert local_www_path
            volumes[local_www_path] = {"bind": "/www", "mode": "ro"}

        return self._create_endpoint(
            image=image,
            role=role,
            name=role.value,
            ipv4_address=self.get_container_ipv4(role),
            ipv6_address=self.get_container_ipv6(role),
            extra_hosts=self.get_extra_hosts(role),
            volumes=volumes,
            env=env,
        )

    def _remove_existing_container(self, role: Role, container_name: str):
        try:
            container = self.docker_clis[role].containers.get(container_name)
            LOGGER.debug("Removing existing container %s", container.name)
            container.stop()
            container.remove()
        except docker.errors.NotFound:
            pass

    def _create_endpoint(
        self,
        image: str,
        role: Role,
        name: str,
        ipv4_address: ipaddress.IPv4Address,
        ipv6_address: ipaddress.IPv6Address,
        volumes: Optional[dict] = None,
        extra_hosts: Optional[dict[str, str]] = None,
        env: Optional[dict] = None,
    ):
        """Create an endpoint container."""
        assert role != Role.BOTH

        network = self.get_network(role)

        container_name = f"{self.project_name}_{name}"

        self._remove_existing_container(role=role, container_name=container_name)

        container = self.docker_clis[role].containers.create(
            image=image,
            cap_add="NET_ADMIN",
            detach=True,
            environment=env,
            extra_hosts=extra_hosts,
            hostname=name,
            labels={
                "de.sedrubal.interop.service": name,
                "de.sedrubal.interop.project": self.project_name,
                "de.sedrubal.interop.working_dir": str(Path().absolute()),
                "de.sedrubal.interop.stage": "1",
            },
            name=container_name,
            network=network.name,
            stdin_open=True,
            tty=True,
            ulimits=[MEMLOCK_ULIMIT],
            volumes=volumes,
        )

        network.connect(
            container,
            ipv4_address=str(ipv4_address),
            ipv6_address=str(ipv6_address),
        )

        return container
