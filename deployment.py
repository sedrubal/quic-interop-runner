#!/usr/bin/env python3
"""Deployment using Docker and SSH (for remote hosts)."""

import ipaddress
import logging
import sys
import tarfile
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Optional, Type, Union

import docker
from termcolor import colored

from evaluation_tools.utils import TerminalFormatter
from implementations import IMPLEMENTATIONS, Implementation, Role
from testcases import Perspective, TestCase
from utils import random_string

DEFAULT_DOCKER_SOCK = "unix:///var/run/docker.sock"
MEMLOCK_ULIMIT = docker.types.Ulimit(name="memlock", hard=67108864, soft=67108864)
IPERF_ENDPOINT_IMG = "martenseemann/quic-interop-iperf-endpoint"
SIM_IMG = "therealsedrubal/quic-network-simulator"

VOID_NETWORK = "none"

Container = Type[docker.models.containers.Container]
Network = Type[docker.models.networks.Network]

LOGGER = logging.getLogger(name="quic-interop-runner")


class ContainerStatus(Enum):
    CREATED = "created"
    RUNNING = "running"
    EXITED = "exited"


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
    exit_codes: dict[str, int]

    def __str__(self):
        log_str = f"log: {len(self.log)} lines"

        if self.timed_out:
            return f"<Result: Timeout; {log_str}>"

        exit_codes_str = " ".join(
            f"{container}: {code}" for container, code in self.exit_codes.items()
        )

        return f"<Result: {exit_codes_str}; {log_str}>"


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
        self._stage_status_cv = threading.Condition()

    def _thread_monitor_container(
        self,
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

        result = container.wait()
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

        def status_changed_callback(container: Container, status: ContainerStatus):
            with self._stage_status_cv:
                data_structure[container].status = status
                self._stage_status_cv.notify()

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

        data_structure: dict[Container, DataStructureEntry] = {
            container: DataStructureEntry(
                monitor_thread=threading.Thread(
                    target=self._thread_monitor_container,
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

        # start according to stage

        timed_out = False
        failed = False

        for stage in sorted(containers_by_stage.keys()):
            LOGGER.debug("Starting containers in stage %i", stage)

            with self._stage_status_cv:
                for container in containers_by_stage[stage]:
                    data_structure[container].status = get_container_status(container)
                    assert data_structure[container].status == ContainerStatus.CREATED

                for container in containers_by_stage[stage]:
                    data_structure[container].monitor_thread.start()

                timed_out = False

                while any(
                    data_structure[container].status == ContainerStatus.CREATED
                    for container in containers_by_stage[stage]
                ):
                    timed_out = not self._stage_status_cv.wait(
                        timeout=max(0, timeout - (time.time() - start))
                    )

                    if timed_out:
                        break

                containers_not_running = [
                    container
                    for container in containers_by_stage[stage]
                    if data_structure[container].status != ContainerStatus.RUNNING
                ]

                if containers_not_running:
                    different_status_str = ", ".join(
                        f"{container.name}: {data_structure[container].status.value}"
                        for container in containers_not_running
                    )
                    LOGGER.error("Some containers did not start successfully. Exiting.")
                    LOGGER.error(different_status_str)
                    timeout = 0
                    end_callback()
                    failed = True

                    # don't start next stage

                    break

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

            if thread.is_alive():
                # timeout
                timed_out = True
                end_callback()
                thread.join(timeout=1)

                if thread.is_alive():
                    end_callback(force=True)
                    thread.join()

        for container in containers:
            status = get_container_status(container)

            if status != ContainerStatus.EXITED:
                logging.error(
                    "Container %s did not exit, but is in %s state.",
                    container.name,
                    status.value,
                )
                #  breakpoint()
                failed = True

                break

        self.disconnect_all_containers()

        if failed:
            LOGGER.error("Starting containers failed.")
            sys.exit(1)

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
        archive_buf = BytesIO()
        bits, _stat = container.get_archive(src)
        # TODO progress bar with stat["size"]

        for tar_chunk in bits:
            archive_buf.write(tar_chunk)

        archive_buf.seek(0)
        with tarfile.open(fileobj=archive_buf) as archive:
            # don't use archive.extractall() because we can't control the target file to extract to.

            for member in archive.getmembers():
                if member.isfile():
                    # construct target path: strip logs/
                    target_path = dst

                    for part in Path(member.path).parts[1:]:
                        target_path /= part

                    LOGGER.debug(
                        "Extracting %s:%s to %s",
                        container.name,
                        member.path,
                        target_path,
                    )
                    target_path.parent.mkdir(exist_ok=True, parents=True)
                    with target_path.open("wb") as target_file:
                        extracted = archive.extractfile(member)
                        assert extracted

                        while True:
                            chunk = extracted.read(10240)

                            if not chunk:
                                break

                            target_file.write(chunk)

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

        result = self.run_and_wait(containers, timeout=30)

        for container in containers:
            container.remove()

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
        server_container = self._create_implementation(
            image=server.image,
            role=Role.SERVER,
            local_certs_path=Path("/dev/null"),
            testcase=testcase,
            version=version,
            local_www_path=Path("/dev/null"),
            local_download_path=Path("/dev/null"),
            entrypoint=["sleep", str(timeout)],
        )
        LOGGER.debug("Creating client container")
        client_container = self._create_implementation(
            image=client.image,
            role=Role.CLIENT,
            local_certs_path=Path("/dev/null"),
            testcase=testcase,
            version=version,
            request_urls="debug-request-url",
            local_www_path=Path("/dev/null"),
            local_download_path=Path("/dev/null"),
            entrypoint=["sleep", str(timeout)],
        )
        containers = [sim_container, client_container, server_container]
        # wait
        LOGGER.debug("Starting containers")
        result = self.run_and_wait(containers, timeout=timeout)

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

        assert self._networks[role]

        return self._networks[role]

    def get_network_name(self, role: Role) -> str:
        return f"{self.project_name}_{NETWORKS[role].name}"

    def disconnect_container_from_void(self, container: Container):
        container.client.networks.get(VOID_NETWORK).disconnect(container)

    def disconnect_all_containers(self):
        """Disconnect all containers from our networks."""

        for network in self._networks.values():
            assert network

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
            f"{other_role.value}4": other_ipv4.exploded,
            f"{other_role.value}6": other_ipv6.exploded,
            f"{other_role.value}46": other_ipv4.exploded,
            f"{other_role.value}46 ": other_ipv6.exploded,
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
            entrypoint=entrypoint,
            environment=environment,
            extra_hosts={
                "server": self.get_container_ipv4(Role.SERVER),
                "server4": self.get_container_ipv4(Role.SERVER),
                "server6": self.get_container_ipv6(Role.SERVER),
                "server46": self.get_container_ipv4(Role.SERVER),
                "server46 ": self.get_container_ipv6(Role.SERVER),
                "client": self.get_container_ipv4(Role.CLIENT),
                "client4": self.get_container_ipv4(Role.CLIENT),
                "client6": self.get_container_ipv6(Role.CLIENT),
                "client46": self.get_container_ipv4(Role.CLIENT),
                "client46 ": self.get_container_ipv6(Role.CLIENT),
            },
            hostname=name,
            labels={
                "de.sedrubal.interop.service": name,
                "de.sedrubal.interop.project": self.project_name,
                "de.sedrubal.interop.working_dir": str(Path().absolute()),
                "de.sedrubal.interop.stage": "0",
            },
            name=container_name,
            # connect to dummy network to avoid connecting to host
            network=VOID_NETWORK,
            stdin_open=True,
            tty=True,
        )
        # TODO - why and how?
        #  expose:
        #    - "57832"

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

    def _create_iperf(
        self,
        role: Role,
        iperf_congestion="cubic",
        entrypoint: Optional[list[str]] = None,
    ) -> Container:
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
            entrypoint=entrypoint,
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
        entrypoint: Optional[list[str]] = None,
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
            entrypoint=entrypoint,
            env=env,
            extra_hosts=self.get_extra_hosts(role),
            ipv4_address=self.get_container_ipv4(role),
            ipv6_address=self.get_container_ipv6(role),
            volumes=volumes,
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
        entrypoint: Optional[list[str]] = None,
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
            entrypoint=entrypoint,
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
            # connect to dummy network to avoid connecting to host
            network=VOID_NETWORK,
            stdin_open=True,
            tty=True,
            ulimits=[MEMLOCK_ULIMIT],
            volumes=volumes,
        )

        self.disconnect_container_from_void(container)
        network.connect(
            container,
            ipv4_address=ipv4_address.exploded,
            ipv6_address=ipv6_address.exploded,
        )

        return container


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
