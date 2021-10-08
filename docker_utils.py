"""Utils for working with docker."""

import logging
import marshal
import sys
import tarfile
import concurrent.futures
from io import BytesIO
from pathlib import Path
from typing import Optional, Type, Union

import docker

from implementations import Implementation

Container = Type[docker.models.containers.Container]
Image = Type[docker.models.images.Image]
Network = Type[docker.models.networks.Network]

LOGGER = logging.getLogger(name="quic-interop-runner")


def copy_file_to_container(
    src: Union[Path, str], container: Container, dst: Union[Path, str]
):
    """Copy a file from this device to the container."""
    archive_buf = BytesIO()
    with tarfile.open(fileobj=archive_buf, mode="w") as archive:
        archive.add(src, dst, recursive=False)

    archive_buf.seek(0)
    container.put_archive("/", archive_buf)


def copy_tree_to_container(
    src: Union[Path, str], container: Container, dst: Union[Path, str]
):
    """Copy a file system tree from this device to the container."""
    archive_buf = BytesIO()
    with tarfile.open(fileobj=archive_buf, mode="w") as archive:
        archive.add(src, dst, recursive=True)

    archive_buf.seek(0)
    container.put_archive("/", archive_buf)
    archive_buf.seek(0)

    with Path("/tmp/tmp.tar").open("wb") as dbg:
        dbg.write(archive_buf.read())


def copy_tree_from_container(container: Container, src: Path, dst: Path):
    """Copy a file system tree from container to this device."""
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


def force_same_img_version(implementation: Implementation, cli: docker.DockerClient):
    """Force a docker host to use the same image version as stated in ``implementation``."""
    try:
        host_str = cli.api._custom_adapter.ssh_host  # noqa
    except AttributeError:
        try:
            host_str = cli.api._custom_adapter.socket_path  # noqa
        except AttributeError:
            host_str = str(cli)

    def tag_if_not_tagged(image: Image):
        """Set tag correctly."""

        if implementation.image not in image.tags:
            LOGGER.debug(
                "Tagging image %s with %s on %s",
                image.id,
                implementation.image,
                host_str,
            )
            image.tag(implementation.image)

    def check_img():
        try:
            image = cli.images.get(implementation.image_id)
            tag_if_not_tagged(image)

            return True
        except docker.errors.NotFound:
            LOGGER.debug(
                "Image %s is (still) not available with id %s on %s",
                implementation.image,
                implementation.image_id,
                host_str,
            )

            return False

    def pull_and_verify(spec: str) -> bool:
        LOGGER.debug("Trying to pull %s on %s", spec, host_str)
        try:
            cli.images.pull(spec)
        except docker.errors.NotFound:
            LOGGER.debug("Could not pull %s on %s", spec, host_str)

            return False
        # check if same id is available

        return check_img()

    # check if same id is available

    if check_img():
        return

    for repo_digest in implementation.image_repo_digests:
        # try to pull repo digests

        if pull_and_verify(repo_digest):
            return

    for version in implementation.image_versions:
        # try to pull image versions
        tag = f"{implementation.image}:{version}"

        if pull_and_verify(tag):
            return

    LOGGER.error(
        "Image %s not available with id %s on %s and could also not be pulled.",
        implementation.image,
        implementation.image_id,
        cli,
    )
    sys.exit(1)


def get_all_public_ips():
    """Get all relevant public ip adresses. ATTENTION: This uses heuristics."""
    import ipaddress
    import socket

    import netifaces

    found = {
        socket.AF_INET.value: set[str](),
        socket.AF_INET6.value: set[str](),
    }

    for iface in netifaces.interfaces():
        # use only eno, enp, eth interfaces (not wlp, br-, lo, virt, docker, ...)

        if not iface.startswith("e"):
            continue

        adresses = netifaces.ifaddresses(iface)

        for family in found.keys():
            connections = adresses.get(family, [])

            for connection in connections:
                ip_addr = ipaddress.ip_address(connection["addr"])

                if ip_addr.is_global:
                    found[family].add(ip_addr.exploded)

    return found


def probe_server() -> bool:
    """Start a udp server on all addresses and listen for probes."""
    import json
    import socket
    import time

    TIMEOUT = 10
    PORT = 4433
    sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
    sock.bind(("::", PORT))
    start = time.time()

    while True:
        sock.settimeout(TIMEOUT - (time.time() - start))
        try:
            data_raw, peer = sock.recvfrom(1024)
        except socket.timeout:
            print("Public IP Probe Server Timeout", file=sys.stderr)

            return False
        try:
            data = json.loads(data_raw.decode("utf-8"))
            nonce = data["nonce"]
            addr = data["addr"]
            port = data["port"]
            family = data["family"]
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError) as err:
            print(str(err), file=sys.stderr)

            continue

        ret_data = json.dumps(
            {
                "success": True,
                "nonce": nonce,
                "addr": addr,
                "port": port,
                "family": family,
            }
        )
        sock.sendto(ret_data.encode("utf-8"), peer)

        return True


def probe_client(addresses) -> Optional[str]:
    """Probe all addresses and return the successful ones."""
    import json
    import random
    import socket
    import string
    import time

    PORT = 4433
    NONCE_LEN = 6
    TIMEOUT = 10

    def gen_nonce():
        return "".join(random.choice(string.ascii_lowercase) for _ in range(NONCE_LEN))

    track = {
        int(family): {
            gen_nonce(): {
                "addr": str(addr),
                "port": PORT,
            }
            for addr in addresses[family]
        }
        for family in addresses.keys()
    }
    socks = {
        int(family): socket.socket(family=family, type=socket.SOCK_DGRAM)
        for family in addresses.keys()
    }

    for family in track.keys():
        sock = socks[family]

        for nonce, data in track[family].items():
            data["nonce"] = nonce
            data["family"] = family
            packet = json.dumps(data).encode("utf-8")
            addr: str = data["addr"]
            sock.sendto(packet, (addr, PORT))

        sock.settimeout(TIMEOUT / 2)
        start = time.time()

        while True:
            sock.settimeout(TIMEOUT - (time.time() - start))
            try:
                data_raw, _peer = sock.recvfrom(1024)
            except socket.timeout:
                print("Public IP Probe Client Timeout", file=sys.stderr)

                return None
            try:
                data = json.loads(data_raw.decode("utf-8"))
                nonce = data["nonce"]
                addr = data["addr"]
                port: int = int(data["port"])
                success: bool = bool(data["success"])
                family = data["family"]
            except (
                json.JSONDecodeError,
                UnicodeDecodeError,
                KeyError,
                ValueError,
            ) as err:
                print(str(err), file=sys.stderr)

                continue

            if not success:
                print("Not successfull")

                continue

            if not family in track.keys():
                print("Unknown family")

                continue

            if not nonce in track[family].keys():
                print(
                    "Unknown nonce",
                    nonce,
                    "Known nonces",
                    ", ".join(track[family].keys()),
                )

                continue

            if not addr == track[family][nonce]["addr"]:
                print(
                    "Wrong address. Expected", track[family][nonce]["addr"], "got", addr
                )

                continue

            if port != PORT:
                print("Wrong port. Expected", PORT, "got", port)

                continue

            print(addr, file=sys.stderr)

            return addr


#  def exec_command_on_ssh(ssh_client, cmd: str) -> tuple[str, str]:
#      """Execute a command a paramiko SSH client connection and return stdout as string."""
#      cmd_stdin, cmd_stdout, cmd_stderr = ssh_client.exec_command(cmd)
#      cmd_stdin.close()
#      err = cmd_stderr.read()
#      out = cmd_stdout.read()
#      cmd_stderr.close()
#      cmd_stdout.close()
#
#      return out, err


def execute_func_on_ssh(ssh_client, function, *args, **kwargs):
    LOGGER.debug("Executing %s on remote host.", function.__name__)
    """Execute a python function on the remote host."""
    script = """
python3.9 -q -c '
import sys, os, marshal, types;
stdin = os.fdopen(0, "rb");
stdout = os.fdopen(1, "wb");
func_code, args, kwargs = marshal.loads(stdin.read());
func = types.FunctionType(func_code, globals(), "func");
ret = func(*args, **kwargs);
marshal.dump(ret, stdout);
'
""".replace(
        "\n", ""
    ).strip()
    stdin, stdout, stderr = ssh_client.exec_command(script)
    try:
        stdin.write(marshal.dumps((function.__code__, args, kwargs)))
        stdin.close()
    except OSError as exc:
        LOGGER.error("Execution failed: %s", str(exc))
        err = stderr.read().decode("utf-8")
        LOGGER.error(err)
        sys.exit(1)

    err = stderr.read().decode("utf-8").strip()
    if err:
        LOGGER.error(err)
    try:
        ret = marshal.loads(stdout.read())
    except EOFError:
        LOGGER.error("Execution failed.")
        sys.exit(1)
    return ret


def execute_python_on_docker_host(docker_cli, function, *args, **kwargs):
    """Execute a python function on the docker host given by the docker client."""

    return execute_func_on_ssh(
        docker_cli.api._custom_adapter.ssh_client, function, *args, **kwargs
    )


def negotiate_server_ip(server_cli, client_cli) -> str:
    LOGGER.debug("Try to get all public IPs on server host")
    all_public_ips = execute_python_on_docker_host(server_cli, get_all_public_ips)
    LOGGER.debug("Received public ips: %s", str(all_public_ips))

    def server_thread_func():
        LOGGER.debug("Starting probe server")
        return execute_python_on_docker_host(server_cli, probe_server)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        server_thread = executor.submit(server_thread_func)

        LOGGER.debug("Starting probe client")
        public_ip: str = execute_python_on_docker_host(
            client_cli, probe_client, all_public_ips
        )

        LOGGER.debug("Waiting for server to end...")
        server_ret: bool = server_thread.result()

    if not public_ip:
        LOGGER.error(
            "Found no public ip on server host, that is reachable from the client."
        )
        assert server_ret is False
        sys.exit(1)

    else:
        assert server_ret

    LOGGER.debug("Found a public IP that is reachable: %s", public_ip)

    return public_ip
