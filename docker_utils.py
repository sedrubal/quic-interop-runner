"""Utils for working with docker."""

import logging
import sys
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Type, Union

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
