"""Load and provide implementations."""

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import docker
import seaborn as sns
from dateutil.parser import parse as parse_date

from enums import ImplementationRole
from result_json_types import JSONImageMetadata
from utils import LOGGER

if TYPE_CHECKING:
    from deployment import Deployment


IMPLEMENTATIONS_JSON_PATH = Path(__file__).parent / "implementations.json"


@dataclass
class Implementation:
    """An server and/or client implementation with metadata."""

    name: str
    url: str
    role: ImplementationRole
    image: Optional[str]

    compliant: Optional[bool] = None

    _image_id: Optional[str] = None
    _image_repo_digests: Optional[frozenset[str]] = None
    _image_versions: Optional[frozenset[str]] = None
    _image_created: Optional[datetime] = None

    def gather_infos_from_docker(self, docker_cli: docker.DockerClient):
        assert self.image

        img = None

        if self._image_id:
            try:
                img = docker_cli.images.get(self._image_id)
            except docker.errors.ImageNotFound:
                pass

        if not img:
            try:
                img = docker_cli.images.get(self.image)
            except docker.errors.ImageNotFound:
                LOGGER.info(
                    "Pulling image %s on %s host",
                    self.image,
                    ImplementationRole.CLIENT.value,
                )
                img = docker_cli.images.pull(self.image)

        image_base = self.image.split(":", 1)[0]
        self._image_id = img.id
        self._image_versions = frozenset(
            (tag.replace(f"{image_base}:", "") for tag in img.tags)
        )
        self._image_repo_digests = (
            frozenset(img.attrs["RepoDigests"]) if "RepoDigests" in img.attrs else None
        )
        created_raw: Optional[str] = img.attrs.get("Created")
        self._image_created = (
            parse_date(created_raw).replace(second=0, microsecond=0, tzinfo=None)
            if created_raw
            else None
        )

    @property
    def image_versions(self) -> frozenset[str]:
        assert self._image_versions, f"Image version of {self.name} not yet determined."

        return self._image_versions

    @property
    def image_id(self) -> str:
        assert self._image_id, f"Image ID of {self.name} not yet determined."

        return self._image_id

    @image_id.setter
    def image_id(self, value: str):
        self._image_id = value

    @property
    def image_repo_digests(self) -> frozenset[str]:
        assert (
            self._image_repo_digests
        ), f"Image repo digest of {self.name} not yet determined."

        return self._image_repo_digests

    @property
    def image_created(self) -> Optional[datetime]:
        return self._image_created

    def img_metadata_json(self) -> JSONImageMetadata:
        assert self.image
        if not self._image_id:
            LOGGER.warning("image_id of %s not yet determined.", self.name)
        if not self._image_repo_digests:
            LOGGER.warning("image_repo_digests of %s not yet determined.", self.name)
        if not self._image_versions:
            LOGGER.warning("image_versions of %s not yet determined.", self.name)
        if not self._image_created:
            LOGGER.warning("image_created of %s not yet determined.", self.name)
        return JSONImageMetadata(
            image=self.image,
            id=self._image_id,
            repo_digests=list(self.image_repo_digests)
            if self._image_repo_digests
            else [],
            versions=list(self.image_versions) if self._image_versions else [],
            created=(
                self.image_created.strftime("%Y-%m-%d %H:%M")
                if self.image_created
                else None
            ),
            compliant=self.compliant,
        )

    @property
    def unique_marker(self) -> str:
        """Return a unique, well distinguishable matplotlib marker."""

        known_impls = sorted(IMPLEMENTATIONS.keys())
        if self.name not in known_impls:
            LOGGER.warning(
                "Implementation %s not in inventory. Marker might not be unique.",
                self.name,
            )
            known_impls.append(self.name)
        index = known_impls.index(self.name)
        markers = sns._core.unique_markers(len(known_impls))
        return markers[index]

    def __str__(self):
        role_flags = "&".join(
            flag
            for flag in (
                "C" if self.role.is_client else None,
                "S" if self.role.is_server else None,
            )
            if flag
        )
        compliance_flag = (
            "✔" if self.compliant else "?" if self.compliant is None else "⨯"
        )

        return f"<{self.name} ({role_flags}{compliance_flag} {self.url} {self.image})>"


IMPLEMENTATIONS = dict[str, Implementation]()


with IMPLEMENTATIONS_JSON_PATH.open("r") as file:
    data = json.load(file)

name: str
val: dict[str, str]

for name, val in data.items():
    IMPLEMENTATIONS[name] = Implementation(
        name=name,
        image=val["image"],
        url=val["url"],
        role=ImplementationRole(val["role"]),
    )
