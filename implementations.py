"""Load and provide implementations."""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Optional, TypedDict

import docker
from dateutil.parser import parse as parse_date

from enums import ImplementationRole

if TYPE_CHECKING:
    from deployment import Deployment

LOGGER = logging.getLogger(name="quic-interop-runner")


class ImgMetadataJson(TypedDict):
    image: str
    id: str
    repo_digests: list[str]
    versions: list[str]
    created: Optional[str]
    compliant: Optional[bool]


@dataclass
class Implementation:
    name: str
    image: str
    url: str
    role: ImplementationRole
    compliant: Optional[bool] = None
    _img_versions: Optional[frozenset[str]] = None
    _img_id: Optional[str] = None
    _img_repo_digests: Optional[frozenset[str]] = None
    _img_created: Optional[datetime] = None

    def gather_infos_from_docker(self, docker_cli: docker.DockerClient):
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
        self._img_id = img.id
        self._img_versions = frozenset(
            (tag.replace(f"{image_base}:", "") for tag in img.tags)
        )
        self._img_repo_digests = (
            frozenset(img.attrs["RepoDigests"]) if "RepoDigests" in img.attrs else None
        )
        created_raw: Optional[str] = img.attrs.get("Created")
        self._img_created = parse_date(created_raw) if created_raw else None

    @property
    def image_versions(self) -> frozenset[str]:
        assert self._img_versions

        return self._img_versions

    @property
    def image_id(self) -> str:
        assert self._img_id

        return self._img_id

    @property
    def image_repo_digests(self) -> frozenset[str]:
        assert self._img_repo_digests

        return self._img_repo_digests

    @property
    def image_created(self) -> Optional[datetime]:
        return self._img_created

    def img_metadata_json(self) -> ImgMetadataJson:
        return ImgMetadataJson(
            image=self.image,
            id=self.image_id,
            repo_digests=list(self.image_repo_digests),
            versions=list(self.image_versions),
            created=(
                self.image_created.strftime("%Y-%m-%d %H:%M")
                if self.image_created
                else None
            ),
            compliant=self.compliant,
        )

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


with open("implementations.json", "r") as f:
    data = json.load(f)
    name: str
    val: dict[str, str]

    for name, val in data.items():
        IMPLEMENTATIONS[name] = Implementation(
            name=name,
            image=val["image"],
            url=val["url"],
            role=ImplementationRole(val["role"]),
        )
