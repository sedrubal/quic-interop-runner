import json
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional, Union

import docker
from dateutil.parser import parse as parse_date

if TYPE_CHECKING:
    from deployment import Deployment

LOGGER = logging.getLogger(name="quic-interop-runner")


class Role(Enum):
    BOTH = "both"
    SERVER = "server"
    CLIENT = "client"


@dataclass
class Implementation:
    name: str
    image: str
    url: str
    role: Role
    compliant: Optional[bool] = None
    _img_versions: Optional[list[str]] = None
    _img_id: Optional[str] = None
    _img_created: Optional[datetime] = None

    def gather_infos_from_docker(self, deployment: "Deployment"):
        try:
            client_img = deployment.docker_clis[Role.CLIENT].images.get(self.image)
        except docker.errors.ImageNotFound:
            LOGGER.info("Pulling image %s on %s host", self.image, Role.CLIENT.value)
            client_img = deployment.docker_clis[Role.CLIENT].images.pull(self.image)

        try:
            server_img = deployment.docker_clis[Role.SERVER].images.get(self.image)
        except docker.errors.ImageNotFound:
            LOGGER.info("Pulling image %s on %s host", self.image, Role.SERVER.value)
            server_img = deployment.docker_clis[Role.SERVER].images.pull(self.image)

        image_base = self.image.split(":", 1)[0]
        self._img_id = client_img.id
        assert self._img_id == server_img.id
        self._img_versions = [
            *(tag.replace(f"{image_base}:", "") for tag in client_img.tags),
            *(tag.replace(f"{image_base}:", "") for tag in server_img.tags),
        ]
        created_raw: Optional[str] = client_img.attrs.get(
            "Created", server_img.attrs.get("Created")
        )
        self._img_created = parse_date(created_raw) if created_raw else None

    @property
    def image_versions(self) -> list[str]:
        assert self._img_versions

        return self._img_versions

    @property
    def image_id(self) -> str:
        assert self._img_id

        return self._img_id

    @property
    def image_created(self) -> Optional[datetime]:
        return self._img_created

    def img_metadata_json(self) -> dict[str, Union[str, list[str], None, bool]]:
        return {
            "image": self.image,
            "id": self.image_id,
            "versions": self.image_versions,
            "created": (
                self.image_created.strftime("%Y-%m-%d %H:%M")
                if self.image_created
                else None
            ),
            "compliant": self.compliant,
            #  "revision": self.image_revision,
        }


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
            role=Role(val["role"]),
        )
