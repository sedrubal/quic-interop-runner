import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Union

import docker
from dateutil.parser import parse as parse_date


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

    def gather_infos_from_docker(self, docker_cli: docker.DockerClient):
        image = docker_cli.images.get(self.image)
        image_base = self.image.split(":", 1)[0]
        self._img_versions = [tag.replace(f"{image_base}:", "") for tag in image.tags]
        self._img_id = image.id
        created_raw: Optional[str] = image.attrs.get("Created")
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
