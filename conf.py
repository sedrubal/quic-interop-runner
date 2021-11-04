from pathlib import Path

from typing import Optional
import yaml


DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yml"


class Config:
    def __init__(self, path: Path = DEFAULT_CONFIG_PATH):
        with path.open("r") as file:
            self.config = yaml.safe_load(file)

    @property
    def docker_host_urls(self) -> dict[str, str]:
        return self.config["docker_hosts"]

    @property
    def tshark_bin(self) -> Optional[str]:
        return self.config.get("tshark_bin")

    @property
    def pyshark_debug(self) -> bool:
        return self.config.get("pyshark_debug", False)


CONFIG = Config()
