"""Python types for result.json files."""

from typing import Optional, TypedDict, Union


class JSONTestDescr(TypedDict):
    """A test description as parsed from result.json."""

    name: str
    desc: str
    timeout: Optional[int]


class JSONMeasurementDescr(TypedDict):
    """A measurement description as parsed from result.json."""

    name: str
    desc: str
    theoretical_max_value: Optional[float]
    repetitions: Optional[int]
    timeout: Optional[int]


RawTestResultResult = Optional[str]


class JSONTestResult(TypedDict):
    """A test result as parsed from result.json."""

    abbr: str
    result: RawTestResultResult
    error_code: Optional[str]


class JSONMeasurementResult(TypedDict):
    """A measurement result as parsed from result.json."""

    abbr: str
    result: RawTestResultResult
    details: str
    values: Optional[list[float]]
    error_code: Optional[str]


class JSONImageMetadata(TypedDict):
    """Metadata about an image."""

    image: str
    id: Optional[str]
    repo_digests: Optional[list[str]]
    versions: list[str]
    created: Optional[str]
    compliant: Optional[bool]


class JSONResult(TypedDict):
    """The unmodified content of result.json."""

    id: Optional[str]
    start_time: float
    end_time: float
    log_dir: str
    servers: list[str]
    clients: list[str]
    urls: dict[str, str]
    images: Optional[dict[str, JSONImageMetadata]]
    tests: dict[str, Union[JSONTestDescr, JSONMeasurementDescr]]
    quic_draft: int
    quic_version: str
    results: list[list[JSONTestResult]]
    measurements: list[list[JSONMeasurementResult]]
    # TODO add docker system info of hosts.
