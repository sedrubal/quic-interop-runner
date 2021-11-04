#!/usr/bin/env python3
"""Parse quic-interop-runner result.json files."""

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from functools import cached_property
from itertools import chain
from pathlib import Path
from typing import Literal, Optional, TypedDict, Union, cast
from uuid import UUID, uuid4

from dateutil.parser import parse as parse_date

from utils import UrlOrPath

LOGGER = logging.getLogger(name="quic-interop-runner")

DETAILS_RE = re.compile(r"(?P<avg>\d+) \(± (?P<var>\d+)\) (?P<unit>\w+)")


class RawTestDescr(TypedDict):
    """A test description as parsed from result.json."""

    name: str
    desc: str


class RawMeasurementDescr(TypedDict):
    """A measurement description as parsed from result.json."""

    name: str
    desc: str
    theoretical_max_value: Optional[float]
    repetitions: Optional[int]


RawTestResultResult = Union[
    None, Literal["succeeded"], Literal["failed"], Literal["unsupported"]
]


class RawTestResult(TypedDict):
    """A test result as parsed from result.json."""

    abbr: str
    result: RawTestResultResult


class RawMeasurement(TypedDict):
    """A measurement result as parsed from result.json."""

    abbr: str
    result: RawTestResultResult
    details: str


class RawImageMetadata(TypedDict):
    """Metadata about an image."""

    image: str
    id: str
    repo_digests: Optional[list[str]]
    versions: list[str]
    created: Optional[str]
    compliant: Optional[bool]


class RawResult(TypedDict):
    """The unmodified content of result.json."""

    id: Optional[str]
    start_time: float
    end_time: float
    log_dir: str
    servers: list[str]
    clients: list[str]
    urls: dict[str, str]
    images: Optional[dict[str, RawImageMetadata]]
    tests: dict[str, Union[RawTestDescr, RawMeasurementDescr]]
    quic_draft: int
    quic_version: str
    results: list[list[RawTestResult]]
    measurements: list[list[RawMeasurement]]


class ImplementationRole(Enum):
    """The role of an implementation."""

    SERVER = "server"
    CLIENT = "client"
    BOTH = "both"


@dataclass(frozen=True)
class Implementation:
    """An server and/or client implementation with metadata."""

    name: str
    url: str
    role: ImplementationRole

    image: Optional[str] = None
    image_id: Optional[str] = None
    image_repo_digests: Optional[frozenset[str]] = None
    image_versions: Optional[frozenset[str]] = None
    image_created: Optional[datetime] = None
    compliant: Optional[bool] = None

    def img_metadata_json(self) -> Optional[RawImageMetadata]:
        if not self.image or not self.image_id:
            return None

        return {
            "image": self.image,
            "id": self.image_id,
            "repo_digests": list(self.image_repo_digests)
            if self.image_repo_digests
            else [],
            "versions": list(self.image_versions) if self.image_versions else [],
            "created": (
                self.image_created.strftime("%Y-%m-%d %H:%M")
                if self.image_created
                else None
            ),
            "compliant": self.compliant,
        }


@dataclass(frozen=True)
class TestDescription:
    """The description of a test."""

    abbr: str
    name: str
    desc: str

    def to_raw(self) -> RawTestDescr:
        """Convert to a raw test description."""

        return RawTestDescr(
            name=self.name,
            desc=self.desc,
        )


@dataclass(frozen=True)
class MeasurmentDescription(TestDescription):
    """The description of a measurement."""

    theoretical_max_value: Optional[float]
    repetitions: Optional[int]

    def to_raw(self) -> RawMeasurementDescr:
        """Convert to a raw test description."""

        return RawMeasurementDescr(
            name=self.name,
            desc=self.desc,
            theoretical_max_value=self.theoretical_max_value,
            repetitions=self.repetitions,
        )

    @classmethod
    def from_test_desc(cls, test_desc: TestDescription) -> "MeasurmentDescription":
        return cls(
            abbr=test_desc.abbr,
            name=test_desc.name,
            desc=test_desc.desc,
            theoretical_max_value=None,
            repetitions=None,
        )


@dataclass(frozen=True)  # type: ignore
class _ExtendedTestResultMixin(ABC):
    result: RawTestResultResult
    server: Implementation
    client: Implementation
    test: Union[TestDescription, MeasurmentDescription]
    _base_log_dir: UrlOrPath

    @property
    def succeeded(self) -> bool:
        """True if the test succeeded."""

        return self.result == "succeeded"

    @property
    def combination(self) -> str:
        """Return a combination of server and client as string."""

        return f"{self.server.name}_{self.client.name}"

    @property
    def log_dir_for_test(self) -> UrlOrPath:
        """Return the log dir for this test."""

        return self._base_log_dir / self.combination / self.test.name

    @abstractmethod
    def to_raw(self):
        """Convert to a raw result."""


@dataclass(frozen=True)
class ExtendedTestResult(_ExtendedTestResultMixin):
    """Test result with more information."""

    test: TestDescription

    def to_raw(self) -> RawTestResult:
        """Return a raw measurement result."""

        return RawTestResult(
            abbr=self.test.abbr,
            result=self.result,
        )


@dataclass(frozen=True)
class ExtendedMeasurementResult(_ExtendedTestResultMixin):
    """Measurement result with more information."""

    test: MeasurmentDescription
    details: str

    @cached_property
    def repetition_log_dirs(self) -> list[Path]:
        """Return a list of log dirs for each test repetition."""
        assert self.log_dir_for_test.is_path
        try:
            repetitions = sorted(
                iterdir
                for iterdir in self.log_dir_for_test.path.iterdir()
                if iterdir.is_dir() and iterdir.name.isnumeric()
            )
            repetition_nums = [int(iterdir.name) for iterdir in repetitions]
        except FileNotFoundError as err:
            if self.result == "success":
                breakpoint()
                raise err
            else:
                return []

        for index, cur_num in enumerate(repetition_nums):
            if index + 1 != cur_num:
                raise AssertionError(
                    f"Expected the {index}th repetition directory "
                    f"to be named {index} instead of {cur_num}."
                )

        return repetitions

    @property
    def num_repetitions(self) -> int:
        """Return the number of test repetitions found for this test case."""

        return len(self.repetition_log_dirs)

    @property
    def _details_match(self) -> re.Match:
        assert self.succeeded, "Can't parse details, because test did not succeed."
        match = DETAILS_RE.match(self.details)
        assert match, (
            f"Measurement details `{self.details}` do not match pattern "
            f"in test {self.test.abbr} for combination {self.combination}."
        )

        return match

    @property
    def avg(self) -> int:
        """The average value."""

        return int(self._details_match.group("avg"))

    @property
    def var(self) -> int:
        """The variance value."""

        return int(self._details_match.group("var"))

    @property
    def unit(self) -> str:
        """The unit of ``avg`` and ``var``."""

        return self._details_match.group("unit")

    def to_raw(self) -> RawMeasurement:
        """Return a raw measurement result."""

        return RawMeasurement(
            abbr=self.test.abbr,
            result=self.result,
            details=self.details,
        )


TestResults = dict[str, dict[str, dict[str, ExtendedTestResult]]]
MeasurementResults = dict[str, dict[str, dict[str, ExtendedMeasurementResult]]]


class Result:
    """A pythonic version of result.json."""

    def __init__(
        self, file_path: Union[Path, str], raw_data: Optional[RawResult] = None
    ):
        self.file_path = UrlOrPath(file_path)
        self._raw_data = raw_data
        self._test_results: Optional[TestResults] = None
        self._measurement_results: Optional[MeasurementResults] = None
        self._implementations_changed = False

    def __str__(self):
        return (
            f"<{self.__class__.__name__} {self.file_path.path.name} "
            f"{len(self.tests)} test(s) "
            f"{len(self.implementations)} impl(s)>"
        )

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.file_path)})"

    @property
    def raw_data(self) -> RawResult:
        """Load and return the raw json data."""

        if not self._raw_data:
            content = self.file_path.read()
            self._raw_data = json.loads(content)
            assert self._raw_data

        return self._raw_data

    @raw_data.setter
    def raw_data(self, value: RawResult):
        self._raw_data = value

    @property
    def id(self) -> UUID:
        """The UUID of this test."""

        if not self.raw_data.get("id"):
            self.raw_data["id"] = str(uuid4())
            self.save()

        raw_id = self.raw_data["id"]
        assert raw_id

        return UUID(hex=raw_id)

    @id.setter
    def id(self, value: UUID):
        self.raw_data["id"] = str(value)

    @property
    def start_time(self) -> datetime:
        """The start time of the test run."""

        return datetime.fromtimestamp(self.raw_data["start_time"])

    @start_time.setter
    def start_time(self, value: datetime):
        self.raw_data["start_time"] = value.timestamp()

    @property
    def end_time(self) -> datetime:
        """The end time of the test run."""

        return datetime.fromtimestamp(self.raw_data["end_time"])

    @end_time.setter
    def end_time(self, value: datetime):
        self.raw_data["end_time"] = value.timestamp()

    @property
    def duration(self) -> timedelta:
        """The duration of the test run."""

        return self.end_time - self.start_time

    @property
    def quic_draft(self) -> int:
        """The quic draft version used in this test run."""

        return int(self.raw_data["quic_draft"])

    @quic_draft.setter
    def quic_draft(self, value: int):
        self.raw_data["quic_draft"] = value

    @property
    def quic_version(self) -> int:
        """The hexadecimal quic version used in this test run."""

        return int(self.raw_data["quic_version"], base=16)

    @quic_version.setter
    def quic_version(self, value: int):
        self.raw_data["quic_version"] = hex(value)

    @property
    def log_dir(self) -> UrlOrPath:
        """The path to the detailed logs."""
        log_dir = UrlOrPath(self.raw_data["log_dir"])

        if not log_dir.is_absolute():
            abs_log_dir = UrlOrPath(self.file_path.parent / log_dir)

            if abs_log_dir.is_dir():
                log_dir = abs_log_dir
            elif self.file_path.parent.name == log_dir.name:
                log_dir = self.file_path.parent
                #  LOGGER.warning(
                #      "Log dir in result file %s is not correct. Using %s",
                #      self.file_path,
                #      log_dir,
                #  )
            elif self.file_path.is_path:
                LOGGER.warning(
                    "The log dir %s given in %s does not exist", log_dir, self.file_path
                )

        return log_dir

    @log_dir.setter
    def log_dir(self, value: UrlOrPath):
        self.raw_data["log_dir"] = str(value)

    def get_image_metadata(
        self, impl: Union[str, Implementation]
    ) -> Union[RawImageMetadata, dict]:
        images = self.raw_data.get("images", {}) or {}
        impl_name = impl if isinstance(impl, str) else impl.name

        return images.get(impl_name, {})

    def _update_implementations(
        self, value: list[Implementation], role: ImplementationRole
    ):
        assert role != ImplementationRole.BOTH

        for impl in value:
            img_info = self.get_image_metadata(impl.name)

            if impl.name not in self.raw_data["urls"]:
                self.raw_data["urls"][impl.name] = impl.url
            elif impl.url != self.raw_data["urls"][impl.name]:
                raise ValueError(
                    "There are two different urls for implementation "
                    f"{impl.url} and {self.raw_data['urls'][impl.name]}"
                )
            elif impl.image_id and "id" in img_info and impl.image_id != img_info["id"]:
                raise ValueError(
                    f"There current image ID of {impl.name} differs from the image ID "
                    f"used in the other run: {impl.image_id} != {img_info['id']}"
                )

            list_key: Union[Literal["servers"], Literal["clients"]] = (
                "servers" if role == ImplementationRole.SERVER else "clients"
            )

            if impl.name in self.raw_data[list_key]:
                return

            self._ensure_test_results_loaded()
            self._implementations_changed = True
            self.raw_data[list_key].append(impl.name)

    def _get_implementations(self, role: ImplementationRole) -> list[Implementation]:
        assert role != ImplementationRole.BOTH
        ret = list[Implementation]()
        lookup = (
            self.raw_data["clients"]
            if role == ImplementationRole.CLIENT
            else self.raw_data["servers"]
        )
        lookup_other = (
            self.raw_data["servers"]
            if role == ImplementationRole.CLIENT
            else self.raw_data["clients"]
        )

        for name in lookup:
            img_metadata = self.get_image_metadata(name)
            created_raw: Optional[str] = img_metadata.get("created")
            created = parse_date(created_raw) if created_raw else None
            image_versions = img_metadata.get("versions")
            image_repo_digests = img_metadata.get("repo_digests")
            ret.append(
                Implementation(
                    name=name,
                    url=self.raw_data["urls"][name],
                    role=ImplementationRole.BOTH if name in lookup_other else role,
                    image_id=img_metadata.get("id"),
                    image_repo_digests=frozenset(image_repo_digests)
                    if image_repo_digests
                    else None,
                    image_versions=frozenset(image_versions)
                    if image_versions
                    else None,
                    image_created=created,
                    compliant=img_metadata.get("compliant"),
                )
            )

        return ret

    @property
    def servers(self) -> list[Implementation]:
        """The list of servers with metadata used in this test run."""

        return self._get_implementations(ImplementationRole.SERVER)

    @servers.setter
    def servers(self, value: list[Implementation]):
        self._update_implementations(value, role=ImplementationRole.SERVER)

    @property
    def clients(self) -> list[Implementation]:
        """The list of clients with metadata used in this test run."""

        return self._get_implementations(ImplementationRole.CLIENT)

    @clients.setter
    def clients(self, value: list[Implementation]):
        self._update_implementations(value, role=ImplementationRole.CLIENT)

    @property
    def implementations(self) -> dict[str, Implementation]:
        """Return a mapping of involved implementations."""

        return {
            **{impl.name: impl for impl in self.servers},
            **{impl.name: impl for impl in self.clients},
        }

    @property
    def tests(self) -> dict[str, Union[TestDescription, MeasurmentDescription]]:
        """
        Return a dict of test and measurement abbr.s and description that ran during this run.
        """
        tests = dict[str, Union[TestDescription, MeasurmentDescription]]()

        for abbr, test in self.raw_data["tests"].items():
            if "theoretical_max_value" in test.keys() or "repetitions" in test.keys():
                meas_desc: RawMeasurementDescr = cast(RawMeasurementDescr, test)
                tests[abbr] = MeasurmentDescription(
                    abbr=abbr,
                    name=test["name"],
                    desc=test["desc"],
                    theoretical_max_value=meas_desc.get("theoretical_max_value"),
                    repetitions=meas_desc.get("repetitions"),
                )
            else:
                tests[abbr] = TestDescription(
                    abbr=abbr, name=test["name"], desc=test["desc"]
                )

        return tests

    @property
    def measurement_descriptions(self) -> dict[str, MeasurmentDescription]:
        """Return a dict of measurment abbrs and their descriptions."""

        return {
            abbr: meas
            for abbr, meas in self.tests.items()
            if isinstance(meas, MeasurmentDescription)
        }

    @property
    def test_results(self) -> TestResults:
        """
        The test results of this test run in a nested dict.

        Dict keys are <server name> -> <client name> -> <test abbr>
        """

        if not self._test_results:
            self._test_results = self._load_test_results()

        return self._test_results

    @property
    def all_test_results(self) -> list[ExtendedTestResult]:
        """Return all test results."""

        return [
            test_result
            for results_by_server in self.test_results.values()
            for results_by_client in results_by_server.values()
            for test_result in results_by_client.values()
        ]

    def get_test_results_for_combination(
        self, server: Union[str, Implementation], client: Union[str, Implementation]
    ) -> dict[str, ExtendedTestResult]:
        """Return all test results for a combination of client and server."""
        server_name = server if isinstance(server, str) else server.name
        client_name = client if isinstance(client, str) else client.name

        return self.test_results[server_name][client_name]

    def get_test_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        test_abbr: str,
    ) -> ExtendedTestResult:
        """Get a specific test result."""

        return self.get_test_results_for_combination(server, client)[test_abbr]

    def get_all_tests_of_type(
        self,
        test_abbr: str,
        succeeding: Optional[bool] = None,
    ) -> list[ExtendedTestResult]:
        """Return a list of test results of a specific type."""

        tests = list[ExtendedTestResult]()

        for server in self.servers:
            for client in self.clients:
                test_results_for_combi = self.test_results[server.name][client.name]

                if test_abbr not in test_results_for_combi.keys():
                    continue

                test_result = test_results_for_combi[test_abbr]

                if succeeding is not None and test_result.succeeded != succeeding:
                    continue

                tests.append(test_result)

        return tests

    @property
    def measurement_results(self) -> MeasurementResults:
        """
        The measurement results of this test run in a nested dict.

        Dict keys are <server name> -> <client name> -> <measurement abbr>
        """

        if not self._measurement_results:
            self._measurement_results = self._load_measurement_results()

        return self._measurement_results

    @property
    def all_measurement_results(self) -> list[ExtendedMeasurementResult]:
        """Return all measurement results."""

        return [
            measurement_result
            for results_by_server in self.measurement_results.values()
            for results_by_client in results_by_server.values()
            for measurement_result in results_by_client.values()
        ]

    def get_measurements_for_combination(
        self, server: Union[str, Implementation], client: Union[str, Implementation]
    ) -> dict[str, ExtendedMeasurementResult]:
        """Return all measurements for a combination of client and server."""
        server_name = server if isinstance(server, str) else server.name
        client_name = client if isinstance(client, str) else client.name

        return self.measurement_results[server_name][client_name]

    def get_measurement(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        measurement_abbr: str,
    ) -> ExtendedMeasurementResult:
        """Get a specific measurement result."""

        return self.get_measurements_for_combination(server, client)[measurement_abbr]

    def get_all_measuements_of_type(
        self,
        measurement_abbr: str,
        succeeding: Optional[bool] = None,
    ) -> list[ExtendedMeasurementResult]:
        """Return a list of measurement results of a specific type."""
        measurement_results = list[ExtendedMeasurementResult]()

        for server in self.servers:
            for client in self.clients:
                measurement_results_for_combi = self.measurement_results[server.name][
                    client.name
                ]

                if measurement_abbr not in measurement_results_for_combi.keys():
                    continue

                measuement_result = measurement_results_for_combi[measurement_abbr]

                if succeeding is not None and measuement_result.succeeded != succeeding:
                    continue

                measurement_results.append(measuement_result)

        return measurement_results

    def _load_test_results(self) -> TestResults:
        assert not self._implementations_changed

        results = TestResults()

        for server_index, server in enumerate(self.servers):
            results[server.name] = dict[str, dict[str, ExtendedTestResult]]()

            for client_index, client in enumerate(self.clients):
                results[server.name][client.name] = dict[str, ExtendedTestResult]()

                index = client_index * len(self.servers) + server_index

                for test in self.raw_data["results"][index]:
                    if not test["result"]:
                        continue
                    ext_result = ExtendedTestResult(
                        result=test["result"],
                        server=server,
                        client=client,
                        test=self.tests[test["abbr"]],
                        _base_log_dir=self.log_dir,
                    )
                    results[server.name][client.name][test["abbr"]] = ext_result

        return results

    def _load_measurement_results(self) -> MeasurementResults:
        assert not self._implementations_changed

        results = MeasurementResults()

        for server_index, server in enumerate(self.servers):
            results[server.name] = dict[str, dict[str, ExtendedMeasurementResult]]()

            for client_index, client in enumerate(self.clients):
                results[server.name][client.name] = dict[
                    str, ExtendedMeasurementResult
                ]()

                index = client_index * len(self.servers) + server_index

                for measurement in self.raw_data["measurements"][index]:
                    if not measurement["result"]:
                        continue
                    test_desc = self.tests[measurement["abbr"]]
                    meas_desc = MeasurmentDescription.from_test_desc(test_desc)
                    ext_result = ExtendedMeasurementResult(
                        result=measurement["result"],
                        details=measurement["details"],
                        server=server,
                        client=client,
                        test=meas_desc,
                        _base_log_dir=self.log_dir,
                    )
                    results[server.name][client.name][measurement["abbr"]] = ext_result

        return results

    def _ensure_test_results_loaded(self):
        """Ensure that all test results are loaded."""
        self._test_results = self._load_test_results()
        self._measurement_results = self._load_measurement_results()

    def merge(
        self,
        other: "Result",
        file_path: Union[Path, str],
        log_dir: Union[Path, str],
        update_failed=True,
    ) -> "Result":
        """Merge this result with another result."""
        assert self.quic_draft == other.quic_draft
        assert self.quic_version == other.quic_version

        servers1 = frozenset(server.name for server in self.servers)
        servers2 = frozenset(server.name for server in other.servers)
        clients1 = frozenset(client.name for client in self.clients)
        clients2 = frozenset(client.name for client in other.clients)

        servers_merged = sorted(servers1 | servers2)
        clients_merged = sorted(clients1 | clients2)

        # check and merge test and measurements
        tests_merged = dict[str, dict[str, dict[str, ExtendedTestResult]]]()
        meass_merged = dict[str, dict[str, dict[str, ExtendedMeasurementResult]]]()

        for server in servers_merged:
            tests_merged[server] = dict[str, dict[str, ExtendedTestResult]]()
            meass_merged[server] = dict[str, dict[str, ExtendedMeasurementResult]]()

            for client in clients_merged:
                tests_merged[server][client] = dict[str, ExtendedTestResult]()
                meass_merged[server][client] = dict[str, ExtendedMeasurementResult]()

                # merge tests
                try:
                    tests_for_combi1 = self.get_test_results_for_combination(
                        server, client
                    )
                except KeyError:
                    tests_for_combi1 = dict[str, ExtendedTestResult]()

                try:
                    tests_for_combi2 = other.get_test_results_for_combination(
                        server, client
                    )
                except KeyError:
                    tests_for_combi2 = dict[str, ExtendedTestResult]()

                for test_abbr, test in chain(
                    tests_for_combi1.items(),
                    tests_for_combi2.items(),
                ):
                    if test_abbr in tests_merged[server][client].keys():
                        if update_failed:
                            test_included: ExtendedTestResult = tests_merged[server][
                                client
                            ][test_abbr]

                            if not test_included.succeeded and test.succeeded:
                                # overwrite failed test:
                                tests_merged[server][client][test_abbr] = test
                            elif not test.succeeded:
                                # do not overwrite with a failed test:

                                continue
                            else:
                                breakpoint()
                                raise ValueError(
                                    f"Both results have a result for the test {test_abbr} "
                                    f"for {server}_{client} and both succeeded."
                                )
                        else:
                            breakpoint()
                            raise ValueError(
                                f"Both results have a result for the test {test_abbr}."
                            )
                    else:
                        tests_merged[server][client][test_abbr] = test

                # merge measurements
                try:
                    meass_for_combi1 = self.get_measurements_for_combination(
                        server, client
                    )
                except KeyError:
                    meass_for_combi1 = dict[str, ExtendedMeasurementResult]()

                try:
                    meass_for_combi2 = other.get_measurements_for_combination(
                        server, client
                    )
                except KeyError:
                    meass_for_combi2 = dict[str, ExtendedMeasurementResult]()

                for meas_abbr, meas in chain(
                    meass_for_combi1.items(),
                    meass_for_combi2.items(),
                ):
                    if meas_abbr in meass_merged[server][client].keys():
                        if update_failed:
                            meas_included: ExtendedMeasurementResult = meass_merged[
                                server
                            ][client][meas_abbr]

                            if not meas_included.succeeded and meas.succeeded:
                                # overwrite failed test:
                                meass_merged[server][client][meas_abbr] = meas
                            elif not meas.succeeded:
                                # do not overwrite with a failed test:

                                continue
                            else:
                                breakpoint()
                                raise ValueError(
                                    f"Both results have a result for the test {meas_abbr} "
                                    f"for {server}_{client} and both succeeded."
                                )
                        else:
                            breakpoint()
                            raise ValueError(
                                f"Both results have a result for the test {meas_abbr}."
                            )
                    else:
                        meass_merged[server][client][meas_abbr] = meas

        # linearize tests and measurements
        tests_lin = list[list[RawTestResult]]()
        meass_lin = list[list[RawMeasurement]]()

        for client in clients_merged:
            for server in servers_merged:
                tests_lin.append(
                    [test.to_raw() for test in tests_merged[server][client].values()]
                )
                meass_lin.append(
                    [test.to_raw() for test in meass_merged[server][client].values()]
                )

        urls = dict[str, str]()
        images = dict[str, RawImageMetadata]()

        for name, impl in self.implementations.items():
            own_img_metadata = impl.img_metadata_json()
            common_img_metadata: Optional[RawImageMetadata] = None

            if name in other.implementations.keys():
                other_impl = other.implementations[name]
                assert impl.url == other_impl.url
                other_img_metadata = other_impl.img_metadata_json()

                if own_img_metadata and other_img_metadata:
                    assert own_img_metadata == other_img_metadata
                    common_img_metadata = own_img_metadata
                elif own_img_metadata and not other_img_metadata:
                    common_img_metadata = own_img_metadata
                elif not own_img_metadata and other_img_metadata:
                    common_img_metadata = other_img_metadata
            else:
                common_img_metadata = own_img_metadata

            urls[name] = impl.url

            if common_img_metadata:
                images[name] = common_img_metadata

        for name, impl in other.implementations.items():
            if name not in self.implementations.keys():
                urls[name] = impl.url
                img_metadata = impl.img_metadata_json()

                if img_metadata:
                    images[name] = img_metadata

        test_descriptions: dict[str, Union[RawTestDescr, RawMeasurementDescr]] = {
            **{abbr: test.to_raw() for abbr, test in self.tests.items()},
            **{abbr: test.to_raw() for abbr, test in other.tests.items()},
        }

        output: RawResult = {
            "id": str(self.id),
            "start_time": min(self.start_time, other.start_time).timestamp(),
            "end_time": max(self.end_time, other.end_time).timestamp(),
            "log_dir": str(log_dir),
            "servers": servers_merged,
            "clients": clients_merged,
            "urls": urls,
            "images": images,
            "tests": test_descriptions,
            "quic_draft": self.quic_draft,
            "quic_version": hex(other.quic_version),
            "results": tests_lin,
            "measurements": meass_lin,
        }

        return Result(file_path, raw_data=output)

    def save(self):
        """Save to file."""
        assert self.file_path.is_path
        json_data = json.dumps(self.raw_data, indent=" " * 4)
        with self.file_path.path.open("w") as file:
            file.write(json_data)


def main():
    import sys

    path = sys.argv[-1]
    result = Result(path)
    print(result)
    breakpoint()


if __name__ == "__main__":
    main()
