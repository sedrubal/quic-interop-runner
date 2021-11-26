#!/usr/bin/env python3
"""Parse quic-interop-runner result.json files."""

import json
import logging
import re
import statistics
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import cached_property
from itertools import chain
from pathlib import Path
from typing import Iterable, Optional, Sequence, Union, cast
from uuid import UUID, uuid4

import pandas
import prettytable
from dateutil.parser import parse as parse_date
from termcolor import colored

from enums import ImplementationRole, TestResult
from exceptions import ConflictError
from implementations import IMPLEMENTATIONS, Implementation
from result_json_types import (
    JSONMeasurementDescr,
    JSONMeasurementResult,
    JSONResult,
    JSONTestDescr,
    JSONTestResult,
)
from units import DataRate
from utils import LOGGER, Statistics, UrlOrPath, compare_and_merge

DETAILS_RE = re.compile(r"(?P<avg>\d+) \(± (?P<stdev>\d+)\) (?P<unit>\w+)")


@dataclass(frozen=True)
class TestDescription:
    """The description of a test."""

    abbr: str
    name: str
    desc: str
    timeout: Optional[int]

    def to_json(self) -> JSONTestDescr:
        """Convert to a raw test description."""

        return JSONTestDescr(name=self.name, desc=self.desc, timeout=self.timeout)


@dataclass(frozen=True)
class MeasurementDescription(TestDescription):
    """The description of a measurement."""

    #: The value, that can theoretically reached in best case (same unit as values)
    theoretical_max_value: Optional[float]
    repetitions: Optional[int]

    def to_json(self) -> JSONMeasurementDescr:
        """Convert to a raw test description."""

        return JSONMeasurementDescr(
            name=self.name,
            desc=self.desc,
            timeout=self.timeout,
            theoretical_max_value=self.theoretical_max_value,
            repetitions=self.repetitions,
        )

    @classmethod
    def from_test_desc(cls, test_desc: TestDescription) -> "MeasurementDescription":
        return cls(
            abbr=test_desc.abbr,
            name=test_desc.name,
            desc=test_desc.desc,
            timeout=test_desc.timeout,
            theoretical_max_value=None,
            repetitions=None,
        )

    def __lt__(self, other: "MeasurementDescription") -> bool:
        return self.name < other.name


@dataclass(frozen=True)  # type: ignore
class _ResultInfoMixin(ABC):
    result: Optional[TestResult]
    server: Implementation
    client: Implementation
    test: Union[TestDescription, MeasurementDescription]
    _base_log_dir: UrlOrPath

    @property
    def succeeded(self) -> bool:
        """True if the test succeeded."""

        return self.result == TestResult.SUCCEEDED

    @property
    def combination(self) -> str:
        """Return a combination of server and client as string."""

        return f"{self.server.name}_{self.client.name}"

    @property
    def log_dir_for_test(self) -> UrlOrPath:
        """Return the log dir for this test."""

        return self._base_log_dir / self.combination / self.test.name

    @abstractmethod
    def to_json(self):
        """Convert to a raw result."""


@dataclass(frozen=True)
class TestResultInfo(_ResultInfoMixin):
    """Information about a test result."""

    test: TestDescription

    def to_json(self) -> JSONTestResult:
        """Return a raw measurement result."""

        return JSONTestResult(
            abbr=self.test.abbr,
            result=self.result.value if self.result else None,
        )


@dataclass(frozen=True)
class MeasurementResultInfo(_ResultInfoMixin):
    """Information about a measurement result."""

    test: MeasurementDescription
    details: str
    values: list[float]

    @cached_property
    def repetition_log_dirs(self) -> list[Path]:
        """Return a list of log dirs for each test repetition."""
        assert self.log_dir_for_test.is_path
        try:
            repetitions = sorted(
                (int(iterdir.name), iterdir)
                for iterdir in self.log_dir_for_test.path.iterdir()
                if iterdir.is_dir() and iterdir.name.isnumeric()
            )
        except FileNotFoundError as err:
            if self.result == TestResult.SUCCEEDED:
                breakpoint()
                raise err
            else:
                return []

        for index, (cur_num, _path) in enumerate(repetitions):
            if index + 1 != cur_num:
                raise AssertionError(
                    f"Expected the {index}th repetition directory of test "
                    f"{self.test.abbr} for server={self.server.name} and client={self.client.name} "
                    f"to be named {index} instead of {cur_num}."
                )

        return [path for (_index, path) in repetitions]

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
    def stdev(self) -> int:
        """The standard deviation value."""

        return int(self._details_match.group("stdev"))

    @property
    def unit(self) -> str:
        """The unit of ``avg`` and ``stdev``."""

        return self._details_match.group("unit")

    def to_json(self) -> JSONMeasurementResult:
        """Return a raw measurement result."""

        return JSONMeasurementResult(
            abbr=self.test.abbr,
            result=self.result.value if self.result else None,
            details=self.details,
            values=self.values,
        )

    @property
    def avg_efficiency(self) -> float:
        """The average efficiency."""
        assert self.test.theoretical_max_value
        assert self.succeeded

        eff = self.avg / self.test.theoretical_max_value
        assert 0 < eff <= 1
        return eff


TestResults = dict[str, dict[str, dict[str, TestResultInfo]]]
MeasurementResults = dict[str, dict[str, dict[str, MeasurementResultInfo]]]


class Result:
    """A pythonic version of result.json."""

    def __init__(
        self,
        file_path: Union[None, UrlOrPath, Path, str],
        log_dir: Union[None, UrlOrPath, Path, str] = None,
        id: Optional[UUID] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        quic_draft: Optional[int] = None,
        quic_version: Optional[int] = None,
    ):
        self.file_path: Optional[UrlOrPath] = (
            UrlOrPath(file_path) if file_path else None
        )
        self._log_dir: Optional[UrlOrPath] = UrlOrPath(log_dir) if log_dir else None

        self._id: Optional[UUID] = id
        self._start_time: Optional[datetime] = start_time
        self._end_time: Optional[datetime] = end_time
        self._quic_draft: Optional[int] = quic_draft
        self._quic_version: Optional[int] = quic_version
        self._servers = dict[str, Implementation]()
        self._clients = dict[str, Implementation]()
        self._test_descriptions = dict[
            str, Union[TestDescription, MeasurementDescription]
        ]()
        self._test_results = TestResults()
        self._meas_results = MeasurementResults()

    def __str__(self):
        return (
            f"<{self.__class__.__name__} "
            f"{self.file_path.path.name if self.file_path else '[in memory]'} "
            f"{len(self.test_descriptions)} test(s) "
            f"{len(self.implementations)} impl(s)>"
        )

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.file_path)})"

    def load_from_json(self):
        assert self.file_path
        content = self.file_path.read()
        raw_data: JSONResult = json.loads(content)
        assert isinstance(raw_data, dict)
        # parse result ID

        if raw_data.get("id"):
            self._id = UUID(hex=raw_data.get("id"))
        # parse start time
        self._start_time = datetime.fromtimestamp(raw_data["start_time"])
        # parse start time
        self._end_time = datetime.fromtimestamp(raw_data["end_time"])
        # parse quic_draft
        self._quic_draft = int(raw_data["quic_draft"])
        # parse quic_version
        self._quic_version = int(raw_data["quic_version"], base=16)
        # parse log_dir
        self.log_dir = UrlOrPath(raw_data["log_dir"])

        if not self.log_dir.is_absolute():
            abs_log_dir = UrlOrPath(self.file_path.parent / self.log_dir)

            if abs_log_dir.is_dir():
                self.log_dir = abs_log_dir
            elif self.file_path.parent.name == self.log_dir.name:
                self.log_dir = self.file_path.parent
                #  LOGGER.warning(
                #      "Log dir in result file %s is not correct. Using %s",
                #      self.file_path,
                #      log_dir,
                #  )
            elif self.file_path.is_path:
                LOGGER.warning(
                    "The log dir %s given in %s does not exist",
                    self.log_dir,
                    self.file_path,
                )

        # parse implementations
        client_names = {client for client in raw_data["clients"]}
        server_names = {server for server in raw_data["servers"]}

        for name in client_names | server_names:
            img_metadata = (raw_data.get("images", {}) or {}).get(name, {})

            created_raw: Optional[str] = img_metadata.get("created")
            created = parse_date(created_raw) if created_raw else None
            image_versions = img_metadata.get("versions")
            image_repo_digests = img_metadata.get("repo_digests")
            image = img_metadata.get("image")

            if not image:
                try:
                    image = IMPLEMENTATIONS[name].image
                except KeyError:
                    LOGGER.warning("Image for %s not known", name)
                    image = None

            if name in client_names and name in server_names:
                role = ImplementationRole.BOTH
            elif name in client_names:
                role = ImplementationRole.CLIENT
            elif name in server_names:
                role = ImplementationRole.SERVER
            else:
                assert False

            implementation = Implementation(
                name=name,
                url=raw_data["urls"][name],
                role=role,
                image=image,
                _image_id=img_metadata.get("id"),
                _image_repo_digests=frozenset(image_repo_digests)
                if image_repo_digests
                else None,
                _image_versions=frozenset(image_versions) if image_versions else None,
                _image_created=created,
                compliant=img_metadata.get("compliant"),
            )
            self.add_implementation(implementation, implementation.role)

        # parse test (descriptions)
        test_descriptions = dict[str, Union[TestDescription, MeasurementDescription]]()

        for abbr, test in raw_data["tests"].items():
            if "theoretical_max_value" in test.keys() or "repetitions" in test.keys():
                json_meas_desc: JSONMeasurementDescr = cast(JSONMeasurementDescr, test)
                meas_desc = MeasurementDescription(
                    abbr=abbr,
                    name=test["name"],
                    desc=test["desc"],
                    timeout=test.get("timeout"),
                    theoretical_max_value=json_meas_desc.get("theoretical_max_value"),
                    repetitions=json_meas_desc.get("repetitions"),
                )
                test_descriptions[abbr] = meas_desc
            else:
                test_descriptions[abbr] = TestDescription(
                    abbr=abbr,
                    name=test["name"],
                    desc=test["desc"],
                    timeout=test.get("timeout"),
                )

        self._test_descriptions = test_descriptions

        # load test and measurement results

        for server_index, server_name in enumerate(raw_data["servers"]):
            for client_index, client_name in enumerate(raw_data["clients"]):

                index = client_index * len(self.servers) + server_index

                if index < len(raw_data["results"]):
                    for test in raw_data["results"][index]:
                        if not test["result"]:
                            continue

                        self.add_test_result(
                            server=server_name,
                            client=client_name,
                            test_abbr=test["abbr"],
                            test_result=TestResult(test["result"]),
                        )
                else:
                    LOGGER.warning(
                        (
                            "Malformed result.json: No test results for "
                            "client=%s server=%s (index=%d out of range)."
                        ),
                        client_name,
                        server_name,
                        index,
                    )

                if index < len(raw_data["measurements"]):
                    for measurement in raw_data["measurements"][index]:
                        result = measurement["result"]

                        self.add_measurement_result(
                            server=server_name,
                            client=client_name,
                            meas_abbr=measurement["abbr"],
                            meas_result=TestResult(result) if result else None,
                            details=measurement["details"],
                            values=measurement.get("values") or list[float](),
                        )
                else:
                    LOGGER.warning(
                        (
                            "Malformed result.json: No measurement results for "
                            "client=%s server=%s (index=%d out of range)."
                        ),
                        client_name,
                        server_name,
                        index,
                    )

    def to_json(self) -> JSONResult:
        """Return the raw json data."""

        servers = sorted(self.servers.keys())
        clients = sorted(self.clients.keys())

        # linearize tests and measurements
        test_results_lin = list[list[JSONTestResult]]()
        meas_results_lin = list[list[JSONMeasurementResult]]()

        for client in clients:
            for server in servers:
                try:
                    test_results_for_combination = [
                        test_result.to_json()
                        for test_result in self.get_test_results_for_combination(
                            server, client
                        ).values()
                    ]
                except KeyError:
                    test_results_for_combination = []
                test_results_lin.append(test_results_for_combination)
                try:
                    meas_results_for_combination = [
                        meas_result.to_json()
                        for meas_result in self.get_measurements_for_combination(
                            server, client
                        ).values()
                    ]
                except KeyError:
                    meas_results_for_combination = []
                meas_results_lin.append(meas_results_for_combination)

        test_descriptions: dict[str, Union[JSONTestDescr, JSONMeasurementDescr]] = {
            abbr: test.to_json() for abbr, test in self.test_descriptions.items()
        }

        output: JSONResult = {
            "id": str(self.id),
            "start_time": self.start_time.timestamp(),
            "end_time": self.end_time.timestamp(),
            "log_dir": str(self.log_dir),
            "servers": servers,
            "clients": clients,
            "urls": {
                name: impl.url for name, impl in sorted(self.implementations.items())
            },
            "images": {
                name: impl.img_metadata_json()
                for name, impl in sorted(self.implementations.items())
            },
            "tests": test_descriptions,
            "quic_draft": self.quic_draft,
            "quic_version": hex(self.quic_version),
            "results": test_results_lin,
            "measurements": meas_results_lin,
        }

        return output

    @property
    def id(self) -> UUID:
        """The UUID of this test."""

        if not self._id:
            self._id = uuid4()

        return self._id

    @id.setter
    def id(self, value: UUID):
        self._id = value

    @property
    def start_time(self) -> datetime:
        """The start time of the test run."""
        assert (
            self._start_time
        ), "No start time set. Did you already call load_from_json()?"

        return self._start_time

    @start_time.setter
    def start_time(self, value: datetime):
        self._start_time = value

    @property
    def end_time(self) -> datetime:
        """The end time of the test run."""
        assert (
            self._end_time
        ), f"End Time is missing in {self.file_path}. Did you already call load_from_json()?"

        return self._end_time

    @end_time.setter
    def end_time(self, value: datetime):
        self._end_time = value

    @property
    def duration(self) -> timedelta:
        """The duration of the test run."""

        return self.end_time - self.start_time

    @property
    def quic_draft(self) -> int:
        """The quic draft version used in this test run."""
        assert (
            self._quic_draft is not None
        ), "No QUIC draft set. Did you already call load_from_json()?"

        return self._quic_draft

    @quic_draft.setter
    def quic_draft(self, value: int):
        self._quic_draft = value

    @property
    def quic_version(self) -> int:
        """The hexadecimal quic version used in this test run."""
        assert (
            self._quic_version is not None
        ), "No QUIC version set. Did you already call load_from_json()?"

        return self._quic_version

    @quic_version.setter
    def quic_version(self, value: int):
        self._quic_version = value

    @property
    def log_dir(self) -> UrlOrPath:
        """The path to the detailed logs."""
        assert (
            self._log_dir is not None
        ), "No log dir set. Did you already call load_from_json()?"

        return self._log_dir

    @log_dir.setter
    def log_dir(self, value: UrlOrPath):
        self._log_dir = value

    @property
    def servers(self) -> dict[str, Implementation]:
        """The servers with metadata used in this test run."""

        return self._servers

    @property
    def clients(self) -> dict[str, Implementation]:
        """The clients with metadata used in this test run."""

        return self._clients

    @property
    def implementations(self) -> dict[str, Implementation]:
        """Return a mapping of involved implementations."""

        return {
            **self.servers,
            **self.clients,
        }

    def add_implementation(self, impl: Implementation, role: ImplementationRole):
        assert role in impl.role

        if impl.name in self.implementations.keys():
            impl2 = self.implementations[impl.name]
            assert impl.name == impl2.name
            if impl.url != impl2.url:
                raise ConflictError(
                    f"The URL of implementation {impl.name} changed: {impl.url} != {impl2.url}."
                )
            if impl.image != impl2.image:
                raise ConflictError(
                    f"The docker image of implementation {impl.name} changed: {impl.image} != {impl2.image}."
                )

            # merge compliant

            if impl.compliant is not None and impl2.compliant is not None:
                if impl.compliant is True and impl2.compliant is True:
                    compliant = True
                elif impl.compliant is False or impl2.compliant is False:
                    compliant = False
                else:
                    compliant = None
            elif impl.compliant is not None:
                compliant = impl.compliant
            else:
                compliant = impl2.compliant
            # merge / update
            impl.role = impl.role | impl2.role
            impl.compliant = compliant
            impl.image = impl.image

            error_msg = f"Conflict while adding image {impl.name}"
            impl._image_id = compare_and_merge("_image_id", impl, impl2, error_msg)
            impl._image_repo_digests = compare_and_merge(
                "_image_repo_digests", impl, impl2, error_msg
            )
            impl._image_versions = compare_and_merge(
                "_image_versions", impl, impl2, error_msg
            )
            impl._image_created = compare_and_merge(
                "_image_created", impl, impl2, error_msg
            )

        if role.is_server:
            self.servers[impl.name] = impl

        if role.is_client:
            self.clients[impl.name] = impl

    @property
    def test_descriptions(
        self,
    ) -> dict[str, Union[TestDescription, MeasurementDescription]]:
        """
        Return a dict of test and measurement abbr.s and description that ran during this run.
        """

        return self._test_descriptions

    @property
    def measurement_descriptions(self) -> dict[str, MeasurementDescription]:
        """Return a dict of measurement abbrs and their descriptions."""

        return {
            abbr: test_desc
            for abbr, test_desc in self.test_descriptions.items()
            if isinstance(test_desc, MeasurementDescription)
        }

    def add_test_description(
        self, test_desc: Union[TestDescription, MeasurementDescription]
    ):
        if test_desc.abbr in self.test_descriptions.keys():
            test_desc2 = self.test_descriptions[test_desc.abbr]

            error_msg = (
                f"Conflict while adding test description for test {test_desc.abbr}"
            )
            abbr = compare_and_merge("abbr", test_desc, test_desc2, error_msg)
            name = compare_and_merge("name", test_desc, test_desc2, error_msg)
            desc = compare_and_merge("desc", test_desc, test_desc2, error_msg)
            assert isinstance(abbr, str)
            assert isinstance(name, str)
            assert isinstance(desc, str)
            timeout: Optional[int] = compare_and_merge(
                "timeout", test_desc, test_desc2, error_msg
            )

            if isinstance(test_desc2, MeasurementDescription):
                if isinstance(test_desc, MeasurementDescription):
                    theoretical_max_value = compare_and_merge(
                        "theoretical_max_value", test_desc, test_desc2, error_msg
                    )
                    repetitions = compare_and_merge(
                        "repetitions", test_desc, test_desc2, error_msg
                    )
                else:
                    theoretical_max_value = test_desc2.theoretical_max_value
                    repetitions = test_desc2.repetitions

                test_desc_merged = MeasurementDescription(
                    abbr,
                    name,
                    desc,
                    timeout,
                    theoretical_max_value,
                    repetitions,
                )
            else:
                test_desc_merged = TestDescription(
                    abbr,
                    name,
                    desc,
                    timeout,
                )
        else:
            test_desc_merged = test_desc

        self._test_descriptions[test_desc.abbr] = test_desc_merged

    @property
    def test_results(self) -> TestResults:
        """
        The test results of this test run in a nested dict.

        Dict keys are <server name> -> <client name> -> <test abbr>
        """

        return self._test_results

    @property
    def all_test_results(self) -> list[TestResultInfo]:
        """Return all test results."""

        return [
            test_result
            for results_by_server in self.test_results.values()
            for results_by_client in results_by_server.values()
            for test_result in results_by_client.values()
        ]

    def get_test_results_for_combination(
        self, server: Union[str, Implementation], client: Union[str, Implementation]
    ) -> dict[str, TestResultInfo]:
        """Return all test results for a combination of client and server."""
        server_name = server if isinstance(server, str) else server.name
        client_name = client if isinstance(client, str) else client.name

        try:
            return self.test_results[server_name][client_name]
        except KeyError:
            return {}

    def get_test_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        test_abbr: str,
    ) -> TestResultInfo:
        """Get a specific test result."""

        return self.get_test_results_for_combination(server, client)[test_abbr]

    def get_all_tests_of_type(
        self,
        test_abbr: str,
        succeeding: Optional[bool] = None,
    ) -> list[TestResultInfo]:
        """Return a list of test results of a specific type."""

        tests = list[TestResultInfo]()

        for server_name in self.servers.keys():
            for client_name in self.clients.keys():
                test_results_for_combi = self.test_results.get(server_name, {}).get(
                    client_name, {}
                )

                if test_abbr not in test_results_for_combi.keys():
                    continue

                test_result = test_results_for_combi[test_abbr]

                if succeeding is not None and test_result.succeeded != succeeding:
                    continue

                tests.append(test_result)

        return tests

    def add_test_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        test_abbr: str,
        test_result: Optional[TestResult],
        update_failed=False,
    ):
        server_impl = (
            server if isinstance(server, Implementation) else self.servers[server]
        )
        client_impl = (
            client if isinstance(client, Implementation) else self.clients[client]
        )

        if server_impl.name not in self.test_results.keys():
            self._test_results[server_impl.name] = dict[
                str, dict[str, TestResultInfo]
            ]()

        if client_impl.name not in self.test_results[server_impl.name].keys():
            self._test_results[server_impl.name][client_impl.name] = dict[
                str, TestResultInfo
            ]()

        test_result_info = TestResultInfo(
            result=test_result,
            server=server_impl,
            client=client_impl,
            test=self.test_descriptions[test_abbr],
            _base_log_dir=self.log_dir,
        )

        if test_abbr in self.test_results[server_impl.name][client_impl.name].keys():
            if update_failed:
                test_included: TestResultInfo = self._test_results[server_impl.name][
                    client_impl.name
                ][test_abbr]

                if not test_included.succeeded and test_result == TestResult.SUCCEEDED:
                    # overwrite failed test:
                    self._test_results[server_impl.name][client_impl.name][
                        test_abbr
                    ] = test_result_info
                elif test_result != TestResult.SUCCEEDED:
                    # do not overwrite with a failed test:

                    return
                else:
                    breakpoint()
                    raise ValueError(
                        f"Both results have a result for the test {test_abbr} "
                        f"for {server_impl.name}_{client_impl.name} and both succeeded."
                    )
            else:
                breakpoint()
                raise ValueError(
                    f"Both results have a result for the test {test_abbr}."
                )
        else:
            self._test_results[server_impl.name][client_impl.name][
                test_abbr
            ] = test_result_info

    def remove_test_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        test_abbr: str,
    ):
        server_impl = (
            server if isinstance(server, Implementation) else self.servers[server]
        )
        client_impl = (
            client if isinstance(client, Implementation) else self.clients[client]
        )

        if server_impl.name not in self.test_results.keys():
            return

        if client_impl.name not in self.test_results[server_impl.name].keys():
            return

        if test_abbr in self.test_results[server_impl.name][client_impl.name].keys():
            del self.test_results[server_impl.name][client_impl.name][test_abbr]

    @property
    def measurement_results(self) -> MeasurementResults:
        """
        The measurement results of this test run in a nested dict.

        Dict keys are <server name> -> <client name> -> <measurement abbr>
        """

        return self._meas_results

    @property
    def all_measurement_results(self) -> list[MeasurementResultInfo]:
        """Return all measurement results."""

        return [
            measurement_result
            for results_by_server in self.measurement_results.values()
            for results_by_client in results_by_server.values()
            for measurement_result in results_by_client.values()
        ]

    def get_measurements_for_combination(
        self, server: Union[str, Implementation], client: Union[str, Implementation]
    ) -> dict[str, MeasurementResultInfo]:
        """Return all measurements for a combination of client and server."""
        server_name = server if isinstance(server, str) else server.name
        client_name = client if isinstance(client, str) else client.name

        try:
            return self.measurement_results[server_name][client_name]
        except KeyError:
            return {}

    def get_measurement_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        measurement_abbr: str,
    ) -> MeasurementResultInfo:
        """Get a specific measurement result."""

        return self.get_measurements_for_combination(server, client)[measurement_abbr]

    def get_all_measurements_of_type(
        self,
        measurement_abbr: str,
        succeeding: Optional[bool] = None,
    ) -> list[MeasurementResultInfo]:
        """Return a list of measurement results of a specific type."""
        measurement_results = list[MeasurementResultInfo]()

        for server_name in self.servers.keys():
            for client_name in self.clients.keys():
                measurement_results_for_combi = self.measurement_results.get(
                    server_name, {}
                ).get(client_name, {})

                if measurement_abbr not in measurement_results_for_combi.keys():
                    continue

                measurement_result = measurement_results_for_combi[measurement_abbr]

                if (
                    succeeding is not None
                    and measurement_result.succeeded != succeeding
                ):
                    continue

                measurement_results.append(measurement_result)

        return measurement_results

    def _get_meas_desc(self, meas_abbr: str) -> MeasurementDescription:
        """Get the measurement description for a measurement abbreviation."""
        test_desc = self.test_descriptions[meas_abbr]

        if isinstance(test_desc, MeasurementDescription):
            meas_desc = test_desc
        else:
            meas_desc = MeasurementDescription.from_test_desc(test_desc)
            # update measurement description (as we know now that this belongs to a measurement and not to a test).
            self._test_descriptions[meas_abbr] = meas_desc

        return meas_desc

    def add_measurement_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        meas_abbr: str,
        meas_result: Optional[TestResult],
        details: str,
        values: list[float],
        update_failed=False,
    ):
        server_impl = (
            server if isinstance(server, Implementation) else self.servers[server]
        )
        client_impl = (
            client if isinstance(client, Implementation) else self.clients[client]
        )

        if server_impl.name not in self._meas_results.keys():
            self._meas_results[server_impl.name] = dict[
                str, dict[str, MeasurementResultInfo]
            ]()

        if client_impl.name not in self._meas_results[server_impl.name].keys():
            self._meas_results[server_impl.name][client_impl.name] = dict[
                str, MeasurementResultInfo
            ]()

        meas_desc = self._get_meas_desc(meas_abbr)

        meas_result_info = MeasurementResultInfo(
            result=meas_result,
            server=server_impl,
            client=client_impl,
            test=meas_desc,
            _base_log_dir=self.log_dir,
            details=details,
            values=values,
        )

        if meas_abbr in self._meas_results[server_impl.name][client_impl.name].keys():
            if update_failed:
                meas_included: MeasurementResultInfo = self._meas_results[
                    server_impl.name
                ][client_impl.name][meas_abbr]

                if not meas_included.succeeded and meas_result == TestResult.SUCCEEDED:
                    # overwrite failed measurement:
                    self._meas_results[server_impl.name][client_impl.name][
                        meas_abbr
                    ] = meas_result_info
                elif meas_result != TestResult.SUCCEEDED:
                    # do not overwrite with a failed measurement:
                    breakpoint()

                    return
                else:
                    breakpoint()
                    raise ValueError(
                        f"Both results have a result for the measurement {meas_abbr} "
                        f"for {server}_{client} and both succeeded."
                    )
            else:
                breakpoint()
                raise ValueError(
                    f"Both results have a result for the measurement {meas_abbr}."
                )
        else:
            self._meas_results[server_impl.name][client_impl.name][
                meas_abbr
            ] = meas_result_info

    def add_single_measurement_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        meas_abbr: str,
        meas_result: Optional[TestResult],
        value: Optional[float],
        num_repetitions: int,
        values_unit: str,
        update_failed=False,
    ):
        server_impl = (
            server if isinstance(server, Implementation) else self.servers[server]
        )
        client_impl = (
            client if isinstance(client, Implementation) else self.clients[client]
        )

        if server_impl.name not in self._meas_results.keys():
            self._meas_results[server_impl.name] = dict[
                str, dict[str, MeasurementResultInfo]
            ]()

        if client_impl.name not in self._meas_results[server_impl.name].keys():
            self._meas_results[server_impl.name][client_impl.name] = dict[
                str, MeasurementResultInfo
            ]()

        meas_desc = self._get_meas_desc(meas_abbr)

        if (
            meas_abbr
            not in self._meas_results[server_impl.name][client_impl.name].keys()
        ):
            values = []
        else:
            existing_meas_result_info = self._meas_results[server_impl.name][
                client_impl.name
            ][meas_abbr]
            values = existing_meas_result_info.values

            if existing_meas_result_info.result:
                if update_failed:
                    if existing_meas_result_info.result == TestResult.SUCCEEDED:
                        raise ConflictError(
                            f"A result for measurement {meas_abbr} already exists and it succeeded before."
                        )
                else:
                    raise ConflictError(
                        f"A result for measurement {meas_abbr} already exists and we do not update failed results: "
                        f"{existing_meas_result_info.result.value}"
                    )

            if len(values) >= num_repetitions:
                raise ConflictError(
                    f"Too many values for measurement {meas_abbr} after adding the new one: "
                    ", ".join(map(str, values))
                )

        if value is not None:
            values.append(value)

        if len(values) == num_repetitions or meas_result != TestResult.SUCCEEDED:
            # measurement is completed

            if meas_result == TestResult.SUCCEEDED:
                mean = statistics.mean(values)
                stdev = statistics.stdev(values)
                details = f"{mean:.0f} (± {stdev:.0f}) {values_unit}"
            else:
                details = ""

            meas_result_info = MeasurementResultInfo(
                result=meas_result,
                server=server_impl,
                client=client_impl,
                test=meas_desc,
                _base_log_dir=self.log_dir,
                details=details,
                values=values,
            )
        else:
            meas_result_info = MeasurementResultInfo(
                result=None,
                server=server_impl,
                client=client_impl,
                test=meas_desc,
                _base_log_dir=self.log_dir,
                details="",
                values=values,
            )

        self._meas_results[server_impl.name][client_impl.name][
            meas_abbr
        ] = meas_result_info

    def remove_measurement_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        meas_abbr: str,
    ):
        server_impl = (
            server if isinstance(server, Implementation) else self.servers[server]
        )
        client_impl = (
            client if isinstance(client, Implementation) else self.clients[client]
        )

        if server_impl.name not in self._meas_results.keys():
            return

        if client_impl.name not in self._meas_results[server_impl.name].keys():
            return

        if meas_abbr in self._meas_results[server_impl.name][client_impl.name].keys():
            del self._meas_results[server_impl.name][client_impl.name][meas_abbr]

    def remove_impl_results(
        self,
        impl: Union[str, Implementation],
        role: ImplementationRole = ImplementationRole.BOTH,
        abbrs: Optional[Iterable[str]] = None,
    ):
        """Remove test and measurement results for the given implementation."""
        if isinstance(impl, Implementation):
            impl_name = impl.name
        else:
            impl_name = impl

        if not abbrs:
            abbrs = self.test_descriptions.keys()

        if role.is_server:
            for client_name in self.clients.keys():
                for abbr in abbrs:
                    self.remove_test_result(
                        server=impl_name, client=client_name, test_abbr=abbr
                    )
                    self.remove_measurement_result(
                        server=impl_name, client=client_name, meas_abbr=abbr
                    )
        if role.is_client:
            for server_name in self.servers.keys():
                for abbr in abbrs:
                    self.remove_test_result(
                        server=server_name, client=impl_name, test_abbr=abbr
                    )
                    self.remove_measurement_result(
                        server=server_name, client=impl_name, meas_abbr=abbr
                    )

    def get_measurement_results_as_dataframe(
        self, include_failed: bool = True
    ) -> pandas.DataFrame:
        """Return the measurement results as data frame."""
        meas_descs = sorted(self.measurement_descriptions.values())

        data = list[tuple[str, str, str, int, Union[int, float], float]]()
        assert all(meas_desc.theoretical_max_value for meas_desc in meas_descs)
        for meas_desc in meas_descs:
            # assert that the result.json file format is new enough to contain theoretical_max_value, repetitions and values
            assert meas_desc.theoretical_max_value is not None
            assert meas_desc.repetitions is not None
            # remember unit of values[] when test failed. We use kbps anyway.
            default_unit: int = DataRate.KBPS
            for meas in self.get_all_measurements_of_type(
                meas_desc.abbr, succeeding=None if include_failed else True
            ):
                for iteration, value in enumerate(meas.values):
                    unit = (
                        DataRate.from_str(meas.unit) if meas.succeeded else default_unit
                    )
                    data.append(
                        (
                            meas.server.name,
                            meas.client.name,
                            meas_desc.name,
                            iteration,
                            value * unit,
                            value / meas_desc.theoretical_max_value,
                        )
                    )

                if not meas.succeeded and include_failed:
                    # append goodput=0 & efficiency=0 for failed run
                    # (which is the last iteration and there is not value recorded)
                    failed_iteration = len(meas.values)
                    assert failed_iteration < meas_desc.repetitions
                    data.append(
                        (
                            meas.server.name,
                            meas.client.name,
                            meas_desc.name,
                            failed_iteration,
                            0,
                            0.0,
                        )
                    )

        df = pandas.DataFrame(
            data,
            columns=[
                "server",
                "client",
                "measurement",
                "repetition",
                "value",
                "efficiency",
            ],
        )
        return df.sort_values(["server", "client", "measurement", "repetition"])

    def get_efficiency_stats(
        self,
        implementation: Union[str, Implementation],
        role: ImplementationRole,
        measurement_abbr: str,
    ) -> Optional[Statistics]:
        """
        :return: Statistics of efficiency for the measurements ``measurement_abbr``, where ``implementations`` was used as ``role``.
        """
        impl = (
            (
                self.servers[implementation]
                if role.is_server
                else self.clients[implementation]
            )
            if isinstance(implementation, str)
            else implementation
        )
        assert role in impl.role

        effs = [
            meas.avg_efficiency
            for meas in self.get_all_measurements_of_type(
                measurement_abbr, succeeding=True
            )
            if (
                (role.is_server and meas.server.name == impl.name)
                or (role.is_client and meas.client.name == impl.name)
            )
        ]

        if not effs:
            return None
        else:
            return Statistics.calc(effs)

    def get_measurement_value_stats(
        self,
        implementation: Union[str, Implementation],
        role: ImplementationRole,
        measurement_abbr: str,
    ) -> Optional[Statistics]:
        """
        :return: Statistics of measurement values of ``measurement_abbr``, where ``implementations`` was used as ``role``.
        """
        impl = (
            (
                self.servers[implementation]
                if role.is_server
                else self.clients[implementation]
            )
            if isinstance(implementation, str)
            else implementation
        )
        assert role in impl.role

        avgs = [
            meas.avg
            for meas in self.get_all_measurements_of_type(
                measurement_abbr, succeeding=True
            )
            if (
                (role.is_server and meas.server.name == impl.name)
                or (role.is_client and meas.client.name == impl.name)
            )
        ]

        if not avgs:
            return None
        else:
            return Statistics.calc(avgs)

    def get_overall_measurement_value_stats(
        self, measurement_abbr: str
    ) -> Optional[Statistics]:
        avgs = [
            meas.avg
            for meas in self.get_all_measurements_of_type(
                measurement_abbr, succeeding=True
            )
        ]

        if not avgs:
            return None
        else:
            return Statistics.calc(avgs)

    def get_overall_measurement_efficiency_stats(
        self, measurement_abbr: str
    ) -> Optional[Statistics]:
        effs = [
            meas.avg_efficiency
            for meas in self.get_all_measurements_of_type(
                measurement_abbr, succeeding=True
            )
        ]

        if not effs:
            return None
        else:
            return Statistics.calc(effs)

    def get_marginalized_efficiency_stats(
        self, measurement_abbr: str, role: ImplementationRole
    ) -> Optional[Statistics]:
        """
        :Return: Stats of the marginalized efficiency averages.

        I.E.: Use the measurement average efficiency of each matrix cell.
        Calculate statistic of column (``role=ImplementationRole.SERVER``) or row (``role=ImplementationRole.CLIENT``).
        Use the average values of these statistics.
        Calculate statistic of these average values.
        """
        assert role is not ImplementationRole.BOTH
        stats = [
            self.get_efficiency_stats(server, role, measurement_abbr)
            for server in self.servers.keys()
        ]
        # filter out None values
        stats = [stat for stat in stats if stat]
        if not stats:
            return None
        else:
            return Statistics.calc([stat.avg for stat in stats])

    def print_tables(
        self,
        servers: Optional[list[str]] = None,
        clients: Optional[list[str]] = None,
        test_abbrs: Optional[list[str]] = None,
        measurement_abbrs: Optional[list[str]] = None,
    ):
        """Print the result tables to the terminal."""
        servers = servers if servers is not None else sorted(self.servers.keys())
        clients = clients if clients is not None else sorted(self.clients.keys())
        test_abbrs = (
            test_abbrs
            if test_abbrs is not None
            else sorted(self.test_descriptions.keys())
        )
        measurement_abbrs = (
            measurement_abbrs
            if measurement_abbrs is not None
            else sorted(self.measurement_descriptions.keys())
        )

        # filter out test_abbrs
        for meas_abbr in measurement_abbrs:
            if meas_abbr in test_abbrs:
                test_abbrs.remove(meas_abbr)

        def get_letters(
            tests_for_combi: Iterable[TestResultInfo],
            result: TestResult,
            color: str,
        ) -> str:
            return colored(
                "".join(
                    [
                        test_result.test.abbr
                        for test_result in tests_for_combi
                        if test_result.result is result
                    ]
                ),
                color=color,
            )

        if self.test_results and test_abbrs:
            table = prettytable.PrettyTable()
            table.title = "Test Cases"
            table.hrules = prettytable.ALL
            table.vrules = prettytable.ALL
            table.field_names = [""] + servers

            for client_name in clients:
                row = [client_name]

                for server_name in servers:
                    tests_for_combi = self.get_test_results_for_combination(
                        server_name, client_name
                    ).values()
                    res = "\n".join(
                        (
                            get_letters(
                                tests_for_combi,
                                TestResult.SUCCEEDED,
                                "green",
                            ),
                            get_letters(
                                tests_for_combi,
                                TestResult.UNSUPPORTED,
                                "grey",
                            ),
                            get_letters(tests_for_combi, TestResult.FAILED, "red"),
                        )
                    )
                    row.append(res)
                table.add_row(row)

            print(table)

        if self.measurement_results and measurement_abbrs:
            table = prettytable.PrettyTable()
            table.title = "Measurements"
            table.hrules = prettytable.ALL
            table.vrules = prettytable.ALL
            table.field_names = [""] + servers

            for client_name in clients:
                row = [client_name]

                for server_name in servers:
                    results = []

                    for meas_abbr in measurement_abbrs:
                        try:
                            res = self.get_measurement_result(
                                server_name, client_name, meas_abbr
                            )
                        except KeyError:
                            continue

                        if not hasattr(res, "result"):
                            continue

                        if res.result == TestResult.SUCCEEDED:
                            results.append(
                                colored(
                                    f"{meas_abbr}: {res.details}",
                                    "green",
                                )
                            )
                        elif res.result == TestResult.UNSUPPORTED:
                            results.append(colored(meas_abbr, "grey"))
                        elif res.result == TestResult.FAILED:
                            results.append(colored(meas_abbr, "red"))
                    row.append("\n".join(results))
                table.add_row(row)

            print(table)

    def merge(
        self,
        other: "Result",
        update_failed: bool = True,
    ) -> "Result":
        """Merge this result with another result."""

        if self.quic_draft != other.quic_draft:
            raise ConflictError(
                f"QUIC Draft missmatch: {self.quic_draft} != {other.quic_draft}"
            )

        if self.quic_version != other.quic_version:
            raise ConflictError(
                f"QUIC version missmatch: {self.quic_version} != {other.quic_version}"
            )

        ret = Result(self.file_path)
        ret.id = self.id
        ret.start_time = min(self.start_time, other.start_time)
        ret.end_time = max(self.end_time, other.end_time)
        ret.quic_draft = self.quic_draft
        ret.quic_version = self.quic_version

        if not (
            self.log_dir.is_path
            and other.log_dir.is_path
            and self.log_dir.path.absolute() == other.log_dir.path.absolute()
        ) and not (self.log_dir == other.log_dir):
            raise ConflictError(
                f"Log directory missmatch: {self.log_dir} != {other.log_dir}"
            )

        ret.log_dir = self.log_dir

        for impl in chain(
            self.implementations.values(), other.implementations.values()
        ):
            ret.add_implementation(impl, role=impl.role)

        for test_desc in chain(
            self.test_descriptions.values(), other.test_descriptions.values()
        ):
            ret.add_test_description(test_desc)

        # check and merge test and measurements

        for server_name, server in ret.servers.items():
            for client_name, client in ret.clients.items():

                # merge tests
                try:
                    tests_for_combi1 = self.get_test_results_for_combination(
                        server_name, client_name
                    )
                except KeyError:
                    tests_for_combi1 = dict[str, TestResultInfo]()

                try:
                    tests_for_combi2 = other.get_test_results_for_combination(
                        server_name, client_name
                    )
                except KeyError:
                    tests_for_combi2 = dict[str, TestResultInfo]()

                for test_abbr, test in chain(
                    tests_for_combi1.items(),
                    tests_for_combi2.items(),
                ):
                    ret.add_test_result(
                        server_name,
                        client_name,
                        test_abbr,
                        test.result,
                        update_failed,
                    )

                # merge measurements
                try:
                    meass_for_combi1 = self.get_measurements_for_combination(
                        server, client
                    )
                except KeyError:
                    meass_for_combi1 = dict[str, MeasurementResultInfo]()

                try:
                    meass_for_combi2 = other.get_measurements_for_combination(
                        server, client
                    )
                except KeyError:
                    meass_for_combi2 = dict[str, MeasurementResultInfo]()

                for meas_abbr, meas in chain(
                    meass_for_combi1.items(),
                    meass_for_combi2.items(),
                ):
                    ret.add_measurement_result(
                        server=server_name,
                        client=client_name,
                        meas_abbr=meas_abbr,
                        meas_result=meas.result,
                        details=meas.details,
                        values=meas.values,
                        update_failed=update_failed,
                    )

        return ret

    def save(self):
        """Save to file."""
        assert self.file_path and self.file_path.is_path
        json_data = json.dumps(self.to_json(), indent=" " * 4, ensure_ascii=False)
        with self.file_path.path.open("w") as file:
            file.write(json_data)


def main():
    import sys

    from IPython import embed

    path = sys.argv[-1]
    result = Result(path)
    assert result.file_path

    if result.file_path.is_file():
        result.load_from_json()
    print(result)
    embed()


if __name__ == "__main__":
    main()
