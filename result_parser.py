#!/usr/bin/env python3
"""Parse quic-interop-runner result.json files."""

import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import cached_property
from itertools import chain
from pathlib import Path
from typing import Optional, Union, cast
from uuid import UUID, uuid4

from dateutil.parser import parse as parse_date

from enums import ImplementationRole, TestResult
from exceptions import ConflictError
from implementations import IMPLEMENTATIONS, Implementation
from result_json_types import (
    JSONMeasurement,
    JSONMeasurementDescr,
    JSONResult,
    JSONTestDescr,
    JSONTestResult,
)
from utils import UrlOrPath

LOGGER = logging.getLogger(name="quic-interop-runner")

DETAILS_RE = re.compile(r"(?P<avg>\d+) \(± (?P<var>\d+)\) (?P<unit>\w+)")


@dataclass(frozen=True)
class TestDescription:
    """The description of a test."""

    abbr: str
    name: str
    desc: str

    def to_json(self) -> JSONTestDescr:
        """Convert to a raw test description."""

        return JSONTestDescr(
            name=self.name,
            desc=self.desc,
        )


@dataclass(frozen=True)
class MeasurmentDescription(TestDescription):
    """The description of a measurement."""

    theoretical_max_value: Optional[float]
    repetitions: Optional[int]

    def to_json(self) -> JSONMeasurementDescr:
        """Convert to a raw test description."""

        return JSONMeasurementDescr(
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
class _ResultInfoMixin(ABC):
    result: Optional[TestResult]
    server: Implementation
    client: Implementation
    test: Union[TestDescription, MeasurmentDescription]
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

    test: MeasurmentDescription
    details: str

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
            if self.result == "success":
                breakpoint()
                raise err
            else:
                return []

        for index, (cur_num, _path) in enumerate(repetitions):
            if index + 1 != cur_num:
                raise AssertionError(
                    f"Expected the {index}th repetition directory "
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
    def var(self) -> int:
        """The variance value."""

        return int(self._details_match.group("var"))

    @property
    def unit(self) -> str:
        """The unit of ``avg`` and ``var``."""

        return self._details_match.group("unit")

    def to_json(self) -> JSONMeasurement:
        """Return a raw measurement result."""

        return JSONMeasurement(
            abbr=self.test.abbr,
            result=self.result.value if self.result else None,
            details=self.details,
        )


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
            str, Union[TestDescription, MeasurmentDescription]
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
                image=img_metadata.get("image", IMPLEMENTATIONS[name].image),
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
        test_descriptions = dict[str, Union[TestDescription, MeasurmentDescription]]()

        for abbr, test in raw_data["tests"].items():
            if "theoretical_max_value" in test.keys() or "repetitions" in test.keys():
                json_meas_desc: JSONMeasurementDescr = cast(JSONMeasurementDescr, test)
                meas_desc = MeasurmentDescription(
                    abbr=abbr,
                    name=test["name"],
                    desc=test["desc"],
                    theoretical_max_value=json_meas_desc.get("theoretical_max_value"),
                    repetitions=json_meas_desc.get("repetitions"),
                )
                test_descriptions[abbr] = meas_desc
            else:
                test_descriptions[abbr] = TestDescription(
                    abbr=abbr, name=test["name"], desc=test["desc"]
                )

        self._test_descriptions = test_descriptions

        # load test and measurement results
        for server_index, server_name in enumerate(raw_data["servers"]):
            for client_index, client_name in enumerate(raw_data["clients"]):

                index = client_index * len(self.servers) + server_index

                for test in raw_data["results"][index]:
                    if not test["result"]:
                        continue

                    self.add_test_result(
                        server=server_name,
                        client=client_name,
                        test_abbr=test["abbr"],
                        test_result=TestResult(test["result"]),
                    )

                for measurement in raw_data["measurements"][index]:
                    if not measurement["result"]:
                        continue

                    self.add_measurement_result(
                        server=server_name,
                        client=client_name,
                        meas_abbr=measurement["abbr"],
                        meas_result=TestResult(measurement["result"]),
                        details=measurement["details"],
                    )

    def to_json(self) -> JSONResult:
        """Return the raw json data."""

        servers = sorted(self.servers.keys())
        clients = sorted(self.clients.keys())

        # linearize tests and measurements
        test_results_lin = list[list[JSONTestResult]]()
        meas_results_lin = list[list[JSONMeasurement]]()

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
        assert self._start_time
        return self._start_time

    @start_time.setter
    def start_time(self, value: datetime):
        self._start_time = value

    @property
    def end_time(self) -> datetime:
        """The end time of the test run."""
        assert self._end_time
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
        assert self._quic_draft is not None
        return self._quic_draft

    @quic_draft.setter
    def quic_draft(self, value: int):
        self._quic_draft = value

    @property
    def quic_version(self) -> int:
        """The hexadecimal quic version used in this test run."""
        assert self._quic_version is not None
        return self._quic_version

    @quic_version.setter
    def quic_version(self, value: int):
        self._quic_version = value

    @property
    def log_dir(self) -> UrlOrPath:
        """The path to the detailed logs."""
        assert self._log_dir is not None
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

        if impl.name in self.servers.keys():
            impl2 = self.implementations[impl.name]
            assert impl.name == impl2.name
            assert impl.url == impl2.url
            assert impl.image == impl2.image

            def compare(prop, val1, val2):
                if val1 is not None and val2 is not None:
                    if val1 != val2:
                        raise ConflictError(
                            f"Conflict while adding image {impl.name}:"
                            f" Property {prop}: {val1} != {val2}"
                        )
                return val1 or val2

            # merge compliant
            if impl.compliant is True and impl2.compliant is True:
                compliant = True
            elif impl.compliant is False or impl2.compliant is False:
                compliant = False
            else:
                compliant = None
            # merge / update
            impl.role = impl.role | impl2.role
            impl.compliant = compliant
            impl.image = impl.image
            impl._image_id = compare("Image ID", impl.image_id, impl2.image_id)
            impl._image_repo_digests = compare(
                "repo digest",
                impl.image_repo_digests,
                impl2.image_repo_digests,
            )
            impl._image_versions = compare(
                "image_versions",
                impl.image_versions,
                impl2.image_versions,
            )
            impl._image_created = compare(
                "image_created",
                impl.image_created,
                impl2.image_created,
            )

        if role.is_server:
            self.servers[impl.name] = impl
        if role.is_client:
            self.clients[impl.name] = impl

    @property
    def test_descriptions(
        self,
    ) -> dict[str, Union[TestDescription, MeasurmentDescription]]:
        """
        Return a dict of test and measurement abbr.s and description that ran during this run.
        """
        return self._test_descriptions

    @property
    def measurement_descriptions(self) -> dict[str, MeasurmentDescription]:
        """Return a dict of measurment abbrs and their descriptions."""
        return {
            abbr: test_desc
            for abbr, test_desc in self.test_descriptions.items()
            if isinstance(test_desc, MeasurmentDescription)
        }

    def add_test_description(
        self, test_desc: Union[TestDescription, MeasurmentDescription]
    ):
        if test_desc.abbr in self.test_descriptions.keys():
            test_desc2 = self.test_descriptions[test_desc.abbr]

            def compare(name, val1, val2):
                if val1 != val2:
                    raise ConflictError(f"{name}: {val1} != {val2}")

            compare("abbr", test_desc.abbr, test_desc2.abbr)
            compare("name", test_desc.name, test_desc2.name)
            compare("desc", test_desc.desc, test_desc2.desc)
            if isinstance(test_desc2, MeasurmentDescription):
                if isinstance(test_desc, MeasurmentDescription):
                    compare(
                        "theoretical_max_value",
                        test_desc.theoretical_max_value,
                        test_desc2.theoretical_max_value,
                    )
                    compare(
                        "repetitions", test_desc.repetitions, test_desc2.repetitions
                    )
                else:
                    test_desc = test_desc2

        self._test_descriptions[test_desc.abbr] = test_desc

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

        return self.test_results[server_name][client_name]

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
                test_results_for_combi = self.test_results[server_name][client_name]

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

        return self.measurement_results[server_name][client_name]

    def get_measurement_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        measurement_abbr: str,
    ) -> MeasurementResultInfo:
        """Get a specific measurement result."""

        return self.get_measurements_for_combination(server, client)[measurement_abbr]

    def get_all_measuements_of_type(
        self,
        measurement_abbr: str,
        succeeding: Optional[bool] = None,
    ) -> list[MeasurementResultInfo]:
        """Return a list of measurement results of a specific type."""
        measurement_results = list[MeasurementResultInfo]()

        for server_name in self.servers.keys():
            for client_name in self.clients.keys():
                measurement_results_for_combi = self.measurement_results[server_name][
                    client_name
                ]

                if measurement_abbr not in measurement_results_for_combi.keys():
                    continue

                measuement_result = measurement_results_for_combi[measurement_abbr]

                if succeeding is not None and measuement_result.succeeded != succeeding:
                    continue

                measurement_results.append(measuement_result)

        return measurement_results

    def add_measurement_result(
        self,
        server: Union[str, Implementation],
        client: Union[str, Implementation],
        meas_abbr: str,
        meas_result: Optional[TestResult],
        details: str,
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

        test_desc = self.test_descriptions[meas_abbr]

        if isinstance(test_desc, MeasurmentDescription):
            meas_desc = test_desc
        else:
            meas_desc = MeasurmentDescription.from_test_desc(test_desc)
            # update measurement description (as we know now that this belongs to a measurement and not to a test).
            self._test_descriptions[meas_abbr] = meas_desc

        meas_result_info = MeasurementResultInfo(
            result=meas_result,
            server=server_impl,
            client=client_impl,
            test=meas_desc,
            _base_log_dir=self.log_dir,
            details=details,
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
                        server_name,
                        client_name,
                        meas_abbr,
                        meas.result,
                        meas.details,
                        update_failed,
                    )

        return ret

    def save(self):
        """Save to file."""
        assert self.file_path and self.file_path.is_path
        json_data = json.dumps(self.to_json(), indent=" " * 4)
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
