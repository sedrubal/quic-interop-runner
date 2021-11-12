"""Run interoperability tests and fill the matrix."""

import concurrent.futures
import logging
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from itertools import chain
from pathlib import Path
from typing import Iterable, Optional, Type, Union

import prettytable  # type: ignore
from termcolor import colored

import testcases
from deployment import Deployment
from enums import ImplementationRole, TestResult
from exceptions import ConflictError, TestFailed, TestUnsupported
from implementations import IMPLEMENTATIONS, Implementation
from result_parser import Result, TestResultInfo
from testcases import Measurement, TestCase
from utils import LogFileFormatter, TerminalFormatter

CONSOLE_LOG_HANDLER = logging.StreamHandler(stream=sys.stderr)

LOGGER = logging.getLogger(name="quic-interop-runner")

UNSUPPORTED_EXIT_CODE = 127


@dataclass
class ScheduledTest:
    """A test or measurment that has to be executed."""

    #: The name if the server to use.
    server_name: str
    #: The name if the client to use
    client_name: str
    #: The test case / measurement test case to execute.
    test: Union[Type[TestCase], Type[Measurement]]
    #: postfix(?) for the log dir (number of iteration for measurements)
    log_dir_prefix: Optional[str] = field(default=None)


class InteropRunner:
    def __init__(
        self,
        servers: list[str],
        clients: list[str],
        tests: list[Type[testcases.TestCase]],
        measurements: list[Type[testcases.Measurement]],
        output: Optional[Path],
        debug: bool = False,
        save_files: bool = False,
        log_dir: Optional[Path] = None,
        skip_compliance_check: bool = False,
        retry_failed: bool = False,
    ):
        LOGGER.setLevel(logging.DEBUG)

        if debug:
            CONSOLE_LOG_HANDLER.setLevel(logging.DEBUG)
        else:
            CONSOLE_LOG_HANDLER.setLevel(logging.INFO)
        CONSOLE_LOG_HANDLER.setFormatter(TerminalFormatter())
        LOGGER.addHandler(CONSOLE_LOG_HANDLER)

        start_time = datetime.now()

        if not log_dir:
            log_dir = Path(f"logs_{start_time:%Y-%m-%dT%H:%M:%S}")

        self._tests = tests
        self._measurements = measurements
        self._servers = servers
        self._clients = clients

        self._save_files = save_files
        self._skip_compliance_check = skip_compliance_check
        self._retry_failed = retry_failed

        self._deployment = Deployment()

        self._num_skip_runs = 0
        self._nr_runs = (
            len(self._servers)
            * len(self._clients)
            * (len(self._tests) + sum(meas.repetitions for meas in self._measurements))
        )
        self._nr_complete = 0
        self._nr_failed = 0

        self._result = Result(
            file_path=output,
            log_dir=log_dir,
            quic_version=int(testcases.QUIC_VERSION, base=16),
            quic_draft=testcases.QUIC_DRAFT,
            start_time=start_time,
        )

        with concurrent.futures.ThreadPoolExecutor() as executor:

            def add_impl(impl_name):
                implementation = IMPLEMENTATIONS[impl_name]
                implementation.gather_infos_from_docker(
                    self._deployment.get_docker_cli()
                )

                if impl_name in self._servers and impl_name in self._clients:
                    role = ImplementationRole.BOTH
                elif impl_name in self._servers:
                    role = ImplementationRole.SERVER
                elif impl_name in self._clients:
                    role = ImplementationRole.CLIENT
                else:
                    assert False, "Unknown implementation role"
                self._result.add_implementation(implementation, role)

                return True

            future_results = executor.map(
                add_impl, frozenset(self._servers) | frozenset(self._clients)
            )
            assert all(future_results)

        for test in chain(self._tests, self._measurements):
            self._result.add_test_description(test.to_desc())

        if self._result.file_path and self._result.file_path.is_file():
            LOGGER.warning(
                "Output json file %s already exists. Trying to resume run...",
                self._result.file_path,
            )
            orig_result = Result(self._result.file_path)
            orig_result.load_from_json()
            self._result.end_time = datetime.now()
            try:
                self._result = orig_result.merge(self._result)
            except ConflictError as err:
                # raise err
                sys.exit(colored(str(err), color="red"))

            for client in self._clients:
                for server in self._servers:
                    for test_case in self._tests:
                        try:
                            test_result = self._result.get_test_result(
                                server,
                                client,
                                test_case.abbreviation,
                            )
                        except KeyError:
                            continue

                        if test_result.succeeded or not self._retry_failed:
                            self._num_skip_runs += 1
                        elif (
                            self._retry_failed
                            and test_result.result == TestResult.FAILED
                        ):
                            self._result.remove_test_result(
                                server, client, test_case.abbreviation
                            )

                    for meas_case in self._measurements:
                        try:
                            meas_result = self._result.get_measurement_result(
                                server,
                                client,
                                meas_case.abbreviation,
                            )
                        except KeyError:
                            continue

                        if meas_result.succeeded or not self._retry_failed:
                            assert meas_result.test.repetitions
                            self._num_skip_runs += meas_result.test.repetitions
                        elif (
                            self._retry_failed
                            and meas_result.result == TestResult.FAILED
                        ):
                            self._result.remove_measurement_result(
                                server, client, meas_case.abbreviation
                            )

            LOGGER.info(
                "Skipping %d tests and measurement runs from previous run",
                self._num_skip_runs,
            )

        elif self._result.log_dir.is_dir():
            sys.exit(f"Log dir {self._result.log_dir} already exists.")

        log_dir.mkdir(parents=True, exist_ok=True)

        LOGGER.info("Saving logs to %s.", self._result.log_dir)
        LOGGER.info(
            "Will run %d tests and measurement runs",
            self._nr_runs - self._num_skip_runs,
        )

        self._scheduled_tests = list[ScheduledTest]()

    def _check_impl_is_compliant(self, implementation: Implementation) -> bool:
        """Check if an implementation return UNSUPPORTED for unknown test cases."""

        if implementation.compliant is not None:
            LOGGER.debug(
                "%s already tested for compliance: %s",
                implementation.name,
                implementation.compliant,
            )

            return implementation.compliant

        www_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="compliance_www_")
        certs_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="compliance_certs_")
        downloads_dir = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="compliance_downloads_"
        )

        testcases.generate_cert_chain(certs_dir.name)

        for role in (ImplementationRole.SERVER, ImplementationRole.CLIENT):

            exec_result = self._deployment.run_compliance_check(
                implementation=implementation,
                role=role,
                local_certs_path=Path(certs_dir.name),
                local_www_path=Path(www_dir.name),
                local_downloads_path=Path(downloads_dir.name),
                version=testcases.QUIC_VERSION,
            )

            if exec_result.timed_out:
                LOGGER.error(
                    "Compliance check for %s %s timed out ⏲️",
                    implementation.name,
                    role.value,
                )
                implementation.compliant = False

                return False

            if exec_result.exit_codes[role.value] != UNSUPPORTED_EXIT_CODE:
                LOGGER.error(
                    "%s %s is not compliant ❌", implementation.name, role.value
                )
                implementation.compliant = False

                return False

            LOGGER.debug("%s %s is compliant ✅", implementation.name, role.value)

        # remember compliance test result
        implementation.compliant = True

        return True

    def _print_results(self):
        """Print the interop tables."""
        LOGGER.info("Run took %s", datetime.now() - self._result.start_time)

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

        if self._tests:
            table = prettytable.PrettyTable()
            table.title = "Test Cases"
            table.hrules = prettytable.ALL
            table.vrules = prettytable.ALL
            table.field_names = [""] + self._servers

            for client in self._clients:
                row = [client]

                for server in self._servers:
                    tests_for_combi = self._result.get_test_results_for_combination(
                        server, client
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

        if self._measurements:
            table = prettytable.PrettyTable()
            table.title = "Measurements"
            table.hrules = prettytable.ALL
            table.vrules = prettytable.ALL
            table.field_names = [""] + self._servers

            for client in self._clients:
                row = [client]

                for server in self._servers:
                    results = []

                    for measurement in self._measurements:
                        res = self._result.get_measurement_result(
                            server, client, measurement.abbreviation
                        )

                        if not hasattr(res, "result"):
                            continue

                        if res.result == TestResult.SUCCEEDED:
                            results.append(
                                colored(
                                    f"{measurement.abbreviation}: {res.details}",
                                    "green",
                                )
                            )
                        elif res.result == TestResult.UNSUPPORTED:
                            results.append(colored(measurement.abbreviation, "grey"))
                        elif res.result == TestResult.FAILED:
                            results.append(colored(measurement.abbreviation, "red"))
                    row.append("\n".join(results))
                table.add_row(row)

            print(table)

    def _export_results(self):
        if not self._result.file_path:
            return
        self._result.end_time = datetime.now()
        self._result.save()

    def _schedule_testcase(
        self,
        server: str,
        client: str,
        test: Type[testcases.TestCase],
    ):
        """Schedule a test case."""
        self._scheduled_tests.append(
            ScheduledTest(server_name=server, client_name=client, test=test)
        )

    def _schedule_measurement(
        self,
        server: str,
        client: str,
        measurement: Type[testcases.Measurement],
    ):
        """Schedule a measurement (with multiple iterations)."""

        repetitions: int = measurement.repetitions

        for iteration in range(repetitions):
            self._scheduled_tests.append(
                ScheduledTest(
                    server_name=server,
                    client_name=client,
                    log_dir_prefix=f"{iteration + 1}",
                    test=measurement,
                )
            )

    def _run_test(
        self,
        server: str,
        client: str,
        log_dir_prefix: Optional[str],
        test: Type[testcases.TestCase],
    ) -> tuple[TestResult, Optional[float]]:
        """Run a test case or a single measurement iteration."""
        start_time = datetime.now()
        log_dir: Path = self._result.log_dir.path / f"{server}_{client}" / test.name

        if log_dir_prefix:
            log_dir /= log_dir_prefix

        if log_dir.is_dir():
            LOGGER.warning("Target log dir %s exists. Overwriting...", log_dir)
            shutil.rmtree(log_dir)

        sim_log_dir = log_dir / "sim"
        server_log_dir = log_dir / "server"
        client_log_dir = log_dir / "client"
        sim_log_dir.mkdir(parents=True)
        server_log_dir.mkdir(parents=True)
        client_log_dir.mkdir(parents=True)

        log_file = tempfile.NamedTemporaryFile(dir="/tmp", prefix="output_log_")
        log_handler = logging.FileHandler(log_file.name)
        log_handler.setLevel(logging.DEBUG)

        formatter = LogFileFormatter("%(asctime)s %(message)s")
        log_handler.setFormatter(formatter)
        LOGGER.addHandler(log_handler)

        testcase = test(
            sim_log_dir=sim_log_dir,
            client_keylog_file=client_log_dir / "keys.log",
            server_keylog_file=server_log_dir / "keys.log",
        )
        msg_parts = [
            colored(f"[{self.progress:3} %]", color="cyan", attrs=["bold"]),
            colored("Server:", color="cyan"),
            colored(server, color="cyan", attrs=["bold"]),
            colored("Client:", color="cyan"),
            colored(client, color="cyan", attrs=["bold"]),
            colored("Running test case:", color="cyan"),
            colored(str(testcase), color="cyan", attrs=["bold"]),
        ]

        if issubclass(test, testcases.Measurement):
            try:
                meas_result = self._result.get_measurement_result(
                    server=server, client=client, measurement_abbr=test.abbreviation
                )
                iteration = len(meas_result.values)
            except KeyError:
                iteration = 0

            msg_parts.extend(
                (
                    colored("Iteration:", color="cyan"),
                    colored(str(iteration + 1), color="cyan", attrs=["bold"]),
                    colored("of", color="cyan"),
                    colored(str(test.repetitions), color="cyan", attrs=["bold"]),
                )
            )

        print(" ".join(msg_parts))

        reqs = " ".join([testcase.urlprefix() + p for p in testcase.get_paths()])
        LOGGER.debug("Requests: %s", reqs)

        status = TestResult.FAILED

        exec_result = self._deployment.run_testcase(
            log_path=log_dir,
            timeout=testcase.timeout,
            testcase=testcase,
            local_certs_path=Path(testcase.certs_dir),
            local_www_path=Path(testcase.www_dir),
            local_downloads_path=Path(testcase.download_dir),
            client=self._result.implementations[client],
            server=self._result.implementations[server],
            request_urls=reqs,
            version=testcases.QUIC_VERSION,
        )

        if exec_result.timed_out:
            LOGGER.debug("Test failed: took longer than %ds.", testcase.timeout)
        else:
            if any(
                exit_code == UNSUPPORTED_EXIT_CODE
                for exit_code in exec_result.exit_codes.values()
            ):
                status = TestResult.UNSUPPORTED
            elif exec_result.exit_codes["client"] == 0:
                try:
                    testcase.check()
                    status = TestResult.SUCCEEDED
                except TestUnsupported as exc:
                    LOGGER.warning(exc)
                    status = TestResult.UNSUPPORTED
                except TestFailed as exc:
                    LOGGER.warning(exc)
                    status = TestResult.FAILED
                except FileNotFoundError as err:
                    LOGGER.error("testcase.check() threw FileNotFoundError: %s", err)
                    status = TestResult.FAILED

        # save logs
        LOGGER.removeHandler(log_handler)
        log_handler.close()

        shutil.copyfile(log_file.name, log_dir / "output.txt")

        if status in (TestResult.FAILED, TestResult.SUCCEEDED):

            if self._save_files and status == TestResult.FAILED:
                shutil.copytree(testcase.www_dir, log_dir / "www")
                try:
                    shutil.copytree(testcase.download_dir, log_dir / "downloads")
                except Exception as exception:
                    LOGGER.info("Could not copy downloaded files: %s", exception)
                    breakpoint()

        testcase.cleanup()
        LOGGER.debug("Test took %ss", (datetime.now() - start_time).total_seconds())

        # measurements also have a value

        if isinstance(testcase, Measurement):
            value: Optional[float] = testcase.result
        else:
            value = None

        LOGGER.log(
            {
                TestResult.SUCCEEDED: logging.INFO,
                TestResult.UNSUPPORTED: logging.WARNING,
                TestResult.FAILED: logging.ERROR,
            }[status],
            "Test Result: %s%s",
            status.value,
            f" ({value})" if value else "",
        )

        self._nr_complete += 1

        return status, value

    @property
    def progress(self) -> int:
        """Return the progress in percent."""

        # TODO use len(self._scheduled_tests)
        return int((self._nr_complete + self._num_skip_runs) * 100 / self._nr_runs)

    def run(self):
        """run the interop test suite and output the table"""

        for server_name in self._servers:
            for client_name in self._clients:
                server_implementation = self._result.implementations[server_name]
                client_implementation = self._result.implementations[client_name]
                LOGGER.debug(
                    "Running with server %s (%s) and client %s (%s)",
                    server_name,
                    self._result.implementations[server_name].image,
                    client_name,
                    self._result.implementations[client_name].image,
                )

                if self._skip_compliance_check:
                    LOGGER.info(
                        "Skipping compliance check for %s and %s",
                        server_name,
                        client_name,
                    )
                elif not self._check_impl_is_compliant(server_implementation):
                    LOGGER.info(
                        "%s is not compliant, skipping %s-%s",
                        server_implementation.name,
                        server_implementation.name,
                        client_implementation.name,
                    )
                    self._export_results()

                    continue
                elif not self._check_impl_is_compliant(client_implementation):
                    LOGGER.info(
                        "%s is not compliant, skipping %s-%s",
                        client_implementation.name,
                        server_implementation.name,
                        client_implementation.name,
                    )
                    self._export_results()

                    continue

                # save compliance
                self._export_results()

                # schedule the test cases

                for testcase in self._tests:
                    try:
                        existing_test_result = self._result.get_test_result(
                            server_name, client_name, testcase.abbreviation
                        )
                    except KeyError:
                        existing_test_result = None

                    if existing_test_result and existing_test_result.result:
                        LOGGER.info(
                            (
                                "Skipping testcase %s for server=%s and client=%s, "
                                "because it was executed before. Result: %s"
                            ),
                            testcase.abbreviation,
                            server_name,
                            client_name,
                            existing_test_result.result.value,
                        )

                        continue

                    self._schedule_testcase(server_name, client_name, testcase)

                # schedule the measurements

                for measurement in self._measurements:
                    try:
                        existing_meas_result = self._result.get_measurement_result(
                            server_name, client_name, measurement.abbreviation
                        )
                    except KeyError:
                        existing_meas_result = None

                    if existing_meas_result and existing_meas_result.result:
                        LOGGER.info(
                            (
                                "Skipping measurement %s for server=%s and client=%s, "
                                "because it was executed before. Result: %s"
                            ),
                            measurement.abbreviation,
                            server_name,
                            client_name,
                            existing_meas_result.result.value,
                        )

                        continue

                    self._schedule_measurement(
                        server_name,
                        client_name,
                        measurement,
                    )

        while True:
            try:
                scheduled_test = self._scheduled_tests.pop()
            except IndexError:
                break

            result, value = self._run_test(
                server=scheduled_test.server_name,
                client=scheduled_test.client_name,
                log_dir_prefix=scheduled_test.log_dir_prefix,
                test=scheduled_test.test,
            )

            if result == TestResult.FAILED:
                self._nr_failed += 1

            if issubclass(scheduled_test.test, Measurement):
                # a measurement
                assert value is not None

                self._result.add_single_measurement_result(
                    server=scheduled_test.server_name,
                    client=scheduled_test.client_name,
                    meas_abbr=scheduled_test.test.abbreviation,
                    meas_result=result,
                    value=value,
                    num_repetitions=scheduled_test.test.repetitions,
                    values_unit=scheduled_test.test.unit,
                    update_failed=self._retry_failed,
                )

                if result != TestResult.SUCCEEDED:
                    # unschedule all further measurements of same type with same implementations
                    for future_scheduled_test in self._scheduled_tests:
                        if (
                            future_scheduled_test.server_name
                            == scheduled_test.server_name
                            and future_scheduled_test.client_name
                            == scheduled_test.client_name
                            and future_scheduled_test.test == scheduled_test.test
                        ):
                            self._scheduled_tests.remove(future_scheduled_test)
                            self._num_skip_runs += 1

            else:
                # a test case
                self._result.add_test_result(
                    server=scheduled_test.server_name,
                    client=scheduled_test.client_name,
                    test_abbr=scheduled_test.test.abbreviation,
                    test_result=result,
                    update_failed=self._retry_failed,
                )

            # save results after each run
            self._export_results()

        self._print_results()

        return self._nr_failed
