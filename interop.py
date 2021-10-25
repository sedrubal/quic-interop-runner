import json
import logging
import re
import shutil
import statistics
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Type

import prettytable
from termcolor import colored

import testcases
from deployment import Deployment
from implementations import Implementation, Role
from result import TestResult
from result_parser import Result
from testcases import MEASUREMENTS, TESTCASES
from utils import TerminalFormatter

CONSOLE_LOG_HANDLER = logging.StreamHandler(stream=sys.stderr)

LOGGER = logging.getLogger(name="quic-interop-runner")

UNSUPPORTED_EXIT_CODE = 127


@dataclass
class MeasurementResult:
    result: TestResult
    details: str


class LogFileFormatter(logging.Formatter):
    def format(self, record):
        msg = super(LogFileFormatter, self).format(record)
        # remove color control characters

        return re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]").sub("", msg)


class InteropRunner:
    def __init__(
        self,
        implementations: dict[str, Implementation],
        servers: list[str],
        clients: list[str],
        tests: list[Type[testcases.TestCase]],
        measurements: list[Type[testcases.Measurement]],
        output: str,
        debug: bool,
        save_files=False,
        log_dir: Optional[str] = None,
        skip_compliance_check=False,
    ):
        LOGGER.setLevel(logging.DEBUG)

        if debug:
            CONSOLE_LOG_HANDLER.setLevel(logging.DEBUG)
        else:
            CONSOLE_LOG_HANDLER.setLevel(logging.INFO)
        CONSOLE_LOG_HANDLER.setFormatter(TerminalFormatter())
        LOGGER.addHandler(CONSOLE_LOG_HANDLER)

        self._start_time = datetime.now()
        self._tests = tests
        self._measurements = measurements
        self._servers = servers
        self._clients = clients
        self._implementations = implementations
        self._output = Path(output) if output else None
        self._deployment = Deployment()

        for impl_name in frozenset(self._servers) | frozenset(self._clients):
            implementation = self._implementations[impl_name]
            implementation.gather_infos_from_docker(self._deployment.get_docker_cli())

        if not log_dir:
            self._log_dir = Path(f"logs_{self._start_time:%Y-%m-%dT%H:%M:%S}")
        else:
            self._log_dir = Path(log_dir)

        self._save_files = save_files
        self._skip_compliance_check = skip_compliance_check

        self.test_results = defaultdict[
            str, defaultdict[str, dict[Type[testcases.TestCase], TestResult]]
        ](
            lambda: defaultdict[str, dict[Type[testcases.TestCase], TestResult]](
                dict[Type[testcases.TestCase], TestResult]
            )
        )
        self.measurement_results = defaultdict[
            str,
            defaultdict[str, dict[Type[testcases.Measurement], MeasurementResult]],
        ](
            lambda: defaultdict[
                str, dict[Type[testcases.Measurement], MeasurementResult]
            ](dict[Type[testcases.Measurement], MeasurementResult])
        )

        self._num_skip_runs = 0
        self._nr_runs = (
            len(self._servers)
            * len(self._clients)
            * (len(self._tests) + sum(meas.repetitions for meas in self._measurements))
        )
        self._nr_run = 0

        if self._output and self._output.is_file():
            LOGGER.warning(
                "Output json file %s already exists. Trying to resume run...",
                self._output,
            )
            result = Result(self._output)

            if result.log_dir.path.absolute() != self._log_dir.absolute():
                sys.exit(
                    f"You specified another log_dir than the result file {self._output} used before"
                )

            self._start_time = result.start_time
            assert (
                int(testcases.QUIC_VERSION, base=16) == result.quic_version
            ), f"QUIC VERSION differs: {int(testcases.QUIC_VERSION, base=16)} != {result.quic_version}"
            assert (
                testcases.QUIC_DRAFT == result.quic_draft
            ), f"QUIC draft differs: {testcases.QUIC_DRAFT} != {result.quic_draft}"

            for impl_name in frozenset(self._servers) | frozenset(self._clients):
                implementation = self._implementations[impl_name]
                old_impl = result.implementations.get(impl_name)

                if not old_impl:
                    continue

                if old_impl.image_id and old_impl.image_id != implementation.image_id:
                    raise AssertionError(
                        f"ID of image {implementation.name} differs from previous run."
                        f" Previous: {old_impl.image_id} now: {implementation.image_id}"
                    )

                if old_impl.compliant is not None:
                    implementation.compliant = old_impl.compliant

                    if not implementation.compliant:
                        LOGGER.warning(
                            "Implementation %s seems not to be compliant.",
                            implementation.name,
                        )

            testcases_mapping = {
                testcase.abbreviation: testcase for testcase in TESTCASES
            }

            for test in result.all_test_results:
                if not test.result:
                    # TODO don't retry failed ones? Check with is None

                    continue
                test_cls = testcases_mapping[test.test.abbr]

                self.test_results[test.server.name][test.client.name][
                    test_cls
                ] = TestResult(test.result)

                if (
                    test.server.name in self._servers
                    and test.client.name in self._clients
                ):
                    self._num_skip_runs += 1

            measuements_mapping = {meas.abbreviation: meas for meas in MEASUREMENTS}

            for res_meas in result.all_measurement_results:
                meas_cls = measuements_mapping[res_meas.test.abbr]

                if res_meas.test.repetitions != meas_cls.repetitions:
                    LOGGER.debug(
                        (
                            "Measurement %s for server=%s and client=%s has a different amount "
                            "of repetitions. Will delete logs and run measurement again.",
                        ),
                        res_meas.test.abbr,
                        res_meas.server.name,
                        res_meas.client.name,
                    )
                    shutil.rmtree(res_meas.log_dir_for_test, ignore_errors=True)

                    continue
                self.measurement_results[res_meas.server.name][res_meas.client.name][
                    meas_cls
                ] = MeasurementResult(
                    result=TestResult(res_meas.result),
                    details=res_meas.details,
                )

                if (
                    res_meas.server.name in self._servers
                    and res_meas.client.name in self._clients
                ):
                    self._num_skip_runs += meas_cls.repetitions

            LOGGER.info(
                "Skipping %d tests and measurement runs from previous run",
                self._num_skip_runs,
            )

        elif self._log_dir.is_dir():
            sys.exit(f"Log dir {self._log_dir} already exists.")
        LOGGER.info("Saving logs to %s.", self._log_dir)
        LOGGER.info(
            "Will run %d tests and measurement runs",
            self._nr_runs - self._num_skip_runs,
        )

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

        for role in (Role.SERVER, Role.CLIENT):

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
        """print the interop table"""
        LOGGER.info("Run took %s", datetime.now() - self._start_time)

        def get_letters(result):
            return "".join([test.abbreviation for test in cell if cell[test] is result])

        if len(self._tests) > 0:
            table = prettytable.PrettyTable()
            table.hrules = prettytable.ALL
            table.vrules = prettytable.ALL
            table.field_names = [""] + [name for name in self._servers]

            for client in self._clients:
                row = [client]

                for server in self._servers:
                    cell = self.test_results[server][client]
                    res = colored(get_letters(TestResult.SUCCEEDED), "green") + "\n"
                    res += colored(get_letters(TestResult.UNSUPPORTED), "grey") + "\n"
                    res += colored(get_letters(TestResult.FAILED), "red")
                    row += [res]
                table.add_row(row)
            print(table)

        if not self._measurements:
            table = prettytable.PrettyTable()
            table.hrules = prettytable.ALL
            table.vrules = prettytable.ALL
            table.field_names = [""] + [name for name in self._servers]

            for client in self._clients:
                row = [client]

                for server in self._servers:
                    cell = self.measurement_results[server][client]
                    results = []

                    for measurement in self._measurements:
                        res = cell[measurement]

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
                    row += ["\n".join(results)]
                table.add_row(row)
            print(table)

    def _export_results(self):
        if not self._output:
            return
        out = {
            "start_time": self._start_time.timestamp(),
            "end_time": datetime.now().timestamp(),
            "log_dir": str(self._log_dir),
            "servers": [name for name in self._servers],
            "clients": [name for name in self._clients],
            "urls": {
                x: self._implementations[x].url for x in self._servers + self._clients
            },
            "images": {
                x: self._implementations[x].img_metadata_json()
                for x in self._servers + self._clients
            },
            "tests": {
                test.abbreviation: test.to_json()
                for test in self._tests + self._measurements
            },
            "quic_draft": testcases.QUIC_DRAFT,
            "quic_version": testcases.QUIC_VERSION,
            "results": [],
            "measurements": [],
        }

        for client in self._clients:
            for server in self._servers:
                results = []

                for test in self._tests:
                    result = None

                    if test in self.test_results[server][client].keys():
                        result = self.test_results[server][client][test].value
                    results.append(
                        {
                            "abbr": test.abbreviation,
                            "result": result,
                        }
                    )
                out["results"].append(results)

                measurements = []

                for measurement in self._measurements:

                    if measurement in self.measurement_results[server][client].keys():
                        res = self.measurement_results[server][client][measurement]
                        result = res.result.value
                        details = res.details
                    else:
                        result = None
                        details = ""
                    measurements.append(
                        {
                            "abbr": measurement.abbreviation,
                            "result": result,
                            "details": details,
                        }
                    )
                out["measurements"].append(measurements)

        with open(self._output, "w") as file:
            json.dump(out, file)

    def _run_testcase(
        self,
        server: str,
        client: str,
        test: Type[testcases.TestCase],
    ) -> TestResult:
        return self._run_test(server, client, None, test)[0]

    def _run_test(
        self,
        server: str,
        client: str,
        log_dir_prefix: Optional[str],
        test: Type[testcases.TestCase],
        iteration: Optional[int] = None,
        repetitions: Optional[int] = None,
    ) -> tuple[TestResult, Optional[float]]:
        start_time = datetime.now()
        log_dir: Path = self._log_dir / f"{server}_{client}" / test.name

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

        if iteration is not None:
            msg_parts.extend(
                (
                    colored("Iteration:", color="cyan"),
                    colored(str(iteration + 1), color="cyan", attrs=["bold"]),
                )
            )

        if repetitions is not None:
            msg_parts.extend(
                (
                    colored("of", color="cyan"),
                    colored(str(repetitions), color="cyan", attrs=["bold"]),
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
            client=self._implementations[client],
            server=self._implementations[server],
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
                    status = testcase.check()
                except FileNotFoundError as err:
                    LOGGER.error("testcase.check() threw FileNotFoundError: %s", err)
                    status = TestResult.FAILED

        # save logs
        LOGGER.removeHandler(log_handler)
        log_handler.close()

        if status in (TestResult.FAILED, TestResult.SUCCEEDED):
            shutil.copyfile(log_file.name, log_dir / "output.txt")

            if self._save_files and status == TestResult.FAILED:
                shutil.copytree(testcase.www_dir, log_dir / "www")
                try:
                    shutil.copytree(testcase.download_dir, log_dir / "downloads")
                except Exception as exception:
                    LOGGER.info("Could not copy downloaded files: %s", exception)

        testcase.cleanup()
        LOGGER.debug("Test took %ss", (datetime.now() - start_time).total_seconds())

        # measurements also have a value

        if hasattr(testcase, "result"):
            value = testcase.result
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

        self._nr_run += 1

        return status, value

    def _run_measurement(
        self,
        server: str,
        client: str,
        test: Type[testcases.Measurement],
    ) -> MeasurementResult:
        values = list[float]()

        for iteration in range(test.repetitions):
            result, value = self._run_test(
                server,
                client,
                f"{iteration + 1}",
                test,
                iteration=iteration,
                repetitions=test.repetitions,
            )
            assert value is not None

            if result != TestResult.SUCCEEDED:
                res = MeasurementResult(
                    result=result,
                    details="",
                )
                self._num_skip_runs += test.repetitions - 1 - iteration

                return res
            values.append(value)

        res = MeasurementResult(
            result=TestResult.SUCCEEDED,
            details="{:.0f} (± {:.0f}) {}".format(
                statistics.mean(values), statistics.stdev(values), test.unit
            ),
        )

        return res

    @property
    def progress(self) -> int:
        """Return the progress in percent."""

        return int(self._nr_run * 100 / (self._nr_runs - self._num_skip_runs))

    def run(self):
        """run the interop test suite and output the table"""
        nr_failed = 0

        for server in self._servers:
            for client in self._clients:
                server_implementation = self._implementations[server]
                client_implementation = self._implementations[client]
                LOGGER.debug(
                    "Running with server %s (%s) and client %s (%s)",
                    server,
                    self._implementations[server].image,
                    client,
                    self._implementations[client].image,
                )

                if self._skip_compliance_check:
                    LOGGER.info(
                        "Skipping compliance check for %s and %s", server, client
                    )
                elif not self._check_impl_is_compliant(server_implementation):
                    LOGGER.info(
                        "%s is not compliant, skipping %s-%s",
                        server_implementation.name,
                        server_implementation.name,
                        client_implementation.name,
                    )

                    continue
                elif not self._check_impl_is_compliant(client_implementation):
                    LOGGER.info(
                        "%s is not compliant, skipping %s-%s",
                        client_implementation.name,
                        server_implementation.name,
                        client_implementation.name,
                    )

                    continue

                # run the test cases

                for testcase in self._tests:
                    if testcase in self.test_results[server][client].keys():
                        LOGGER.info(
                            "Skipping testcase %s for server=%s and client=%s, because it was executed before.",
                            testcase.abbreviation,
                            server,
                            client,
                        )

                        continue

                    status = self._run_testcase(server, client, testcase)
                    self.test_results[server][client][testcase] = status

                    if status == TestResult.FAILED:
                        nr_failed += 1

                    # save results after each run
                    self._export_results()

                # run the measurements

                for measurement in self._measurements:
                    if measurement in self.measurement_results[server][client].keys():
                        LOGGER.info(
                            "Skipping measurement %s for server=%s and client=%s, because it was executed before.",
                            measurement.abbreviation,
                            server,
                            client,
                        )

                        continue

                    res = self._run_measurement(
                        server,
                        client,
                        measurement,
                    )
                    self.measurement_results[server][client][measurement] = res

                    # save results after each run
                    self._export_results()

        self._print_results()

        return nr_failed
