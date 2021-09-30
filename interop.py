import json
import logging
import os
import random
import re
import shutil
import statistics
import string
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, Type

import prettytable
from termcolor import colored, cprint

import testcases
from evaluation_tools.result_parser import Result
from evaluation_tools.utils import TerminalFormatter
from result import TestResult
from testcases import MEASUREMENTS, TESTCASES, Perspective

CONSOLE_LOG_HANDLER = logging.StreamHandler(stream=sys.stderr)


def random_string(length: int):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase

    return "".join(random.choice(letters) for i in range(length))


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
        implementations: dict,
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
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

        if debug:
            CONSOLE_LOG_HANDLER.setLevel(logging.DEBUG)
        else:
            CONSOLE_LOG_HANDLER.setLevel(logging.INFO)
        CONSOLE_LOG_HANDLER.setFormatter(TerminalFormatter())
        logger.addHandler(CONSOLE_LOG_HANDLER)

        self._start_time = datetime.now()
        self._tests = tests
        self._measurements = measurements
        self._servers = servers
        self._clients = clients
        self._implementations = implementations
        self._output = Path(output) if output else None

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
            logging.warning(
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

            for impl_name, implementation in self._implementations.items():
                old_impl = result.get_image_info(impl_name)
                old_img_id = old_impl.get("id")
                assert not old_img_id or old_img_id == implementation.image_id

            testcases_mapping = {
                testcase.abbreviation: testcase for testcase in TESTCASES
            }

            for test in result.all_test_results:
                if not test.result:
                    continue
                test_cls = testcases_mapping[test.test.abbr]

                self.test_results[test.server.name][test.client.name][
                    test_cls
                ] = TestResult(test.result)
                self._num_skip_runs += 1

            measuements_mapping = {meas.abbreviation: meas for meas in MEASUREMENTS}

            for res_meas in result.all_measurement_results:
                meas_cls = measuements_mapping[res_meas.test.abbr]

                if res_meas.test.repetitions != meas_cls.repetitions:
                    logging.debug(
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
                self._num_skip_runs += res_meas.num_repetitions

            logging.info(
                "Skipping %d tests and measurement runs from previous run",
                self._num_skip_runs,
            )

        elif self._log_dir.is_dir():
            sys.exit(f"Log dir {self._log_dir} already exists.")
        logging.info("Saving logs to %s.", self._log_dir)

        #: TODO store this information in result
        self.compliant = dict[str, bool]()

        logging.info("Will run %d tests and measurement runs", self._nr_runs)

    def _is_unsupported(self, lines: list[str]) -> bool:
        return any("exited with code 127" in line for line in lines) or any(
            "exit status 127" in line for line in lines
        )

    def _check_impl_is_compliant(self, name: str) -> bool:
        """check if an implementation return UNSUPPORTED for unknown test cases"""

        if name in self.compliant:
            logging.debug(
                "%s already tested for compliance: %s", name, str(self.compliant)
            )

            return self.compliant[name]

        client_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_client_")
        www_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="compliance_www_")
        certs_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="compliance_certs_")
        downloads_dir = tempfile.TemporaryDirectory(
            dir="/tmp", prefix="compliance_downloads_"
        )

        testcases.generate_cert_chain(certs_dir.name)

        # check that the client is capable of returning UNSUPPORTED
        logging.info("Checking compliance of %s client", name)
        env = {
            "CERTS": certs_dir.name,
            "TESTCASE_CLIENT": random_string(6),
            "SERVER_LOGS": "/dev/null",
            "CLIENT_LOGS": client_log_dir.name,
            "WWW": www_dir.name,
            "DOWNLOADS": downloads_dir.name,
            "SCENARIO": "simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25",
            "CLIENT": self._implementations[name].image,
        }
        cmd = "docker-compose up --timeout 0 --abort-on-container-exit -V sim client"
        proc = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            check=False,
        )

        if not self._is_unsupported(proc.stdout.splitlines()):
            logging.error("%s client not compliant.", name)
            logging.debug("%s", proc.stdout)
            self.compliant[name] = False

            return False
        logging.debug("%s client compliant.", name)

        # check that the server is capable of returning UNSUPPORTED
        logging.debug("Checking compliance of %s server", name)
        server_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_server_")
        env = {
            "CERTS": certs_dir.name,
            "TESTCASE_SERVER": random_string(6),
            "SERVER_LOGS": server_log_dir.name,
            "CLIENT_LOGS": "/dev/null",
            "WWW": www_dir.name,
            "DOWNLOADS": downloads_dir.name,
            "SERVER": self._implementations[name].image,
        }
        cmd = "docker-compose up -V server"
        output = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )

        if not self._is_unsupported(output.splitlines()):
            logging.error("%s server not compliant.", name)
            logging.debug("%s", output)
            self.compliant[name] = False

            return False
        logging.debug("%s server compliant.", name)

        # remember compliance test outcome
        self.compliant[name] = True

        return True

    def _print_results(self):
        """print the interop table"""
        logging.info("Run took %s", datetime.now() - self._start_time)

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
            "versions": {
                x: self._implementations[x].img_info_json()
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

    def _copy_logs(self, container: str, dir: tempfile.TemporaryDirectory):
        try:
            subprocess.check_output(
                f'docker cp "$(docker-compose --log-level ERROR ps -q {container})":/logs/. {dir.name}',
                shell=True,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except subprocess.CalledProcessError as err:
            logging.info("Copying logs from %s failed: %s", container, err.stdout)

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
    ) -> tuple[TestResult, Optional[float]]:
        start_time = datetime.now()
        sim_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_sim_")
        server_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_server_")
        client_log_dir = tempfile.TemporaryDirectory(dir="/tmp", prefix="logs_client_")
        log_file = tempfile.NamedTemporaryFile(dir="/tmp", prefix="output_log_")
        log_handler = logging.FileHandler(log_file.name)
        log_handler.setLevel(logging.DEBUG)

        formatter = LogFileFormatter("%(asctime)s %(message)s")
        log_handler.setFormatter(formatter)
        logging.getLogger().addHandler(log_handler)

        testcase = test(
            sim_log_dir=sim_log_dir,
            client_keylog_file=client_log_dir.name + "/keys.log",
            server_keylog_file=server_log_dir.name + "/keys.log",
        )
        msg = "  ".join(
            (
                colored(f"[{self.progress:3} %]", color="cyan", attrs=["bold"]),
                colored("Server:", color="cyan"),
                colored(server, color="cyan", attrs=["bold"]),
                colored("Client:", color="cyan"),
                colored(client, color="cyan", attrs=["bold"]),
                colored("Running test case:", color="cyan"),
                colored(str(testcase), color="cyan", attrs=["bold"]),
            )
        )
        print(msg)

        reqs = " ".join([testcase.urlprefix() + p for p in testcase.get_paths()])
        logging.debug("Requests: %s", reqs)
        params = {
            "WAITFORSERVER": "server:443",
            "CERTS": testcase.certs_dir,
            "TESTCASE_SERVER": testcase.testname(Perspective.SERVER),
            "TESTCASE_CLIENT": testcase.testname(Perspective.CLIENT),
            "WWW": testcase.www_dir,
            "DOWNLOADS": testcase.download_dir,
            "SERVER_LOGS": server_log_dir.name,
            "CLIENT_LOGS": client_log_dir.name,
            "SCENARIO": testcase.scenario,
            "CLIENT": self._implementations[client].image,
            "SERVER": self._implementations[server].image,
            "REQUESTS": reqs,
            "VERSION": testcases.QUIC_VERSION,
        }
        params.update(testcase.additional_envs())
        containers = f"sim client server {' '.join(testcase.additional_containers())}"
        cmd = f"docker-compose up --timeout 1 --abort-on-container-exit {containers}"
        logging.debug(
            "Command: %s %s",
            " ".join((f'{k}="{v}"' for k, v in params.items())),
            cmd,
        )

        status = TestResult.FAILED
        output = ""
        expired = False
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=testcase.timeout,
                text=True,
                env=params,
                check=False,
            )
            output = proc.stdout
        except subprocess.TimeoutExpired as ex:
            output = ex.stdout.decode("utf-8")
            expired = True

        logging.debug("%s", output)

        if expired:
            logging.debug("Test failed: took longer than %ds.", testcase.timeout)
            try:
                proc = subprocess.run(
                    f"docker-compose stop {containers}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=60,
                    text=True,
                    check=False,
                )
                logging.debug("%s", proc.stdout)
            except subprocess.TimeoutExpired as ex:
                logging.debug(ex.stdout.decode("utf-8"))
                logging.error(str(ex))

        # copy the pcaps from the simulator
        self._copy_logs("sim", sim_log_dir)
        self._copy_logs("client", client_log_dir)
        self._copy_logs("server", server_log_dir)

        if not expired:
            lines = output.splitlines()

            if self._is_unsupported(lines):
                status = TestResult.UNSUPPORTED
            elif any("client exited with code 0" in str(line) for line in lines):
                try:
                    status = testcase.check()
                except FileNotFoundError as err:
                    logging.error("testcase.check() threw FileNotFoundError: %s", err)
                    status = TestResult.FAILED

        # save logs
        logging.getLogger().removeHandler(log_handler)
        log_handler.close()

        if status in (TestResult.FAILED, TestResult.SUCCEEDED):
            log_dir = self._log_dir / f"{server}_{client}" / str(testcase)

            if log_dir_prefix:
                log_dir /= log_dir_prefix

            if log_dir.is_dir():
                logging.warning("Target log dir %s exists. Overwriting...", log_dir)
                shutil.rmtree(log_dir)

            shutil.copytree(server_log_dir.name, log_dir / "server")
            shutil.copytree(client_log_dir.name, log_dir / "client")
            shutil.copytree(sim_log_dir.name, log_dir / "sim")
            shutil.copyfile(log_file.name, log_dir / "output.txt")

            if self._save_files and status == TestResult.FAILED:
                shutil.copytree(testcase.www_dir, log_dir / "www")
                try:
                    shutil.copytree(testcase.download_dir, log_dir / "downloads")
                except Exception as exception:
                    logging.info("Could not copy downloaded files: %s", exception)

        testcase.cleanup()
        server_log_dir.cleanup()
        client_log_dir.cleanup()
        sim_log_dir.cleanup()
        logging.debug("Test took %ss", (datetime.now() - start_time).total_seconds())

        # measurements also have a value

        if hasattr(testcase, "result"):
            value = testcase.result
        else:
            value = None

        self._nr_run += 1

        return status, value

    def _run_measurement(
        self,
        server: str,
        client: str,
        test: Type[testcases.Measurement],
    ) -> MeasurementResult:
        values = list[float]()

        for i in range(test.repetitions):
            result, value = self._run_test(server, client, f"{i + 1}", test)
            assert value is not None

            if result != TestResult.SUCCEEDED:
                res = MeasurementResult(
                    result=result,
                    details="",
                )
                self._num_skip_runs += test.repetitions - 1 - i

                return res
            values.append(value)

        logging.debug(values)
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
                logging.debug(
                    "Running with server %s (%s) and client %s (%s)",
                    server,
                    self._implementations[server].image,
                    client,
                    self._implementations[client].image,
                )

                if self._skip_compliance_check:
                    logging.info(f"Skipping compliance check for {server} and {client}")
                elif not (
                    self._check_impl_is_compliant(server)
                    and self._check_impl_is_compliant(client)
                ):
                    logging.info("Not compliant, skipping")

                    continue

                # run the test cases

                for testcase in self._tests:
                    if testcase in self.test_results[server][client].keys():
                        logging.info(
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
                        logging.info(
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
