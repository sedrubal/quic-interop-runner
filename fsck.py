#!/usr/bin/env python3
"""Consistency check."""

import argparse
import re
from statistics import mean, stdev
from typing import Literal, Optional, Union

from enums import TestResult
from result_parser import Result
from utils import LOGGER


def parse_args():
    """Parse command line args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run in debug mode.",
    )
    parser.add_argument(
        "--ignore-missing-files",
        action="store_true",
        help="Ignore missing files.",
    )
    parser.add_argument(
        "results",
        type=Result,
        metavar="result",
        nargs="+",
        help="Path to result file.",
    )
    return parser.parse_args()


class Fsck:
    """Consistency check."""

    def __init__(self, results: list[Result], ignore_missing_files=False):
        """Initialize."""
        self.results = results
        self.ignore_missing_files = ignore_missing_files
        self._scope: Optional[str] = None
        self._assertion_counter = 0

    def _assert(
        self, condition: bool, message: str, stop_if_failed=False, mute=False
    ) -> bool:
        """Assert."""
        self._assertion_counter += 1
        if not condition:
            if self._scope:
                message = f"{self._scope} | {message}"
            if stop_if_failed:
                LOGGER.error(message)
                raise AssertionError(message)
            elif not mute:
                LOGGER.warning(message)

        return condition

    def _assert_eq(self, a, b, message: str, stop_if_failed=False) -> bool:
        condition = a == b
        return self._assert(condition, f"{message}: {a} != {b}", stop_if_failed)

    def _set_scope(self, server: str, client: str, meas_abbr: str):
        """Set scope."""
        self._scope = f"{server}-{client}-{meas_abbr}"

    def check(self, result: Result):
        """Check result for consistency."""
        self._assertion_counter = 0

        # metadata
        self._assert(
            result.start_time <= result.end_time, "Start time is not before end time."
        )
        # logs
        result_log_re = re.compile(
            r".*Transferring \d+ MiB took (?P<time>\d+) ms. Goodput: (?P<goodput>\d+) kbps"
        )
        self._assert(result.log_dir.is_dir(), "Log directory does not exist.")
        for server in result.servers:
            for client in result.clients:
                for meas_abbr, meas in result.get_measurements_for_combination(
                    server=server, client=client
                ).items():
                    self._set_scope(server=server, client=client, meas_abbr=meas_abbr)
                    self._assert(
                        meas.test.abbr == meas_abbr,
                        "Measurement abbreviation does not match.",
                    )

                    goodputs = list[Union[int, None, Literal["failed"]]]()
                    assert meas.test.repetitions
                    for i in range(1, meas.test.repetitions + 1):
                        output = meas.log_dir_for_test / str(i) / "output.txt"
                        if not output.is_file():
                            goodputs.append(None)
                            continue
                            # else:
                            #     self._assert(False, f"Output file {output} does not exist.")
                        last_line = list(output.readline())[-1].strip()
                        match = result_log_re.match(last_line)
                        if not match:
                            goodputs.append("failed")
                            continue
                        goodput = int(match.group("goodput"))
                        goodputs.append(goodput)

                    if meas.result == TestResult.SUCCEEDED:
                        self._assert_eq(
                            len(goodputs),
                            meas.test.repetitions,
                            "Number of goodputs does not match.",
                        )
                        self._assert_eq(
                            len(goodputs),
                            len(meas.values),
                            "Number of values does not match.",
                        )
                        if not self._assert(
                            all(isinstance(gp, int) for gp in goodputs),
                            f"Goodputs are not all available: {goodputs}",
                            mute=self.ignore_missing_files,
                        ):
                            continue
                        self._assert(
                            all(
                                abs(value - goodput) < 2
                                for value, goodput in zip(meas.values, goodputs)
                            ),
                            f"Goodputs in logs and values in result.json differ:\n\t{meas.values} !=\n\t{goodputs}",
                        )
                        mean_gp = mean(goodputs)
                        stdev_gp = stdev(goodputs)
                        self._assert(
                            abs(meas.avg - mean_gp) < 2,
                            "Average goodput does not match.",
                        )
                        self._assert(
                            abs(meas.stdev - stdev_gp) < 2,
                            "Stdev goodput does not match.",
                        )
                    elif meas.result == TestResult.UNSUPPORTED:
                        self._assert(
                            all(gp is None for gp in goodputs[1:]),
                            f"Goodputs are available in logs for unsupported tests: {goodputs}",
                        )
                        self._assert(
                            goodputs[0] in (None, "failed"),
                            f"In unsupported test cases, the first experiment must fail: {goodputs}",
                        )
                        self._assert_eq(
                            len(meas.values),
                            0,
                            f"Goodputs are available in result.json for unsupported tests: {meas.values}",
                        )
                    elif meas.result == TestResult.FAILED:
                        if not self._assert(
                            any(gp is not None for gp in goodputs),
                            f"Goodputs are not all available for failed test: {goodputs}",
                            mute=self.ignore_missing_files,
                        ):
                            continue
                        try:
                            none_index = goodputs.index(None)
                            self._assert(
                                all(gp is None for gp in goodputs[none_index:]),
                                "Should stop after failed",
                            )
                            goodputs = [gp for gp in goodputs if gp is not None]
                        except ValueError:
                            # none is not in list -> last experiment failed?
                            pass
                        self._assert(
                            goodputs[-1] == "failed",
                            "Last log did not say failed but testcase is failed",
                        )
                    else:
                        self._assert(False, "Test not yet completed.")

        LOGGER.info("Ran %d assertions.", self._assertion_counter)

    def run(self):
        """Run."""
        for result in self.results:
            try:
                result.load_from_json()
                self.check(result)
            except AssertionError as err:
                LOGGER.error(err)
                LOGGER.error("Cannot continue.")


def main():
    args = parse_args()
    cli = Fsck(
        results=args.results,
        ignore_missing_files=args.ignore_missing_files,
    )
    cli.run()


if __name__ == "__main__":
    main()
