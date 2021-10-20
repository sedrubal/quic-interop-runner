#!/usr/bin/env python3

import argparse
import enum
import sys
from functools import cached_property
from itertools import product
from pathlib import Path
from typing import Optional

from termcolor import colored, cprint

from result_parser import Result
from utils import YaspinWrapper, existing_dir_path

Series = list[Optional[bool]]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "logs_dir", type=existing_dir_path, help="The dir where the logs are stored in."
    )
    parser.add_argument(
        "--combination",
        nargs="+",
        action="extend",
        help="The combinations to analyse",
    )
    parser.add_argument(
        "--testcase",
        nargs="+",
        action="extend",
        help="The testcases and measurements to analyse",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode",
    )

    return parser.parse_args()


class AnalyzeResult(enum.IntEnum):
    ALWAYS_SUCCESS = enum.auto()
    ALWAYS_FAILED = enum.auto()
    ALMOST_ALWAYS_SUCCESS = enum.auto()
    ALMOST_ALWAYS_FAILED = enum.auto()
    GOT_FIXED = enum.auto()
    GOT_BROKEN = enum.auto()
    OTHER = enum.auto()

    @classmethod
    @property
    def _unknown_threshold(cls) -> float:
        return 0.05

    @classmethod
    @property
    def _almost_threshold(cls) -> float:
        return 0.05

    @classmethod
    @property
    def _old_threshold(cls) -> float:
        return 0.20

    @classmethod
    @property
    def _new_threshold(cls) -> float:
        return 0.20

    @classmethod
    def from_series(cls, series: Series) -> "AnalyzeResult":
        num_unknown = sum(1 for result in series if result is None)
        num_succeeded = sum(1 for result in series if result is True)
        num_failed = sum(1 for result in series if result is False)

        if num_unknown / len(series) > cls._unknown_threshold:
            return cls.OTHER
        elif num_succeeded == len(series) - num_unknown:
            return cls.ALWAYS_SUCCESS
        elif num_failed == len(series) - num_unknown:
            return cls.ALWAYS_FAILED
        elif num_succeeded >= (len(series) - num_unknown) * (1 - cls._almost_threshold):
            return cls.ALMOST_ALWAYS_SUCCESS
        elif num_failed >= (len(series) - num_unknown) * (1 - cls._almost_threshold):
            return cls.ALMOST_ALWAYS_FAILED

        len_old = len(series) * cls._old_threshold
        len_new = len(series) * cls._new_threshold
        num_old_succeeded = 0
        num_old_failed = 0
        num_old = 0

        for result in series:
            if result is None:
                continue

            if result:
                num_old_succeeded += 1
            else:
                num_old_failed += 1
            num_old += 1

            if num_old >= len_old:
                break

        if num_old < len_old:
            return cls.OTHER

        num_new_succeeded = 0
        num_new_failed = 0
        num_new = 0

        for result in reversed(series):
            if result is None:
                continue

            if result:
                num_new_succeeded += 1
            else:
                num_new_failed += 1
            num_new += 1

            if num_new >= len_new:
                break

        if num_new < len_new:
            return cls.OTHER

        old_succeeded = num_old_succeeded / len_old >= cls._almost_threshold
        new_succeeded = num_new_succeeded / len_new >= cls._almost_threshold

        if not old_succeeded and new_succeeded:
            return cls.GOT_FIXED
        elif old_succeeded and not new_succeeded:
            return cls.GOT_BROKEN

        return cls.OTHER


class Cli:
    def __init__(
        self, logs_dir: Path, combinations: list[str], testcases: list[str], debug=False
    ):
        self.logs_dir = logs_dir
        self.combinations = combinations
        self.testcases = testcases
        self.debug = debug

    @cached_property
    def results(self) -> list[Result]:
        results = list[Result]()

        with YaspinWrapper(
            debug=self.debug, text="Loading result files", color="cyan"
        ) as spinner:
            for log_dir in self.logs_dir.iterdir():
                if not log_dir.is_dir():
                    spinner.write(colored(f"Ignoring {log_dir}", color="red"))

                    continue

                result_path = log_dir / "result.json"

                if not result_path.is_file():
                    spinner.write(
                        colored(
                            f"Result {result_path} does not exist",
                            color="red",
                        )
                    )

                    continue

                results.append(Result(result_path))

        results.sort(key=lambda result: result.end_time)

        return results

    @cached_property
    def all_combinations(self) -> set[str]:
        clients = {client.name for result in self.results for client in result.clients}
        servers = {server.name for result in self.results for server in result.servers}

        return {f"{server}_{client}" for server, client in product(servers, clients)}

    def run(self):
        results = self.results
        combinations_to_inspect = self.combinations or self.all_combinations
        max_combination_len = max([len(combi) for combi in combinations_to_inspect])
        analyze_results = dict[str, dict[AnalyzeResult, list[tuple[str, Series]]]]()

        with YaspinWrapper(text="Analyzing", debug=self.debug, color="cyan") as spinner:
            for testcase in self.testcases:
                analyze_results[testcase] = dict[
                    AnalyzeResult, list[tuple[str, Series]]
                ]()

                for analyze_result in AnalyzeResult:
                    analyze_results[testcase][analyze_result] = list[
                        tuple[str, Series]
                    ]()

            for combination in combinations_to_inspect:
                server, client = combination.split("_", 1)

                for testcase in self.testcases:
                    test_results = Series()

                    for test_result in results:
                        try:
                            succeeded = test_result.get_test_result(
                                server=server, client=client, test_abbr=testcase
                            ).succeeded
                        except KeyError:
                            succeeded = None

                        test_results.append(succeeded)

                    analyze_result = AnalyzeResult.from_series(test_results)
                    analyze_results[testcase][analyze_result].append(
                        (combination, test_results)
                    )

        print()
        print(
            f"Timespan: {results[0].start_time:%Y-%m-%d %H:%M} - {results[-1].end_time:%Y-%m-%d %H:%M}"
        )

        for testcase, combinations_by_analzyse_results in analyze_results.items():
            print()
            cprint(f"## {testcase}", attrs=["bold"])
            print()

            for (
                analyze_result,
                combinations,
            ) in combinations_by_analzyse_results.items():
                print()
                cprint(f"### {analyze_result.name}", attrs=["bold"])
                print()

                for combination, series in combinations:
                    test_results_str = "".join(
                        colored("?", color="white", on_color="on_grey")
                        if succeeded is None
                        else colored("✔", color="white", on_color="on_green")
                        if succeeded
                        else colored("⨯", color="white", on_color="on_red")
                        for succeeded in series
                    )
                    print(
                        f"{combination:{max_combination_len}}",
                        test_results_str,
                    )

                if not combinations:
                    cprint("*No combinations*", color="grey", attrs=["italic"])


def main():
    args = parse_args()
    cli = Cli(
        logs_dir=args.logs_dir,
        combinations=args.combination,
        testcases=args.testcase,
        debug=args.debug,
    )
    cli.run()


if __name__ == "__main__":
    main()
