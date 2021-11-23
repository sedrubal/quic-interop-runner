#!/usr/bin/env python3

import argparse
import enum
from collections import defaultdict
from functools import cached_property
from itertools import product
from pathlib import Path
from typing import Iterable, Optional

from matplotlib import pyplot as plt
from termcolor import colored, cprint

from result_parser import Result
from units import DataRate
from utils import Subplot, YaspinWrapper, existing_dir_path, natural_data_rate

Series = list[tuple[Optional[bool], Optional[float]]]

# limit values to that value. Every other value seems to be buggy.
MAX_AVG = 100 * DataRate.MBPS


COLORS = [
    "xkcd:darkish red",
    "xkcd:terracotta",
    "xkcd:true green",
    "xkcd:light indigo",
    "xkcd:moss",
    "xkcd:toxic green",
    "xkcd:cobalt blue",
    "xkcd:dark lime",
    "xkcd:cornflower blue",
    "xkcd:bright aqua",
    "xkcd:hot purple",
    "xkcd:tealish green",
    "xkcd:light lilac",
    "xkcd:indian red",
    "xkcd:pinky red",
    "xkcd:darkish green",
    "xkcd:fern",
    "xkcd:lemon",
    "xkcd:bright cyan",
    "xkcd:tealish",
    "xkcd:earth",
    "xkcd:medium grey",
    "xkcd:ugly pink",
    "xkcd:parchment",
    "xkcd:grey purple",
    "xkcd:turtle green",
    "xkcd:sickly green",
    "xkcd:amethyst",
    "xkcd:light bluish green",
    "xkcd:steel",
    "xkcd:piss yellow",
    "xkcd:pale gold",
    "xkcd:lipstick",
    "xkcd:midnight",
    "xkcd:chocolate brown",
    "xkcd:lemon lime",
    "xkcd:grey brown",
]


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
        "--output",
        type=Path,
        help="Render the plot there.",
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
        num_unknown = sum(1 for (succeeded, _avg) in series if succeeded is None)
        num_succeeded = sum(1 for (succeeded, _avg) in series if succeeded is True)
        num_failed = sum(1 for (succeeded, _avg) in series if succeeded is False)

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


AnalyzeResults = dict[str, dict[AnalyzeResult, list[tuple[str, Series]]]]


class LTECli:
    def __init__(
        self,
        logs_dir: Path,
        combinations: list[str],
        testcases: list[str],
        debug=False,
        output: Optional[Path] = None,
    ):
        self.logs_dir = logs_dir
        self.combinations = combinations
        self.testcases = testcases
        self.output = output
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

                #  spinner.write(f"Loading {result_path}...")
                result = Result(result_path)
                result.load_from_json()
                results.append(result)
                spinner.text = f"Loading result files ({len(results)})"

        results.sort(key=lambda result: result.end_time)

        return results

    @cached_property
    def all_combinations(self) -> set[str]:
        clients = {
            client_name
            for result in self.results
            for client_name in result.clients.keys()
        }
        servers = {
            server_name
            for result in self.results
            for server_name in result.servers.keys()
        }

        return {f"{server}_{client}" for server, client in product(servers, clients)}

    def run(self):
        results = self.results
        combinations_to_inspect = self.combinations or self.all_combinations
        max_combination_len = max([len(combi) for combi in combinations_to_inspect])
        analyze_results = AnalyzeResults()

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
                            result = test_result.get_measurement_result(
                                server=server,
                                client=client,
                                measurement_abbr=testcase,
                            )
                            succeeded = result.succeeded

                            if succeeded:
                                unit = DataRate.from_str(result.unit)
                                avg = result.avg * unit

                                if avg > MAX_AVG:
                                    spinner.write(
                                        f"Got avg value {avg} in {test_result.file_path} {combination}, which seems very unlikely. Ignoring."
                                    )
                                    avg = None
                            else:
                                avg = None
                        except KeyError:
                            try:
                                succeeded = test_result.get_test_result(
                                    server=server, client=client, test_abbr=testcase
                                ).succeeded
                                avg = None
                            except KeyError:
                                succeeded = None
                                avg = None

                        test_results.append((succeeded, avg))

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
                percentage = len(combinations) * 100 / len(self.all_combinations)
                print()
                cprint(
                    f"### {analyze_result.name} ({percentage:.0f} %)", attrs=["bold"]
                )
                print()

                for combination, series in sorted(combinations):
                    test_results_str = "".join(
                        colored("?", color="white", on_color="on_grey")
                        if succeeded is None
                        else colored("✔", color="white", on_color="on_green")
                        if succeeded
                        else colored("⨯", color="white", on_color="on_red")
                        for (succeeded, _avg) in series
                    )
                    print(
                        f"{combination:{max_combination_len}}",
                        test_results_str,
                    )

                if not combinations:
                    cprint("*No combinations*", color="grey", attrs=["italic"])

        self.plot_avgs(analyze_results)

    def plot_avgs(self, analyze_results: AnalyzeResults):
        dates = [result.end_time for result in self.results]
        with Subplot(nrows=len(analyze_results)) as (fig, axs):

            axs: Iterable[plt.Axes] = [axs] if len(analyze_results) == 1 else axs
            fig.title = "Long Term Evaluation of QUIC Interop Runner results"

            for ax, (testcase, combinations_by_analzyse_results) in zip(
                axs, analyze_results.items()
            ):
                ax.set_title(f"Measurement Case: {testcase}")
                ax.set_xlabel("Run")
                ax.set_ylabel("Average Goodput of each Implementation")
                ax.yaxis.set_major_formatter(lambda val, _pos: natural_data_rate(val))
                ax.grid()

                avgs_by_server = defaultdict[str, list[list[Optional[float]]]](
                    list[list[Optional[float]]]
                )

                for category in (
                    AnalyzeResult.ALWAYS_SUCCESS,
                    AnalyzeResult.ALMOST_ALWAYS_SUCCESS,
                    AnalyzeResult.GOT_FIXED,
                ):
                    for combination, series in combinations_by_analzyse_results[
                        category
                    ]:
                        server_name, _client_name = combination.split("_")
                        values: list[Optional[float]] = [
                            (avg if avg else None) for (_success, avg) in series
                        ]
                        avgs_by_server[server_name].append(values)

                for server_index, (server, avg_series) in enumerate(
                    sorted(avgs_by_server.items())
                ):
                    avgs_for_server = list[Optional[float]]()

                    for run_index in range(len(avg_series[0])):
                        avg_values: list[float] = [
                            series[run_index]
                            for series in avg_series
                            if series[run_index] is not None
                        ]

                        if avg_values:
                            avgs_for_server.append(sum(avg_values) / len(avg_values))
                        else:
                            avgs_for_server.append(None)

                    ax.plot(
                        dates,
                        avgs_for_server,
                        marker=".",
                        label=server,
                        color=COLORS[server_index % len(COLORS)],
                    )

                ax.legend(title="Server Implementation")

            testcases_str = "-".join(sorted(analyze_results.keys()))
            fig.savefig(
                self.output or f"long_term_evaluation-{testcases_str}.png",
                dpi=300,
                #  transparent=True,
                bbox_inches="tight",
            )
            plt.show()


def main():
    args = parse_args()
    cli = LTECli(
        logs_dir=args.logs_dir,
        combinations=args.combination,
        testcases=args.testcase,
        output=args.output,
        debug=args.debug,
    )
    cli.run()


if __name__ == "__main__":
    main()
