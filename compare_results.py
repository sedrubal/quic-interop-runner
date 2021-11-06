#!/usr/bin/env python3


import argparse
from functools import cached_property
from pathlib import Path

import requests
from matplotlib import pyplot as plt
from termcolor import colored, cprint

from result_parser import Result
from utils import Subplot

SAME_AVG_THRESH_PERC = 0.05
SAME_VAR_THRESH_PERC = 0.10
HIGH_AVG_DEVIATION_PERC = 0.2
HIGH_VAR_DEVIATION_PERC = 0.2


def parse_args():
    """Parse command line args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--plot",
        action="store_true",
        help="Plot a box plot.",
    )
    parser.add_argument(
        "--output",
        action="store",
        default=None,
        type=Path,
        help="Store the plot into this file",
    )
    parser.add_argument(
        "result1",
        type=Result,
        help="Result.",
    )
    parser.add_argument(
        "result2",
        type=Result,
        help="Result.",
    )
    parser.add_argument(
        "measurement",
        type=str,
        help="The measurement abbr to compare.",
    )

    return parser.parse_args()


def fetch_result(url: str) -> Result:
    result = requests.get(url)
    result.raise_for_status()
    data = result.json()

    return Result(url, data)


class CompareCli:
    def __init__(
        self,
        result1: Result,
        result2: Result,
        measurement: str,
        plot=False,
        output=None,
    ):
        self.result1 = result1
        self.result2 = result2
        self.measurement = measurement
        self.plot = plot
        self.output = output
        self._unit = ""

    @cached_property
    def result_comparison(self):
        """
        Compare 2 results.
        """
        measurements1 = self.result1.get_all_measuements_of_type(self.measurement)
        measurements2 = self.result2.get_all_measuements_of_type(self.measurement)

        compare_result = {
            "missing in 1": list[str](),
            "missing in 2": list[str](),
            "failed in 1": list[str](),
            "failed in 2": list[str](),
            "same avg and var": list[tuple[str, float, float, float]](),
            "same avg different var": list[
                tuple[str, tuple[float, float, float], tuple[float, float, float], bool]
            ](),
            "different avg same var": list[
                tuple[str, tuple[float, float, float], tuple[float, float, float], bool]
            ](),
            "different avg and var": list[
                tuple[str, tuple[float, float, float], tuple[float, float, float], bool]
            ](),
            "tldr": "",
        }

        lookup1 = {
            meas_result.combination: meas_result for meas_result in measurements1
        }
        num_missing_or_failed = 0
        num_almost_equal = 0
        num_different_meas_results = 0
        avgs1 = list[float]()
        avgs2 = list[float]()

        for meas_result2 in measurements2:
            combi: str = meas_result2.combination
            meas_result1 = lookup1.pop(combi, None)

            if not meas_result1 or (
                meas_result1.result == "unsupported"
                and meas_result2.result != "unsupported"
            ):
                compare_result["missing in 1"].append(combi)
                num_missing_or_failed += 1
            elif not meas_result1.succeeded and meas_result2.succeeded:
                compare_result["failed in 1"].append(combi)
                num_missing_or_failed += 1
            elif meas_result1.succeeded and not meas_result2.succeeded:
                compare_result["failed in 2"].append(combi)
                num_missing_or_failed += 1
            elif (
                meas_result1.succeeded and meas_result2.succeeded
            ):
                assert meas_result1.unit == meas_result2.unit
                self._unit = meas_result1.unit
                # compare avg
                assert meas_result2.avg and meas_result1.avg
                avg_dev = meas_result2.avg / meas_result1.avg - 1
                same_avg = abs(avg_dev) < SAME_AVG_THRESH_PERC
                high_avg_dev = abs(avg_dev) > HIGH_AVG_DEVIATION_PERC
                # compare var
                diff_var = meas_result1.var - meas_result2.var
                var_dev = diff_var / meas_result1.avg
                same_var = abs(var_dev) < SAME_VAR_THRESH_PERC
                high_var_dev = abs(var_dev) > HIGH_VAR_DEVIATION_PERC
                data: tuple[
                    str, tuple[float, float, float], tuple[float, float, float], bool
                ] = (
                    combi,
                    (meas_result1.avg, meas_result2.avg, avg_dev),
                    (meas_result1.var, meas_result2.var, var_dev),
                    high_avg_dev or high_var_dev,
                )

                if same_avg and same_var:
                    key = "same avg and var"
                    num_almost_equal += 1
                elif same_avg and not same_var:
                    key = "same avg different var"
                    num_different_meas_results += 1
                elif not same_avg and same_var:
                    key = "different avg same var"
                    num_different_meas_results += 1
                else:
                    key = "different avg and var"
                    num_different_meas_results += 1
                compare_result[key].append(data)
                avgs1.append(meas_result1.avg)
                avgs2.append(meas_result2.avg)

        compare_result["missing in 2"].extend(
            meas_result1.combination for meas_result1 in lookup1.values()
        )
        num_missing_or_failed += len(lookup1)

        compare_result["tldr"] = "\n".join(
            (
                "There are "
                + colored(
                    f"{num_missing_or_failed or 'no'} missing or failing results",
                    color="red",
                )
                + " in either of the two result files.",
                colored(
                    f"{num_almost_equal} have (almost) equal results.",
                    color="green",
                ),
                colored(
                    f"{num_different_meas_results} have different results.",
                    color="yellow",
                ),
                colored(
                    f"The average of the average values of result1 is {sum(avgs1) / len(avgs1):.0f}.",
                    color="cyan",
                ),
                colored(
                    f"The average of the average values of result2 is {sum(avgs2) / len(avgs2):.0f}.",
                    color="cyan",
                ),
            )
        )

        return compare_result

    def pretty_print_compare_result(self):
        """
        Pretty print it.
        """

        def error_helper(prop: str):
            lst = self.result_comparison[prop]
            cprint(f"{prop} ({len(lst)}):", color="red", attrs=["bold"])

            for entry in lst:
                cprint(f"  - {entry}", color="red")

            print()

        def detailed_helper(prop: str, color: str):
            lst = self.result_comparison[prop]
            cprint(f"{prop} ({len(lst)}):", color=color, attrs=["bold"])

            for entry in lst:
                cprint(
                    f"  - {entry[0]}\t ({entry[1][0]} / {entry[1][1]} ± {entry[2][0]} / {entry[2][1]} | deviation: {entry[1][2] * 100:.0f} % ± {entry[2][2] * 100:.0f} %)",
                    color=color,
                    attrs=["bold"] if entry[3] else None,
                )

            print()

        error_helper("missing in 1")
        error_helper("missing in 2")
        error_helper("failed in 1")
        error_helper("failed in 2")
        detailed_helper("different avg and var", color="yellow")
        detailed_helper("different avg same var", color="yellow")
        detailed_helper("same avg different var", color="green")
        detailed_helper("same avg and var", color="green")

        cprint("TL;DR;", attrs=["bold"])
        print()
        print(self.result_comparison["tldr"])

    def plot_deviation(self):
        """
        Plot something.
        """
        avgs1 = [
            *(x[1][0] for x in self.result_comparison["same avg and var"]),
            *(x[1][0] for x in self.result_comparison["same avg different var"]),
            *(x[1][0] for x in self.result_comparison["different avg same var"]),
            *(x[1][0] for x in self.result_comparison["different avg and var"]),
        ]
        avgs2 = [
            *(x[1][1] for x in self.result_comparison["same avg and var"]),
            *(x[1][1] for x in self.result_comparison["same avg different var"]),
            *(x[1][1] for x in self.result_comparison["different avg same var"]),
            *(x[1][1] for x in self.result_comparison["different avg and var"]),
        ]
        avg1 = sum(avgs1) / len(avgs1)
        avg2 = sum(avgs2) / len(avgs2)
        assert len(avgs1) == len(avgs2)

        if self.result1.file_path.name != self.result2.file_path.name:
            label1 = self.result1.file_path.name
            label2 = self.result2.file_path.name
        elif self.result1.file_path.is_path != self.result2.file_path.is_path:
            label1 = (
                "local"
                if self.result1.file_path.is_path
                else f"online\n{self.result1.file_path.mtime.strftime('%Y-%m-%d %H:%M')}"
            )
            label2 = (
                "local"
                if self.result2.file_path.is_path
                else f"online\n{self.result1.file_path.mtime.strftime('%Y-%m-%d %H:%M')}"
            )
        else:
            label1 = str(self.result1.file_path)
            label2 = str(self.result2.file_path)

        with Subplot() as (fig, ax):
            ax.set_ylabel("Average Data Rate of Implementation Combination")
            ax.set_title(
                f"Comparison of Results of Measurement {self.measurement}"
                f"\n({len(avgs1)} combinations)"
            )
            ax.yaxis.set_major_formatter(lambda val, _pos: f"{int(val)} {self._unit}")
            ax.boxplot(
                [avgs1, avgs2],
                labels=[
                    f"{label1}\n(avg. {avg1:.0f} {self._unit})",
                    f"{label2}\n(avg. {avg2:.0f} {self._unit})",
                ],
            )

            if self.output:
                fig.savefig(self.output, bbox_inches="tight")
            else:
                plt.show()

    def run(self):
        self.pretty_print_compare_result()

        if self.plot:
            self.plot_deviation()


def main():
    args = parse_args()
    cli = CompareCli(
        result1=args.result1,
        result2=args.result2,
        measurement=args.measurement,
        plot=args.plot,
        output=args.output,
    )
    cli.run()


if __name__ == "__main__":
    main()
