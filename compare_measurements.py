#!/usr/bin/env python3


import argparse
from functools import cached_property
from pathlib import Path

import requests
from matplotlib import pyplot as plt
from termcolor import colored, cprint

from enums import TestResult
from result_parser import Result
from utils import Subplot

SAME_EFF_THRESH_PERC = 0.10
HIGH_EFF_DEVIATION_PERC = 0.5


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
        "result",
        type=Result,
        help="Result.",
    )
    parser.add_argument(
        "measurement1",
        type=str,
        help="The measurement abbr to compare.",
    )
    parser.add_argument(
        "measurement2",
        type=str,
        help="The measurement abbr to compare.",
    )

    return parser.parse_args()


class CompareCli:
    def __init__(
        self,
        result: Result,
        measurement1: str,
        measurement2: str,
        plot=False,
        output=None,
    ):
        self.result = result
        self.measurement1 = measurement1
        self.measurement2 = measurement2
        self.plot = plot
        self.output = output
        self._unit = ""

    @property
    def miss_in_1_txt(self):
        return f"missing in {self.measurement1}"

    @property
    def miss_in_2_txt(self):
        return f"missing in {self.measurement2}"

    @property
    def failed_in_1_txt(self):
        return f"failed in {self.measurement1}"

    @property
    def failed_in_2_txt(self):
        return f"failed in {self.measurement2}"

    @cached_property
    def result_comparison(self):
        """
        Compare 2 results.
        """
        measurements1 = self.result.get_all_measurements_of_type(self.measurement1)
        measurements2 = self.result.get_all_measurements_of_type(self.measurement2)

        compare_result = {
            self.miss_in_1_txt: list[str](),
            self.miss_in_2_txt: list[str](),
            self.failed_in_1_txt: list[str](),
            self.failed_in_2_txt: list[str](),
            "same efficiency": list[tuple[str, float, float, float]](),
            "different efficiency": list[
                tuple[str, tuple[float, float, float, float, float], bool]
            ](),
            "tldr": "",
        }

        lookup1 = {
            meas_result.combination: meas_result for meas_result in measurements1
        }
        num_missing_or_failed = 0
        num_almost_equal = 0
        num_different_meas_results = 0
        effs1 = list[float]()
        effs2 = list[float]()
        avgs1 = list[float]()
        avgs2 = list[float]()
        meas1 = self.result.measurement_descriptions[self.measurement1]
        meas2 = self.result.measurement_descriptions[self.measurement2]
        theoretical_max_value1 = meas1.theoretical_max_value
        theoretical_max_value2 = meas2.theoretical_max_value
        assert theoretical_max_value1 and theoretical_max_value2

        for meas_result2 in measurements2:
            combi: str = meas_result2.combination
            meas_result1 = lookup1.pop(combi, None)

            if not meas_result1 or (
                meas_result1.result == TestResult.UNSUPPORTED
                and meas_result2.result != TestResult.UNSUPPORTED
            ):
                compare_result[self.miss_in_1_txt].append(combi)
                num_missing_or_failed += 1
            elif not meas_result1.succeeded and meas_result2.succeeded:
                compare_result[self.failed_in_1_txt].append(combi)
                num_missing_or_failed += 1
            elif meas_result1.succeeded and not meas_result2.succeeded:
                compare_result[self.failed_in_2_txt].append(combi)
                num_missing_or_failed += 1
            elif meas_result1.succeeded and meas_result2.succeeded:
                self._unit = meas_result1.unit
                assert meas_result1.unit == meas_result2.unit
                eff1 = meas_result1.avg / theoretical_max_value1
                eff2 = meas_result2.avg / theoretical_max_value2
                # compare
                assert eff1 and eff2
                eff_dev = eff2 / eff1 - 1
                same_eff = abs(eff_dev) < SAME_EFF_THRESH_PERC
                high_eff_dev = abs(eff_dev) > HIGH_EFF_DEVIATION_PERC
                data: tuple[str, tuple[float, float, float, float, float], bool] = (
                    combi,
                    (meas_result1.avg, meas_result2.avg, eff1, eff2, eff_dev),
                    high_eff_dev,
                )

                if same_eff:
                    key = "same efficiency"
                    num_almost_equal += 1
                else:
                    key = "different efficiency"
                    num_different_meas_results += 1
                compare_result[key].append(data)
                avgs1.append(meas_result1.avg)
                avgs2.append(meas_result2.avg)
                effs1.append(eff1)
                effs2.append(eff2)

        compare_result[self.miss_in_2_txt].extend(
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
                + " in either of the two measurements.",
                colored(
                    f"{num_almost_equal} have (almost) equal results.",
                    color="green",
                ),
                colored(
                    f"{num_different_meas_results} have different results.",
                    color="yellow",
                ),
                colored(
                    f"The average efficiency in {self.measurement1} is {sum(effs1) / len(effs1) * 100:.0f} %.",
                    color="cyan",
                ),
                colored(
                    f"The average efficiency in {self.measurement2} is {sum(effs2) / len(effs2) * 100:.0f} %.",
                    color="cyan",
                ),
                colored(
                    f"The average value of the averages in {self.measurement1} is {sum(avgs1) / len(avgs1):.1f} {self._unit}.",
                    color="cyan",
                ),
                colored(
                    f"The average value of the averages in {self.measurement2} is {sum(avgs2) / len(avgs2):.1f} {self._unit}.",
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
                    f"  - {entry[0]}\t ({entry[1][2] * 100:.0f} % / {entry[1][3] * 100:.0f} % | deviation: {entry[1][4] * 100:.0f} %)",
                    color=color,
                    attrs=["bold"] if entry[2] else None,
                )

            print()

        error_helper(self.miss_in_1_txt)
        error_helper(self.miss_in_2_txt)
        error_helper(self.failed_in_1_txt)
        error_helper(self.failed_in_2_txt)
        detailed_helper("different efficiency", color="yellow")
        detailed_helper("same efficiency", color="green")

        cprint("TL;DR;", attrs=["bold"])
        print()
        print(self.result_comparison["tldr"])

    def plot_deviation(self):
        """
        Plot something.
        """
        effs1 = [
            *(x[1][2] for x in self.result_comparison["same efficiency"]),
            *(x[1][2] for x in self.result_comparison["different efficiency"]),
        ]
        effs2 = [
            *(x[1][3] for x in self.result_comparison["same efficiency"]),
            *(x[1][3] for x in self.result_comparison["different efficiency"]),
        ]
        assert len(effs1) == len(effs2)
        avg1 = sum(effs1) / len(effs1)
        avg2 = sum(effs2) / len(effs2)
        with Subplot() as (fig, ax):
            ax.set_ylabel("Efficiency of Implementation Combinations")
            ax.set_title(
                f"Comparison of Results of Measurement {self.measurement1} and {self.measurement2}"
                f"\n({len(effs1)} combinations)"
            )
            ax.yaxis.set_major_formatter(lambda val, _pos: f"{val * 100:.0f} %")
            ax.set_ylim(bottom=0, top=1)
            ax.boxplot(
                [effs1, effs2],
                labels=[
                    f"{self.measurement1}\n(avg. eff. {avg1 * 100:.0f} %)",
                    f"{self.measurement2}\n(avg. eff. {avg2 * 100:.0f} %)",
                ],
            )

            if self.output:
                fig.savefig(self.output, bbox_inches="tight")
            else:
                plt.show()

    def run(self):
        self.result.load_from_json()

        self.pretty_print_compare_result()

        if self.plot:
            self.plot_deviation()


def main():
    args = parse_args()
    cli = CompareCli(
        result=args.result,
        measurement1=args.measurement1,
        measurement2=args.measurement2,
        plot=args.plot,
        output=args.output,
    )
    cli.run()


if __name__ == "__main__":
    main()
