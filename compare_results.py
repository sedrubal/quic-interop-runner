#!/usr/bin/env python3

"""Script to compare two result.json files to see, if the results are (almost) the same."""

import argparse
import sys
from functools import cached_property
from pathlib import Path
from typing import Optional

import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from termcolor import colored, cprint

from enums import TestResult
from result_parser import MeasurementDescription, MeasurementResultInfo, Result
from units import DataRate
from utils import Statistics, Subplot, natural_data_rate

SAME_AVG_THRESH_PERC = 0.05
SAME_STDEV_THRESH_PERC = 0.10
HIGH_AVG_DEVIATION_PERC = 0.2
HIGH_STDEV_DEVIATION_PERC = 0.2


PGF_PREAMBLE = r"""
\usepackage{acronym}
\usepackage{lmodern}
\usepackage{helvet}
\usepackage[bitstream-charter,sfscaled=false]{mathdesign}
% More encoding and typesetting fixes and tweaks
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{textcomp}
% \input{latex_cmds}

\RequirePackage[%
	binary-units,
    % range-phrase={--},
	range-units=single,
    per-mode=symbol,
    detect-all,
    load-configurations=binary,
    forbid-literal-units,
]{siunitx}
\catcode`\%=12\relax
\DeclareSIUnit[number-unit-product=]\percent{%}
\catcode`\%=14\relax

\def\lr/{\mbox{\textsc{LongRTT}}}
\def\g/{\mbox{\textsc{Goodput}}}
\def\sat/{\mbox{\textsc{Sat}}}
\def\satl/{\mbox{\textsc{SatLoss}}}
\def\eut/{\mbox{\textsc{Eutelsat}}}
\def\astra/{\mbox{\textsc{Astra}}}
\def\crosstraffic/{\mbox{\textsc{CrossTraffic}}}
"""


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
        "--label1",
        type=str,
        help="The label for result 1.",
    )
    parser.add_argument(
        "--label2",
        type=str,
        help="The label for result 2.",
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
        "test_abbr",
        type=str,
        help="The test / measurement abbr to compare.",
    )

    return parser.parse_args()


class CompareCli:
    def __init__(
        self,
        result1: Result,
        result2: Result,
        test_abbr: str,
        label1: Optional[str] = None,
        label2: Optional[str] = None,
        plot=False,
        output=None,
    ):
        self.result1 = result1
        self.result2 = result2
        self.label1 = label1
        self.label2 = label2
        self.test_abbr = test_abbr
        self.plot = plot
        self.output = output
        self._unit = ""
        if self.output.suffix == ".pgf":
            self._latex_mode = True
            plt.rcParams.update(
                {
                    "text.usetex": True,
                    "font.family": "serif",
                    #  # don't setup fonts from rc parameters
                    "pgf.rcfonts": False,
                    # Use LaTeX default serif font.
                    "font.serif": [],
                    # "font.sans-serif": [],
                    "pgf.texsystem": "pdflatex",
                    "pgf.preamble": PGF_PREAMBLE,
                }
            )
        else:
            self._latex_mode = False

    @property
    def measurement(self) -> MeasurementDescription:
        """The measurement description to use."""

        return self.result2.measurement_descriptions[self.test_abbr]

    @cached_property
    def result_comparison(self):
        """
        Compare 2 results.
        """

        results1 = self.result1.get_all_measurements_of_type(self.test_abbr)
        results2 = self.result2.get_all_measurements_of_type(self.test_abbr)
        if not results1 and not results2:
            results1 = self.result1.get_all_tests_of_type(self.test_abbr)
            results2 = self.result2.get_all_tests_of_type(self.test_abbr)

        if not results1:
            existing_test_abbrs = ", ".join(
                meas.abbr for meas in self.result1.test_descriptions.values()
            )
            sys.exit(
                f"Found no test results of type {self.test_abbr} in first result. Existing test abbreviations are {existing_test_abbrs}"
            )
        if not results2:
            existing_test_abbrs = ", ".join(
                meas.abbr for meas in self.result2.test_descriptions.values()
            )
            sys.exit(
                f"Found no test results of type {self.test_abbr} in second result. Existing test abbreviations are {existing_test_abbrs}"
            )

        compare_result = {
            "missing in 1": list[str](),
            "missing in 2": list[str](),
            "failed in 1": list[str](),
            "failed in 2": list[str](),
            "succeeded in both": list[str](),
            "same avg and stdev": list[tuple[str, float, float, float]](),
            "same avg different stdev": list[
                tuple[str, tuple[float, float, float], tuple[float, float, float], bool]
            ](),
            "different avg same stdev": list[
                tuple[str, tuple[float, float, float], tuple[float, float, float], bool]
            ](),
            "different avg and stdev": list[
                tuple[str, tuple[float, float, float], tuple[float, float, float], bool]
            ](),
            "tldr": "",
        }

        lookup1 = {meas_result.combination: meas_result for meas_result in results1}
        num_missing_or_failed = 0
        num_almost_equal = 0
        num_different_meas_results = 0
        num_succeeded = 0
        avgs1 = list[float]()
        avgs2 = list[float]()

        for meas_result2 in results2:
            combi: str = meas_result2.combination
            meas_result1 = lookup1.pop(combi, None)

            if not meas_result1 or (
                meas_result1.result == TestResult.UNSUPPORTED
                and meas_result2.result != TestResult.UNSUPPORTED
            ):
                compare_result["missing in 1"].append(combi)
                num_missing_or_failed += 1
            elif not meas_result1.succeeded and meas_result2.succeeded:
                compare_result["failed in 1"].append(combi)
                num_missing_or_failed += 1
            elif meas_result1.succeeded and not meas_result2.succeeded:
                compare_result["failed in 2"].append(combi)
                num_missing_or_failed += 1
            elif meas_result1.succeeded and meas_result2.succeeded:
                num_succeeded += 1
                compare_result["succeeded in both"].append(combi)
                if isinstance(meas_result1, MeasurementResultInfo) and isinstance(
                    meas_result2, MeasurementResultInfo
                ):
                    assert meas_result1.unit == meas_result2.unit
                    self._unit = meas_result1.unit
                    # compare avg
                    assert meas_result2.avg and meas_result1.avg
                    avg_dev = meas_result2.avg / meas_result1.avg - 1
                    same_avg = abs(avg_dev) < SAME_AVG_THRESH_PERC
                    high_avg_dev = abs(avg_dev) > HIGH_AVG_DEVIATION_PERC
                    # compare stdev
                    diff_stdev = meas_result1.stdev - meas_result2.stdev
                    stdev_dev = diff_stdev / meas_result1.avg
                    same_stdev = abs(stdev_dev) < SAME_STDEV_THRESH_PERC
                    high_stdev_dev = abs(stdev_dev) > HIGH_STDEV_DEVIATION_PERC
                    data: tuple[
                        str,
                        tuple[float, float, float],
                        tuple[float, float, float],
                        bool,
                    ] = (
                        combi,
                        (meas_result1.avg, meas_result2.avg, avg_dev),
                        (meas_result1.stdev, meas_result2.stdev, stdev_dev),
                        high_avg_dev or high_stdev_dev,
                    )

                    if same_avg and same_stdev:
                        key = "same avg and stdev"
                        num_almost_equal += 1
                    elif same_avg and not same_stdev:
                        key = "same avg different stdev"
                        num_different_meas_results += 1
                    elif not same_avg and same_stdev:
                        key = "different avg same stdev"
                        num_different_meas_results += 1
                    else:
                        key = "different avg and stdev"
                        num_different_meas_results += 1
                    compare_result[key].append(data)
                    avgs1.append(meas_result1.avg)
                    avgs2.append(meas_result2.avg)

        compare_result["missing in 2"].extend(
            meas_result1.combination for meas_result1 in lookup1.values()
        )
        num_missing_or_failed += len(lookup1)

        tldr_lines = [
            "There are "
            + colored(
                f"{num_missing_or_failed or 'no'} missing or failing results",
                color="red",
            )
            + " in either of the two result files.",
            colored(f"{num_succeeded or 'No'} succeeded", color="green")
            + " in both results.",
        ]

        if avgs1 and avgs2:
            # measurement
            tldr_lines.extend(
                [
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
                ]
            )

        compare_result["tldr"] = "\n".join(tldr_lines)

        return compare_result

    def pretty_print_compare_result(self):
        """
        Pretty print it.
        """

        def short_helper(prop: str, color: str = "red"):
            lst = self.result_comparison[prop]
            cprint(f"{prop} ({len(lst)}):", color=color, attrs=["bold"])

            for entry in sorted(lst):
                cprint(f"  - {entry}", color=color)

            print()

        def detailed_helper(prop: str, color: str):
            lst = self.result_comparison.get(prop)
            if not lst:
                # it is a test and not a measurement
                return

            cprint(f"{prop} ({len(lst)}):", color=color, attrs=["bold"])

            for entry in sorted(lst):
                cprint(
                    f"  - {entry[0]}\t ({entry[1][0]} / {entry[1][1]} ± {entry[2][0]} / {entry[2][1]} | deviation: {entry[1][2] * 100:.0f} % ± {entry[2][2] * 100:.0f} %)",
                    color=color,
                    attrs=["bold"] if entry[3] else None,
                )

            print()

        short_helper("missing in 1")
        short_helper("missing in 2")
        short_helper("failed in 1")
        short_helper("failed in 2")
        short_helper("succeeded in both", color="green")
        detailed_helper("different avg and stdev", color="yellow")
        detailed_helper("different avg same stdev", color="yellow")
        detailed_helper("same avg different stdev", color="green")
        detailed_helper("same avg and stdev", color="green")

        cprint("TL;DR;", attrs=["bold"])
        print()
        print(self.result_comparison["tldr"])

    def plot_deviation(self):
        """
        Plot something.
        """
        factor = DataRate.from_str(self._unit)
        avgs1 = [
            *(x[1][0] * factor for x in self.result_comparison["same avg and stdev"]),
            *(
                x[1][0] * factor
                for x in self.result_comparison["same avg different stdev"]
            ),
            *(
                x[1][0] * factor
                for x in self.result_comparison["different avg same stdev"]
            ),
            *(
                x[1][0] * factor
                for x in self.result_comparison["different avg and stdev"]
            ),
        ]
        avgs2 = [
            *(x[1][1] * factor for x in self.result_comparison["same avg and stdev"]),
            *(
                x[1][1] * factor
                for x in self.result_comparison["same avg different stdev"]
            ),
            *(
                x[1][1] * factor
                for x in self.result_comparison["different avg same stdev"]
            ),
            *(
                x[1][1] * factor
                for x in self.result_comparison["different avg and stdev"]
            ),
        ]
        assert len(avgs1) == len(avgs2)
        stats1 = Statistics.calc(avgs1)
        stats2 = Statistics.calc(avgs2)

        if self.label1 and self.label2:
            label1 = self.label1
            label2 = self.label2
        elif self.result1.file_path.name != self.result2.file_path.name:
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

        def format_data_rate(val, _pos=None):
            value = natural_data_rate(val)
            if self._latex_mode:
                number, unit = value.split(" ")
                unit = {
                    "bit/s": r"\bit\per\second",
                    "kbit/s": r"\kilo\bit\per\second",
                    "Mbit/s": r"\mega\bit\per\second",
                    "Gbit/s": r"\giga\bit\per\second",
                }[unit]
                value = fr"\SI{{{number}}}{{{unit}}}"

            return value

        label1 = f"{label1}\n{stats1.mpl_label_narrow(format_data_rate)}"
        label2 = f"{label2}\n{stats2.mpl_label_narrow(format_data_rate)}"

        df1 = pd.DataFrame(avgs1, columns=["avg. Goodput"])
        df2 = pd.DataFrame(avgs2, columns=["avg. Goodput"])
        df1.append(["Source"])
        df2.append(["Source"])
        df1["Source"] = label1
        df2["Source"] = label2
        df = pd.concat([df1, df2])

        with Subplot() as (fig, ax):
            ax.set_ylabel("Average Data Rate of Implementation Combination")
            ax.set_title(
                f"Comparison of Results of Measurement {self.measurement.name.title()}"
                f"\n({len(avgs1)} Combinations)"
            )
            ax.yaxis.set_major_formatter(format_data_rate)
            ax.set_ylim(ymin=0, ymax=10 * DataRate.MBPS)
            sns.boxplot(
                data=df,
                x="Source",
                y="avg. Goodput",
                ax=ax,
            )

            if self.output:
                fig.savefig(self.output, bbox_inches="tight")
            else:
                plt.show()

    def run(self):
        self.result1.load_from_json()
        self.result2.load_from_json()

        self.pretty_print_compare_result()

        if self.plot:
            self.plot_deviation()


def main():
    args = parse_args()
    cli = CompareCli(
        result1=args.result1,
        result2=args.result2,
        test_abbr=args.test_abbr,
        label1=args.label1,
        label2=args.label2,
        plot=args.plot,
        output=args.output,
    )
    cli.run()


if __name__ == "__main__":
    main()
