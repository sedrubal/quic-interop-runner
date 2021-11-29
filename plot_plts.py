#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path
from typing import Optional

import numpy as np
from matplotlib import pyplot as plt
from termcolor import colored

from enums import Side
from result_parser import MeasurementResultInfo, Result
from tango_colors import Tango
from trace_analyzer2 import Trace
from utils import Statistics, Subplot, YaspinWrapper, LOGGER


def parse_args():
    """Parse command line args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "test",
        type=str,
        help="The measurement case to plot.",
    )
    parser.add_argument(
        "results",
        nargs="+",
        type=Result,
        help="Result files to use",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run in debug mode.",
    )
    parser.add_argument(
        "--binwidth",
        type=float,
        default=0.5,
        help="Width of bins in the histograms.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        action="store",
        type=Path,
        help="The output file.",
    )
    return parser.parse_args()


class PlotPltsCli:
    def __init__(
        self,
        test_abbr: str,
        results: list[Result],
        debug: bool = False,
        binwidth: int = 100,
        output_file: Optional[Path] = None,
    ) -> None:
        self.test_abbr = test_abbr
        self.results = results
        self.debug = debug
        self._spinner: Optional[YaspinWrapper] = None
        self.binwidth = binwidth
        self.output_file = output_file
        self._colors = Tango()

    def _log(self, msg: str, log_level: int = logging.INFO):
        if self._spinner:
            self._spinner.write(msg)
        else:
            LOGGER.log(level=log_level, msg=msg)

    def load_measurement_results(self) -> list[MeasurementResultInfo]:
        self._log("⚒ Loading results")
        measurement_results = list[MeasurementResultInfo]()
        for result in self.results:
            result.load_from_json()
            measurement_results.extend(
                result.get_all_measurements_of_type(self.test_abbr, succeeding=True)
            )
        self._log(f"✔ Using {len(measurement_results)} measurement results")
        return measurement_results

    def get_plt(self, log_dir: Path) -> float:
        left_trace_file = log_dir / "sim" / "trace_node_left_with_secrets.pcapng"
        right_trace_file = log_dir / "sim" / "trace_node_right_with_secrets.pcapng"
        left_trace = Trace(left_trace_file, side=Side.LEFT)
        right_trace = Trace(right_trace_file, side=Side.RIGHT)
        right_trace.pair_trace = left_trace
        plt = float(right_trace.extended_facts["plt"])
        return plt

    def get_average_plt(self, measurement_result: MeasurementResultInfo) -> float:
        plts = [
            self.get_plt(log_dir) for log_dir in measurement_result.repetition_log_dirs
        ]
        return sum(plts) / len(plts)

    def get_timeout(self) -> int:
        self._log("Loading test timeouts")
        timeouts_all = [
            result.measurement_descriptions[self.test_abbr].timeout
            for result in self.results
        ]
        timeouts: list = [timeout for timeout in timeouts_all if timeout]
        assert timeouts, "Timeout not specified in results"
        timeout = timeouts[0]
        assert all(
            timeout == timeout for timeout in timeouts[1:]
        ), f"Timeouts in result files differ: {', '.join(map(str, timeouts))}"
        return timeout

    def run(self):
        with YaspinWrapper(
            debug=self.debug, text="Plotting...", color="cyan"
        ) as spinner:
            self._spinner = spinner
            measurement_results = self.load_measurement_results()

            timeout = self.get_timeout()

            values = [
                self.get_average_plt(measurement_result)
                for measurement_result in measurement_results
            ]

            self._log("Calculating stats")
            stats = Statistics.calc(values)

            with Subplot() as (fig, ax):
                ax.set_title(
                    f"Time to Complete of different Implementation Combinations for Test Case '{self.test_abbr}'"
                )
                ax.set_xlabel("Time to Complete (s)")
                ax.set_ylabel("Number of Implementation Combinations")
                # ax.set_xlim(xmax=max((*values, timeout)) + 1)
                ax.yaxis.set_major_formatter(lambda val, _pos: str(int(val)))
                # ax.xaxis.set_major_formatter(lambda val, _pos: f'{val:.2f}s')
                hist = ax.hist(
                    values,
                    bins=np.arange(stats.min, stats.max + self.binwidth, self.binwidth),
                    color=self._colors.LightPlum,
                    edgecolor="k",
                )
                # annotate statistical things
                ax.axvline(
                    x=stats.min,
                    linestyle="dotted",
                    color=self._colors.Chameleon,
                    label=f"Min: {stats.min:.2f} s",
                )
                # ax.axvline(x=stats.max, linestyle="dotted", color=self._colors.ScarletRed, label=f"Max: {stats.max:.2f} s")
                ax.axvline(
                    x=stats.avg,
                    linestyle="dotted",
                    color=self._colors.Plum,
                    label=f"Mean: {stats.avg:.2f} s",
                )
                ax.axvline(
                    x=stats.med,
                    linestyle="dotted",
                    color=self._colors.SkyBlue,
                    label=f"Median: {stats.med:.2f} s",
                )

                if timeout < ((stats.max - stats.min) * 1.25 + stats.min):
                    ax.axvline(
                        x=timeout,
                        linestyle="dotted",
                        color=self._colors.ScarletRed,
                        label=f"Timeout: {timeout:.2f} s",
                    )

                ax.legend()

                self._save(fig, self.output_file, spinner)

    def _save(
        self, figure: plt.Figure, output_file: Optional[Path], spinner: YaspinWrapper
    ):
        """Save or show the plot."""

        if output_file:
            figure.savefig(
                output_file,
                dpi=300,
                #  transparent=True,
                bbox_inches="tight",
            )
            spinner.text = colored(f"{output_file} written.", color="green")
        else:
            spinner.write(f"✔ {spinner.text}")
            spinner.text = "Showing plot"
            spinner.ok("✔")
            plt.show()


def main():
    """Main."""
    args = parse_args()
    cli = PlotPltsCli(
        test_abbr=args.test,
        results=args.results,
        debug=args.debug,
        binwidth=args.binwidth,
        output_file=args.output_file,
    )
    cli.run()


if __name__ == "__main__":
    main()
