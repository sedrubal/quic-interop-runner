#!/usr/bin/env python3

"""Plot some statistics about a result file."""

# TODO merge into plot_stats?


import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from termcolor import colored

from implementations import LOGGER
from result_parser import MeasurementDescription, Result
from tango_colors import Tango
from utils import YaspinWrapper

LOGGER = logging.getLogger("quic-interop-runner")


def parse_args():
    """Parse command line args."""
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument(
        "--test",
        dest="tests",
        nargs="*",
        type=str,
        default=None,
        help="The measurement cases to plot.",
    )
    parser.add_argument(
        "results",
        nargs="+",
        type=Result,
        help="Result file to use.",
    )
    # parser.add_argument(
    #     "-t",
    #     "--plot-type",
    #     type=PlotType,
    #     choices=PlotType,
    #     help="The type of plot to plot.",
    # )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run in debug mode.",
    )
    parser.add_argument(
        "-o",
        "--img-path",
        dest="img_path",
        action="store",
        type=Path,
        default=Path(__file__).parent,
        help="The directory to render the images to.",
    )
    parser.add_argument(
        "-n",
        "--no-interactive",
        action="store_true",
        help="Do not open plot preview.",
    )
    parser.add_argument(
        "-f",
        "--img-format",
        type=str,
        default="png",
        help="The format of the image to save",
    )
    return parser.parse_args()


class PlotStatsCli:
    def __init__(
        self,
        results: list[Result],
        # plot_type: PlotType,
        img_path: Path,
        img_format: str,
        test_abbrs: Optional[list[str]] = None,
        debug: bool = False,
        no_interactive: bool = False,
    ) -> None:
        self.test_abbrs = test_abbrs
        self.results = results
        # self.plot_type = plot_type
        self.debug = debug
        self._spinner: Optional[YaspinWrapper] = None
        self.img_path = img_path
        self.img_format = img_format
        self._colors = Tango()
        for result in self.results:
            result.load_from_json()
        self.no_interactive = no_interactive

    def _log(self, msg: str, log_level: int = logging.INFO):
        if self._spinner:
            self._spinner.write(msg)
        else:
            LOGGER.log(level=log_level, msg=msg)

    @property
    def measurements(self) -> list[MeasurementDescription]:
        """The measurements to use."""

        measurements = list[MeasurementDescription]()
        available_measurements = set[str]()
        for result in self.results:
            available_measurements.update(result.measurement_descriptions.keys())
        if not self.test_abbrs:
            self.test_abbrs = sorted(available_measurements)
        for test_abbr in self.test_abbrs:
            for result in self.results:
                test_desc = result.measurement_descriptions.get(test_abbr, None)
                if test_desc is None:
                    continue
                else:
                    measurements.append(test_desc)
                    break
            else:
                sys.exit(
                    f"Unknown measurement in {', '.join(self.test_abbrs)}. "
                    f"Known ones are: {', '.join(sorted(available_measurements))}"
                )

        return measurements

    def format_value(
        self, value: Union[float, int], _pos: Optional[Any] = None, latex: bool = False
    ) -> str:
        """A formatter for the current unit."""
        text = f"{value * 100:.0f}%"
        # if latex:
        #     text = str.translate(
        #         text,
        #         str.maketrans(
        #             {
        #                 " ": r"\,",
        #                 "%": r"\%",
        #             }
        #         ),
        #     )
        return text

    def plot_pairplot(self):
        dfs = [result.get_measurement_results_as_dataframe() for result in self.results]
        df = pd.concat(dfs)
        # calculate mean values for efficiencies / values per server-client-measurement triple
        # could also use avg_efficiency / avg_value
        df = (
            df[["server", "client", "measurement", "efficiency"]]
            .groupby(["server", "client", "measurement"])
            .mean("efficiency")
            .reset_index()
        )

        # convert measurement names to a column
        # reset_index to resolve multi index
        df = df.pivot(
            index=["server", "client"], columns="measurement", values="efficiency"
        ).reset_index()

        sns.set_theme(style="whitegrid")
        plt.rc("legend", fontsize=14)

        g = sns.pairplot(
            data=df,
            hue="server",
            corner=True,
            dropna=True,
            kind="scatter",
            aspect=1,
            markers=[
                self.results[0].servers[server_name].unique_marker
                for server_name in sorted(df.server.unique())
            ],
            diag_kind="hist",
            diag_kws={
                "hue": None,
            },
            grid_kws={
                "layout_pad": 1,
            },
        )
        # g.map_lower(sns.kdeplot, levels=4, color=".9")

        # Title will be added by latex figure
        # g.fig.suptitle(
        #     f"Correlation between Average Efficiency Values between Different Measurements of the same Implementation Combinations"
        # )
        # plt.subplots_adjust(top=0.9)

        # place legend in upper right triangle
        g._legend.set_bbox_to_anchor((0.85, 0.7))
        g.fig.subplots_adjust(right=0.98)

        meas_names = [meas.name for meas in sorted(self.measurements)]
        watermarks_diagonal = [meas.abbr.upper() for meas in sorted(self.measurements)]
        watermarks = list("ABCDEFHKLMOPRSTUWXYZ")
        watermark_index = 0
        plot_regression_in = frozenset({"A", "D", "E", "H", "K", "M"})
        # rotate axis labels and clip axes
        for row, axes in enumerate(g.axes):
            for col, ax in enumerate(axes[: row + 1]):
                # limit (efficiencies)
                ax.set_xlim(xmin=0, xmax=1)
                ax.set_xticks([0, 0.25, 0.5, 0.75, 1])
                # set axis formatter
                ax.xaxis.set_major_formatter(self.format_value)
                # rotate labels at the bottom
                for label in ax.get_xticklabels():
                    label.set_rotation(90)

                if col < row:
                    # lower triangle: scatter plot (not hist)
                    ax.set_ylim(ymin=0, ymax=1)
                    ax.set_yticks([0, 0.25, 0.5, 0.75, 1])
                    ax.yaxis.set_major_formatter(self.format_value)
                    # watermark
                    watermark = watermarks[watermark_index]
                    ax.text(
                        0.5,
                        0.5,
                        watermark,
                        transform=ax.transAxes,
                        fontsize=40,
                        color="grey",
                        alpha=0.25,
                        ha="center",
                        va="center",
                    )
                    watermark_index += 1
                    if watermark in plot_regression_in:
                        # regression (one regression for all instead of one for each hue)
                        row_meas_name = meas_names[row]
                        col_meas_name = meas_names[col]
                        sns.regplot(
                            x=col_meas_name,
                            y=row_meas_name,
                            data=df[["server", "client", row_meas_name, col_meas_name]],
                            robust=True,
                            ci=None,
                            scatter=False,
                            fit_reg=True,
                            color="red",
                            truncate=False,
                            line_kws={
                                "alpha": 0.25,
                                # "color": "red",
                                # "linestyle": "dashed",
                                "linewidth": 1,
                            },
                            ax=ax,
                        )
                    # diagonal line
                    ax.axline(
                        [0, 0],
                        [1, 1],
                        color="grey",
                        linewidth=1,
                        alpha=0.25,
                        linestyle="dashed",
                    )
                else:
                    # diagonal
                    # watermark
                    ax.text(
                        0.5,
                        0.5,
                        watermarks_diagonal[row],
                        transform=ax.transAxes,
                        fontsize=40,
                        color="grey",
                        alpha=0.25,
                        ha="center",
                        va="center",
                    )

        self._save(
            g.fig,
            f"pairplot-{'-'.join(meas.abbr for meas in self.measurements)}",
        )

    def run(self):
        with YaspinWrapper(
            debug=self.debug, text="Plotting...", color="cyan"
        ) as spinner:
            self._spinner = spinner
            self.plot_pairplot()
            self._spinner.ok("✔")

    def _save(self, figure: plt.Figure, output_file_base_name: str):
        """Save or show the plot."""

        output_file = self.img_path / f"{output_file_base_name}.{self.img_format}"
        assert self._spinner
        figure.savefig(
            output_file,
            dpi=300,
            #  transparent=True,
            bbox_inches="tight",
        )
        text = colored(f"{output_file} written.", color="green")
        self._spinner.write(f"✔ {text}")
        if not self.no_interactive:
            self._spinner.text = "Showing plot"
            plt.show()


def main():
    """Main."""
    args = parse_args()
    cli = PlotStatsCli(
        test_abbrs=args.tests,
        results=args.results,
        # plot_type=args.plot_type,
        debug=args.debug,
        img_path=args.img_path,
        img_format=args.img_format,
        no_interactive=args.no_interactive,
    )
    cli.run()


if __name__ == "__main__":
    main()
