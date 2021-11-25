#!/usr/bin/env python3

"""Plot some statistics about a result file."""


import argparse
import logging
import sys
from collections import defaultdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Literal, Optional, Union

import numpy as np
import pandas as pd
import prettytable
import seaborn as sns
from matplotlib import pyplot as plt
from termcolor import colored

from enums import ImplementationRole
from implementations import LOGGER
from result_parser import MeasurementDescription, Result
from tango_colors import Tango
from units import DataRate
from utils import Statistics, Subplot, YaspinWrapper, natural_data_rate

LOGGER = logging.getLogger("quic-interop-runner")


class PlotType(Enum):
    BOXPLOT = "boxplot"
    KDES = "kdes"
    HEATMAP = "heatmap"
    RIDGELINE = "ridgeline"


def parse_args():
    """Parse command line args."""
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument(
        "--test",
        dest="tests",
        nargs="+",
        type=str,
        help="The measurement cases to plot.",
    )
    parser.add_argument(
        "results",
        nargs="+",
        type=Result,
        help="Result file to use.",
    )
    parser.add_argument(
        "--efficiency",
        action="store_true",
        help="Use efficiencies instead of goodput (/avg).",
    )
    parser.add_argument(
        "-t",
        "--plot-type",
        type=PlotType,
        choices=PlotType,
        help="The type of plot to plot.",
    )
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
        test_abbrs: str,
        results: list[Result],
        plot_type: PlotType,
        img_path: Path,
        img_format: str,
        efficiency: bool = False,
        debug: bool = False,
        no_interactive: bool = False,
    ) -> None:
        self.test_abbrs = test_abbrs
        self.results = results
        self.plot_type = plot_type
        self.efficiency = efficiency
        self.debug = debug
        self._spinner: Optional[YaspinWrapper] = None
        self.img_path = img_path
        self.img_format = img_format
        self._colors = Tango()
        self.no_interactive = no_interactive
        for result in self.results:
            result.load_from_json()

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

    @property
    def meas_prop_key(self) -> str:
        """Return the property name of a measurement to use."""

        return "efficiency" if self.efficiency else "value"

    @property
    def meas_prop_name(self) -> str:
        """Return Goodput / Efficiency."""

        return "Efficiency" if self.efficiency else "Goodput"

    @property
    def meas_prop_unit(self) -> str:
        """Return the unit for the property value"""

        return "%" if self.efficiency else "kbps"

    def format_percentage(self, value: Union[float, int], _pos=None) -> str:
        return f"{value * 100:.0f} %"

    def format_data_rate(self, value: Union[float, int], _pos=None) -> str:
        """A formatter for the current unit."""
        return natural_data_rate(int(value))

    def _format_latex(self, text: str) -> str:
        return str.translate(
            text,
            str.maketrans(
                {
                    " ": r"\,",
                    "%": r"\%",
                }
            ),
        )

    def format_value(
        self, value: Union[float, int], _pos: Optional[Any] = None, latex: bool = False
    ) -> str:
        """A formatter for the current unit."""
        text = (
            self.format_percentage(value)
            if self.efficiency
            else self.format_data_rate(value)
        )
        if latex:
            return self._format_latex(text)
        return text

    def get_dataframe(self) -> pd.DataFrame:
        dfs = [result.get_measurement_results_as_dataframe() for result in self.results]
        return pd.concat(dfs)

    def plot_boxplot(self):
        # sns.set_theme(style="whitegrid")
        df = self.get_dataframe()
        df = df[["measurement", "value", "efficiency"]]

        # replace measurements with abbreviations
        for measurement in self.measurements:
            df.loc[df.measurement == measurement.name, "measurement"] = measurement.abbr

        with Subplot(ncols=2) as (fig, axs):
            assert not isinstance(axs, plt.Axes)
            [ax1, ax2] = axs
            assert isinstance(ax1, plt.Axes)
            assert isinstance(ax2, plt.Axes)

            ax1.grid()
            ax2.grid()
            # breakpoint()
            sns.boxplot(
                ax=ax1,
                x="measurement",
                y="value",
                data=df[["measurement", "value"]],
            )
            sns.boxplot(
                ax=ax2,
                x="measurement",
                y="efficiency",
                data=df[["measurement", "efficiency"]],
            )
            # ax.set_title(f"{self.meas_prop_name.title()} by Measurement")
            ax1.yaxis.set_major_formatter(self.format_data_rate)
            ax2.yaxis.set_major_formatter(self.format_percentage)
            ax1.set_ylim(ymin=0)
            ax2.set_ylim(ymin=0, ymax=1)
            # no labels, will be explained in titles
            ax1.set_xlabel("")
            ax1.set_ylabel("")
            ax2.set_xlabel("")
            ax2.set_ylabel("")
            # titles
            ax1.set_title("Goodput")
            ax2.set_title("Efficiency")
            # move tickes of right axis to right
            ax2.yaxis.tick_right()
            # padding between subplots
            fig.subplots_adjust(wspace=0.1)

            table = prettytable.PrettyTable()
            table.hrules = prettytable.FRAME
            table.vrules = prettytable.ALL
            table.field_names = [
                "Measurement",
                "Type",
                "AVG",
                "Med",
                "std",
                "min",
                "max",
                "q05",
                "q95",
            ]

            for measurement in self.measurements:
                val_stats = Statistics.calc(
                    df[df.measurement == measurement.abbr]["value"]
                )
                eff_stats = Statistics.calc(
                    df[df.measurement == measurement.abbr]["efficiency"]
                )
                table.add_row(
                    [
                        measurement.name.title(),
                        "Values",
                        self.format_data_rate(val_stats.avg),
                        self.format_data_rate(val_stats.med),
                        self.format_data_rate(val_stats.std),
                        self.format_data_rate(val_stats.min),
                        self.format_data_rate(val_stats.max),
                        self.format_data_rate(val_stats.q_05),
                        self.format_data_rate(val_stats.q_95),
                    ]
                )
                table.add_row(
                    [
                        measurement.name.title(),
                        "Efficiencies",
                        self.format_percentage(eff_stats.avg),
                        self.format_percentage(eff_stats.med),
                        self.format_percentage(eff_stats.std),
                        self.format_percentage(eff_stats.min),
                        self.format_percentage(eff_stats.max),
                        self.format_percentage(eff_stats.q_05),
                        self.format_percentage(eff_stats.q_95),
                    ]
                )

            print(table)

            # TODO: Use ax.violinplot?
            self._save(
                fig,
                f"boxplots-{'-'.join(meas.abbr for meas in sorted(self.measurements))}",
            )

    def plot_kdes(self):
        with Subplot() as (fig, ax):
            assert isinstance(ax, plt.Axes)
            sns.set_theme(style="whitegrid")
            fig.suptitle(
                f"KDE of {self.meas_prop_name} for Different Measurement Cases"
            )

            # for i, measurement in enumerate(self.measurements):
            #     assert isinstance(axs[i], plt.Axes)

            #     axs[i].grid()
            #     axs[i].set_title(f"Measurement {measurement.name}")

            #     axs[i].xaxis.set_major_formatter(self.format_value)

            # stats_by_server = [
            #     self.result.get_measurement_value_stats(
            #         server_name, ImplementationRole.SERVER, measurement.abbr
            #     )
            #     for server_name in self.result.servers.keys()
            # ]
            # stats_by_client = [
            #     self.result.get_measurement_value_stats(
            #         client_name, ImplementationRole.CLIENT, measurement.abbr
            #     )
            #     for client_name in self.result.clients.keys()
            # ]
            # values_for_ax = [
            #     [
            #         meas.avg
            #         for meas in self.result.get_all_measurements_of_type(
            #             measurement.abbr, succeeding=True
            #         )
            #     ],
            #     [stat.avg for stat in stats_by_server if stat],
            #     [stat.avg for stat in stats_by_client if stat],
            # ]
            # labels = (("All Measurements", "By Server", "By Client"),)

            # # for index, (values, series_name) in enumerate(
            # #     zip(values_for_ax, labels)
            # # ):
            # #     sns.kdeplot(
            # #         ax=axs[i],
            # #         x=values,
            # #         label=series_name,
            # #         fill=index > 0,
            # #         common_norm=False,
            # #         # palette="crest",
            # #         alpha=0.5,
            # #         linewidth=0 if index > 0 else 1,
            # #     )
            # #     axs[i].hist(
            # #         x=values,
            # #         label=series_name,
            # #         # fill=index > 0,
            # #         # common_norm=False,
            # #         # palette="crest",
            # #         # alpha=0.5,
            # #         # linewidth=0 if index > 0 else 1,
            # #     )

            # # axs[i].legend()

            df = self.result.get_measurement_results_as_dataframe()
            by_server = (
                df.groupby(["measurement", "server"])[self.meas_prop_key]
                .mean()
                .reset_index()
            )
            by_server["by"] = "server"
            by_server.rename(columns={"server": "implementation"}, inplace=True)
            by_client = (
                df.groupby(["measurement", "client"])[self.meas_prop_key]
                .mean()
                .reset_index()
            )
            by_client["by"] = "client"
            by_client.rename(columns={"client": "implementation"}, inplace=True)
            df = by_server.append(by_client)
            sns.violinplot(
                ax=ax,
                x="measurement",
                y=self.meas_prop_key,
                hue="by",
                split=True,
                data=df,
                clip=[0, 1] if self.efficiency else 0,
            )
            ax.set_xlabel("")
            ax.set_ylabel("")
            ax.yaxis.set_major_formatter(self.format_value)
            if self.efficiency:
                ax.set_ylim(ymin=0, ymax=1)
            else:
                ax.set_ylim(ymin=0)

            self._save(
                fig,
                f"kdes-{self.meas_prop_name.lower()}-{'-'.join(meas.abbr for meas in self.measurements)}",
            )

    def plot_heatmap(self):
        df = self.result.get_measurement_results_as_dataframe()
        sns.set_theme(style="whitegrid")
        measurement = self.measurements[0]
        g = sns.relplot(
            data=df[df.measurement == measurement.name],
            x="server",
            y="client",
            hue=self.meas_prop_key,
            size=self.meas_prop_key,
            palette=sns.color_palette("ch:start=.2,rot=-.3", as_cmap=True),
            # palette=sns.color_palette("coolwarm", as_cmap=True).reversed(),
            hue_norm=(df[self.meas_prop_key].min(), df[self.meas_prop_key].max()),
            size_norm=(
                df[self.meas_prop_key].min(),
                df[self.meas_prop_key].max(),
            ),
            edgecolor="0.7",
            height=10,
            sizes=(5, 250),
        )
        # g.set(xlabel="", ylabel="")
        g.fig.suptitle(
            f"Average {self.meas_prop_name.title()} of Measurement {measurement.name.title()}"
        )
        g.set(aspect="equal")
        g.despine(left=True, bottom=True)
        g.ax.margins(0.02)
        if g.legend:
            for text in g.legend.texts:
                if self.efficiency:
                    text.set_text(f"{float(text.get_text()) * 100:.0f} %")
                else:
                    text.set_text(natural_data_rate(int(float(text.get_text()))))
            for artist in g.legend.legendHandles:
                artist.set_edgecolor(".7")
        for label in g.ax.get_xticklabels():
            label.set_rotation(90)

        self._save(g.fig, f"heatmap_{self.meas_prop_name.lower()}_{measurement.abbr}")

    # def plot_heatmap_for_servers(self):
    #     with Subplot() as (fig, ax):
    #         assert isinstance(ax, plt.Axes)
    #         df = pd.DataFrame(
    #             data=[
    #                 [
    #                     meas.abbr,
    #                     server,
    #                     stat.avg if stat else None,
    #                     stat.std if stat else None,
    #                 ]
    #                 for server in self.result.servers.keys()
    #                 for meas in self.measurements
    #                 for stat in [
    #                     self.result.get_measurement_value_stats(
    #                         server, ImplementationRole.SERVER, meas.abbr
    #                     )
    #                 ]
    #             ],
    #             columns=["measurement", "server", "avg", "std"],
    #         )
    #         df.sort_values("server")
    #         sns.set_theme(style="whitegrid")
    #         measurement = self.measurements[-1]
    #         g = sns.scatterplot(
    #             ax=ax,
    #             data=df[df.measurement == measurement.name],
    #             x="server",
    #             y=0,
    #             hue=self.meas_prop_key,
    #             size=self.meas_prop_key,
    #             palette=sns.color_palette("ch:start=.2,rot=-.3", as_cmap=True),
    #             # palette=sns.color_palette("coolwarm", as_cmap=True).reversed(),
    #             hue_norm=(df[self.meas_prop_key].min(), df[self.meas_prop_key].max()),
    #             size_norm=(
    #                 df[self.meas_prop_key].min(),
    #                 df[self.meas_prop_key].max(),
    #             ),
    #             edgecolor="0.7",
    #             # height=10,
    #             sizes=(5, 250),
    #             legend=False,
    #         )
    #         # g.set(ylabel="")
    #         ax.axes.get_yaxis().set_visible(False)
    #         ax.set_ylim(ymin=0, ymax=0)
    #         ax.set_yticks([0])
    #         ax.yaxis.grid(True)
    #         ax.axhline(0, color="gray", linewidth=0.5)
    #         # g.fig.suptitle(
    #         #     f"Average {self.meas_prop_name} of Measurement {measurement.name}"
    #         # )
    #         # g.set(aspect="equal")
    #         # g.despine(left=True, bottom=True)
    #         ax.margins(0.02)
    #         # for text in g.legend.texts:
    #         #     if self.efficiency:
    #         #         text.set_text(f"{float(text.get_text()) * 100:.0f} %")
    #         #     else:
    #         #         text.set_text(natural_data_rate(int(text.get_text())))
    #         for label in ax.get_xticklabels():
    #             label.set_rotation(90)
    #         # for artist in g.legend.legendHandles:
    #         #     artist.set_edgecolor(".7")

    #         self._save(fig, self.output_file)

    def plot_ridgeline(self, dimension: Union[Literal["server"], Literal["client"]]):
        sns.set_theme(style="white", rc={"axes.facecolor": (0, 0, 0, 0)})

        df = self.result.get_measurement_results_as_dataframe()
        # filter by measurement
        measurement = self.measurements[0]
        df = df[df.measurement == measurement.name]

        # we generate a pd.Serie with the mean temperature for each month (used later for colors in the FacetGrid plot), and we create a new column in temp dataframe
        mean_series = df.groupby(dimension)[self.meas_prop_key].mean()
        df[f"mean_{dimension}"] = df[dimension].map(mean_series)

        # we generate a color palette with Seaborn.color_palette()
        pal = sns.color_palette(palette="coolwarm", n_colors=12)

        # in the sns.FacetGrid class, the 'hue' argument is the one that is the one that will be represented by colors with 'palette'
        g = sns.FacetGrid(
            df,
            row=dimension,
            hue=f"mean_{dimension}",
            aspect=12.5,
            height=0.85,
            # height=0.75,
            palette=pal,
        )

        # then we add the densities kdeplots for each month
        g.map(
            sns.kdeplot,
            self.meas_prop_key,
            bw_adjust=1,
            clip_on=False,
            fill=True,
            alpha=1,
            linewidth=1.5,
            clip=(0, 1) if self.efficiency else None,
            cut=0,
        )

        # # # here we add a white line that represents the contour of each kdeplot
        # g.map(
        #     sns.kdeplot, self.meas_prop_key, bw_adjust=1, clip_on=False, color="w", lw=1
        # )

        # here we add a horizontal line for each plot
        g.map(plt.axhline, y=0, lw=2, clip_on=False)

        # we loop over the FacetGrid figure axes (g.axes.flat) and add the month as text with the right color
        # notice how ax.lines[-1].get_color() enables you to access the last line's color in each matplotlib.Axes
        for ax, impl_name in zip(g.axes.flat, df[dimension].unique()):
            ax.text(
                0 if measurement.abbr == "G" else 1,
                0,
                impl_name,
                horizontalalignment="left" if measurement.abbr == "G" else "right",
                verticalalignment="bottom",
                color=ax.lines[-1].get_color(),
                transform=ax.transAxes,
            )
            # label.set_rotation(0)
            if self.efficiency:
                ax.set_xlim(xmin=0, xmax=1)
            else:
                ax.set_xlim(xmin=0)

        g.axes.flat[-1].xaxis.set_major_formatter(self.format_value)

        # we use matplotlib.Figure.subplots_adjust() function to get the subplots to overlap
        g.fig.subplots_adjust(hspace=-0.3)

        # eventually we remove axes titles, yticks and spines
        g.set_titles("")
        g.set(yticks=[])
        g.despine(bottom=True, left=True)
        g.set(ylabel="")

        # plt.setp(ax.get_xticklabels(), fontsize=15, fontweight="bold")
        plt.xlabel(self.meas_prop_name)
        g.fig.suptitle(
            f"KDEs of {self.meas_prop_name} of {dimension.title()}s in Measurement {measurement.name.title()}"
        )

        self._save(
            g.fig,
            f"{self.meas_prop_name.lower()}-kdes-marginalized-by-{dimension}-{measurement.abbr}",
        )

    def run(self):
        with YaspinWrapper(
            debug=self.debug, text="Plotting...", color="cyan"
        ) as spinner:
            self._spinner = spinner
            if self.plot_type == PlotType.BOXPLOT:
                self.plot_boxplot()
            elif self.plot_type == PlotType.KDES:
                self.plot_kdes()
            elif self.plot_type == PlotType.HEATMAP:
                self.plot_heatmap()
            elif self.plot_type == PlotType.RIDGELINE:
                self.plot_ridgeline("server")
                spinner.text = "Plotting..."
                self.plot_ridgeline("client")
            else:
                assert False

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
        plot_type=args.plot_type,
        efficiency=args.efficiency,
        debug=args.debug,
        img_path=args.img_path,
        img_format=args.img_format,
        no_interactive=args.no_interactive,
    )
    cli.run()


if __name__ == "__main__":
    main()
