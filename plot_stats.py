#!/usr/bin/env python3

"""Plot some statistics about a result file."""


import argparse
import logging
import sys
from enum import Enum
from functools import cached_property
from pathlib import Path
from typing import Any, Literal, Optional, Union

import matplotlib
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from matplotlib.ticker import FuncFormatter
from pandas.api.types import CategoricalDtype
from pandas.core.frame import DataFrame
from termcolor import colored

from enums import TestResult
from result_parser import MeasurementDescription, Result, TestResultInfo
from tango_colors import Tango
from units import DataRate
from utils import LOGGER, Statistics, Subplot, YaspinWrapper, natural_data_rate

IMPL_CCAS = {
    "aioquic": {
        "cca": "NewReno",
    },
    "chrome": {
        "supported ccas": ["BBRv2", "CUBIC"],
    },
    "kwik": {
        "cca": "NewReno",
    },
    "lsquic": {
        "cca": "BBR",
    },
    "msquic": {
        "cca": "CUBIC",
    },
    "mvfst": {
        "supported ccas": [
            "BBR",
            "NewReno",
            "CUBIC",
            "(Copa)",
            "(Copa2)",
            "(CCP)",
        ],
        "cca": "CUBIC",
    },
    "neqo": {
        "supported ccas": ["CUBIC", "NewReno"],
        "cca": "NewReno",
    },
    "nginx": {},
    "ngtcp2": {
        "cca": "CUBIC",
    },
    "picoquic": {
        "cca": "BBR",
    },
    "quant": {
        "cca": "NewReno",
    },
    "quic-go": {
        "cca": "Reno",
    },
    "quiche": {
        "cca": "CUBIC",
    },
    "quicly": {
        "cca": "Reno",
    },
    "xquic": {
        "supported ccas": ["Reno", "BBR", "CUBIC"],
        "cca": "BBR",
    },
}

CAT_CCA_ORDER = CategoricalDtype(
    ["Reno", "NewReno", "CUBIC", "BBR", "unknown"], ordered=True
)

CCA_PALETTE = {
    "Reno": Tango().Plum,
    "NewReno": Tango().DarkSkyBlue,
    "CUBIC": Tango().Chameleon,
    "BBR": Tango().Orange,
    "unknown": Tango().aluminium4,
}


def meas_tex_format(measurement: MeasurementDescription) -> str:
    keyword = measurement.abbr.lower()
    return fr"\textsc{{\{keyword}/}}"


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
\DeclareSIUnit\byte{Byte}
\DeclareSIUnit\bit{bit}
\DeclareSIUnit\decibelm{dBm}
\DeclareSIUnit\mph{mph}
\DeclareSIUnit\month{month}
\DeclareSIUnit\year{yr}
\catcode`\%=12\relax
\DeclareSIUnit[number-unit-product=]\percent{%}
\catcode`\%=14\relax

\def\lr/{\mbox{\textsc{LongRTT}}}
\def\g/{\mbox{\textsc{Goodput}}}
\def\sat/{\mbox{\textsc{Sat}}}
\def\satl/{\mbox{\textsc{SatLoss}}}
\def\eut/{\mbox{\textsc{Eutelsat}}}
\def\ast/{\mbox{\textsc{Astra}}}
\def\crosstraffic/{\mbox{\textsc{CrossTraffic}}}
"""


class PlotType(Enum):
    BOXPLOT = "boxplot"
    KDES = "kdes"
    HEATMAP = "heatmap"
    RIDGELINE = "ridgeline"
    ANALYZE = "analyze"
    SWARM = "swarm"
    CCAS = "ccas"
    VIOLINS = "violins"

    def __str__(self) -> str:
        return self.value


def parse_args():
    """Parse command line args."""
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument(
        "-m",
        "--measurement",
        dest="measurements",
        nargs="+",
        type=str,
        help="The test cases to plot (only for heatmap).",
    )
    parser.add_argument(
        "--test",
        dest="tests",
        nargs="*",
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
        "--prop",
        action="store",
        choices={"efficiency", "goodput"},
        default="goodput",
        help="Use efficiencies or goodput (/avg).",
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
        meas_abbrs: list[str],
        test_abbrs: list[str],
        results: list[Result],
        plot_type: PlotType,
        img_path: Path,
        img_format: str,
        efficiency: bool = False,
        debug: bool = False,
        no_interactive: bool = False,
    ) -> None:
        self.meas_abbrs = meas_abbrs
        self.test_abbrs = test_abbrs
        self.results = results
        self.plot_type = plot_type
        self.efficiency = efficiency
        self.debug = debug
        self._spinner: Optional[YaspinWrapper] = None
        self.img_path = img_path
        self.img_format = img_format
        self.no_interactive = no_interactive
        self._colors = Tango(model="HTML")

        self.set_theme()

        for result in self.results:
            result.load_from_json()

    def _log(self, msg: str, log_level: int = logging.INFO):
        if self._spinner:
            self._spinner.write(msg)
        else:
            LOGGER.log(level=log_level, msg=msg)

    def set_theme(self):
        if self.img_format in {"tex", "pgf", "pdf"}:
            self.tex_mode = True
            if self.img_format == "pdf":
                matplotlib.use("pgf")
            # latex_cmds = Path("../../thesis/99-cmds.tex").resolve().absolute()

            sns.set(
                "paper",
                "white",
                rc={
                    # "font.size": 10,
                    # "axes.labelsize": 10,
                    # "legend.fontsize": 8,
                    # "axes.titlesize": 10,
                    # "xtick.labelsize": 8,
                    # "ytick.labelsize": 8,
                    "pgf.rcfonts": False,
                },
            )
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
            sns.set("paper", "white")
            self.tex_mode = False

    @property
    def measurements(self) -> list[MeasurementDescription]:
        """The measurements to use."""
        default_order = ["G", "SAT", "SATL", "AST", "EUT"]

        def sort_key(value: str):
            try:
                return str(default_order.index(value))
            except IndexError:
                return value

        measurements = list[MeasurementDescription]()
        available_measurements = set[str]()
        for result in self.results:
            available_measurements.update(result.measurement_descriptions.keys())
        if not self.meas_abbrs:
            self.meas_abbrs = sorted(available_measurements, key=sort_key)
        for test_abbr in self.meas_abbrs:
            for result in self.results:
                test_desc = result.measurement_descriptions.get(test_abbr, None)
                if test_desc is None:
                    continue
                else:
                    measurements.append(test_desc)
                    break
            else:
                sys.exit(
                    f"Unknown measurement in {', '.join(self.meas_abbrs)}. "
                    f"Known ones are: {', '.join(sorted(available_measurements, key=sort_key))}"
                )

        return measurements

    @cached_property
    def first_measurement(self) -> MeasurementDescription:
        """The first measurement to use."""
        measurement = self.measurements[0]
        assert self._spinner
        self._spinner.write(f"⚒ Using measurement {measurement.name}...")
        return measurement

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
        if self.tex_mode:
            return fr"\SI{{{value * 100:.0f}}}{{\percent}}"
        else:
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

    @property
    def formatter(self):
        return FuncFormatter(self.format_value)

    def get_dataframe(self, include_failed: bool = True) -> pd.DataFrame:
        dfs = [
            result.get_measurement_results_as_dataframe(include_failed=include_failed)
            for result in self.results
        ]
        return pd.concat(dfs)

    def plot_boxplot(self):
        self.set_theme()
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
            # don't use AST or EUT max values, because they are too high
            max_values = [
                meas.theoretical_max_value
                for meas in self.measurements
                if meas.abbr not in ("AST", "EUT") and meas.theoretical_max_value
            ]
            max_goodput_to_show = (
                max(max_values) * DataRate.KBPS * 1.01 if max_values else None
            )
            ax1.set_ylim(ymin=0, ymax=max_goodput_to_show)
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

            for i, measurement in enumerate(self.measurements):
                assert measurement.theoretical_max_value
                ax1.axhline(
                    y=measurement.theoretical_max_value * DataRate.KBPS,
                    xmin=i / len(self.measurements),
                    xmax=(i + 1) / len(self.measurements),
                    color=self._colors.ScarletRed,
                    linestyle="--",
                )

            # TODO: Use ax.violinplot?
            self._save(
                fig,
                f"boxplots-{'-'.join(meas.abbr for meas in sorted(self.measurements))}",
            )

    def plot_violins(self, meas_abbr: str):
        self.set_theme()

        measurement = [meas for meas in self.measurements if meas.abbr == meas_abbr][0]

        df = self.get_dataframe(include_failed=False)
        # filter by measurement
        df = df[df["measurement"] == measurement.name]
        # filter by columns
        df = df[["server", "client", "value"]]

        # collect all implementations
        implementations = sorted({*df.server.unique(), *df.client.unique()})

        # restructure dataframe
        partial_dfs = list[pd.DataFrame]()
        IGNORE_RATIO_LT = 0.3
        IGNORE_AMOUNT_LT = len(implementations) * (len(implementations) / 5)
        for implementation in implementations:
            by_impl = df.loc[
                (df["server"] == implementation) | (df["client"] == implementation)
            ]
            if len(by_impl) < IGNORE_AMOUNT_LT:
                print(
                    f"Skipping {implementation}, which is only represented by less than {IGNORE_AMOUNT_LT} entries"
                )
                continue
            roles = by_impl["server"].map(
                lambda server: "Server" if server == implementation else "Client"
            )
            role_counts_normalized = roles.value_counts(normalize=True)
            if role_counts_normalized.get("Client") is None:
                print(f"Skipping {implementation}, which is only a server")
                continue
            elif role_counts_normalized.get("Server", 0) < IGNORE_RATIO_LT:
                print(
                    f"Skipping {implementation}, which has less than {IGNORE_RATIO_LT * 100:.0f} % entries for servers"
                )
                continue
            elif role_counts_normalized.get("Server") is None:
                print(f"Skipping {implementation}, which is only a clients")
                continue
            elif role_counts_normalized.get("Client", 0) < IGNORE_RATIO_LT:
                print(
                    f"Skipping {implementation}, which has less than {IGNORE_RATIO_LT * 100:.0f} % entries for client"
                )
                continue

            values_by_impl = by_impl["value"]
            by_impl = pd.concat(
                [
                    roles.to_frame("Role"),
                    values_by_impl.to_frame(self.meas_prop_name),
                ],
                axis=1,
            )
            by_impl["Implementation"] = implementation
            partial_dfs.append(by_impl)

        df = pd.concat(partial_dfs)

        with Subplot() as (fig, ax):
            assert isinstance(ax, plt.Axes)

            sns.violinplot(
                ax=ax,
                data=df,
                x="Implementation",
                y=self.meas_prop_name,
                hue="Role",
                split=True,
                clip=[0, 1] if self.efficiency else 0,
                scale="count",
                inner="quartile",
                bw=0.2,
                cut=0,
                palette={
                    "Server": self._colors.LightOrange,
                    "Client": self._colors.LightSkyBlue,
                },
                hue_order=["Server", "Client"],
            )
            ax.yaxis.set_major_formatter(self.format_value)

            if self.efficiency:
                ax.set_ylim(ymin=0, ymax=1)
            else:
                ax.set_ylim(
                    ymin=0, ymax=measurement.theoretical_max_value * DataRate.KBPS
                )

            # rotate x tick labels
            for tick in ax.get_xticklabels():
                tick.set_rotation(45)

            ax.text(
                0.5,
                0.25 if meas_abbr == "G" else 0.75,
                meas_abbr.upper(),
                transform=ax.transAxes,
                fontsize=50,
                color="grey",
                alpha=0.25,
                ha="center",
                va="center",
            )

            # add additional efficiency axis and style it like the original seaborn plot
            # add a second x-axis to last subplot
            y_axis_eff = ax.twinx()
            # force position = bottom
            # y_axis_eff.yaxis.set_ticks_position("right")
            # y_axis_eff.yaxis.set_label_position("right")
            # set 0% 100% as limits
            y_axis_eff.set_ylim(ymin=0, ymax=1)
            # format auto generated labels (don't set the ticks manually, as this does not work...)
            for label in y_axis_eff.get_yticklabels():
                label.set_fontproperties(ax.get_xticklabels()[0].get_fontproperties())
            # use percentage formatter
            y_axis_eff.yaxis.set_major_formatter(self.format_percentage)
            # increase distance between frame and axis
            # add spines again (???)
            color = ax.yaxis.label.get_color()
            for pos in ("left", "right", "top", "bottom"):
                y_axis_eff.spines[pos].set_color(color)
            # remove tick marks
            for axis in (ax, y_axis_eff):
                axis.tick_params(
                    left=False,
                    bottom=False,
                    top=False,
                    right=False,
                )
            # set label and hide title
            y_axis_eff.set_ylabel(
                "Efficiency",
                fontproperties=ax.yaxis.label.get_font_properties(),
            )
            # y_axis_eff.set_title("")
            y_axis_eff.grid(False)

            self._save(
                fig,
                f"violins-{meas_abbr.lower()}",
            )

    def plot_kdes(self):
        self.set_theme()
        with Subplot() as (fig, ax):
            assert isinstance(ax, plt.Axes)
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

            df = self.get_dataframe()
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

    def plot_test_case_heatmap(self):
        assert self.test_abbrs
        assert self._spinner
        test_abbr = self.test_abbrs[0]
        self._spinner.write(f"Using Test Case {test_abbr}")
        data: Optional[list[TestResultInfo]] = None
        # test_case: Optional[TestDescription] = None

        for result in self.results:
            if test_abbr in result.test_descriptions.keys():
                # test_case = result.test_descriptions[test_abbr]
                data = result.get_all_tests_of_type(test_abbr)
                break
        else:
            raise ValueError(f"No test case with abbr {test_abbr} found")

        df = DataFrame(
            data=[
                (
                    result.server.name,
                    result.client.name,
                    result.result == TestResult.SUCCEEDED,
                )
                for result in data
            ],
            columns=["server", "client", "succeeded"],
        )

        self.set_theme()

        with Subplot() as (fig, ax):
            assert isinstance(ax, plt.Axes)

            ax.grid(True, lw=0.5)

            x_labels = [name for name in sorted(df.server.unique())]
            y_labels = [name for name in reversed(sorted(df.client.unique()))]
            x_to_num = {name: i for i, name in enumerate(x_labels)}
            y_to_num = {name: i for i, name in enumerate(y_labels)}

            for succeeded in (True, False):
                ax.scatter(
                    x=df[df.succeeded == succeeded].server.map(x_to_num),
                    y=df[df.succeeded == succeeded].client.map(y_to_num),
                    c=self._colors.Chameleon if succeeded else self._colors.ScarletRed,
                    # marker="$✔$" if succeeded else "x",
                    marker="o" if succeeded else "x",
                )

            ax.set_xticks([x_to_num[name] for name in x_labels])
            ax.set_yticks([y_to_num[name] for name in y_labels])
            ax.set_xticklabels(x_labels, rotation=90, horizontalalignment="center")
            ax.set_yticklabels(y_labels)

            ax.set_box_aspect(len(y_labels) / len(x_labels))
            # despine
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.spines["bottom"].set_visible(False)
            ax.spines["left"].set_visible(False)

            ax.set_xlabel("Server")
            ax.set_ylabel("Client")

            ax.xaxis.set_ticks_position("top")
            ax.xaxis.set_label_position("top")

            # remove tick marks
            ax.tick_params(
                left=False,
                bottom=False,
                top=False,
                right=False,
            )

            self._save(
                fig,
                f"heatmap_test_{test_abbr}",
            )

    def plot_heatmap(self, meas_abbr: str):
        measurement = [meas for meas in self.measurements if meas.abbr == meas_abbr][0]
        df = self.get_dataframe(include_failed=False)
        self.set_theme()

        # use the min/max for all measurements as reference
        max_val = df[self.meas_prop_key].max()
        min_val = df[self.meas_prop_key].min()

        # filter by measurement
        df = df[df.measurement == measurement.name]
        # filter columns
        df = df[["server", "client", self.meas_prop_key]]
        # use mean values of same experiments
        df = df.groupby(["server", "client"]).mean().reset_index()

        with Subplot() as (fig, ax):
            assert isinstance(ax, plt.Axes)

            ax.grid(True, lw=0.5)
            # fig.suptitle(
            #     f"Average {self.meas_prop_name.title()} of Measurement {measurement.name.title()}"
            # )

            if meas_abbr == "G":
                x_labels = list(sorted(self.results[-1].servers.keys()))
                y_labels = list(reversed(sorted(self.results[-1].clients.keys())))
            else:
                x_labels = list(sorted(df.server.unique()))
                y_labels = list(reversed(sorted(df.client.unique())))
            x_to_num = {name: i for i, name in enumerate(x_labels)}
            y_to_num = {name: i for i, name in enumerate(y_labels)}

            hue_scale = 250

            def scale_for_size(val):
                return hue_scale * (val - min_val) / (max_val - min_val)

            # def inverse_scale_for_size(val):
            #     return val / hue_scale * (max_val - min_val) + min_val

            hue = df[self.meas_prop_key]
            sizes = hue.map(scale_for_size)

            color_palette = sns.color_palette("ch:start=.2,rot=-.3", as_cmap=True)

            scatter = ax.scatter(
                x=df.server.map(x_to_num),
                y=df.client.map(y_to_num),
                s=sizes,
                c=hue,
                marker="o",
                cmap=color_palette,
            )

            indices = df.set_index(["server", "client"]).index
            missing_indices = list[tuple[str, str]]()
            for server in x_labels:
                for client in y_labels:
                    if (server, client) not in indices:
                        missing_indices.append((server, client))
            ax.scatter(
                x=[x_to_num[e[0]] for e in missing_indices],
                y=[y_to_num[e[1]] for e in missing_indices],
                c=self._colors.ScarletRed,
                marker="x",
            )

            ax.set_xticks([x_to_num[name] for name in x_labels])
            ax.set_yticks([y_to_num[name] for name in y_labels])
            ax.set_xticklabels(x_labels, rotation=90, horizontalalignment="center")
            ax.set_yticklabels(y_labels)

            ax.set_box_aspect(len(y_labels) / len(x_labels))
            # despine
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.spines["bottom"].set_visible(False)
            ax.spines["left"].set_visible(False)

            ax.set_xlabel("Server")
            ax.set_ylabel("Client")

            ax.xaxis.set_ticks_position("top")
            ax.xaxis.set_label_position("top")
            ax.tick_params(
                left=False,
                bottom=False,
                top=False,
                right=False,
            )

            ax.legend(
                *scatter.legend_elements(
                    num=5,
                    fmt=self.formatter,
                    prop="colors",
                    # prop can unfortunately only be colors or sizes.
                    # for sizes use:
                    # func=inverse_scale_for_size,
                ),
                title=self.meas_prop_name.title(),
                bbox_to_anchor=(0.5 if self.efficiency else 1, -0.25),
                loc="lower center" if self.efficiency else "lower right",
                facecolor="white",
                edgecolor="white",
                ncol=3,
            )

            self._save(
                fig,
                f"heatmap_{self.meas_prop_name.lower()}_{measurement.abbr}",
            )

    def plot_swarmplot(self):
        df = self.get_dataframe(include_failed=False)
        self.set_theme()

        # filter by measurement
        meas_name_set = {meas.name for meas in self.measurements}
        df = df[df.measurement.isin(meas_name_set)]
        # filter columns
        df = df[["server", "client", "measurement", self.meas_prop_key]]

        # use mean values of iterations
        df = df.groupby(["server", "client", "measurement"]).mean().reset_index()

        meas_order = CategoricalDtype(
            [meas.name for meas in self.measurements], ordered=True
        )
        df["measurement"] = df["measurement"].astype(meas_order)

        # sort by measurement
        df.sort_values(by=["measurement", "server"], inplace=True)

        max_goodput = df[self.meas_prop_key].max()

        # rename columns
        df.rename(
            columns={
                "server": "Server",
                "client": "Client",
                "measurement": "Measurement",
                self.meas_prop_key: self.meas_prop_name.title(),
            },
            inplace=True,
        )

        with Subplot() as (fig, ax):
            assert isinstance(ax, plt.Axes)

            ax = sns.swarmplot(
                data=df,
                x="Measurement",
                y=self.meas_prop_name.title(),
                hue="Server",
                size=3,
                ax=ax,
            )

            ax.yaxis.set_major_formatter(self.format_value)

            ax.legend(
                loc="center left",
                # ncol=3,
                bbox_to_anchor=(1, 0.5),
            )

            ax.set_ylim(ymin=0, ymax=1 if self.efficiency else max_goodput * 1.1)

            meas_abbrs = "-".join(meas.abbr for meas in self.measurements)
            self._save(
                fig,
                f"swarmplot_{self.meas_prop_name.lower()}_{meas_abbrs}",
            )

    def plot_ridgeline(
        self, dimension: Union[Literal["server"], Literal["client"]], meas_abbr: str
    ):
        self.set_theme()
        sns.set_theme(rc={"axes.facecolor": (0, 0, 0, 0)})

        measurement = [meas for meas in self.measurements if meas.abbr == meas_abbr][0]

        df = self.get_dataframe(include_failed=True)
        # filter by measurement
        df = df[df.measurement == measurement.name]
        # filter columns
        df = df[[dimension, "value"]]

        # we generate a pd.Serie with the mean temperature for each month (used later for colors in the FacetGrid plot), and we create a new column in temp dataframe
        mean_series = df.groupby(dimension)["value"].mean()
        df[f"mean_{dimension}"] = df[dimension].map(mean_series)

        # bring in some variance to values == 0 for kde
        df.value = df.value.map(lambda v: np.random.normal(0, 0.001) if v == 0 else v)
        # breakpoint()

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
            sharex=True,
            sharey=False,
        )

        max_goodput = measurement.theoretical_max_value
        assert max_goodput
        max_goodput = max_goodput * DataRate.KBPS
        # then we add the densities kdeplots for each month
        g.map(
            sns.kdeplot,
            self.meas_prop_key,
            bw_adjust=1,
            clip_on=False,
            fill=True,
            alpha=1,
            linewidth=1.5,
            clip=(0, max_goodput),
            # there may be some lines without entries.
            # kde estimation will complain about 0 variance.
            # we can ignore this error.
            # warn_singular=False,
        )

        # # here we add a white line that represents the contour of each kdeplot
        g.map(sns.kdeplot, "value", bw_adjust=1, clip_on=False, color="w", lw=1)

        # here we add a horizontal line for each plot
        g.map(plt.axhline, y=0, lw=2, clip_on=False)

        # we loop over the FacetGrid figure axes (g.axes.flat) and add the month as text with the right color
        # notice how ax.lines[-1].get_color() enables you to access the last line's color in each matplotlib.Axes
        for ax, impl_name in zip(g.axes.flat, df[dimension].unique()):
            ax.text(
                0.01 if measurement.abbr == "G" else 0.99,
                0.2,
                impl_name,
                horizontalalignment="left" if measurement.abbr == "G" else "right",
                verticalalignment="bottom",
                color=ax.lines[-1].get_color(),
                transform=ax.transAxes,
                # bbox=dict(facecolor="white", alpha=0.75),
            )
            # label.set_rotation(0)
            ax.set_xlim(xmin=0, xmax=max_goodput)

        g.axes.flat[-1].xaxis.set_major_formatter(self.format_value)
        g.axes.flat[-1].set_xlabel("Goodput")

        # add additional efficiency axis
        # add a second x-axis to last subplot
        x_axis_eff = g.axes.flat[-1].twiny()
        # force position = bottom
        x_axis_eff.xaxis.set_ticks_position("bottom")
        x_axis_eff.xaxis.set_label_position("bottom")
        # set 0% 100% as limits
        x_axis_eff.set_xlim(xmin=0, xmax=1)
        # add 6 ticks
        x_axis_eff.set_xticks(np.arange(0, 1.2, 0.2))
        # use percentage formatter
        x_axis_eff.xaxis.set_major_formatter(self.format_percentage)
        # increase distance between frame and axis
        x_axis_eff.spines["bottom"].set_position(("axes", -0.8))
        # ???
        x_axis_eff.spines["bottom"].set_visible(True)
        # set label and hide title
        x_axis_eff.set_xlabel("Efficiency")
        x_axis_eff.set_title("")
        # increase shown area of plot at bottom so that additional axis is visible
        g.fig.subplots_adjust(bottom=0.1)

        # we use matplotlib.Figure.subplots_adjust() function to get the subplots to overlap
        g.fig.subplots_adjust(hspace=-0.1)

        # eventually we remove axes titles, yticks and spines
        g.set_titles("")
        g.set(yticks=[])
        g.despine(bottom=True, left=True)
        g.set(ylabel="")

        # plt.setp(ax.get_xticklabels(), fontsize=15, fontweight="bold")
        g.fig.suptitle(
            f"KDEs of {dimension.title()}s in Measurement {measurement.name.title()}"
        )

        g.fig.subplots_adjust(right=0.9)

        self._save(
            g.fig,
            f"kdes-marginalized-by-{dimension}-{measurement.abbr}",
            tight=False,
        )

    def plot_ccas(self):
        self.set_theme()

        meas1, meas2, *_ = self.measurements
        print(f"Using {meas1.name} and {meas2.name}")

        df = self.get_dataframe()
        # calculate mean values for efficiencies / values per server-client-measurement triple
        # could also use avg_efficiency / avg_value
        df = (
            df[["server", "client", "measurement", "efficiency"]]
            .groupby(["server", "client", "measurement"])
            .mean("efficiency")
            .reset_index()
        )
        # drop client columns which is now unnecessary
        del df["client"]
        # filter by measurement
        df_meas1 = df[df["measurement"] == meas1.name].reset_index()
        df_meas2 = df[df["measurement"] == meas2.name].reset_index()
        # remove measurement column, which is now unnecessary
        del df_meas1["measurement"]
        del df_meas2["measurement"]
        del df_meas1["index"]
        del df_meas2["index"]
        # rename efficiency column
        if self.tex_mode:
            eff_lbl_1 = f"Efficiency in {meas_tex_format(meas1)}"
            eff_lbl_2 = f"Efficiency in {meas_tex_format(meas2)}"
            cca_lbl = r"Server \acs{CCA}"
        else:
            eff_lbl_1 = f"Efficiency in {meas1.name}"
            eff_lbl_2 = f"Efficiency in {meas2.name}"
            cca_lbl = "Server CCA"
        df_meas1.rename(columns={"efficiency": eff_lbl_1}, inplace=True)
        df_meas2.rename(columns={"efficiency": eff_lbl_2}, inplace=True)

        # map server names to congestion controls
        def get_cca_from_server_name(server_name: str) -> str:
            data = IMPL_CCAS[server_name]
            if "cca" in data:
                return data["cca"]
            else:
                return "unknown"

        ccas = (
            df_meas1["server"]
            .map(get_cca_from_server_name)
            .astype(CAT_CCA_ORDER)
            .to_frame(name=cca_lbl)
        )
        print(ccas[cca_lbl].value_counts())

        # join the dataframes
        df = pd.concat([ccas, df_meas1[eff_lbl_1], df_meas2[eff_lbl_2]], axis=1)

        # sort by cca:
        df.sort_values(by=cca_lbl, inplace=True)

        # plot
        with Subplot() as (fig, ax):
            assert isinstance(ax, plt.Axes)

            ax.set_xlim(xmin=0, xmax=1)
            ax.set_ylim(ymin=0, ymax=1)
            ax.set_aspect("equal")

            ax = sns.scatterplot(
                data=df,
                x=eff_lbl_1,
                y=eff_lbl_2,
                hue=cca_lbl,
                legend="full",
                palette=CCA_PALETTE,
                ax=ax,
            )

            # ax.xaxis.label.set_text(ax.xaxis.label.get_text() + r" in \si{\percent}")
            # ax.yaxis.label.set_text(ax.yaxis.label.get_text() + r" in \si{\percent}")

            ax.xaxis.set_major_formatter(self.format_percentage)
            # rotate labels at the bottom
            for label in ax.get_xticklabels():
                label.set_rotation(90)

            ax.yaxis.set_major_formatter(self.format_percentage)

            # despine
            # ax.spines["top"].set_visible(False)
            # ax.spines["right"].set_visible(False)
            # ax.spines["bottom"].set_visible(False)
            # ax.spines["left"].set_visible(False)

            self._save(fig, f"cca-plot-{meas1.abbr}-{meas2.abbr}")

    def print_analyze(self):
        df = self.get_dataframe(include_failed=True)[
            ["server", "client", "measurement", "value", "efficiency"]
        ]

        columns_cfg = ["l"]
        first_row = [""]
        cols = {}
        perc_failed_row = ["failed"]
        for i, measurement in enumerate(self.measurements):
            multi_col_cfg = "c" if i == len(self.measurements) - 1 else "c|"
            columns_cfg.extend(
                (
                    "            S[table-format=2.2]",
                    "            r",
                )
            )
            first_row.append(
                fr"\multicolumn{{2}}{{{multi_col_cfg}}}{{\{measurement.abbr.lower()}/}}"
            )
            df_for_meas = df[df.measurement == measurement.name]
            cols[measurement.abbr] = {
                "val_stats": Statistics.calc(df_for_meas["value"]),
                "eff_stats": Statistics.calc(df_for_meas["efficiency"]),
            }
            mins = df_for_meas.groupby(["server", "client"]).min().reset_index()
            perc_failed = (mins.value == 0).sum() * 100 / len(mins)
            perc_failed_row.append(
                fr"\multicolumn{{2}}{{{multi_col_cfg}}}{{{perc_failed:.1f}\,\%}}"
            )

        rows = []
        for label, key in (
            ("mean", "avg"),
            ("median", "med"),
            (r"std.\ dev.", "std"),
            ("maximum", "max"),
        ):
            row = [label]
            for measurement in self.measurements:
                val_stat = getattr(cols[measurement.abbr]["val_stats"], key)
                eff_stat = getattr(cols[measurement.abbr]["eff_stats"], key)

                row.extend(
                    (
                        f"{val_stat / DataRate.MBPS:.3g}",
                        fr"{eff_stat * 100:.1f}\,\%",
                    )
                )
            rows.append(row)

        columns_cfg_str = "|\n".join(columns_cfg)
        max_first_row = max(map(len, first_row))
        max_last_row = max(map(len, perc_failed_row))
        max_col_len = max(max(map(len, row)) for row in rows)
        first_row_str = " & ".join(col.ljust(max_first_row) for col in first_row)
        latex_table = fr"""
\begin{{tabular}}{{%
            {columns_cfg_str}
        }}
        \toprule
        {first_row_str.lstrip()} \\
        \midrule
"""
        for row in rows:
            row_str = " & ".join(col.ljust(max_col_len) for col in row)
            latex_table += fr"        {row_str} \\" + "\n"

        perc_failed_str = " & ".join(col.ljust(max_last_row) for col in perc_failed_row)
        latex_table += rf"""
        \midrule
        {perc_failed_str.lstrip()} \\
        \bottomrule
    \end{{tabular}}
"""

        assert self._spinner
        with self._spinner.hidden():
            print(latex_table.strip())

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
                for meas_abbr in self.meas_abbrs:
                    self.plot_heatmap(meas_abbr)
                if self.test_abbrs:
                    self.plot_test_case_heatmap()
            elif self.plot_type == PlotType.RIDGELINE:
                for meas_abbr in self.meas_abbrs:
                    self.plot_ridgeline("server", meas_abbr)
                    spinner.text = "Plotting..."
                    self.plot_ridgeline("client", meas_abbr)
            elif self.plot_type == PlotType.ANALYZE:
                self.print_analyze()
            elif self.plot_type == PlotType.SWARM:
                self.plot_swarmplot()
            elif self.plot_type == PlotType.CCAS:
                self.plot_ccas()
            elif self.plot_type == PlotType.VIOLINS:
                for meas_abbr in self.meas_abbrs:
                    self.plot_violins(meas_abbr)
            else:
                assert False, f"Invalid plot type {self.plot_type}"

            self._spinner.ok("✔")

    def _save(
        self,
        figure: plt.Figure,
        output_file_base_name: str,
        tight: bool = True,
        transparent: bool = False,
    ):
        """Save or show the plot."""

        output_file = self.img_path / f"{output_file_base_name}.{self.img_format}"
        assert self._spinner
        kwargs: dict[str, Any] = {
            "dpi": 300,
        }
        if tight:
            kwargs["bbox_inches"] = "tight"
        if transparent:
            kwargs["transparent"] = True
        figure.savefig(
            output_file,
            **kwargs,
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
        meas_abbrs=args.measurements,
        test_abbrs=args.tests,
        results=args.results,
        plot_type=args.plot_type,
        efficiency=args.prop == "efficiency",
        debug=args.debug,
        img_path=args.img_path,
        img_format=args.img_format,
        no_interactive=args.no_interactive,
    )
    cli.run()


if __name__ == "__main__":
    main()
