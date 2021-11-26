#!/usr/bin/env python3

import argparse
import sys
from datetime import datetime
from pathlib import Path

import matplotlib.dates as mdates
import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt
from termcolor import colored

from result_parser import MeasurementDescription, Result
from utils import Subplot, natural_data_rate


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "result",
        type=Result,
        help="The result file to use",
    )
    parser.add_argument(
        "--measurement",
        nargs="+",
        type=str,
        default=["AST", "EUT"],
        help="The measurements to use",
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
        "--format",
        type=str,
        default="png",
        help="The format of the image to save",
    )

    return parser.parse_args()


class PlotSatCli:
    def __init__(
        self,
        result: Result,
        measurements: list[str],
        img_path: Path,
        img_format: str,
        # debug: bool = False,
        no_interactive: bool = False,
    ):
        self.result = result
        self._meas_abbrs = measurements
        self.img_path = img_path
        self.img_format = img_format
        # self._colors = Tango()
        self.no_interactive = no_interactive

    @property
    def measurements(self) -> list[MeasurementDescription]:
        """The measurements to use."""

        try:
            return [
                self.result.measurement_descriptions[abbr] for abbr in self._meas_abbrs
            ]
        except KeyError:
            sys.exit(
                f"Unknown measurement in {', '.join(self._meas_abbrs)}. "
                f"Known ones are: {', '.join(sorted(self.result.measurement_descriptions.keys()))}"
            )

    def run(self):
        data = self.collect_data()
        self.plot_data(data)

    def _save(self, figure: plt.Figure, output_file_base_name: str):
        """Save or show the plot."""

        output_file = self.img_path / f"{output_file_base_name}.{self.img_format}"
        # assert self._spinner
        figure.savefig(
            output_file,
            dpi=300,
            #  transparent=True,
            bbox_inches="tight",
        )
        text = colored(f"{output_file} written.", color="green")
        print(text)
        # self._spinner.write(f"✔ {text}")
        if not self.no_interactive:
            # self._spinner.text = "Showing plot"
            print("Showing plot")
            plt.show()

    def plot_data(self, df: pd.DataFrame):
        with Subplot(ncols=2, sharey=True) as (fig, axs):
            assert not isinstance(axs, plt.Axes)
            [ax1, ax2] = axs
            assert isinstance(ax1, plt.Axes)
            assert isinstance(ax2, plt.Axes)

            # ax1.yaxis.tick_right()
            ax1.yaxis.set_major_formatter(lambda val, _pos: natural_data_rate(val))
            ax1.yaxis.set_label_coords(1, y=1)
            ax1.yaxis.label.set_rotation(0)

            fig.suptitle("Measurement Results using Real Satellite Links over Time")

            cmap = sns.color_palette(as_cmap=True)
            color_map = {meas.name: cmap[i] for i, meas in enumerate(self.measurements)}

            for label, color in color_map.items():
                ax1.scatter(
                    x=df[df["Measurement"] == label]["Time"],
                    y=df[df["Measurement"] == label]["Goodput"],
                    facecolors=color,
                    edgecolors="white",
                    linewidth=0.5,
                    label=label,
                )
                ax2.scatter(
                    x=df[df["Measurement"] == label]["Time of Day"],
                    y=df[df["Measurement"] == label]["Goodput"],
                    facecolors=color,
                    edgecolors="white",
                    linewidth=0.5,
                    label=label,
                )

            # ax2.xaxis.set_major_locator(mdates.HourLocator())
            ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
            ax2.set_xlim(xmin=datetime(1970, 1, 1, 0, 0), xmax=datetime(1970, 1, 2))

            ax1.set_title("Time")
            ax2.set_title("Time of Day")

            for label in (*ax1.get_xticklabels(), *ax2.get_xticklabels()):
                label.set_rotation(45)

            lines, labels = fig.axes[-1].get_legend_handles_labels()
            fig.legend(
                lines,
                labels,
                title="Measurement",
                loc="lower center",
                ncol=3,
                bbox_to_anchor=(0.5, -0.2),
            )

            # fig.tight_layout()

            meas_abbrs = "-".join(meas.abbr for meas in self.measurements)
            self._save(
                fig,
                f"real-sat-experiment-results-{meas_abbrs}",
            )

    def collect_data(self) -> pd.DataFrame:
        data = list[tuple[datetime, datetime, float, str]]()

        for meas_desc in self.measurements:
            for meas in self.result.get_all_measurements_of_type(meas_desc.abbr):
                for i, value in enumerate(meas.values):
                    output = meas.repetition_log_dirs[i] / "output.txt"

                    if output.is_file():
                        with output.open("r") as file:
                            first_line = file.readline()
                            date = datetime.fromisoformat(first_line.split(",")[0])
                        time = date.replace(year=1970, month=1, day=1)
                        data.append((date, time, value * 1000, meas.test.name))

        df = pd.DataFrame(
            data,
            columns=["Time", "Time of Day", "Goodput", "Measurement"],
        )

        # if self.use_time:
        #     df["Time"] = pd.to_datetime(df["Time"], format='%H:%M:%S')
        #     df["Time"] = pd.to_timedelta(df["Time"], unit='s')

        return df


def main():
    args = parse_args()

    result = args.result
    result.load_from_json()

    cli = PlotSatCli(
        result=result,
        measurements=args.measurement,
        img_path=args.img_path,
        img_format=args.format,
        no_interactive=args.no_interactive,
    )
    cli.run()


if __name__ == "__main__":
    main()
