#!/usr/bin/env python3

import shutil
import sys
from argparse import ArgumentParser
from pathlib import Path
from enum import Enum

from termcolor import colored, cprint

from plot_diagram import PlotMode
from result_parser import Result
from utils import create_relpath


class CollectMode(Enum):
    SYMLINK = "symlink"
    COPY = "copy"


def parse_args():
    """docstring for parse_args"""
    parser = ArgumentParser()
    parser.add_argument(
        "--clean", action="store_true", help="Clean collect dir before."
    )
    parser.add_argument("--force", action="store_true", help="Update existing files.")
    parser.add_argument("result", type=Result, help="The result file to use.")
    parser.add_argument(
        "--collect-mode",
        action="store",
        choices=CollectMode,
        type=CollectMode,
        default=CollectMode.SYMLINK,
        help="Symlink (default) or copy files.",
    )
    parser.add_argument(
        "--plot-mode",
        action="store",
        choices=PlotMode,
        nargs="+",
        type=PlotMode,
        default=[mode for mode in PlotMode],
        help="The mode of plotting to collect",
    )
    parser.add_argument(
        "collect_dir", type=Path, help="The directory to collect the images."
    )

    return parser.parse_args()


def collect_plots(
    result: Result,
    collect_dir: Path,
    collect_mode: CollectMode,
    plot_modes: list[PlotMode],
    force=False,
    clean=False,
):
    if clean:
        shutil.rmtree(collect_dir, ignore_errors=True)

    collect_dir.mkdir(parents=True, exist_ok=True)

    for meas in result.get_all_measuements_of_type("SAT", succeeding=True):
        files = [
            meas.log_dir_for_test.path / f"time_{mode.value}_plot.png"
            for mode in plot_modes
        ]

        for png in files:
            if not png.is_file():
                cprint(f"Plot {png} does not exist.", color="red")

                continue

            target = collect_dir / f"{meas.combination}_{png.name}"

            if target.is_file():
                if force:
                    target.unlink()
                else:
                    sys.exit(
                        colored(f"{target} already exists. Use --force.", color="red")
                    )

            if collect_mode == CollectMode.SYMLINK:
                cprint(f"Symlinking {target} -> {create_relpath(png)}", color="green")
                target.symlink_to(png)
            elif collect_mode == CollectMode.COPY:
                cprint(f"Copying {create_relpath(png)} -> {target}", color="green")
                shutil.copy(png, target)


def main():
    args = parse_args()
    collect_plots(
        result=args.result,
        collect_dir=args.collect_dir,
        collect_mode=args.collect_mode,
        plot_modes=args.plot_mode,
        force=args.force,
        clean=args.clean,
    )


if __name__ == "__main__":
    main()
