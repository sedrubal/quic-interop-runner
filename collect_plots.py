#!/usr/bin/env python3

import shutil
import sys
from argparse import ArgumentParser
from enum import Enum
from pathlib import Path
import logging

from termcolor import colored, cprint

from plot_diagram import PlotMode
from result_parser import Result
from utils import create_relpath, LOGGER


class CollectMode(Enum):
    SYMLINK = "symlink"
    COPY = "copy"


def parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        "--clean", action="store_true", help="Clean collect dir before."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Update existing files.",
    )
    parser.add_argument(
        "results",
        nargs="+",
        type=Result,
        help="The result files to use.",
    )
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
        "-o",
        "--collect-dir",
        type=Path,
        help="The directory to collect the images.",
    )
    parser.add_argument(
        "-t",
        "--test",
        "-m",
        "--measurement",
        dest="meas_abbr",
        nargs="*",
        help="The measurements to use.",
    )

    return parser.parse_args()


def collect_plots(
    results: list[Result],
    meas_abbrs: list[str],
    collect_dir: Path,
    collect_mode: CollectMode,
    plot_modes: list[PlotMode],
    force=False,
    clean=False,
):
    if clean:
        shutil.rmtree(collect_dir, ignore_errors=True)

    collect_dir.mkdir(parents=True, exist_ok=True)

    for result in results:
        result.load_from_json()
        LOGGER.info("Using %s", result)
        for meas_abbr in meas_abbrs:
            LOGGER.info("Using %s", meas_abbr)
            for meas in result.get_all_measurements_of_type(meas_abbr, succeeding=True):
                LOGGER.info("Found result for %s", meas.combination)
                files = [
                    meas.log_dir_for_test.path / f"time_{mode.value}_plot.png"
                    for mode in plot_modes
                ]

                for png in files:
                    LOGGER.info("Searching for %s", png)
                    if not png.is_file():
                        LOGGER.error(f"Plot %s does not exist.", png)

                        continue

                    target = collect_dir / f"{meas.combination}_{png.name}"

                    if target.is_file():
                        if force:
                            target.unlink()
                        else:
                            sys.exit(
                                colored(
                                    f"{target} already exists. Use --force.",
                                    color="red",
                                )
                            )

                    if collect_mode == CollectMode.SYMLINK:
                        LOGGER.info("Symlinking %s -> %s", target, png)
                        target.symlink_to(png)
                    elif collect_mode == CollectMode.COPY:
                        LOGGER.info("Copying %s -> %s", png, target)
                        shutil.copy(png, target)


def main():
    args = parse_args()
    collect_plots(
        results=args.results,
        meas_abbrs=args.measurements,
        collect_dir=args.collect_dir,
        collect_mode=args.collect_mode,
        plot_modes=args.plot_mode,
        force=args.force,
        clean=args.clean,
    )


if __name__ == "__main__":
    main()
