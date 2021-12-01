#!/usr/bin/env python3

import argparse
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from termcolor import colored

from enums import CacheMode, PlotMode, Side
from plot_diagram import DEFAULT_TITLES, PlotCli
from result_parser import MeasurementResultInfo, Result
from trace_analyzer2 import ParsingError
from utils import LOGGER, TraceTriple, create_relpath, existing_file_path

DEFAULT_TITLE = "{mode_default_title} ({test_abbr}, server: {server}, client: {client})"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "results",
        nargs="+",
        type=existing_file_path,
        help="quic-interop-runner result.json files.",
    )
    parser.add_argument(
        "--only-sat",
        action="store_true",
        help="Plot only for for SAT testcase.",
    )
    parser.add_argument(
        "--include-failed",
        action="store_true",
        help="Plot also failed test cases.",
    )
    parser.add_argument(
        "-t",
        "--title",
        action="store",
        default=DEFAULT_TITLE,
        help=(
            f"The title for the diagram (default='{DEFAULT_TITLE}'). "
            "WATCH OUT! THIS TTILE WILL BE FORMATTED → WE TRUST THE FORMAT STRING!"
        ),
    )
    parser.add_argument(
        "--no-annotation",
        action="store_true",
        help="Hide TTFB, PLT, ... markers.",
    )
    parser.add_argument(
        "--format",
        action="store",
        default="png",
        choices=("svg", "png", "pdf"),
        help="The file format to plot.",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force overwriting existing plot.",
    )
    parser.add_argument(
        "--mode",
        action="store",
        choices=PlotMode,
        nargs="+",
        type=PlotMode,
        default=list(PlotMode),
        help="The mode of plotting (time vs. packet-number or time vs. file-size or both)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode.",
    )
    parser.add_argument(
        "-j",
        "--workers",
        action="store",
        type=int,
        default=1,
        help="Number of workers for plotting. NOTE: >1 breaks output",
    )

    return parser.parse_args()


def plot_in_meas_run_dir(
    measurement_result: MeasurementResultInfo,
    modes: list[PlotMode],
    current_log_dir: Path,
    include_failed: bool,
    annotate: bool,
    interruptable_logging: bool,
    output_format: str,
    title: str,
    force: bool,
) -> tuple[str, str, list[str]]:
    """Generate plot for for this test case."""
    test_case_dir = measurement_result.log_dir_for_test.path

    ret = (
        measurement_result.combination,
        measurement_result.test.abbr,
        list[str](),
    )

    if not measurement_result.succeeded and not include_failed:
        LOGGER.info(
            "✔ Measurement %s Failed. Skipping. Use --include-failed to include it anyway.",
            measurement_result.log_dir_for_test.path.relative_to(current_log_dir),
        )
        ret[2].append("testacse failed")
        return ret

    trace_triples = list[TraceTriple]()

    for repetition_dir in measurement_result.repetition_log_dirs:
        base_sim_path = repetition_dir / "sim"
        trace_triple = TraceTriple(
            left_pcap_path=(
                base_sim_path / f"trace_node_{Side.LEFT.value}_with_secrets.pcapng"
            ).resolve(),
            right_pcap_path=(
                base_sim_path / f"trace_node_{Side.RIGHT.value}_with_secrets.pcapng"
            ).resolve(),
        )

        if not trace_triple.left_pcap_path.is_file():
            LOGGER.error(
                "⨯ %s does not exist",
                trace_triple.left_pcap_path,
            )

            continue

        if not trace_triple.right_pcap_path.is_file():
            LOGGER.error(
                "⨯ %s does not exist",
                trace_triple.right_pcap_path,
            )

            continue

        trace_triples.append(trace_triple)

    if not trace_triples:
        LOGGER.error(
            "⨯ no pcapng files found for %s. Skipping...",
            test_case_dir,
        )

        ret[2].append("no trace files found")
        return ret

    cli = PlotCli(
        trace_triples=trace_triples,
        annotate=annotate,
        cache=CacheMode.LOAD,
        # enable debug mode with interruptable terminal logging when we use more than 1 worker
        # debug=debug or self.max_workers > 1,
        debug=interruptable_logging,
    )

    for mode in modes:
        output_file = test_case_dir / f"time_{mode.value}_plot.{output_format}"
        err_output_file = test_case_dir / f".time_{mode.value}_plot_error.txt"

        if not force:
            if output_file.is_file():
                LOGGER.debug(
                    "✔ %s already exists. Skipping. Use --force to overwrite.",
                    output_file.relative_to(current_log_dir),
                )

                ret[2].append("already exists")

                continue
            elif err_output_file.is_file():
                with err_output_file.open("r") as file:
                    err_msg = file.read().strip()

                broken_pcap: Optional[str] = None
                try:
                    broken_pcap, err_msg = err_msg.splitlines()
                except ValueError:
                    LOGGER.error(
                        "Error message %s has invalid format.",
                        err_output_file,
                    )

                LOGGER.error(
                    "⨯ Trace could not be plotted in previous run. %s exists: ",
                    err_output_file,
                )
                if broken_pcap:
                    LOGGER.error(broken_pcap)
                LOGGER.error(err_msg)
                LOGGER.error(
                    "Skipping. Use --force to overwrite.",
                )

                ret[2].append(err_msg)

                continue

        LOGGER.info(
            "⚒ Plotting in %s (%d trace pairs) → %s",
            create_relpath(test_case_dir),
            len(trace_triples),
            create_relpath(output_file),
        )
        cli.set_params(
            title=title.format(
                combination=measurement_result.combination,
                client=measurement_result.client.name,
                server=measurement_result.server.name,
                mode_default_title=DEFAULT_TITLES[mode],
                test_abbr=measurement_result.test.abbr,
                test_name=measurement_result.test.name,
                test_desc=measurement_result.test.desc,
            ),
            mode=mode,
            output_file=output_file,
        )
        try:
            cli.run()
        except ParsingError as err:
            LOGGER.error(
                "⨯ Could not parse %s in %s. Skipping...",
                err.trace,
                test_case_dir,
            )
            LOGGER.error("⨯ %s", err)

            with err_output_file.open("w") as file:
                print(
                    f"{err.trace.input_file}:\n",
                    err.msg,
                    file=file,
                )

            ret[2].append(err.msg)

            continue

    return ret


class PlotAllCli:
    def __init__(
        self,
        #  log_dirs: list[Path],
        result_files: list[Path],
        title: str,
        annotate: bool,
        output_format: str,
        force=False,
        only_sat=False,
        include_failed=False,
        modes: list[PlotMode] = list(PlotMode),
        debug=False,
        max_workers: int = 1,
    ):
        #  self.log_dirs = log_dirs
        self.result_files = result_files
        self.only_sat = only_sat
        self.title = title
        self.annotate = annotate
        self.output_format = output_format
        self.force = force
        self.include_failed = include_failed
        self.modes = modes
        self.debug = debug
        self.max_workers = max_workers
        if max_workers > 1 and debug:
            sys.exit("Debug and max_workers > 1 is not advised")

    def plot_in_log_dir(self, result: Result):
        """Generate plots for result file."""
        LOGGER.info(
            "⚒ Plotting results %s (log dir: %s)",
            result,
            result.log_dir,
        )

        plot_results = defaultdict[str, set[str]](set[str])

        executor_factory = (
            ThreadPoolExecutor
            if self.debug or self.max_workers == 1
            else ProcessPoolExecutor
        )

        with executor_factory(max_workers=self.max_workers) as executor:
            futures = []
            for tmp1 in result.measurement_results.values():
                for tmp2 in tmp1.values():
                    measurement_results = list[MeasurementResultInfo]()

                    if self.only_sat:
                        measurement_results = [tmp2["SAT"]]
                    else:
                        measurement_results = list(tmp2.values())

                    for measurement_result in measurement_results:
                        future = executor.submit(
                            plot_in_meas_run_dir,
                            measurement_result,
                            self.modes,
                            result.log_dir.path,
                            self.include_failed,
                            self.annotate,
                            self.debug or self.max_workers > 1,
                            self.output_format,
                            self.title,
                            self.force,
                        )
                        futures.append(future)

            for future in futures:
                combi, test_abbr, results = future.result()

                for plot_result in results:
                    if plot_result == "already_exists":
                        plot_result = colored(plot_result, color="green")
                    plot_results[plot_result].add(f"{combi}-{test_abbr}")

                if not results:
                    plot_results[colored("success", color="green")].add(
                        f"{combi}-{test_abbr}"
                    )

        # Print a summary.
        print()
        print("#### Results:")
        print()

        for msg, combinations in plot_results.items():
            print(f"- {msg}: {len(combinations)}")

            for combination in combinations:
                print(f"  - `{combination}`")

        print()

    def run(self):
        for result_file in self.result_files:
            result = Result(result_file)
            result.load_from_json()
            self.plot_in_log_dir(result)


def main():
    args = parse_args()
    cli = PlotAllCli(
        #  log_dirs=args.log_dirs,
        result_files=args.results,
        only_sat=args.only_sat,
        title=args.title,
        annotate=not args.no_annotation,
        output_format=args.format,
        force=args.force,
        include_failed=args.include_failed,
        modes=args.mode,
        debug=args.debug,
        max_workers=args.workers,
    )
    try:
        cli.run()
    except KeyboardInterrupt:
        sys.exit("\nQuit")

    LOGGER.info("✔ Done")


if __name__ == "__main__":
    main()
