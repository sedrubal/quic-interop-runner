#!/usr/bin/env python3

"""Run sat test for all implementation combinations that support it (that succeeded in a previous run)."""

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Union

from evaluation_tools.result_parser import Result
from implementations import IMPLEMENTATIONS, Role
from interop import InteropRunner
from run import implementations
from testcases import MeasurementSatellite

TEST_ABBR = MeasurementSatellite.abbreviation()
AVAILABLE_COMBINATIONS = {
    f"{server_name}_{client_name}"
    for server_name, server in IMPLEMENTATIONS.items()
    if server["role"] in (Role.BOTH, Role.SERVER)
    for client_name, client in IMPLEMENTATIONS.items()
    if client["role"] in (Role.BOTH, Role.CLIENT)
}


def recursive_chown(
    root: Path, user: Union[str, int, None] = None, group: Union[str, int, None] = None
):
    """Run chown/chgrp recursively on a path."""

    for cur_root, _dirs, files in os.walk(root):
        cur_path = Path(cur_root)
        shutil.chown(cur_path, user=user, group=group)

        for file in files:
            shutil.chown(cur_path / file, user=user, group=group)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="turn on debug logs",
    )
    parser.add_argument(
        "-a",
        "--additional-combinations",
        metavar="COMBI",
        default=set(),
        nargs="+",
        choices=AVAILABLE_COMBINATIONS,
        help="run these implementation combinations (<server>_<client>) in addition to the succeeding",
    )
    parser.add_argument(
        "-l",
        "--log-dir",
        type=Path,
        help="log directory",
        default="",
    )
    parser.add_argument(
        "-f",
        "--save-files",
        action="store_true",
        help="save downloaded files if a test fails",
    )
    parser.add_argument(
        "--skip-compliance-check",
        action="store_true",
        help="Skip compliance check.",
    )
    parser.add_argument(
        "-j",
        "--json",
        type=Path,
        help="output the matrix to file in json format",
    )
    parser.add_argument(
        "last_results",
        type=Result,
        help="output the matrix to file in json format",
    )

    return parser.parse_args()


def find_succeeding(result: Result) -> set[tuple[str, str]]:
    """Find implementation combinations that succeeded before."""
    print(f"Loading results from {result.file_path}")

    combinations_succeeded = set[tuple[str, str]]()

    if TEST_ABBR not in result.tests.keys():
        sys.exit("`SAT` testcase was not executed in this run")

    for measurement_result in result.get_all_measuements_of_type(
        TEST_ABBR, succeeding=True
    ):
        combinations_succeeded.add(
            (measurement_result.server.name, measurement_result.client.name)
        )

    return combinations_succeeded


def run_single(
    server: str,
    client: str,
    output: Path,
    log_dir: Path,
    debug=False,
    save_files=False,
    skip_compliance_check=False,
) -> int:
    """Run measurement for a single combination."""

    combination = f"{server}_{client}"

    with tempfile.TemporaryDirectory(
        prefix=f"log_dir_{combination}_"
    ) as tmp_log_dir_base:
        with tempfile.NamedTemporaryFile(
            prefix=f"results_{combination}_",
            suffix=".json",
            mode="r",
        ) as tmp_results_file:
            tmp_log_dir_path = Path(tmp_log_dir_base) / "logs"

            ret = InteropRunner(
                implementations=implementations,
                servers=[server],
                clients=[client],
                tests=[],
                measurements=[MeasurementSatellite],
                output=tmp_results_file.name,
                debug=debug,
                log_dir=str(tmp_log_dir_path),
                save_files=save_files,
                skip_compliance_check=skip_compliance_check,
            ).run()

            print("copy result files to final destination")
            owner = log_dir.owner()
            group = log_dir.group()
            # 1. merge results json files
            tmp_result = Result(file_path=tmp_results_file.name)

            if output.is_file():
                final_result = Result(output)
                final_result = final_result.merge(
                    tmp_result, file_path=output.absolute(), log_dir=log_dir.absolute()
                )
            else:
                tmp_result.log_dir = log_dir.absolute()
                tmp_result.file_path = output
                final_result = tmp_result

            final_result.save()
            try:
                shutil.chown(final_result.file_path, user=owner, group=group)
            except PermissionError:
                pass

            # 2. move files from log dir
            combi_tmp_log_dir_path = tmp_log_dir_path / combination
            combi_dst_log_dir_path = log_dir / combination

            if combi_tmp_log_dir_path.is_dir():
                shutil.move(combi_tmp_log_dir_path, combi_dst_log_dir_path)
                try:
                    recursive_chown(combi_dst_log_dir_path, user=owner, group=group)
                except PermissionError:
                    pass
            else:
                print(
                    f"Log dir {combi_tmp_log_dir_path} does not exist",
                    file=sys.stderr,
                )
                breakpoint()

    return ret


def main():
    # parse args
    args = get_args()

    # find succeeding combinations from previous run
    combinations_succeeded = find_succeeding(args.last_results)
    print(f"These combinations succeeded for test case {TEST_ABBR}")

    for server, client in combinations_succeeded:
        print(f"- {server}_{client}")

    # omit combinations that already ran according to the output file

    if args.json.is_file():
        print(f"WARNING: Output file {args.json} exists!")
        combinations_already_run = find_succeeding(Result(args.json))
        print(
            f"Will skip {len(combinations_already_run)} combinations that already ran according to {args.json}."
        )
    else:
        combinations_already_run = frozenset()

    combinations_to_run = combinations_succeeded | frozenset(
        args.additional_combinations
    )
    combinations_to_run.difference_update(combinations_already_run)
    print(f"Will run {len(combinations_to_run)} combinations")

    # create output logs directory

    if args.log_dir.is_dir():
        print(f"WARNING: Log dir {args.log_dir} exists!", file=sys.stderr)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    try:
        shutil.chown(
            args.log_dir,
            user=args.log_dir.parent.owner(),
            group=args.log_dir.parent.group(),
        )
    except PermissionError:
        pass

    # run it

    for server, client in combinations_to_run:
        ret = run_single(
            server=server,
            client=client,
            output=args.json,
            log_dir=args.log_dir,
            debug=args.debug,
            save_files=args.save_files,
            skip_compliance_check=args.skip_compliance_check,
        )

        if ret:
            sys.exit(ret)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
