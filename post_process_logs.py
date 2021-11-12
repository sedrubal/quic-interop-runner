#!/usr/bin/env python3

"""
Post process interop runner logs.

This contains:
- gather results in a database
- inject secrets
- search and rename qlog files
"""

import argparse
import logging
import os
import pwd
import shutil
import subprocess
import sys
from itertools import chain
from pathlib import Path
from typing import Optional, Union

from termcolor import colored, cprint

from enums import PostProcessingMode, TestResult
from gather_results import GatherResults
from result_parser import Result
from utils import YaspinWrapper

GATHER_RESULT_DB = "sqlite:///{path}/result.sql"


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "spec",
        nargs="+",
        type=Path,
        help="quic-interop-runner log dirs or result.json files",
    )
    parser.add_argument(
        "--mode",
        action="store",
        default=PostProcessingMode.ALL,
        type=PostProcessingMode.from_str,
        help="The mode of post processing.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete plain pcap files after injecting the secrets into pcapng file.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug",
    )

    return parser.parse_args()


class PostProcessor:
    """The post processor."""

    def __init__(
        self,
        specs: list[Union[Path, Result]],
        clean=False,
        debug=False,
        mode=PostProcessingMode.ALL,
    ):
        self.mode = mode
        self.specs = specs
        self.num_injected = 0
        self.num_already_injected = 0
        self.num_no_secret_found = 0
        self.num_inject_failed = 0
        self.num_qlog_moved = 0
        self.num_qlog_already_moved = 0
        self.num_no_qlog_found = 0
        self._max_log_str_len = 0
        self.debug = debug
        self.clean = clean
        self._spinner: Optional[YaspinWrapper] = None

    def find_qlog_test_run_dir(self, test_run_path: Path, side: str) -> Optional[Path]:
        """Find a qlog file in ``test_run_path`` for ``side``."""
        side_root = test_run_path / side
        qlog_dirs = (
            side_root,
            side_root / "qlog",
        )

        qlog_files = list[Path]()

        for qlog_dir in qlog_dirs:
            if not qlog_dir.is_dir():
                continue

            for file in qlog_dir.iterdir():
                if file.is_file() and file.suffix == ".qlog":
                    qlog_files.append(file)

        if len(qlog_files) == 1:
            return qlog_files.pop()
        elif len(qlog_files) == 0:
            return None
        else:
            self.log(
                f"⚒ found more than one qlog file in {side_root}. Ignoring.",
                color="yellow",
            )

            return None

    def find_keylog_files(self, test_case_path: Path) -> list[Path]:
        """Find the keylog file."""
        results = list[Path]()

        for root, _dirs, files in os.walk(test_case_path):
            for file in files:
                if file == "keys.log":
                    results.append(Path(root) / file)

        return results

    def rename_qlogs_in_test_repetition_run_dir(self, test_run_dir: Path):
        """Rename QLOG files in test repetition run dir."""

        for side in ("server", "client"):
            target = test_run_dir / f"{side}.qlog"

            exists = False

            if target.is_symlink():
                if not self.clean:
                    exists = True
            else:
                if self.clean and target.is_file():
                    exists = True

            try:
                if exists and target.stat().st_size > 0:
                    self.log(
                        f"⚒ {target} already exists. Skipping.",
                        color="grey",
                    )
                    self.num_qlog_already_moved += 1

                    continue
            except FileNotFoundError as err:
                # broken symlink
                self.log(
                    f"⚒ Error while checking qlog target: {err}",
                    color="yellow",
                )

            try:
                target.unlink()
            except FileNotFoundError:
                pass

            qlog_file = self.find_qlog_test_run_dir(test_run_dir, side)

            if not qlog_file:
                self.log(
                    f"⨯ no qlog file found in {test_run_dir} for {side}",
                    color="red",
                )
                self.num_no_qlog_found += 1

                continue

            if self.clean:
                shutil.move(qlog_file, target)
            else:
                target.symlink_to(qlog_file.relative_to(target.parent))

            self.num_qlog_moved += 1

            self.log()

    def inject(self, pcap_path: Path, pcap_ng_path: Path, keylog_files: list[Path]):
        """Inject keylog files into pcap."""

        if not pcap_path.is_file():
            self.log(
                f"⨯ Raw pcap file {pcap_path} not found. Skipping.",
                color="red",
            )

            return

        try:
            self.log(
                f"⚒ Injecting {len(keylog_files)} keylog files into {pcap_path} -> {pcap_ng_path}.",
                color="cyan",
            )
            subprocess.check_call(
                [
                    "editcap",
                    *chain(
                        *(
                            ["--inject-secrets", f"tls,{keylog_file}"]
                            for keylog_file in keylog_files
                        ),
                    ),
                    pcap_path,
                    pcap_ng_path,
                ]
            )
            self.num_injected += 1

            if self.clean:
                pcap_path.unlink()
        except subprocess.CalledProcessError:
            self.log(
                f"⨯ Failed to inject {len(keylog_files)} keylog files into {pcap_path}.",
                color="red",
            )
            self.num_inject_failed += 1

            if pcap_ng_path.is_file():
                pcap_ng_path.unlink()

    def inject_secrets_in_test_repetition_run_dir(self, test_run_dir: Path):
        """docstring for inject_secrets_in_test_repetition_run_dir"""

        keylog_files = self.find_keylog_files(test_run_dir)

        for pcap_name in ("left", "right"):
            pcap_root = test_run_dir / "sim"
            stem = f"trace_node_{pcap_name}"
            pcap_path = pcap_root / f"{stem}.pcap"
            pcap_ng_path = pcap_root / f"{stem}_with_secrets.pcapng"

            if pcap_ng_path.is_file() and pcap_ng_path.stat().st_size > 0:
                if self.clean and pcap_path.is_file():
                    pcap_path.unlink()

                self.log(
                    f"⚒ {pcap_ng_path} already exists. Skipping.",
                    color="grey",
                )
                self.num_already_injected += 1

                continue

            if not keylog_files:
                self.log(
                    f"⨯ no keylog file found in {test_run_dir}",
                    color="red",
                )
                self.num_no_secret_found += 1

                continue

            self.inject(
                pcap_path=pcap_path,
                pcap_ng_path=pcap_ng_path,
                keylog_files=keylog_files,
            )

            self.log()

        if self.clean:
            for keylog_file in keylog_files:
                if keylog_file.is_file():
                    keylog_file.unlink()

    def post_process_test_repetition_run_dir(self, test_run_dir: Path):
        """Inject secrets into a test repetition run log_dir."""

        self.fix_chown(test_run_dir)

        if PostProcessingMode.INJECT_SECRETS in self.mode:
            self.inject_secrets_in_test_repetition_run_dir(test_run_dir)

        if PostProcessingMode.RENAME_QLOGS in self.mode:
            self.rename_qlogs_in_test_repetition_run_dir(test_run_dir)

    def fix_chown(self, *pathes: Path):
        """Fix owner of files and directories."""

        if PostProcessingMode.CHOWN in self.mode:
            uid = os.getuid()
            gid = os.getgid()

            def check_owner(path: Path):
                owner = path.owner()
                struct = pwd.getpwnam(owner)

                return struct.pw_uid == uid and struct.pw_gid == gid

            if not all(check_owner(path) for path in pathes):
                pathes_str = " ".join(f"'{path}'" for path in pathes)

                if self._spinner:
                    self._spinner.hide()

                subprocess.run(
                    f"sudo chown -R {uid}:{gid} {pathes_str}", shell=True, check=True
                )

                if self._spinner:
                    self._spinner.show()

    def post_process_result(self, result: Result):
        """Post process in result log dir."""

        result.load_from_json()

        assert result.file_path
        self.fix_chown(result.file_path.path, result.log_dir.path)

        if PostProcessingMode.GATHER_RESULTS in self.mode:
            gather_results_tool = GatherResults(
                debug=self.debug,
                dburl=GATHER_RESULT_DB.format(path=result.log_dir),
                skip_existing_reasons=True,
            )
            gather_results_tool.run([result])

        for test_result in result.all_test_results:
            if test_result.result == TestResult.UNSUPPORTED:
                continue

            self.post_process_test_repetition_run_dir(test_result.log_dir_for_test.path)

        for meas_result in result.all_measurement_results:
            if meas_result.result == TestResult.UNSUPPORTED:
                continue

            for repetition_log_dir in meas_result.repetition_log_dirs:
                self.post_process_test_repetition_run_dir(repetition_log_dir)

    def post_process_log_dir(self, log_dir: Path):
        """Post process inside a log dir."""

        self.fix_chown(log_dir)

        if PostProcessingMode.GATHER_RESULTS in self.mode:
            msg = "Gather mode requires Result specs."

            if self._spinner:
                self._spinner.write(colored(msg, color="red"))
            else:
                cprint(msg, color="red")
            sys.exit(1)

        for combination in log_dir.iterdir():
            if not combination.is_dir():
                continue

            for test_case in combination.iterdir():
                if not test_case.is_dir():
                    continue

                sim_path = test_case / "sim"

                if sim_path.is_dir():
                    # test case
                    self.post_process_test_repetition_run_dir(test_case)
                else:
                    # meas test case -> iterate over test repetitions

                    for repetition_path in test_case.iterdir():
                        if (
                            not repetition_path.is_dir()
                            or not repetition_path.name.isnumeric()
                        ):
                            continue

                        self.post_process_test_repetition_run_dir(repetition_path)

    def log(self, *args, **kwargs):
        """Log a message."""
        msg: Optional[str] = None

        if args or kwargs:
            msg = " ".join(args).ljust(self._max_log_str_len)

        log_str = ", ".join(
            (
                colored("Secrets", color="white", attrs=["bold"]),
                colored(f"inj.: {self.num_injected}", color="green"),
                colored(f"fail: {self.num_inject_failed}", color="red"),
                colored(f"already inj.: {self.num_already_injected}", color="yellow"),
                colored(f"not found: {self.num_no_secret_found}", color="red"),
                colored("QLOGS", color="white", attrs=["bold"]),
                colored(f"renamed: {self.num_qlog_moved}", color="green"),
                colored(f"already ren.: {self.num_qlog_already_moved}", color="yellow"),
                colored(f"not found: {self.num_no_qlog_found}", color="red"),
            )
        )
        self._max_log_str_len = max(self._max_log_str_len, len(log_str))

        if self._spinner:
            if msg:
                self._spinner.write(colored(msg, **kwargs))
            self._spinner.text = log_str
        else:
            if msg:
                cprint(msg, **kwargs, end="\n")
            cprint(f"⚒ {log_str}", attrs=["bold"], end="\r", flush=True)

    def run(self):
        """Run the post processor."""
        self.redirect_log()

        with YaspinWrapper(
            debug=self.debug, text="Post Processing...", color="green"
        ) as spinner:
            self._spinner = spinner

            for spec in self.specs:
                if isinstance(spec, Result):
                    self.post_process_result(spec)
                else:
                    self.post_process_log_dir(spec)

            spinner.ok("✔")

    def redirect_log(self):
        logger = logging.getLogger(name="quic-interop-runner")
        logger.setLevel(logging.DEBUG)

        class SpinnerLogger(logging.Handler):
            def __init__(self, cli: "PostProcessor"):
                super().__init__()
                self.cli = cli

            def emit(self, record: logging.LogRecord):
                color = {
                    logging.DEBUG: "white",
                    logging.INFO: "cyan",
                    logging.WARNING: "yellow",
                    logging.ERROR: "red",
                    logging.CRITICAL: "red",
                }[record.levelno]
                self.cli.log(record.getMessage().strip(), color=color)

        spinner_log_handler = SpinnerLogger(self)
        spinner_log_handler.setLevel(logging.DEBUG)
        logger.addHandler(spinner_log_handler)


def main():
    """Run the post processor as cli."""
    args = parse_args()
    cli = PostProcessor(
        specs=[Result(spec) if spec.is_file() else spec for spec in args.spec],
        clean=args.clean,
        debug=args.debug,
        mode=args.mode,
    )
    cli.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nQuit")
