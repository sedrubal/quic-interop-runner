#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Optional
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import UUIDType

from enums import TestResult
from result_parser import MeasurementResultInfo, Result, TestResultInfo
from utils import LOGGER, CONSOLE_LOG_HANDLER

Base = declarative_base()


ANALYZE_LAST_N_LINES = 100


class Reason(Enum):
    NO_OUTPUT_FILE = "no output file"
    CUT_SHORT_PCAP = ("pcap appears to have been cut short in the middle of a packet",)
    TSHARK_CRASHED = "TShark seems to have crashed"
    TIMEOUT = "timeout"
    NO_KEYLOG_FILE = "no key log file"
    WRONG_VERSION = "wrong version"
    MISSING_FILES = "downloaded files missing"
    FILE_SIZE_MISSMATCH = "downloaded file size missmatch"
    NUM_CLIENT_HELLO_MISSMATCH = "amount of client hellos missmatch"
    CONTAINER_EXITED = "container exited"
    KNOWN_QUICLY_ISSUE = "known quicly issue"
    SERVER_TIMEOUT = "timeout while waiting for server"


LINE_REASON_MAPPING = {
    re.compile(r".*Test failed: took longer than.*"): Reason.TIMEOUT,
    re.compile(r".*No key log file found.*"): Reason.NO_KEYLOG_FILE,
    re.compile(r".*Wrong version\..*"): Reason.WRONG_VERSION,
    re.compile(r".*Missing files.*"): Reason.MISSING_FILES,
    re.compile(r".*File size of .* doesn't match.*"): Reason.FILE_SIZE_MISSMATCH,
    re.compile(
        r".*Expected at least .* ClientHellos. Got:.*"
    ): Reason.NUM_CLIENT_HELLO_MISSMATCH,
    re.compile(r".*Aborting on container exit.*"): Reason.CONTAINER_EXITED,
    re.compile(
        r".*Illegal instruction\s+\(core dumped\) \/quicly\/cli.*"
    ): Reason.KNOWN_QUICLY_ISSUE,
    re.compile(
        r".*appears to have been cut short in the middle of a packet.*"
    ): Reason.CUT_SHORT_PCAP,
    re.compile(
        r".*TShark seems to have crashed \(retcode: 2\).*"
    ): Reason.CUT_SHORT_PCAP,
    re.compile(
        r".*TShark seems to have crashed \(retcode: ([^2]|\d\d+)\).*"
    ): Reason.TSHARK_CRASHED,
    re.compile(
        r".*timeout occurred after waiting [\d\.]+s for server.*"
    ): Reason.SERVER_TIMEOUT,
}


class TestRun(Base):
    __tablename__ = "test"
    id = sa.Column(UUIDType(binary=False), primary_key=True)
    host = sa.Column(sa.String(512), nullable=True)
    path = sa.Column(sa.String(512), nullable=False)
    start_time = sa.Column(sa.DateTime, nullable=True)
    end_time = sa.Column(sa.DateTime, nullable=True)


class TestCaseRun(Base):
    __tablename__ = "testcase"
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    run = sa.Column(UUIDType(binary=False), sa.ForeignKey(TestRun.id), nullable=False)
    test_abbr = sa.Column(sa.String(255), nullable=False)
    client = sa.Column(sa.String(255), nullable=False)
    server = sa.Column(sa.String(255), nullable=False)
    result = sa.Column(sa.Enum(TestResult))
    reason = sa.Column(sa.Enum(Reason), nullable=True)
    path = sa.Column(sa.String(512))


class MeasurementRun(Base):
    __tablename__ = "measurement"
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    run = sa.Column(UUIDType(binary=False), sa.ForeignKey(TestRun.id), nullable=False)
    test_abbr = sa.Column(sa.String(255), nullable=False)
    client = sa.Column(sa.String(255), nullable=False)
    server = sa.Column(sa.String(255), nullable=False)
    result = sa.Column(sa.Enum(TestResult))
    reason = sa.Column(sa.Enum(Reason), nullable=True)
    planned_repetitions = sa.Column(sa.Integer)
    avg = sa.Column(sa.Integer)
    stdev = sa.Column(sa.Float)


class MeasurementRepetitionRun(Base):
    __tablename__ = "measurement_repetition"
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    run = sa.Column(sa.Integer, sa.ForeignKey(MeasurementRun.id), nullable=False)
    repetition = sa.Column(sa.SmallInteger, nullable=False)
    value = sa.Column(sa.Integer)
    path = sa.Column(sa.String(512))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "results",
        nargs="+",
        type=Result,
        help="quic-interop-runner result.json files.",
    )
    parser.add_argument(
        "--database",
        type=str,
        default="sqlite:///db.sql",
        help="The database connect URL",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode",
    )
    parser.add_argument(
        "--skip-existing-reasons",
        action="store_true",
        help="Don't update reasons",
    )

    return parser.parse_args()


def get_none_or_first(query_result):
    if query_result.count() not in (0, 1):
        raise AssertionError(
            f"Query '{query_result.statement!s}' returned {query_result.count()} items."
        )

    return query_result.first()


class GatherResults:
    def __init__(
        self,
        results: list[Result],
        dburl: str,
        debug=False,
        skip_existing_reasons=False,
    ):
        self.debug = debug
        self.skip_existing_reasons = skip_existing_reasons
        engine = sa.create_engine(dburl)
        Base.metadata.bind = engine
        session_factory = orm.sessionmaker()
        Session = orm.scoped_session(session_factory)
        self.session = Session(bind=engine)
        Base.metadata.create_all(engine)
        self.results = results
        for result in self.results:
            result.load_from_json()

    def run(self):
        for i, result in enumerate(self.results):
            LOGGER.info("Processing result file %d of %d", i + 1, len(self.results))
            self.process_result(result)

    def get_reason(self, output_file: Path) -> Optional[Reason]:
        """Try to parse the reason, why a test failed."""

        if not output_file.is_file():
            return Reason.NO_OUTPUT_FILE

        with output_file.open("r") as file:
            output = file.read().strip().splitlines()

        for line in output[:-ANALYZE_LAST_N_LINES:-1]:
            for line_pattern, reason in LINE_REASON_MAPPING.items():
                if line_pattern.match(line):
                    return reason

        LOGGER.warning(
            f"Didn't find the reason for the fail of test in file {output_file}"
        )
        LOGGER.debug(
            "Last 10 lines (last %d have been analyzed):", ANALYZE_LAST_N_LINES
        )
        LOGGER.debug("---")

        for line in output[-10:]:
            LOGGER.debug(line)
        LOGGER.debug("---")

        return None

    def insert_test_run(self, result: Result) -> UUID:
        assert result.file_path
        path = str(
            result.file_path.path.absolute()
            if result.file_path.is_path
            else result.file_path
        )
        query_result = self.session.query(TestRun).filter(TestRun.path == path)
        test_run = get_none_or_first(query_result)

        if not test_run:
            test_run = TestRun()

        if result.id and test_run.id:
            assert result.id == test_run.id
        else:
            test_run.id = result.id

        test_run.path = path
        test_run.start_time = result.start_time
        test_run.end_time = result.end_time
        test_run.host = os.uname().nodename

        self.session.add(test_run)
        self.session.commit()

        return test_run.id

    def insert_test_case_run(
        self, test_result: TestResultInfo, test_run_id: UUID
    ) -> int:
        run = get_none_or_first(
            self.session.query(TestCaseRun).filter(
                TestCaseRun.run == test_run_id,
                TestCaseRun.test_abbr == test_result.test.abbr,
                TestCaseRun.server == test_result.server.name,
                TestCaseRun.client == test_result.client.name,
            )
        )

        if not run:
            run = TestCaseRun()

        run.run = test_run_id
        run.test_abbr = test_result.test.abbr
        run.server = test_result.server.name
        run.client = test_result.client.name
        run.result = test_result.result
        run.path = str(test_result.log_dir_for_test.path.absolute())

        if test_result.result == TestResult.FAILED:
            if not run.reason or not self.skip_existing_reasons:
                run.reason = self.get_reason(
                    test_result.log_dir_for_test.path / "output.txt"
                )
        else:
            run.reason = None

        self.session.add(run)
        self.session.commit()

        return run.id

    def insert_measurement_repetition_run(
        self, measurement_id: int, repetition: int, log_dir: Path
    ):
        run = get_none_or_first(
            self.session.query(MeasurementRepetitionRun).filter(
                MeasurementRepetitionRun.run == measurement_id,
                MeasurementRepetitionRun.repetition == repetition,
            )
        )

        if not run:
            run = MeasurementRepetitionRun()

        run.run = measurement_id
        run.repetition = repetition
        #  run.value = ...
        run.path = str(log_dir.absolute())

        self.session.add(run)
        self.session.commit()

        LOGGER.info(f"Inserted/Updated measurement repetition run id {run.id}")

        return run.id

    def insert_measurement_run(self, meas_result: MeasurementResultInfo, test_run_id):
        run = get_none_or_first(
            self.session.query(MeasurementRun).filter(
                MeasurementRun.run == test_run_id,
                MeasurementRun.test_abbr == meas_result.test.abbr,
                MeasurementRun.server == meas_result.server.name,
                MeasurementRun.client == meas_result.client.name,
            )
        )

        if not run:
            run = MeasurementRun()

        run.run = test_run_id
        run.test_abbr = meas_result.test.abbr
        run.server = meas_result.server.name
        run.client = meas_result.client.name
        run.result = meas_result.result
        run.planned_repetitions = meas_result.test.repetitions

        if meas_result.succeeded:
            run.avg = meas_result.avg
            run.stdev = meas_result.stdev

        if meas_result.result == TestResult.FAILED and meas_result.repetition_log_dirs:
            if not run.reason or not self.skip_existing_reasons:
                run.reason = self.get_reason(
                    meas_result.repetition_log_dirs[-1] / "output.txt"
                )
        else:
            run.reason = None

        self.session.add(run)
        self.session.commit()

        # for repetition, log_dir in enumerate(meas_result.repetition_log_dirs):
        #     self.insert_measurement_repetition_run(run.id, repetition, log_dir)

        return run.id

    def process_result(self, result: Result):
        """Gather facts for this result."""
        test_run_id = self.insert_test_run(result)
        assert test_run_id
        LOGGER.info(f"Inserted/Updated test run as id {test_run_id}")

        #  with concurrent.futures.ThreadPoolExecutor() as executor:
        #      test_case_ids = executor.map(
        #          lambda test_result: self.insert_test_case_run(
        #              test_result, test_run_id=test_run_id
        #          ),
        #          result.all_test_results,
        #      )
        #      num_test_case_runs = len(list(test_case_ids))
        #      LOGGER.info(f"Inserted/Updated {num_test_case_runs} test case runs")
        #
        #      measurement_ids = executor.map(
        #          lambda meas_result: self.insert_measurement_run(
        #              meas_result, test_run_id=test_run_id
        #          ),
        #          result.all_measurement_results,
        #      )
        #      num_meas_runs = len(list(measurement_ids))
        #      LOGGER.info(f"Inserted/Updated {num_meas_runs} measurement runs")
        test_case_ids = [
            self.insert_test_case_run(test_result, test_run_id=test_run_id)
            for test_result in result.all_test_results
        ]
        num_test_case_runs = len(test_case_ids)
        LOGGER.info(f"Inserted/Updated {num_test_case_runs} test case runs")

        measurement_ids = [
            self.insert_measurement_run(meas_result, test_run_id=test_run_id)
            for meas_result in result.all_measurement_results
        ]
        num_meas_runs = len(measurement_ids)
        LOGGER.info(f"Inserted/Updated {num_meas_runs} measurement runs")


def main():
    args = parse_args()

    if not args.debug:
        CONSOLE_LOG_HANDLER.setLevel(logging.INFO)

    cli = GatherResults(
        results=args.results,
        dburl=args.database,
        debug=args.debug,
        skip_existing_reasons=args.skip_existing_reasons,
    )
    cli.run()


if __name__ == "__main__":
    main()
