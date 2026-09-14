"""`python -m fazerops.actions.growth` — argument handling that must fail as a usage error.

A timestamp with no offset is refused everywhere one enters (`ledger.normalize.parse_timestamp`),
and the CLI is no exception: it is rejected by argparse, before any job runs, rather than reaching
`TimeWindow` and ending the process in a pydantic traceback.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from fazerops.actions.growth import job as job_module
from fazerops.actions.growth.__main__ import main


@pytest.mark.parametrize("option", ["--since", "--until"])
def test_a_timestamp_without_a_timezone_is_a_usage_error(tmp_path, option, capsys):
    with pytest.raises(SystemExit) as exited:
        main(["--state-dir", str(tmp_path), "mine", "--no-collect", option, "2026-09-01"])

    assert exited.value.code == 2
    assert "has no timezone" in capsys.readouterr().err


def test_a_timestamp_with_an_offset_reaches_the_job_in_utc(tmp_path, monkeypatch):
    windows = []

    async def once(state_dir, window, **kwargs):
        windows.append(window)
        return 0, []

    monkeypatch.setattr(job_module, "mine_once", once)
    argv = ["--since", "2026-09-01T00:00:00+02:00", "--until", "2026-09-02T00:00:00Z"]
    assert main(["--state-dir", str(tmp_path), "mine", "--no-collect", *argv]) == 0

    [window] = windows
    assert window.start == datetime(2026, 8, 31, 22, 0, tzinfo=UTC)
    assert window.end == datetime(2026, 9, 2, 0, 0, tzinfo=UTC)
