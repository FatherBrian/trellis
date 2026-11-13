"""The README's "Your own server" guide, step by step: two small files, three commands.

If this fails, the guide is wrong. Fix the guide and this test together.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from mcp.shared.exceptions import MCPError

from reef.agent import AgentClient
from reef.cli import main
from reef.config import load_reef_config
from reef.gateway import Reef
from reef.samples import hr_server
from reef.server import ReefServer
from reef.stack import secret_verifier
from trellisd.app import Trellis
from trellisd.config import load_config

GUIDE = Path(__file__).resolve().parents[1] / "examples" / "your-own-server"
SECRET = "local-hr-secret"


def test_the_guide_works(tmp_path: Path) -> None:
    db = f"sqlite:///{tmp_path / 'trellis.db'}"

    # Step 2: reef grant, with only the guide's two files.
    res = CliRunner().invoke(
        main,
        [
            "grant",
            "--config",
            str(GUIDE / "reef.yaml"),
            "--trellis",
            str(GUIDE / "trellis.yaml"),
            "--db",
            db,
            "--person",
            "me@example.com",
            "--agent",
            "my-bot",
            "--task",
            "Headcount check",
            "--scope",
            "hr",
            "--json",
        ],
        catch_exceptions=False,
    )
    assert res.exit_code == 0, res.output
    token = json.loads(res.output)["token"]

    # Step 3: reef serve in front of the server, then the agent calls through it.
    rc = load_reef_config(GUIDE / "reef.yaml")
    config = rc.apply_to(load_config(GUIDE / "trellis.yaml"))
    with hr_server(secret_verifier(SECRET, "reef")) as hr:
        rc = rc.model_copy(
            update={"servers": {"hr": rc.servers["hr"].model_copy(update={"url": hr.url})}}
        )
        with (
            Trellis(config, db) as trellis,
            ReefServer(Reef(trellis, rc, environ={"REEF_HR_TOKEN": SECRET})) as door,
        ):
            agent = AgentClient(door.url, token)
            assert sorted(t.name for t in agent.list_tools()) == ["hr_headcount", "hr_payroll"]
            result = agent.call("hr_payroll", {})
            rows = json.loads(result.content[0].text)["rows"]  # type: ignore[union-attr]
            assert rows
            assert {r["salary"] for r in rows} == {"***"}  # pii, and my-bot's ceiling has no pii
            assert all(r["employee"] != "***" for r in rows)


def test_without_a_grant_the_door_stays_shut() -> None:
    rc = load_reef_config(GUIDE / "reef.yaml")
    config = rc.apply_to(load_config(GUIDE / "trellis.yaml"))
    with (
        Trellis(config, "sqlite:///:memory:") as trellis,
        ReefServer(Reef(trellis, rc, environ={"REEF_HR_TOKEN": SECRET})) as door,
        pytest.raises(MCPError, match="unknown token"),
    ):
        AgentClient(door.url, "not-a-grant").list_tools()
