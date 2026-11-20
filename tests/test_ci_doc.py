"""CI.md against the workflows and the Makefile it describes. Each job's
make targets, the triggers and schedules, the packages and simulator
settings of the test jobs, the artifact the release workflow reuses, and
the action pinning rule are read from the YAML and compared with the
document."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "CI.md").read_text()
WORKFLOWS = ROOT / ".github" / "workflows"
MAKEFILE = (ROOT / "Makefile").read_text()


def _workflow(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def _triggers(workflow: dict) -> dict:
    # YAML 1.1 reads the bare key `on` as the boolean True.
    return workflow.get("on", workflow.get(True))


def _make_targets(job: dict) -> set[str]:
    runs = " ".join(step.get("run", "") for step in job.get("steps", []))
    return set(re.findall(r"\bmake ([a-z][a-z-]*)", runs))


# CI.md's job table names a job by its display name; these are the job ids.
JOB_IDS = {
    "lint": "lint",
    "test (py3.10 to py3.13)": "test",
    "test (py3.12, arm64)": "test-arm64",
    "security": "security",
    "build": "build",
    "ci-ok": "ci-ok",
}


def _job_table() -> dict[str, set[str]]:
    part = DOC.split("## Jobs", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| ([^|]+?) \| ([^|]+?) \|", part, re.MULTILINE)
    return {
        label: set(re.findall(r"`([a-z-]+)`", targets))
        for label, targets in rows
        if label not in ("Job", "-----")
    }


def test_the_job_table_lists_every_job_with_the_targets_it_runs():
    jobs = _workflow("ci.yml")["jobs"]
    table = _job_table()
    assert set(table) == set(JOB_IDS)
    assert set(JOB_IDS.values()) == set(jobs)
    for label, targets in table.items():
        assert _make_targets(jobs[JOB_IDS[label]]) == targets, label


def test_the_test_jobs_run_the_documented_pythons_and_runners():
    jobs = _workflow("ci.yml")["jobs"]
    assert jobs["test"]["strategy"]["matrix"]["python"] == [
        "3.10",
        "3.11",
        "3.12",
        "3.13",
    ]
    arm = jobs["test-arm64"]
    assert arm["runs-on"] == "ubuntu-24.04-arm"
    assert arm["if"] == "${{ !github.event.repository.private }}"
    assert "`ubuntu-24.04-arm` runner. Skipped on a private repository" in DOC


@pytest.mark.parametrize("job_id", ["test", "test-arm64"])
def test_the_test_jobs_install_and_require_what_the_document_says(job_id):
    job = _workflow("ci.yml")["jobs"][job_id]
    runs = " ".join(step.get("run", "") for step in job["steps"])
    for package in ["bubblewrap", "tpm2-tools", "libtss2-tcti-libtpms0t64", "libtpms0",
                    "softhsm2", "opensc"]:  # fmt: skip
        assert re.search(rf"apt-get install [^\n]*\b{re.escape(package)}\b", runs), (
            package
        )
        assert f"`{package}`" in DOC or package in DOC
    assert "kernel.apparmor_restrict_unprivileged_userns=0" in runs
    assert "`kernel.apparmor_restrict_unprivileged_userns=0`" in DOC
    for var in [
        "NGARI_REQUIRE_BWRAP",
        "NGARI_REQUIRE_TPM_SIM",
        "NGARI_REQUIRE_PKCS11_SIM",
    ]:
        assert job["env"][var] == "1"
        assert f"`{var}=1`" in DOC


def test_ci_ok_waits_for_every_job_and_runs_when_they_fail():
    jobs = _workflow("ci.yml")["jobs"]
    ok = jobs["ci-ok"]
    assert ok["if"] == "always()"
    assert set(ok["needs"]) == set(jobs) - {"ci-ok"}
    gate = ok["steps"][-1]["if"]
    for job in set(jobs) - {"ci-ok", "test-arm64"}:
        assert f"needs.{job}.result != 'success'" in gate
    assert "needs.test-arm64.result != 'skipped'" in gate


def test_the_build_artifact_is_kept_and_reused_as_documented():
    steps = _workflow("ci.yml")["jobs"]["build"]["steps"]
    upload = next(
        s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert (upload["with"]["name"], upload["with"]["retention-days"]) == ("ci-dist", 14)
    assert "as the `ci-dist` artifact\nfor 14 days" in DOC
    assert "name: ci-dist" in (WORKFLOWS / "release.yml").read_text()


@pytest.mark.parametrize(
    ("workflow", "branches", "cron", "sentence"),
    [
        ("ci.yml", ["master", "main", "develop"], "17 6 * * *", "daily at 06:17 UTC"),
        ("codeql.yml", ["master", "main"], "41 5 * * 3", "on Wednesdays at 05:41\nUTC"),
        ("scorecard.yml", ["master", "main"], "17 6 * * 1", "on Mondays at 06:17 UTC"),
    ],
)
def test_triggers_and_schedules_are_the_documented_ones(
    workflow, branches, cron, sentence
):
    on = _triggers(_workflow(workflow))
    assert on["push"]["branches"] == branches
    assert [entry["cron"] for entry in on["schedule"]] == [cron]
    assert "workflow_dispatch" in on
    assert sentence in DOC
    if workflow != "scorecard.yml":
        assert on["pull_request"]["branches"] == branches
    else:
        assert "branch_protection_rule" in on


def test_every_action_is_pinned_and_only_scorecard_is_not_github_owned():
    owners = set()
    for path in WORKFLOWS.glob("*.yml"):
        for line in path.read_text().splitlines():
            m = re.match(r"\s*(?:- )?uses: (\S+)(.*)$", line)
            if not m or m.group(1).startswith("./"):
                continue
            action, rest = m.groups()
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", action), line
            assert re.match(r"\s+# v\d", rest), line
            owners.add(action.split("@")[0])
    outside = {
        a for a in owners if not a.startswith(("actions/", "github/codeql-action"))
    }
    assert outside == {"ossf/scorecard-action"}


def test_local_use_matches_the_makefile():
    assert re.search(r"^check: lint test ", MAKEFILE, re.MULTILINE)
    ci = set(re.search(r"^ci: (.*?) ##", MAKEFILE, re.MULTILINE).group(1).split())
    in_ci_workflow = set().union(
        *(_make_targets(j) for j in _workflow("ci.yml")["jobs"].values())
    )
    # make ci runs every CI target except build, plus test-sandbox, which
    # CI covers inside cov with NGARI_REQUIRE_BWRAP=1.
    assert in_ci_workflow - ci == {"build"}
    assert ci - in_ci_workflow == {"test-sandbox"}
    assert (
        "`make build`, which needs a clean tree and so is not part of `make ci`"
        in " ".join(DOC.split())
    )
    floor = re.search(r"^COV_FLOOR\s+\?= (\d+)", MAKEFILE, re.MULTILINE).group(1)
    assert f"`COV_FLOOR` ({floor})" in DOC
    assert re.search(
        r"^test-sandbox:.*\n\tNGARI_REQUIRE_BWRAP=1 ", MAKEFILE, re.MULTILINE
    )
