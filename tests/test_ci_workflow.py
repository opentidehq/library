from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "opentide.yml"


def test_ci_does_not_require_private_opentide_credentials() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    jobs = workflow["jobs"]

    assert "Require private-repo credentials" not in text
    assert "HAS_DEPLOY_KEY" not in text
    assert "OPENTIDE_DEPLOY_KEY" not in text
    assert "ssh-key:" not in text

    pypi = jobs["validate-pypi"]
    steps = pypi["steps"]
    install = next(step for step in steps if step.get("name") == "Install released opentide")
    assert "pip install opentide" in install["run"]
    assert 'pip install -e "./opentide' not in install["run"]
    validate = next(step for step in steps if step.get("name") == "Validate objects")
    assert "opentide validate --strict" in validate["run"]


def test_ci_keeps_development_head_as_non_blocking_early_warning() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["validate-development"]
    assert job.get("continue-on-error") is True
    checkout = next(step for step in job["steps"] if step.get("name") == "Checkout opentide development")
    assert checkout["with"]["repository"] == "OpenTideHQ/opentide"
    assert checkout["with"]["ref"] == "development"
    assert "token" not in checkout.get("with", {})
    assert "ssh-key" not in checkout.get("with", {})


def test_ci_checks_out_explorer_publicly() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["explorer"]
    checkout = next(step for step in job["steps"] if step.get("name") == "Checkout explorer")
    assert checkout["with"]["repository"] == "OpenTideHQ/explorer"
    assert "token" not in checkout.get("with", {})
    assert "ssh-key" not in checkout.get("with", {})


def test_ci_runs_catalogue_tests() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["catalogue-tests"]
    runs = [step.get("run", "") for step in job["steps"] if "run" in step]
    assert any("pytest" in command for command in runs)
