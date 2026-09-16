from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "opentide.yml"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_ci_does_not_require_private_opentide_credentials() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = _load()
    jobs = workflow["jobs"]

    assert "Require private-repo credentials" not in text
    assert "HAS_DEPLOY_KEY" not in text
    assert "OPENTIDE_DEPLOY_KEY" not in text
    assert "ssh-key:" not in text
    assert "GH_APP_ID" not in text
    assert "create-github-app-token" not in text

    pypi = jobs["validate-pypi"]
    steps = pypi["steps"]
    install = next(step for step in steps if step.get("name") == "Install released opentide")
    assert "pip install opentide" in install["run"]
    assert 'pip install -e "./opentide' not in install["run"]
    validate = next(step for step in steps if step.get("name") == "Validate objects")
    assert "opentide validate --strict" in validate["run"]


def test_ci_keeps_development_head_as_non_blocking_early_warning() -> None:
    workflow = _load()
    job = workflow["jobs"]["validate-development"]
    assert job.get("continue-on-error") is True
    checkout = next(step for step in job["steps"] if step.get("name") == "Checkout opentide development")
    assert checkout["with"]["repository"] == "OpenTideHQ/opentide"
    assert checkout["with"]["ref"] == "development"
    assert "token" not in checkout.get("with", {})
    assert "ssh-key" not in checkout.get("with", {})
    generate = next(step for step in job["steps"] if step.get("name") == "Generate schemas and templates")
    assert "opentide generate schemas" in generate["run"]
    validate = next(
        step for step in job["steps"] if step.get("name") == "Validate objects against development HEAD"
    )
    assert "opentide validate --strict" in validate["run"]


def test_ci_checks_out_explorer_publicly() -> None:
    workflow = _load()
    job = workflow["jobs"]["explorer"]
    checkout = next(step for step in job["steps"] if step.get("name") == "Checkout explorer")
    assert checkout["with"]["repository"] == "OpenTideHQ/explorer"
    assert checkout["with"]["ref"] == "main"
    assert "token" not in checkout.get("with", {})
    assert "ssh-key" not in checkout.get("with", {})


def test_ci_builds_explorer_with_node_not_missing_pypi_cli() -> None:
    workflow = _load()
    job = workflow["jobs"]["explorer"]
    run_text = "\n".join(step.get("run", "") for step in job["steps"] if "run" in step)

    assert "opentide explorer" not in run_text
    assert "pip install opentide" not in run_text

    install = next(step for step in job["steps"] if step.get("name") == "Install explorer dependencies")
    assert install["working-directory"] == "explorer"
    assert "pnpm install --frozen-lockfile" in install["run"]

    build = next(step for step in job["steps"] if step.get("name") == "Build explorer static site")
    assert build["working-directory"] == "explorer"
    assert "node scripts/generate-mock-bundle.mjs" in build["run"]
    assert "pnpm exec next build" in build["run"]
    assert build["env"]["OPENTIDE_REPO_ROOT"] == "${{ github.workspace }}"
    assert build["env"]["NEXT_PUBLIC_BASE_PATH"] == "/library"

    upload = next(step for step in job["steps"] if step.get("name") == "Upload Pages artifact")
    assert upload["with"]["path"] == "./explorer/out"


def test_ci_runs_catalogue_tests_from_requirements_with_coverage() -> None:
    workflow = _load()
    job = workflow["jobs"]["catalogue-tests"]
    install = next(step for step in job["steps"] if "pip install" in step.get("run", ""))
    assert "requirements-dev.txt" in install["run"]
    runs = [step.get("run", "") for step in job["steps"] if "run" in step]
    assert any("pytest" in command and "--cov=migrate_trunk_models" in command for command in runs)
    assert any("--cov-fail-under=98" in command for command in runs)


def test_ci_concurrency_is_per_ref() -> None:
    workflow = _load()
    concurrency = workflow["concurrency"]
    assert "${{ github.ref }}" in concurrency["group"]
    assert concurrency["group"] != "pages"


def test_readme_does_not_tell_users_to_run_missing_pypi_explorer_cli() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "pip install opentide\nexport OPENTIDE_REPO_ROOT=$PWD\nexport OPENTIDE_EXPLORER_PATH" not in text
    assert "generate-mock-bundle.mjs" in text
    # Mentioned only as the command that is missing, not as a working recipe.
    assert "opentide explorer" in text
    assert "have no such Typer command" in text
