"""Fail-closed contract tests for the coordinated SDK release workflow."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/sdk-release.yml"


def job_text(name: str, next_name: str | None = None) -> str:
    """Return one top-level job block from the release workflow."""
    text = workflow_text()
    end = rf"(?=^  {re.escape(next_name)}:|\Z)" if next_name is not None else r"\Z"
    match = re.search(rf"(?ms)^  {re.escape(name)}:.*?{end}", text)
    assert match is not None
    return match.group(0)


def workflow_text() -> str:
    """Return the only workflow allowed to own SDK package publication."""
    assert WORKFLOW.is_file()
    assert not (ROOT / ".github/workflows/native-release.yml").exists()
    return WORKFLOW.read_text(encoding="utf-8")


def test_release_workflow_has_one_build_test_publish_coordinator() -> None:
    text = workflow_text()

    assert 'tags: ["bindings/go/v*"]' in text
    assert "pull_request:" in text
    assert "workflow_dispatch:" in text
    for job in (
        "binding-coverage:",
        "build-platform:",
        "assemble:",
        "test-node-package:",
        "test-python-wheel:",
        "test-python-sdist:",
        "test-native-archive:",
        "publish-github:",
        "publish-pypi:",
        "publish-npm:",
        "complete-release:",
    ):
        assert f"  {job}" in text

    assert "scripts/test-binding-coverage.sh" in text
    assert "scripts/sdk_artifact_manifest.py create" in text
    assert "scripts/sdk_artifact_manifest.py verify" in text
    assert "scripts/test-node-release-artifact.sh" in text
    assert "scripts/test-python-release-artifact.sh" in text
    assert "scripts/test-native-release-artifact.sh" in text


def test_publish_jobs_are_tag_only_ordered_and_protected() -> None:
    text = workflow_text()

    assert "environment: pypi" in text
    assert "environment: npm" in text
    assert "needs: publish-github" in text
    assert "needs: publish-pypi" in text
    assert "needs: publish-npm" in text
    assert "gh release create" in text
    assert "--draft" in text
    assert "--draft=false" in text
    assert "--clobber" not in text
    assert "continue-on-error: true" not in text
    assert "retries" not in text.lower()

    tag_guard = "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/bindings/go/v')"
    assert text.count(tag_guard) >= 4


def test_external_actions_are_pinned_and_permissions_are_job_local() -> None:
    text = workflow_text()

    assert re.search(r"^permissions:\n  contents: read$", text, re.MULTILINE)
    action_lines = [line.strip() for line in text.splitlines() if line.strip().startswith("uses:")]
    assert action_lines
    assert len(action_lines) == text.count("uses:")
    for line in action_lines:
        assert re.fullmatch(r"uses: [^@\s]+@[0-9a-f]{40}(?:\s+#.*)?", line), line


def test_python_artifact_tests_use_only_the_installed_distribution() -> None:
    script = (ROOT / "scripts/test-python-release-artifact.sh").read_text(encoding="utf-8")

    assert 'cd "$work_dir"' in script
    assert '-m pytest -q -p no:cacheprovider "$repo_root/bindings/python/tests"' in script


def test_tag_publication_jobs_keep_fail_closed_runtime_boundaries() -> None:
    text = workflow_text()

    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in text
    assert "release blocked: Go binding still embeds development linker paths" in text
    assert "maturin sdist" in text
    assert "--locked --out dist" not in text

    github_job = job_text("publish-github", "publish-pypi")
    pypi_job = job_text("publish-pypi", "publish-npm")
    npm_job = job_text("publish-npm", "complete-release")
    complete_job = job_text("complete-release")
    for job in (github_job, pypi_job, npm_job, complete_job):
        assert "timeout-minutes:" in job
    assert "actions/setup-python@" in github_job
    assert "actions/setup-python@" in pypi_job


def test_sdist_build_is_reproducible_and_local_lint_is_fail_closed() -> None:
    sdist_job = job_text("test-python-sdist", "test-native-archive")
    assert "Set up Rust" in sdist_job

    pyproject = (ROOT / "bindings/python/pyproject.toml").read_text(encoding="utf-8")
    assert 'include = ["cleverbase.pyi"]' not in pyproject

    lint_script = (ROOT / "scripts/lint.sh").read_text(encoding="utf-8")
    assert "CLEVERBASE_LINT_STRICT" not in lint_script
    assert 'FAILED+=("$1 missing: $2")' in lint_script
