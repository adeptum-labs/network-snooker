# Network Snooker is a live per-host traffic view for Linux routers.
# Copyright © 2026 Adam Waldenberg, Adeptum AB, Org.nr 559494-1824.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Website: https://www.adeptum.se
# Contact: info@adeptum.se


import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "create-release.sh"


def git(repo, *arguments):
    return subprocess.run(["git", *arguments], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()


def make_repo(tmp_path, version="0.1.0.dev0"):
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copy(SCRIPT, repo / "create-release.sh")
    (repo / "pyproject.toml").write_text(f'[project]\nname = "network-snooker"\nversion = "{version}"\n')
    (repo / ".gitignore").write_text("__pycache__/\n.pytest_cache/\n")
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Tester")
    git(repo, "config", "user.email", "tester@example.org")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "Start")
    return repo


def release(repo, *arguments):
    environment = {**os.environ, "PYTHON": sys.executable}
    return subprocess.run(["bash", "create-release.sh", *arguments], cwd=repo, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=environment)


def version_in(repo, revision=None):
    text = git(repo, "show", f"{revision}:pyproject.toml") if revision else (repo / "pyproject.toml").read_text()
    return tomllib.loads(text)["project"]["version"]


def test_a_release_commits_tags_and_opens_the_next_development_version(tmp_path):
    repo = make_repo(tmp_path)
    result = release(repo, "--skip-tests")
    assert result.returncode == 0, result.stderr
    assert git(repo, "log", "--format=%s", "-2").splitlines() == ["Start 0.1.1.dev0", "Release 0.1.0"]
    assert version_in(repo) == "0.1.1.dev0"
    assert version_in(repo, "v0.1.0") == "0.1.0"


def test_the_tag_is_annotated(tmp_path):
    repo = make_repo(tmp_path)
    release(repo, "--skip-tests")
    assert git(repo, "cat-file", "-t", "v0.1.0") == "tag"


@pytest.mark.parametrize(("bump", "next_version"), [("revrevision", "0.1.1.dev0"), ("revision", "0.2.0.dev0"), ("version", "1.0.0.dev0")])
def test_bump_chooses_which_number_the_next_version_raises(tmp_path, bump, next_version):
    repo = make_repo(tmp_path)
    assert release(repo, "--skip-tests", f"--bump={bump}").returncode == 0
    assert version_in(repo) == next_version


def test_the_release_is_named_after_the_version_being_worked_towards(tmp_path):
    repo = make_repo(tmp_path, "0.3.7.dev2")
    release(repo, "--skip-tests")
    assert version_in(repo, "v0.3.7") == "0.3.7"


def test_the_tests_gate_the_release(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_fails.py").write_text("def test_fails():\n    assert False\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "Add a failing test")
    result = release(repo)
    assert result.returncode != 0
    assert version_in(repo) == "0.1.0.dev0"
    assert git(repo, "tag") == ""
    assert git(repo, "status", "--porcelain") == ""


def test_passing_tests_let_the_release_through(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_passes.py").write_text("def test_passes():\n    assert True\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "Add a passing test")
    assert release(repo).returncode == 0
    assert git(repo, "tag") == "v0.1.0"


def test_a_dirty_working_tree_is_refused(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "notes.txt").write_text("x")
    result = release(repo, "--skip-tests")
    assert result.returncode != 0
    assert "not clean" in result.stderr
    assert git(repo, "tag") == ""


def test_an_existing_tag_is_refused(tmp_path):
    repo = make_repo(tmp_path)
    git(repo, "tag", "v0.1.0")
    result = release(repo, "--skip-tests")
    assert result.returncode != 0
    assert "already exists" in result.stderr


def test_a_version_that_is_not_a_development_version_is_refused(tmp_path):
    repo = make_repo(tmp_path, "0.1.0")
    result = release(repo, "--skip-tests")
    assert result.returncode != 0
    assert ".dev" in result.stderr
    assert version_in(repo) == "0.1.0"


def test_an_unknown_bump_is_refused(tmp_path):
    repo = make_repo(tmp_path)
    result = release(repo, "--skip-tests", "--bump=sideways")
    assert result.returncode != 0
    assert "sideways" in result.stderr


def test_help_explains_the_options(tmp_path):
    repo = make_repo(tmp_path)
    result = release(repo, "--help")
    assert result.returncode == 0
    assert "--bump" in result.stdout
    assert "--skip-tests" in result.stdout
    assert "Nothing is pushed" in result.stdout


def test_nothing_is_pushed(tmp_path):
    repo = make_repo(tmp_path)
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    git(repo, "remote", "add", "origin", str(remote))
    release(repo, "--skip-tests")
    assert subprocess.run(["git", "--git-dir", str(remote), "tag"], capture_output=True, text=True).stdout == ""
