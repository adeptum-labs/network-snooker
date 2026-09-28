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


import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "packaging" / "build_deb.py"
spec = importlib.util.spec_from_file_location("build_deb", SCRIPT)
build_deb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_deb)

PROJECT = {
    "name": "network-snooker",
    "version": "1.2.3",
    "description": "Live per-host traffic view for Linux routers",
    "authors": [{"name": "Adam Waldenberg, Adeptum AB", "email": "info@adeptum.se"}],
}


def fields(text):
    return dict(line.split(": ", 1) for line in text.splitlines() if line and not line.startswith(" "))


def test_control_names_the_package_version_and_architecture():
    control = fields(build_deb.control_text(PROJECT, "arm64"))
    assert (control["Package"], control["Version"], control["Architecture"]) == ("network-snooker", "1.2.3-1", "arm64")


def test_control_depends_on_the_tools_it_shells_out_to():
    assert fields(build_deb.control_text(PROJECT, "amd64"))["Depends"] == "conntrack, nftables"


def test_control_takes_maintainer_and_summary_from_the_project():
    control = fields(build_deb.control_text(PROJECT, "amd64"))
    assert control["Maintainer"] == "Adam Waldenberg, Adeptum AB <info@adeptum.se>"
    assert control["Description"] == "Live per-host traffic view for Linux routers"


def test_control_ends_with_a_newline_and_indents_the_long_description():
    lines = build_deb.control_text(PROJECT, "amd64").splitlines()
    assert build_deb.control_text(PROJECT, "amd64").endswith("\n")
    assert all(line.startswith(" ") for line in lines[lines.index(f"Description: {PROJECT['description']}") + 1 :])


@pytest.fixture
def tree(tmp_path):
    bundle = tmp_path / "bundle"
    (bundle / "_internal").mkdir(parents=True)
    executable = bundle / "network-snooker"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    (bundle / "_internal" / "data").write_text("x")
    target = tmp_path / "tree"
    build_deb.assemble(target, bundle, PROJECT, "amd64")
    return target


def test_the_bundle_is_installed_under_usr_lib(tree):
    assert (tree / "usr/lib/network-snooker/_internal/data").read_text() == "x"


def test_the_executable_keeps_its_executable_bit(tree):
    assert os.access(tree / "usr/lib/network-snooker/network-snooker", os.X_OK)


def test_usr_bin_links_to_the_bundle_with_a_relative_path(tree):
    link = tree / "usr/bin/network-snooker"
    assert link.is_symlink()
    assert os.readlink(link) == "../lib/network-snooker/network-snooker"
    assert link.resolve() == (tree / "usr/lib/network-snooker/network-snooker").resolve()


def test_copyright_points_at_the_system_gpl_text(tree):
    text = (tree / "usr/share/doc/network-snooker/copyright").read_text()
    assert "GPL-3+" in text
    assert "/usr/share/common-licenses/GPL-3" in text


def test_the_control_file_is_written_for_the_architecture(tree):
    assert "Architecture: amd64" in (tree / "DEBIAN/control").read_text()


def test_the_host_architecture_comes_from_dpkg():
    calls = []

    def run(command, **options):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="arm64\n")

    assert build_deb.host_architecture(run) == "arm64"
    assert calls == [["dpkg", "--print-architecture"]]
