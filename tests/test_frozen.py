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


import sys

import pytest

from network_snooker.frozen import restore_host_library_path


@pytest.fixture
def frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)


def test_the_hosts_own_library_path_is_put_back(frozen):
    environ = {"LD_LIBRARY_PATH": "/opt/bundle", "LD_LIBRARY_PATH_ORIG": "/usr/local/lib"}
    restore_host_library_path(environ)
    assert environ == {"LD_LIBRARY_PATH": "/usr/local/lib"}


def test_a_path_that_only_the_bundle_set_is_removed(frozen):
    environ = {"LD_LIBRARY_PATH": "/opt/bundle", "HOME": "/root"}
    restore_host_library_path(environ)
    assert environ == {"HOME": "/root"}


def test_an_environment_without_a_library_path_is_left_alone(frozen):
    environ = {"HOME": "/root"}
    restore_host_library_path(environ)
    assert environ == {"HOME": "/root"}


def test_nothing_changes_outside_a_frozen_executable(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    environ = {"LD_LIBRARY_PATH": "/some/dev/lib"}
    restore_host_library_path(environ)
    assert environ == {"LD_LIBRARY_PATH": "/some/dev/lib"}
