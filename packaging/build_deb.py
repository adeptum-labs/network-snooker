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


import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB_DIR = "usr/lib/network-snooker"
DEB_REVISION = 1
DEPENDS = "conntrack, nftables"
LONG_DESCRIPTION = (
    "Reads connection tracking to show what each device on the LAN is talking to,",
    "and blocks services for a host, on a schedule if needed, through nftables.",
    "A background daemon keeps enforcing after the terminal view exits.",
)
COPYRIGHT = """\
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: network-snooker
Source: https://github.com/adeptum-labs/network-snooker

Files: *
Copyright: 2026 Adam Waldenberg, Adeptum AB
License: GPL-3+
 On Debian systems, the full text of the GNU General Public License
 version 3 can be found in /usr/share/common-licenses/GPL-3.
"""


def project_metadata(pyproject: Path = ROOT / "pyproject.toml") -> dict:
    return tomllib.loads(pyproject.read_text())["project"]


def control_text(project: dict, arch: str) -> str:
    author = project["authors"][0]
    header = [
        "Package: network-snooker",
        f"Version: {project['version']}-{DEB_REVISION}",
        f"Architecture: {arch}",
        "Section: net",
        "Priority: optional",
        f"Depends: {DEPENDS}",
        f"Maintainer: {author['name']} <{author['email']}>",
        f"Description: {project['description']}",
    ]
    return "\n".join([*header, *(f" {line}" for line in LONG_DESCRIPTION), ""])


def assemble(tree: Path, bundle: Path, project: dict, arch: str) -> None:
    shutil.copytree(bundle, tree / LIB_DIR)
    binaries = tree / "usr/bin"
    binaries.mkdir(parents=True)
    (binaries / "network-snooker").symlink_to("../lib/network-snooker/network-snooker")
    docs = tree / "usr/share/doc/network-snooker"
    docs.mkdir(parents=True)
    (docs / "copyright").write_text(COPYRIGHT)
    debian = tree / "DEBIAN"
    debian.mkdir()
    (debian / "control").write_text(control_text(project, arch))


# The bundle is built for the machine it runs on, so the label comes from the
# machine rather than from an argument that could disagree with it.
def host_architecture(run=subprocess.run) -> str:
    return run(["dpkg", "--print-architecture"], capture_output=True, text=True, check=True).stdout.strip()


# Textual and rich import some of their modules dynamically, which PyInstaller's
# static analysis cannot see, so their data and submodules are collected whole.
def build_bundle(work: Path) -> Path:
    services = ROOT / "src/network_snooker/services.toml"
    subprocess.run(
        [
            sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir", "--name", "network-snooker",
            "--distpath", str(work / "dist"), "--workpath", str(work / "build"), "--specpath", str(work),
            "--add-data", f"{services}:network_snooker",
            "--collect-all", "textual",
            "--collect-submodules", "rich",
            str(ROOT / "packaging/entry.py"),
        ],
        check=True,
    )
    return work / "dist" / "network-snooker"


def main() -> int:
    project, arch = project_metadata(), host_architecture()
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    deb = output / f"network-snooker_{project['version']}-{DEB_REVISION}_{arch}.deb"
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        assemble(work / "tree", build_bundle(work), project, arch)
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(work / "tree"), str(deb)], check=True)
    print(deb)
    return 0


if __name__ == "__main__":
    sys.exit(main())
