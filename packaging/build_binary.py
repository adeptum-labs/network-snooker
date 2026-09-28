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
import sys
import tempfile
from pathlib import Path

from build_deb import ROOT, build_bundle, host_architecture


# Builds one self-contained executable, named for the machine it was built on.
# It needs conntrack, nft and ip on the host, like the Debian package.
def main() -> int:
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    binary = output / f"network-snooker-linux-{host_architecture()}"
    with tempfile.TemporaryDirectory() as directory:
        shutil.copy2(build_bundle(Path(directory), onefile=True), binary)
    print(binary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
