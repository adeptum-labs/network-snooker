# Network Snooker

[![Tests](https://img.shields.io/github/actions/workflow/status/adeptum-labs/network-snooker/tests.yml?branch=master&label=tests&style=flat-square)](https://github.com/adeptum-labs/network-snooker/actions/workflows/tests.yml)
[![License](https://img.shields.io/github/license/adeptum-labs/network-snooker.svg?style=flat-square)](https://github.com/adeptum-labs/network-snooker/blob/master/LICENSE)

A terminal view of live per-host traffic on a Linux router. It reads
connection tracking to show what each device on the LAN is talking to, and
can block services for a host, on a schedule if needed, through nftables.

![Live traffic per host](docs/hosts.png)

![Per-service schedule for a host](docs/schedule.png)

## Requirements

- Python 3.11 or later
- Root privileges
- `conntrack`, and `nft` for blocking

## Usage

```sh
pip install .
sudo network-snooker
```

`--interval SECONDS` sets the poll interval and `--lan CIDR` (repeatable)
overrides the detected LAN subnets.

## License

Copyright © 2026 Adam Waldenberg, Adeptum AB. Licensed under the GNU General
Public License, version 3 or later. See [LICENSE](LICENSE).
