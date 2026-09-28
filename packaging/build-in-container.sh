#!/bin/sh
# Builds the Debian package inside a debian:12 container, so that the bundled
# binary needs no newer glibc than Debian 12 provides. Run from the repository root.
set -eu
apt-get update -qq
apt-get install -y -qq python3 python3-venv binutils
python3 -m venv /tmp/venv
/tmp/venv/bin/pip install --quiet pyinstaller .
/tmp/venv/bin/python packaging/build_deb.py
