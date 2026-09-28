#!/usr/bin/env bash
#
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
#
# Cuts a release: fixes the version, runs the tests, records the release in a
# commit and a tag, and opens the next development version.
#
# Run ./create-release.sh --help for what it takes.
#
# Nothing is pushed. The tag and the commits stay local until you send them,
# and it is the tag reaching GitHub that builds the packages.

set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PYPROJECT="$ROOT/pyproject.toml"

# The tests need the project's own environment; PYTHON overrides the choice.
python="${PYTHON:-$ROOT/.venv/bin/python}"
[ -x "$python" ] || python="python3"

die() { printf '%s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

usage() {
	cat <<'USAGE'
Cuts a release: sets the version, runs the tests, records the release in a
commit and an annotated tag, and opens the next development version.
Nothing is pushed.

  ./create-release.sh [options]

The version released is the one pyproject.toml is already working towards,
with the development suffix dropped: 0.1.0.dev0 releases 0.1.0. It is shown
and confirmed before anything changes. What is opened afterwards is up to
--bump.

  --bump=revrevision the third number, and the default: 0.1.0 opens
                     0.1.1.dev0.
  --bump=revision    the second, zeroing the third: 0.1.0 opens
                     0.2.0.dev0.
  --bump=version     the first, zeroing the rest: 0.1.0 opens
                     1.0.0.dev0.

  --skip-tests       do not run the tests. Nothing is verified: for a
                     release you have already tested.
  --help, -h         this.

Pushing the tag builds the Debian packages and the single-file executables
and publishes them as a GitHub release.
USAGE
}

tests="run"
bump="revrevision"
for argument in "$@"; do
	case "$argument" in
		--help|-h) usage; exit 0 ;;
		--skip-tests) tests="skip" ;;
		--bump=version|--bump=revision|--bump=revrevision) bump="${argument#--bump=}" ;;
		--bump=*) die "Bump one of version, revision or revrevision, not '${argument#--bump=}'." ;;
		*) usage >&2; die "
Takes no version: pyproject.toml already says which one comes next.
Unexpected argument '$argument'." ;;
	esac
done

is_dev_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.dev[0-9]+$ ]]; }

# The next development version: the named level one higher, everything under
# it back to zero, so a release opens a version rather than an odd corner of
# one.
bumped() {
	local major="${1%%.*}" rest="${1#*.}"
	local minor="${rest%%.*}" patch="${rest#*.}"
	case "$2" in
		version) printf '%s.0.0' "$(( major + 1 ))" ;;
		revision) printf '%s.%s.0' "$major" "$(( minor + 1 ))" ;;
		*) printf '%s.%s.%s' "$major" "$minor" "$(( patch + 1 ))" ;;
	esac
}

project_version() {
	"$python" -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' "$PYPROJECT"
}

# Rewrites the one version line, then reads the file back, so a pattern that
# matched nothing is caught rather than committed.
set_version() {
	sed -i "s/^version = \".*\"/version = \"$1\"/" "$PYPROJECT"
	[ "$(project_version)" = "$1" ] || die "pyproject.toml did not take the version $1."
}

cd "$ROOT"

# --- what the release must be able to assume ---------------------------------

git rev-parse --git-dir >/dev/null 2>&1 || die "Not a git repository."

dirty="$(git status --porcelain)"
[ -z "$dirty" ] || die "Working tree is not clean; commit or stash first:
$dirty"

current="$(project_version)"
is_dev_version "$current" \
	|| die "pyproject.toml reads '$current', which is not a development version.
Set it to a major.minor.patch.devN version first, such as 0.1.0.dev0."
version="${current%.dev*}"
next="$(bumped "$version" "$bump").dev0"

tag="v$version"
git rev-parse -q --verify "refs/tags/$tag" >/dev/null \
	&& die "Tag $tag already exists; that release has been cut."

printf 'Release %s, then open %s?' "$version" "$next"
if [ -t 0 ]; then
	printf ' [Y/n] '
	read -r answer
	case "$answer" in
		""|y|Y|yes) ;;
		*) die "Nothing released." ;;
	esac
else
	printf '\n'
fi

# --- fix the version and verify it --------------------------------------------

step "Setting the version to $version"
set_version "$version"

# Everything is put back if the tests refuse, so a failed release leaves the
# working copy exactly as it was found.
restore_version() {
	git checkout -- pyproject.toml 2>/dev/null || true
}
trap restore_version ERR

case "$tests" in
	run)
		step "Running the tests"
		"$python" -m pytest -q
		;;
	skip)
		step "Skipping the tests; nothing is verified"
		;;
esac

trap - ERR

# --- record it -----------------------------------------------------------------

step "Recording the release"
git add pyproject.toml
git commit -q -m "Release $version

Network Snooker at version $version. The tag on this commit builds the
Debian packages and the single-file executables for each architecture and
publishes them as a GitHub release."

git tag -a "$tag" -m "Network Snooker $version"

step "Opening the next development version"
set_version "$next"
git add pyproject.toml
git commit -q -m "Start $next"

printf '\n\033[1mReleased %s\033[0m\n' "$version"
printf '  tag    %s\n' "$tag"
printf '  next   %s\n' "$next"
printf '\nNothing was pushed. When you are ready:\n'
printf '  git push && git push origin %s\n' "$tag"
printf '\nThe tag is what builds the packages and publishes the release.\n'
