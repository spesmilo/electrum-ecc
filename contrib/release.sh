#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/.."
CONTRIB="$PROJECT_ROOT/contrib"

cd "$PROJECT_ROOT"


git_status=$(git status --porcelain)
if [ ! -z "$git_status" ]; then
    echo "$git_status"
    echo "git repo not clean, aborting"
    exit 1
fi

# clean git submodules
# note: e.g. if you build a wheel, that side-effects the libsecp dir,
#       and build artifacts would leak into a subsequent sdist build.
git submodule update --init
pushd libsecp256k1/
git clean -ffxd
git reset --hard
popd


cd "$PROJECT_ROOT"
python3 -m build --sdist .

