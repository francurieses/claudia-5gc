#!/usr/bin/env bash
#
# clone-fork.sh — set up a throwaway UERANSIM dev fork for working on the 5GC
# modification patch set (tools/ueransim/patches/).
#
# The committed artifact is the *patch set*, not the source tree (so the modded
# UE is portable to any deployment). This script gives you a real, compilable
# source tree to develop against:
#
#   1. clones stock UERANSIM v3.2.8 into tools/ueransim/.fork  (git-ignored)
#   2. applies every tools/ueransim/patches/*.patch in order
#
# Develop in .fork, then export your changes back to a numbered patch:
#
#   cd tools/ueransim/.fork
#   git diff > ../patches/00NN-my-feature.patch      # new feature
#   # or, to refresh an existing patch after edits:
#   git stash; git apply ../patches/0010-foo.patch; ...edit...; \
#     git diff > ../patches/0010-foo.patch
#
# Build natively (needs cmake + g++ + libsctp-dev) for a fast iteration loop:
#   cd tools/ueransim/.fork && cmake -B build . && cmake --build build -j
# or rebuild the Docker image (applies patches from scratch — the CI path):
#   make ueransim-build-only
#
set -euo pipefail

UERANSIM_VERSION="${UERANSIM_VERSION:-v3.2.8}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UERANSIM_DIR="$(dirname "$SCRIPT_DIR")"          # tools/ueransim
FORK_DIR="$UERANSIM_DIR/.fork"
PATCH_DIR="$UERANSIM_DIR/patches"

if [[ -d "$FORK_DIR" ]]; then
    echo "Fork already exists at $FORK_DIR"
    echo "Remove it first to re-clone:  rm -rf $FORK_DIR"
    exit 1
fi

echo "==> Cloning UERANSIM $UERANSIM_VERSION into $FORK_DIR"
git clone --depth 1 --branch "$UERANSIM_VERSION" \
    https://github.com/aligungr/UERANSIM.git "$FORK_DIR"

echo "==> Applying patch set from $PATCH_DIR"
cd "$FORK_DIR"
shopt -s nullglob
for p in "$PATCH_DIR"/*.patch; do
    echo "    applying $(basename "$p")"
    git apply --whitespace=nowarn "$p"
done

echo "==> Done. Dev fork ready at $FORK_DIR"
echo "    Source is patched but uncommitted, so 'git diff' shows the full patch set."
