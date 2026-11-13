#!/usr/bin/env bash
#
# Build a drag-to-Applications .dmg from a built cutter.app.
#
#   packaging/macos/create_dmg.sh [path/to/cutter.app]
#
# Produces dist/cutter-<version>.dmg: a standard installer disk image with an
# /Applications symlink, so a non-technical user just drags the app across. No
# Terminal needed to install; first launch runs the in-app "Set Up Access" flow.
#
# Signing/notarization (optional, needs a Developer ID, see packaging/README.md)
# should happen on the .app BEFORE this script, and on the .dmg AFTER.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="${1:-$REPO_ROOT/dist/cutter.app}"
VOL_NAME="cutter"

if [[ ! -d "$APP" ]]; then
  echo "error: app bundle not found at: $APP" >&2
  echo "build it first:  python build.py            (produces dist/cutter.app)" >&2
  exit 1
fi

VERSION="$(python3 "$REPO_ROOT/build.py" --version | awk '{print $NF}')"
OUT="$REPO_ROOT/dist/cutter-$VERSION.dmg"
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

echo "Staging $APP ..."
cp -R "$APP" "$STAGING/cutter.app"
ln -s /Applications "$STAGING/Applications"

rm -f "$OUT"
echo "Building $OUT ..."
hdiutil create \
  -volname "$VOL_NAME" \
  -srcfolder "$STAGING" \
  -fs HFS+ \
  -format UDZO \
  -ov \
  "$OUT"

echo
echo "Done: $OUT"
echo "Drag cutter into Applications to install. First launch: Set Up Access."
