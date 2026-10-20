#!/bin/bash
# Build and deploy the orchestrator. Run it on the server, inside this repo:
#
#   cd /opt/apps/bentoproxy/dev/bentoproxy-repo && ./deploy/deploy.sh production
#
# Takes over from /opt/apps/bentoproxy/dev/deploy/deploy.sh, which built from
# a separate copy of the source that stopped being updated in 2025 and so
# deployed old code from a clean-looking run.
set -euo pipefail

ENV=${1:-production}
case "$ENV" in
    production|staging) ;;
    *) echo "usage: $0 [production|staging]" >&2; exit 1 ;;
esac

REPO=$(cd "$(dirname "$0")/.." && pwd)
TARGET=/opt/apps/bentoproxy/$ENV
BINARY=bentoproxy-orchestrator
export PATH=$HOME/.cargo/bin:$PATH

cd "$REPO"
echo "==> building $(git log --oneline -1)"
cargo build --release

echo "==> installing to $TARGET"
# Copy then rename: the running binary cannot be written over ("text file
# busy"), but renaming onto it replaces the directory entry, which is fine
# while the old inode is still executing.
sudo cp "target/release/$BINARY" "$TARGET/$BINARY.new"
sudo mv -f "$TARGET/$BINARY.new" "$TARGET/$BINARY"

echo "==> restarting bentoproxy-$ENV"
sudo systemctl restart "bentoproxy-$ENV"
sleep 2
systemctl is-active "bentoproxy-$ENV"
