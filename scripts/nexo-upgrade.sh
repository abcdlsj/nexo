#!/usr/bin/env bash
#
# Replace the systemd-installed nexo binary with a tagged release build, keeping
# the previous one for rollback. Run as root on the host that serves 443.
#
#   nexo-upgrade.sh v0.2.0           # install that tag
#   nexo-upgrade.sh v0.2.0 --dry-run # download and verify, install nothing
#   nexo-upgrade.sh --rollback       # put nexo.prev back and restart
#
# Overrides: NEXO_REPO, NEXO_BIN, NEXO_UNIT, NEXO_PORT.

set -euo pipefail

REPO=${NEXO_REPO:-abcdlsj/nexo}
BIN=${NEXO_BIN:-/usr/local/bin/nexo}
UNIT=${NEXO_UNIT:-nexo}
PORT=${NEXO_PORT:-443}

say() { printf '%s\n' "$*"; }
die() { printf 'nexo-upgrade: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

restart() {
  systemctl restart "$UNIT"
  for _ in $(seq 1 20); do
    if systemctl is-active --quiet "$UNIT" && ss -ltnH "sport = :$PORT" | grep -q LISTEN; then
      return 0
    fi
    sleep 1
  done
  return 1
}

rollback() {
  [ -x "$BIN.prev" ] || die "no $BIN.prev to roll back to"
  cp -a "$BIN.prev" "$BIN"
  restart || die "rollback restarted but :$PORT still is not listening"
  say "rolled back to $("$BIN" version)"
}

if [ "${1:-}" = "--rollback" ]; then
  rollback
  exit 0
fi

TAG=${1:-}
DRY_RUN=false
[ "${2:-}" = "--dry-run" ] && DRY_RUN=true
[ -n "$TAG" ] || die "usage: nexo-upgrade.sh <tag> [--dry-run] | --rollback"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

base="https://github.com/${REPO}/releases/download/${TAG}"
asset="nexo_${TAG}_linux_${ARCH}.tar.gz"

say "downloading ${asset}"
curl -fsSL -o "${work}/${asset}" "${base}/${asset}" || die "no asset ${asset} for ${TAG}"
curl -fsSL -o "${work}/checksums.txt" "${base}/checksums.txt" || die "no checksums.txt for ${TAG}"
(cd "$work" && sha256sum -c --ignore-missing checksums.txt >/dev/null) || die "checksum mismatch"
tar -C "$work" -xzf "${work}/${asset}"
want=$("${work}/nexo" version)
say "release: ${want}"

if $DRY_RUN; then
  say "dry run: nothing installed"
  exit 0
fi

[ -x "$BIN" ] && cp -a "$BIN" "$BIN.prev"
install -m 0755 "${work}/nexo" "$BIN"
if ! restart; then
  say "restart did not come up, rolling back"
  rollback
  exit 1
fi
say "installed: $("$BIN" version)"
