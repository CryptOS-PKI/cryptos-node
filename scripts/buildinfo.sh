#!/usr/bin/env bash
# Print the -ldflags -X arguments that stamp a binary's build identity into
# internal/buildinfo (version, commit, build date). `task build` uses it for
# every binary built from this checkout (init, cryptosctl, cryptos-install), so
# they report the same identity (`cryptosctl status` / `cryptosctl version`).
# cryptos-appliance carries its own copy for the image it builds.
#
#   go build -ldflags "-s -w $(scripts/buildinfo.sh)" ./cmd/cryptosctl
#
# version    `git describe --tags --always --dirty` (CRYPTOS_VERSION overrides)
# commit     full commit hash, suffixed -dirty for a modified tree
# build date the commit time (SOURCE_DATE_EPOCH if set), RFC 3339 UTC, so a
#            rebuild of the same commit stays byte-for-byte reproducible
#
# Without usable git metadata (a source tarball, a CI checkout with no .git) it
# still succeeds: the version falls back to "dev" and the commit and date are
# left for the binary to resolve, which reports them as "unknown".
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
pkg="github.com/CryptOS-PKI/cryptos-node/internal/buildinfo"

version="${CRYPTOS_VERSION:-$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo dev)}"
flags="-X $pkg.Version=$version"

if commit="$(git -C "$root" rev-parse HEAD 2>/dev/null)"; then
  if ! git -C "$root" diff --quiet HEAD -- 2>/dev/null; then
    commit="$commit-dirty"
  fi
  flags="$flags -X $pkg.Commit=$commit"
fi

epoch="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || true)}"
if [ -n "$epoch" ]; then
  # GNU date takes -d @epoch; BSD/macOS date takes -r epoch.
  date="$(date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ)"
  flags="$flags -X $pkg.BuildDate=$date"
fi

echo "$flags"
