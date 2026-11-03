#!/usr/bin/env bash
set -Eeuo pipefail

readonly upstream_tag="v1.14.4"
readonly upstream_commit="c005f35300ce76427dc285481ec5695f5b179cd2"
readonly runtime_version="1.14.4+omni.1"

script_dir="$(cd -- "$(dirname -- "\${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
output="\${SING_BOX_BIN:-$repo_root/.data/lab-runtime/sing-box}"
metadata="\${SING_BOX_METADATA:-\${output%/*}/build-metadata.json}"
source_dir="$(mktemp -d "\${TMPDIR:-/tmp}/omni-sing-box.XXXXXX")"

cleanup() {
  rm -rf "$source_dir"
}
trap cleanup EXIT

command -v curl >/dev/null
command -v git >/dev/null
command -v jq >/dev/null
command -v go >/dev/null

if ! go version | grep -Fq 'go1.26.10'; then
  echo "Go 1.26.10 is required to reproduce the pinned runtime build." >&2
  go version >&2
  exit 1
fi

mkdir -p "$(dirname -- "$output")" "$(dirname -- "$metadata")"

# GitHub reports the upstream release commit as cryptographically verified.
curl --fail --silent --show-error --location \
  "https://api.github.com/repos/SagerNet/sing-box/commits/$upstream_commit" \
  | jq --exit-status --arg commit "$upstream_commit" '
      .sha == $commit
      and .commit.verification.verified == true
      and .commit.verification.reason == "valid"
    ' >/dev/null

git clone --quiet --depth 1 --branch "$upstream_tag" \
  https://github.com/SagerNet/sing-box.git "$source_dir"

actual_commit="$(git -C "$source_dir" rev-parse HEAD)"
if [[ "$actual_commit" != "$upstream_commit" ]]; then
  echo "Upstream tag resolved to an unexpected commit: $actual_commit" >&2
  exit 1
fi

# The official default release build omits V2Ray API. Build only the API tag
# required for this metering experiment; do not inherit unrelated integrations.
build_tags="with_v2ray_api,badlinkname,tfogo_checklinkname0"
shared_ldflags="$(cat "$source_dir/release/LDFLAGS")"

(
  cd "$source_dir"
  export GOTOOLCHAIN=local
  export CGO_ENABLED=0
  go build \
    -trimpath \
    -buildvcs=false \
    -tags "$build_tags" \
    -ldflags "-X github.com/sagernet/sing-box/constant.Version=$runtime_version $shared_ldflags -s -w -buildid=" \
    -o "$output" \
    ./cmd/sing-box
)

chmod 0755 "$output"
"$output" version

artifact_digest="$(sha256sum "$output" | awk '{print $1}')"
jq -n \
  --arg version "$runtime_version" \
  --arg upstreamTag "$upstream_tag" \
  --arg upstreamCommit "$upstream_commit" \
  --arg sourceSignatureStatus "github-api-verified" \
  --arg goVersion "$(go version)" \
  --arg buildTags "$build_tags" \
  --arg artifactSha256 "$artifact_digest" \
  '{
    runtime: "sing-box",
    version: $version,
    upstreamTag: $upstreamTag,
    upstreamCommit: $upstreamCommit,
    sourceSignatureStatus: $sourceSignatureStatus,
    goVersion: $goVersion,
    buildTags: $buildTags,
    artifactSha256: $artifactSha256
  }' > "$metadata"

printf 'Built %s\nSHA-256 %s\nMetadata %s\n' \
  "$output" "$artifact_digest" "$metadata"
