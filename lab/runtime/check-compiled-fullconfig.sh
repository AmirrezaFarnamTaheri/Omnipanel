#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Disposable GitHub Actions native syntax check, NOT an applied-state ACK,
# qualified egress policy, independent witness or public M0 test.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
binary="${SING_BOX_BIN:-$repo_root/.data/lab-runtime/sing-box}"

if [[ ! -x "$binary" ]]; then
  echo "Pinned Sing-box binary missing; run the verified build first." >&2
  exit 2
fi
for tool in jq awk go mktemp; do
  command -v "$tool" >/dev/null
done

private_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/omni-fullconfig.XXXXXX")"
trap 'rm -rf -- "$private_dir"' EXIT

# Native Sing-box generates ephemeral credentials; never publish the key or
# credential-bearing config to action logs, summaries or artifact uploads.
reality_pair="$("$binary" generate reality-keypair)"
private_key="$(awk -F ': ' '$1 == "PrivateKey" {print $2}' <<<"$reality_pair")"
unset reality_pair
if [[ -z "$private_key" ]]; then
  echo "Pinned Sing-box did not generate a usable Reality key." >&2
  exit 1
fi

(
  cd "$repo_root"
  OMNI_NATIVE_FULL_CONFIG_OUTPUT="$private_dir/compiled.json" \
    OMNI_NATIVE_REALITY_KEY="$private_key" \
    go test -count=1 -run '^TestEmitFullConfigForPinnedNativeSingBoxCheck$' ./internal/drivers/singbox
)
unset private_key

if [[ ! -s "$private_dir/compiled.json" ]]; then
  echo "The Go compiler did not create a private full-config fixture." >&2
  exit 1
fi
if ! "$binary" check -c "$private_dir/compiled.json" >/dev/null 2>&1; then
  echo "Pinned Sing-box rejected the policy-compiled full config." >&2
  exit 1
fi

# Native validation must reject an intentionally broken outbound reference.
# This does not establish that egress policy actually works on the wire.
jq '.route.final = "omni-nonexistent-outbound"' \
  "$private_dir/compiled.json" > "$private_dir/invalid.json"
if "$binary" check -c "$private_dir/invalid.json" >/dev/null 2>&1; then
  echo "Pinned Sing-box accepted a deliberately broken outbound reference." >&2
  exit 1
fi

echo "Pinned Sing-box native check accepted generated config and rejected invalid outbound (syntax only, not M0)."
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  echo "Full-config native syntax check passed (not applied-state or external M0 evidence)." >> "$GITHUB_STEP_SUMMARY"
fi
