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

  # Do not print the generated key or staged config. The native test checks
  # exact signed binary digest, native syntax, owner-only staged candidate,
  # durable SQLite guard and zero applied-cursor advancement.
  OMNI_NATIVE_TEST_SING_BOX_BIN="$binary" \
    OMNI_NATIVE_REALITY_KEY="$private_key" \
    go test -count=1 -run '^TestPinnedNativeCandidatePreparation$' ./internal/drivers/singbox
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

# The pinned native `check` command has been observed to ACCEPT an
# unresolved route.final tag. Therefore reference consistency is separately
# enforced in the compiler and asserted here; never trust native syntax alone.
if ! jq --exit-status '
  .route.final as $wanted
  | ([.outbounds[].tag] | index($wanted)) != null
' "$private_dir/compiled.json" >/dev/null; then
  echo "Policy compiler emitted an unresolved final outbound tag." >&2
  exit 1
fi

# Native syntax validation must still reject an actual type violation.
# This negative case is deliberately different from unresolved references.
jq '.inbounds[0].listen_port = "not-an-integer"' \
  "$private_dir/compiled.json" > "$private_dir/invalid.json"
if "$binary" check -c "$private_dir/invalid.json" >/dev/null 2>&1; then
  echo "Pinned Sing-box accepted an invalid listener-port type." >&2
  exit 1
fi

echo "Pinned Sing-box accepted compiled config and rejected invalid schema; OMNIPANEL separately checked outbound references (not M0)."
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  echo "Full-config native syntax check passed (not applied-state or external M0 evidence)." >> "$GITHUB_STEP_SUMMARY"
fi
