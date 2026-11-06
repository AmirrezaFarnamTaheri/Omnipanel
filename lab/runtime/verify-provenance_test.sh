#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
verifier="$script_dir/verify-provenance.sh"
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/omni-provenance-test.XXXXXX")"
trap 'rm -rf "$temp_dir"' EXIT

mkdir -p "$temp_dir/bin"
cat > "$temp_dir/bin/cosign" <<'MOCK_COSIGN'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$1" == "verify-blob" ]] || exit 30
shift
artifact="$1"
shift
bundle=""
identity=""
issuer=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle) bundle="$2"; shift 2 ;;
    --certificate-identity) identity="$2"; shift 2 ;;
    --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
    *) exit 31 ;;
  esac
done
[[ -s "$bundle" ]] || exit 32
[[ "$identity" == "$MOCK_EXPECTED_IDENTITY" ]] || exit 33
[[ "$issuer" == "https://token.actions.githubusercontent.com" ]] || exit 34
[[ "${MOCK_COSIGN_FAIL:-}" != "$artifact" ]] || exit 35
printf '%s\n' "$artifact" >> "$MOCK_COSIGN_LOG"
MOCK_COSIGN
chmod +x "$temp_dir/bin/cosign"

export PATH="$temp_dir/bin:$PATH"
export GITHUB_REPOSITORY="AmirrezaFarnamTaheri/Omnipanel"
export GITHUB_REF="refs/heads/main"
export MOCK_EXPECTED_IDENTITY="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/runtime-smoke.yml@${GITHUB_REF}"
export MOCK_COSIGN_LOG="$temp_dir/cosign.log"

artifact="$temp_dir/sing-box"
metadata="$temp_dir/build-metadata.json"
artifact_bundle="$temp_dir/sing-box.sigstore.json"
metadata_bundle="$temp_dir/build-metadata.sigstore.json"
printf 'runtime binary fixture\n' > "$artifact"
printf 'signed artifact bundle fixture\n' > "$artifact_bundle"
printf 'signed metadata bundle fixture\n' > "$metadata_bundle"
artifact_digest="$(sha256sum "$artifact" | awk '{print $1}')"

node -e '
  const fs = require("node:fs");
  const [outPath, digest] = process.argv.slice(1);
  fs.writeFileSync(outPath, JSON.stringify({
    runtime: "sing-box",
    version: "1.14.4+omni.2",
    sourceRepository: "SagerNet/sing-box",
    upstreamTag: "v1.14.4",
    upstreamCommit: "c005f35300ce76427dc285481ec5695f5b179cd2",
    sourceSignatureStatus: "github-api-verified",
    goVersion: "go version go1.26.10 linux/amd64",
    buildTags: "with_v2ray_api,with_utls,badlinkname,tfogo_checklinkname0",
    artifactSha256: digest,
  }, null, 2) + "\n");
' "$metadata" "$artifact_digest"

# Builder, signed test metadata and runtime runner must agree on the exact
# custom build ID. This detects drift before any privileged namespace work.
build_version="$(awk -F '"' '/^readonly runtime_version=/{ print $2; exit }' "$script_dir/build-sing-box.sh")"
runner_version="$(awk -F '"' '/^runtime_version=/{ print $2; exit }' "$script_dir/run-local-reality.sh")"
fixture_version="$(node -e 'const fs = require("node:fs"); process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).version);' "$metadata")"
if [[ -z "$build_version" || "$build_version" != "$runner_version" || "$runner_version" != "$fixture_version" ]]; then
  echo "FAIL: version mismatch between pinned builder, metadata, and runtime runner" >&2
  exit 1
fi
echo "PASS: signed build and runtime runner version contract"

assert_failure() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $description was accepted" >&2
    exit 1
  fi
  echo "PASS: $description rejected"
}

: > "$MOCK_COSIGN_LOG"
"$verifier" "$artifact" "$metadata" "$artifact_bundle" "$metadata_bundle" >/dev/null
[[ "$(wc -l < "$MOCK_COSIGN_LOG" | tr -d ' ')" == "2" ]]
echo "PASS: valid artifact and metadata signatures verified"

printf 'tampered runtime\n' >> "$artifact"
assert_failure "artifact digest mismatch" "$verifier" "$artifact" "$metadata" "$artifact_bundle" "$metadata_bundle"
printf 'runtime binary fixture\n' > "$artifact"

node -e 'const fs = require("node:fs"); const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); d.version = "latest"; fs.writeFileSync(process.argv[2], JSON.stringify(d));' "$metadata" "$temp_dir/invalid-metadata.json"
assert_failure "unapproved runtime version" "$verifier" "$artifact" "$temp_dir/invalid-metadata.json" "$artifact_bundle" "$metadata_bundle"

# Regression: runtime startup previously failed because a signed custom build
# declared only the V2Ray statistics API and lacked required Reality/uTLS.
node -e 'const fs = require("node:fs"); const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); d.buildTags = "with_v2ray_api,badlinkname,tfogo_checklinkname0"; fs.writeFileSync(process.argv[2], JSON.stringify(d));' "$metadata" "$temp_dir/missing-utls.json"
assert_failure "missing required Reality uTLS build tag" "$verifier" "$artifact" "$temp_dir/missing-utls.json" "$artifact_bundle" "$metadata_bundle"

node -e 'const fs = require("node:fs"); const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); d.buildTags = "with_utls,badlinkname,tfogo_checklinkname0"; fs.writeFileSync(process.argv[2], JSON.stringify(d));' "$metadata" "$temp_dir/missing-stats.json"
assert_failure "missing required per-user stats build tag" "$verifier" "$artifact" "$temp_dir/missing-stats.json" "$artifact_bundle" "$metadata_bundle"

assert_failure "missing artifact bundle" "$verifier" "$artifact" "$metadata" "$temp_dir/missing.bundle" "$metadata_bundle"

assert_failure "invalid artifact signature" env MOCK_COSIGN_FAIL="$artifact" "$verifier" "$artifact" "$metadata" "$artifact_bundle" "$metadata_bundle"

assert_failure "unexpected workflow identity" env GITHUB_REF="refs/heads/untrusted" "$verifier" "$artifact" "$metadata" "$artifact_bundle" "$metadata_bundle"

ln -s "$artifact" "$temp_dir/artifact-link"
assert_failure "symlinked artifact" "$verifier" "$temp_dir/artifact-link" "$metadata" "$artifact_bundle" "$metadata_bundle"

assert_failure "missing arguments" "$verifier"
echo "All provenance verifier tests passed."
