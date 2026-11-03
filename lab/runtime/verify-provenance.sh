#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "Usage: verify-provenance.sh ARTIFACT METADATA ARTIFACT_BUNDLE METADATA_BUNDLE" >&2
  exit 2
}

if [[ "$#" -ne 4 ]]; then
  usage
fi

artifact="$1"
metadata="$2"
artifact_bundle="$3"
metadata_bundle="$4"

for file in "$artifact" "$metadata" "$artifact_bundle" "$metadata_bundle"; do
  if [[ ! -f "$file" || -L "$file" || ! -s "$file" ]]; then
    echo "Required provenance file is missing, empty or not a regular file." >&2
    exit 1
  fi
done

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_REF:?GITHUB_REF is required}"

if [[ ! "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ || "$GITHUB_REF" == *$'\n'* ]]; then
  echo "Invalid GitHub workflow identity context." >&2
  exit 1
fi

command -v cosign >/dev/null
command -v jq >/dev/null
command -v sha256sum >/dev/null

readonly expected_identity="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/runtime-smoke.yml@${GITHUB_REF}"
readonly expected_issuer="https://token.actions.githubusercontent.com"

cosign verify-blob "$artifact" \
  --bundle "$artifact_bundle" \
  --certificate-identity "$expected_identity" \
  --certificate-oidc-issuer "$expected_issuer"

cosign verify-blob "$metadata" \
  --bundle "$metadata_bundle" \
  --certificate-identity "$expected_identity" \
  --certificate-oidc-issuer "$expected_issuer"

artifact_digest="$(sha256sum "$artifact" | awk '{print $1}')"
jq --exit-status --arg digest "$artifact_digest" '
  type == "object"
  and (keys == [
    "artifactSha256",
    "buildTags",
    "goVersion",
    "runtime",
    "sourceRepository",
    "sourceSignatureStatus",
    "upstreamCommit",
    "upstreamTag",
    "version"
  ])
  and .runtime == "sing-box"
  and .version == "1.14.4+omni.2"
  and .sourceRepository == "SagerNet/sing-box"
  and .upstreamTag == "v1.14.4"
  and .upstreamCommit == "c005f35300ce76427dc285481ec5695f5b179cd2"
  and .sourceSignatureStatus == "github-api-verified"
  and .goVersion == "go version go1.26.10 linux/amd64"
  and .buildTags == "with_v2ray_api,with_utls,badlinkname,tfogo_checklinkname0"
  and .artifactSha256 == $digest
' "$metadata" >/dev/null

printf 'Verified Sing-box artifact and build metadata with Sigstore identity %s\n' "$expected_identity"
printf 'Artifact SHA-256: %s\n' "$artifact_digest"
