#!/usr/bin/env bash
set -Eeuo pipefail

# Only run on disposable hosted GitHub Actions VMs, never production.
if [[ "${OMNI_ALLOW_EPHEMERAL_ROOT_SMOKE:-}" != "1" || "${GITHUB_ACTIONS:-}" != "true" || "$(id -u)" != "0" ]]; then
  echo "Root supervisor lab requires explicit ephemeral CI root opt-in." >&2
  exit 2
fi
if [[ -z "${SUDO_USER:-}" || "$SUDO_USER" == "root" || -z "${SUDO_UID:-}" || -z "${SUDO_GID:-}" ]]; then
  echo "Lab requires an unprivileged runner identity." >&2
  exit 2
fi
for exe in jq sha256sum install systemctl python3 go sudo; do
  command -v "$exe" >/dev/null || { echo "Missing lab dependency: $exe" >&2; exit 2; }
done
if [[ ! -f "${SING_BOX_BIN:-}" || ! -x "$SING_BOX_BIN" || ! -x "${ROOT_SUPERVISOR_BIN:-}" ]]; then
  echo "Signed Sing-box and compiled root supervisor are required." >&2
  exit 2
fi

unit="omnipanel-singbox.service"
unit_path="/run/systemd/system/$unit"
if systemctl cat "$unit" >/dev/null 2>&1 || [[ -e "$unit_path" ]]; then
  echo "Refusing to replace a pre-existing Sing-box service." >&2
  exit 2
fi
base="$(mktemp -d /run/omni-sup-lab.XXXXXXXX)"
root_pid=""
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [[ -n "$root_pid" ]]; then kill "$root_pid" >/dev/null 2>&1; wait "$root_pid" >/dev/null 2>&1; fi
  systemctl stop "$unit" >/dev/null 2>&1
  rm -f "$unit_path"
  systemctl daemon-reload >/dev/null 2>&1
  if [[ "$base" == /run/omni-sup-lab.* && -d "$base" ]]; then rm -rf -- "$base"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

runner_gid="$SUDO_GID"
chown "root:$runner_gid" "$base"
chmod 0750 "$base"
mkdir "$base/socket" "$base/private" "$base/generations" "$base/active"
chown "root:$runner_gid" "$base/socket"
chmod 0750 "$base/socket"
chmod 0700 "$base/private" "$base/generations" "$base/active"
install -o root -g root -m 0755 "$SING_BOX_BIN" "$base/sing-box"

systemctl_bin="$(readlink -f "$(command -v systemctl)")"
[[ -f "$systemctl_bin" && -x "$systemctl_bin" ]] || exit 2
sing_digest="$(sha256sum "$base/sing-box" | awk '{print $1}')"
systemctl_digest="$(sha256sum "$systemctl_bin" | awk '{print $1}')"
health_port="$(python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
PY
)"

# Harmless real native config: loopback SOCKS listener, block-only egress.
jq -cn --argjson port "$health_port" '{
  log:{level:"warn"},
  inbounds:[{type:"mixed",tag:"health",listen:"127.0.0.1",listen_port:$port}],
  outbounds:[{type:"block",tag:"block"}],
  route:{final:"block"}
}' > "$base/private/known-good.json"
"$base/sing-box" check -c "$base/private/known-good.json"
lkg_digest="$(sha256sum "$base/private/known-good.json" | awk '{print $1}')"
lkg="sha256:$lkg_digest"
install -o root -g root -m 0600 "$base/private/known-good.json" "$base/generations/$lkg_digest.json"

# A distinct root-owned candidate keeps the same loopback health listener and
# block-only egress. No public exposure, secrets or arbitrary remote paths.
jq '.log.level = "error"' "$base/private/known-good.json" > "$base/private/candidate.json"
"$base/sing-box" check -c "$base/private/candidate.json"
candidate_digest="$(sha256sum "$base/private/candidate.json" | awk '{print $1}')"
candidate="sha256:$candidate_digest"
[[ "$candidate" != "$lkg" ]] || { echo "Candidate must differ from qualified LKG." >&2; exit 1; }
install -o root -g root -m 0600 "$base/private/candidate.json" "$base/generations/$candidate_digest.json"
printf '%s\n' '{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"block","tag":"block"}],"route":{"final":"block"}}' > "$base/active/active.json"
chmod 0600 "$base/active/active.json"

cat > "$unit_path" <<EOF
[Unit]
Description=OmniPanel disposable signed Sing-box root rollback lab
[Service]
Type=simple
User=root
Group=root
NoNewPrivileges=yes
Restart=no
KillMode=control-group
ExecStart=$base/sing-box run -c $base/active/active.json
EOF
chmod 0644 "$unit_path"
systemctl daemon-reload

# Compile the test harness BEFORE creating the short-lived root ticket;
# network/module downloads must not consume its approval window.
go test -c -o "$base/root-host-ipc.test" ./internal/agent/supervisoripc
chown "root:$runner_gid" "$base/root-host-ipc.test"
chmod 0750 "$base/root-host-ipc.test"
expiry="$(python3 -c 'import time; print(int(time.time()) + 110)')"
manifest_digest="$(printf 'a%.0s' {1..64})"

jq -cn \
  --arg socket "$base/socket/restore.sock" \
  --argjson uid "$SUDO_UID" --argjson gid "$SUDO_GID" \
  --arg ref "$lkg" \
  --arg candidate "$candidate" \
  --arg manifest "$manifest_digest" \
  --argjson expiry "$expiry" \
  --arg generations "$base/generations" \
  --arg active "$base/active/active.json" \
  --arg sing "$base/sing-box" --arg singdigest "$sing_digest" \
  --arg systemctl "$systemctl_bin" --arg systemctldigest "$systemctl_digest" \
  --arg addr "127.0.0.1:$health_port" \
  '{
    SocketPath:$socket,WatchdogUID:$uid,WatchdogGID:$gid,
    AllowedGenerations:[$ref],
    Native:{
      GenerationDirectory:$generations,ActiveConfigPath:$active,
      SingBoxBinary:$sing,SingBoxBinaryDigest:$singdigest,
      SystemctlBinary:$systemctl,SystemctlBinaryDigest:$systemctldigest,
      HealthAddress:$addr,
      CandidateApproval:{
        Reference:$candidate,RollbackRef:$ref,
        ManifestDigest:$manifest,
        NodeID:"62c478bb-47c3-4dc6-a363-a2fbde813810",
        Epoch:"ea2429da-7540-4e40-ae70-38fd3f19794b",
        StructuralSequence:2,MembershipSequence:3,
        ExpiresUnix:$expiry
      }
    }
  }' > "$base/private/supervisor.json"
chmod 0600 "$base/private/supervisor.json"

"$ROOT_SUPERVISOR_BIN" --config "$base/private/supervisor.json" > "$base/private/supervisor.log" 2>&1 &
root_pid=$!
for _ in $(seq 1 80); do
  if [[ -S "$base/socket/restore.sock" ]] &&
     sudo -u "$SUDO_USER" test -w "$base/socket/restore.sock"; then
    break
  fi
  if ! kill -0 "$root_pid" >/dev/null 2>&1; then
    echo "Root supervisor terminated before socket authorization." >&2
    exit 1
  fi
  sleep 0.1
done
[[ -S "$base/socket/restore.sock" ]] || { echo "Root supervisor did not become ready." >&2; exit 1; }

# The production unprivileged IPC client drives the real root service and
# kills the real fixed systemd unit to prove recovery after SIGKILL.
sudo -u "$SUDO_USER" -H env \
  "PATH=$PATH" "OMNI_SIGNED_ROOT_HOST_LAB=1" \
  "OMNI_ROOT_LAB_SOCKET=$base/socket/restore.sock" \
  "OMNI_ROOT_LAB_LKG=$lkg" \
  "OMNI_ROOT_LAB_CANDIDATE=$candidate" \
  "$base/root-host-ipc.test" -test.count=1 -test.run '^TestSignedRootHostRollbackAfterSIGKILL$'

# Both the one-shot marker and the former LKG must survive the candidate fault.
test -s "$base/generations/.activation-$candidate_digest.used" || {
  echo "Root candidate ticket consumption was not durable." >&2; exit 1;
}
[[ "$(sha256sum "$base/active/active.json" | awk '{print $1}')" == "$lkg_digest" ]] || {
  echo "Root candidate rollback did not restore the approved previous generation." >&2; exit 1;
}

if [[ -n "${EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$EVIDENCE_DIR"
  jq -cn '{
    test:"root-systemd-signed-sing-box-rollback",
    nativeConfigCheck:true,rootUnixCredentials:true,
    approvedGenerationRestored:true,protectedSOCKSDestinationDenied:true,
    kill9HealthFailureObserved:true,restoredAfterKill9:true,
    unauthorizedGenerationRejected:true,
    oneShotRootCandidateApplied:true,candidateReplayRejected:true,
    formerKnownGoodRestoredAfterCandidateSIGKILL:true,
    productionM0Qualified:false,
    status:"passed"
  }' > "$EVIDENCE_DIR/root-supervisor-host-smoke.json"
fi
echo "PASS: real signed Sing-box root candidate one-shot apply and former LKG rollback after SIGKILL (not M0)"
