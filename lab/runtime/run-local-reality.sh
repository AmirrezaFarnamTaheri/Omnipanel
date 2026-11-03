#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../.." && pwd)"
sing_box_bin="${SING_BOX_BIN:-$repo_root/.data/lab-runtime/sing-box}"
metadata_file="${SING_BOX_METADATA:-${sing_box_bin%/*}/build-metadata.json}"
evidence_dir="${EVIDENCE_DIR:-$repo_root/.data/lab-runtime/evidence}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This isolated network-namespace test must run as root (for example: sudo make test-runtime)." >&2
  exit 2
fi

for command_name in ip openssl jq python3 grpcurl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Required command not found: $command_name" >&2
    exit 2
  fi
done

if [[ ! -x "$sing_box_bin" || ! -s "$metadata_file" ]]; then
  echo "Build the pinned runtime first with lab/runtime/build-sing-box.sh." >&2
  exit 2
fi

runtime_version="1.14.4+omni.2"
runtime_output="$("$sing_box_bin" version)"
if ! grep -Fq "$runtime_version" <<<"$runtime_output"; then
  echo "Unexpected Sing-box version:" >&2
  echo "$runtime_output" >&2
  exit 1
fi

mkdir -p "$evidence_dir"
temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/omni-reality-lab.XXXXXX")"
server_ns="omni-srv-$$"
client_ns="omni-cli-$$"
server_veth="omnis$$"
client_veth="omnic$$"

echo_server_pid=""
tls_server_pid=""
server_pid=""
client_pid=""
session_probe_pid=""

cleanup() {
  local status=$?
  set +e

  for process_id in "$session_probe_pid" "$client_pid" "$server_pid" "$tls_server_pid" "$echo_server_pid"; do
    if [[ -n "$process_id" ]]; then
      kill "$process_id" >/dev/null 2>&1
    fi
  done

  for process_id in "$session_probe_pid" "$client_pid" "$server_pid" "$tls_server_pid" "$echo_server_pid"; do
    if [[ -n "$process_id" ]]; then
      wait "$process_id" >/dev/null 2>&1
    fi
  done

  ip netns del "$client_ns" >/dev/null 2>&1
  ip netns del "$server_ns" >/dev/null 2>&1

  if [[ "$status" -ne 0 ]]; then
    echo "Local Reality smoke failed; sanitized process diagnostics follow." >&2
    for log_file in "$temp_dir/server.log" "$temp_dir/client.log" "$temp_dir/tls.log" "$temp_dir/echo.log" "$temp_dir/session.log"; do
      if [[ -s "$log_file" ]]; then
        echo "--- $log_file ---" >&2
        tail -n 80 "$log_file" >&2
      fi
    done
  fi

  rm -rf "$temp_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

wait_for_tcp() {
  local namespace="$1"
  local address="$2"
  local port="$3"

  for _ in $(seq 1 80); do
    if ip netns exec "$namespace" bash -c "exec 3<>/dev/tcp/$address/$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done

  echo "Timed out waiting for $namespace $address:$port" >&2
  return 1
}

start_server() {
  local config_file="$1"
  ip netns exec "$server_ns" "$sing_box_bin" run -c "$config_file" >"$temp_dir/server.log" 2>&1 &
  server_pid=$!
  wait_for_tcp "$server_ns" 127.0.0.1 18080
  wait_for_tcp "$client_ns" 10.200.1.1 24443
}

start_client() {
  local config_file="$1"
  ip netns exec "$client_ns" "$sing_box_bin" run -c "$config_file" >"$temp_dir/client.log" 2>&1 &
  client_pid=$!
  wait_for_tcp "$client_ns" 127.0.0.1 2080
}

run_probe() {
  local payload_file="$1"
  ip netns exec "$client_ns" python3 "$script_dir/socks5_probe.py" \
    --payload-file "$payload_file"
}

query_user_counter() {
  local counter_name="$1"
  ip netns exec "$server_ns" grpcurl \
    -plaintext \
    -import-path "$script_dir" \
    -proto stats.proto \
    -d "$(jq -cn --arg name "$counter_name" '{name: $name}')" \
    127.0.0.1:18080 \
    v2ray.core.app.stats.command.StatsService/GetStats \
    | jq --exit-status --raw-output '.stat.value | tonumber'
}

ip netns add "$server_ns"
ip netns add "$client_ns"
ip link add "$server_veth" type veth peer name "$client_veth"
ip link set "$server_veth" netns "$server_ns"
ip link set "$client_veth" netns "$client_ns"

ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$server_ns" address add 10.200.1.1/24 dev "$server_veth"
ip -n "$client_ns" address add 10.200.1.2/24 dev "$client_veth"
ip -n "$server_ns" link set "$server_veth" up
ip -n "$client_ns" link set "$client_veth" up

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$temp_dir/handshake.key" \
  -out "$temp_dir/handshake.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  >/dev/null 2>&1

key_pair="$("$sing_box_bin" generate reality-keypair)"
private_key="$(awk -F ': ' '$1 == "PrivateKey" { print $2 }' <<<"$key_pair")"
public_key="$(awk -F ': ' '$1 == "PublicKey" { print $2 }' <<<"$key_pair")"
user_uuid="$("$sing_box_bin" generate uuid)"
short_id="$(openssl rand -hex 4)"

if [[ -z "$private_key" || -z "$public_key" || -z "$user_uuid" || -z "$short_id" ]]; then
  echo "Sing-box did not generate the required Reality identity material." >&2
  exit 1
fi

jq -n \
  --arg uuid "$user_uuid" \
  --arg privateKey "$private_key" \
  --arg shortId "$short_id" \
  '{
    log: {level: "warn", timestamp: true},
    inbounds: [{
      type: "vless",
      tag: "reality-in",
      listen: "10.200.1.1",
      listen_port: 24443,
      users: [{name: "lab-user", uuid: $uuid, flow: "xtls-rprx-vision"}],
      tls: {
        enabled: true,
        server_name: "localhost",
        reality: {
          enabled: true,
          handshake: {server: "127.0.0.1", server_port: 18443},
          private_key: $privateKey,
          short_id: [$shortId]
        }
      }
    }],
    outbounds: [{type: "direct", tag: "direct"}],
    route: {final: "direct"},
    experimental: {
      v2ray_api: {
        listen: "127.0.0.1:18080",
        stats: {enabled: true, users: ["lab-user"]}
      }
    }
  }' > "$temp_dir/server.json"

jq -n \
  --arg uuid "$user_uuid" \
  --arg publicKey "$public_key" \
  --arg shortId "$short_id" \
  '{
    log: {level: "warn", timestamp: true},
    inbounds: [{
      type: "mixed",
      tag: "local-proxy",
      listen: "127.0.0.1",
      listen_port: 2080
    }],
    outbounds: [
      {
        type: "vless",
        tag: "reality",
        server: "10.200.1.1",
        server_port: 24443,
        uuid: $uuid,
        flow: "xtls-rprx-vision",
        network: "tcp",
        tls: {
          enabled: true,
          server_name: "localhost",
          utls: {enabled: true, fingerprint: "chrome"},
          reality: {
            enabled: true,
            public_key: $publicKey,
            short_id: $shortId
          }
        }
      },
      {type: "direct", tag: "direct"}
    ],
    route: {final: "reality"}
  }' > "$temp_dir/client.json"

# The Reality client requires uTLS explicitly, not merely a binary compiled
# with with_utls. This structural check avoids a misleading native-start test.
jq --exit-status '
  [.outbounds[] | select(.type == "vless")] as $outbounds
  | ($outbounds | length) == 1
    and $outbounds[0].tls.utls.enabled == true
    and $outbounds[0].tls.utls.fingerprint == "chrome"
' "$temp_dir/client.json" >/dev/null

# Reality accepts only the inbound TLS server_name. With an empty or different
# SNI allowlist, the server forwards this client to the decoy endpoint instead
# of authenticating its Reality session. Never mask that failure with insecure.
if ! jq --exit-status --slurpfile client "$temp_dir/client.json" '
  ([.inbounds[] | select(.type == "vless" and .tls.reality.enabled == true)] | first) as $inbound
  | ([$client[0].outbounds[] | select(.type == "vless")] | first) as $outbound
  | ($inbound.tls.server_name | type == "string" and length > 0)
    and ($inbound.tls.server_name == $outbound.tls.server_name)
    and ($outbound.tls.insecure != true)
' "$temp_dir/server.json" >/dev/null; then
  echo "Reality inbound SNI must match the client SNI without disabling TLS verification." >&2
  exit 1
fi

"$sing_box_bin" check -c "$temp_dir/server.json"
"$sing_box_bin" check -c "$temp_dir/client.json"

ip netns exec "$server_ns" python3 "$script_dir/echo_server.py" \
  --host 127.0.0.1 --port 19090 >"$temp_dir/echo.log" 2>&1 &
echo_server_pid=$!

ip netns exec "$server_ns" openssl s_server \
  -quiet -www -accept 127.0.0.1:18443 \
  -cert "$temp_dir/handshake.crt" \
  -key "$temp_dir/handshake.key" \
  >"$temp_dir/tls.log" 2>&1 &
tls_server_pid=$!

wait_for_tcp "$server_ns" 127.0.0.1 19090
wait_for_tcp "$server_ns" 127.0.0.1 18443

start_server "$temp_dir/server.json"
start_client "$temp_dir/client.json"

payload_file="$temp_dir/payload.bin"
head -c 1048576 /dev/urandom > "$payload_file"
probe_result="$temp_dir/probe.json"
run_probe "$payload_file" > "$probe_result"

payload_bytes="$(wc -c < "$payload_file" | tr -d ' ')"
payload_digest="$(sha256sum "$payload_file" | awk '{print $1}')"
probe_bytes="$(jq --exit-status --raw-output '.bytes | tonumber' "$probe_result")"
probe_digest="$(jq --exit-status --raw-output '.sha256' "$probe_result")"

if [[ "$probe_bytes" -ne "$payload_bytes" || "$probe_digest" != "$payload_digest" ]]; then
  echo "The Reality/Vision client did not return the exact TCP payload." >&2
  exit 1
fi

uplink_counter="$(query_user_counter 'user>>>lab-user>>>traffic>>>uplink')"
downlink_counter="$(query_user_counter 'user>>>lab-user>>>traffic>>>downlink')"
max_relative_error="$(awk -v up="$uplink_counter" -v down="$downlink_counter" -v expected="$payload_bytes" '
  BEGIN {
    up_error = (up - expected) / expected
    down_error = (down - expected) / expected
    if (up_error < 0) up_error = -up_error
    if (down_error < 0) down_error = -down_error
    printf "%.8f", (up_error > down_error ? up_error : down_error)
  }')"

if ! awk -v error="$max_relative_error" 'BEGIN { exit !(error <= 0.05) }'; then
  echo "Per-user counters exceed the 5% local payload error bound." >&2
  echo "Expected=$payload_bytes uplink=$uplink_counter downlink=$downlink_counter" >&2
  exit 1
fi

# A rejected candidate config must not disturb the already running process.
jq '.inbounds[0].listen_port = 0' "$temp_dir/server.json" > "$temp_dir/invalid.json"
if "$sing_box_bin" check -c "$temp_dir/invalid.json" >"$temp_dir/invalid-check.log" 2>&1; then
  echo "Sing-box unexpectedly accepted a zero listener port." >&2
  exit 1
fi
"$sing_box_bin" check -c "$temp_dir/server.json" >/dev/null
head -c 4096 /dev/urandom > "$temp_dir/preflight-probe.bin"
run_probe "$temp_dir/preflight-probe.bin" >/dev/null

# Existing sessions are observed across a full core restart. This is not a
# claim that Sing-box supports hot per-user removal.
printf 'session-probe-payload' > "$temp_dir/session.bin"
ip netns exec "$client_ns" python3 "$script_dir/socks5_probe.py" \
  --payload-file "$temp_dir/session.bin" \
  --hold-seconds 5 \
  --ready-file "$temp_dir/session.ready" \
  >"$temp_dir/session-result.json" 2>"$temp_dir/session.log" &
session_probe_pid=$!

for _ in $(seq 1 80); do
  [[ -f "$temp_dir/session.ready" ]] && break
  sleep 0.1
done
if [[ ! -f "$temp_dir/session.ready" ]]; then
  echo "The long-lived test session did not become ready." >&2
  exit 1
fi

kill "$server_pid"
wait "$server_pid" >/dev/null 2>&1 || true
server_pid=""
wait "$session_probe_pid"
session_probe_pid=""
jq --exit-status '.sessionTerminated == true' "$temp_dir/session-result.json" >/dev/null

# Replace the credential and restart the core. The previous client identity
# must fail, while the newly provisioned identity must work.
rotated_uuid="$("$sing_box_bin" generate uuid)"
jq \
  --arg uuid "$rotated_uuid" \
  '.inbounds[0].users = [{name: "lab-user-rotated", uuid: $uuid, flow: "xtls-rprx-vision"}]
   | .experimental.v2ray_api.stats.users = ["lab-user-rotated"]' \
  "$temp_dir/server.json" > "$temp_dir/server-rotated.json"
"$sing_box_bin" check -c "$temp_dir/server-rotated.json"
start_server "$temp_dir/server-rotated.json"

if run_probe "$temp_dir/session.bin" >"$temp_dir/old-credential.log" 2>&1; then
  echo "The old VLESS credential remained valid after core restart." >&2
  exit 1
fi

kill "$client_pid"
wait "$client_pid" >/dev/null 2>&1 || true
client_pid=""

jq \
  --arg uuid "$rotated_uuid" \
  '.outbounds |= map(if .type == "vless" then .uuid = $uuid else . end)' \
  "$temp_dir/client.json" > "$temp_dir/client-rotated.json"
"$sing_box_bin" check -c "$temp_dir/client-rotated.json"
start_client "$temp_dir/client-rotated.json"
run_probe "$temp_dir/session.bin" > "$temp_dir/rotated-probe.json"

build_digest="$(jq --exit-status --raw-output '.artifactSha256' "$metadata_file")"
source_commit="$(jq --exit-status --raw-output '.upstreamCommit' "$metadata_file")"
client_version="$(head -n 1 <<<"$runtime_output")"
report_file="$evidence_dir/local-reality-smoke.json"

jq -n \
  --arg runtimeVersion "$runtime_version" \
  --arg clientVersion "$client_version" \
  --arg sourceCommit "$source_commit" \
  --arg artifactSha256 "$build_digest" \
  --arg topology "two isolated Linux network namespaces joined by a veth pair" \
  --arg protocol "vless-reality-vision" \
  --argjson payloadBytes "$payload_bytes" \
  --argjson uplinkCounterBytes "$uplink_counter" \
  --argjson downlinkCounterBytes "$downlink_counter" \
  --argjson maxRelativeError "$max_relative_error" \
  '{
    status: "passed",
    scope: "local-runtime-smoke-only",
    runtime: "sing-box",
    runtimeVersion: $runtimeVersion,
    client: $clientVersion,
    upstreamCommit: $sourceCommit,
    artifactSha256: $artifactSha256,
    topology: $topology,
    protocol: $protocol,
    connectivity: "passed",
    accounting: "passed",
    payloadBytesPerDirection: $payloadBytes,
    uplinkCounterBytes: $uplinkCounterBytes,
    downlinkCounterBytes: $downlinkCounterBytes,
    maxRelativeError: $maxRelativeError,
    invalidConfigurationRejected: true,
    activeServiceSurvivedPreflightRejection: true,
    existingSessionTerminatedByCoreRestart: true,
    oldCredentialRejectedAfterCoreRestart: true,
    replacementCredentialConnected: true,
    publicVPSConnectivity: "not tested",
    mobileClientImport: "not tested",
    agentInitiatedReconciliation: "not implemented",
    safeLastGoodApplyRecovery: "not tested",
    productionQualification: false
  }' > "$report_file"

echo "Local Sing-box Reality/Vision smoke passed:"
cat "$report_file"
