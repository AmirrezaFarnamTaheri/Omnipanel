"use server";

import { revalidatePath } from "next/cache";
import { actorOf, requireRole } from "@/lib/auth";
import { act, str, int, type ActionState } from "@/lib/action-helpers";
import { ProblemError } from "@/lib/problem";
import {
  createCdnMapping,
  listCdnMappings,
  listCdnProviders,
  createRelayTunnel,
  listRelayTunnels,
  listRelayNodes,
  configureWarp,
  listWarpPeers,
  getBpbPolicy,
  updateBpbPolicy,
  getXrayNodeConfig,
  checkM2Capability,
} from "@/lib/m2";

const refresh = () => revalidatePath("/", "layout");

/* ========================================================================
   CDN
   ======================================================================== */

export async function createCdnMappingAction(
  _p: ActionState,
  fd: FormData,
): Promise<ActionState> {
  return act(async () => {
    await requireRole("operator");
    const domain = str(fd, "domain");
    const origin = str(fd, "origin");
    const provider = str(fd, "provider");
    const r = await createCdnMapping({ domain, origin, provider });
    refresh();
    return {
      message: `CDN mapping for ${r.domain} created (status: ${r.status}).`,
    };
  });
}

/* ========================================================================
   Relay
   ======================================================================== */

export async function createRelayTunnelAction(
  _p: ActionState,
  fd: FormData,
): Promise<ActionState> {
  return act(async () => {
    await requireRole("operator");
    const sourceNode = str(fd, "sourceNode");
    const destination = str(fd, "destination");
    const protocol = str(fd, "protocol");
    const r = await createRelayTunnel({ sourceNode, destination, protocol });
    refresh();
    return {
      message: `Relay tunnel ${r.id} created (status: ${r.status}).`,
    };
  });
}

/* ========================================================================
   WARP
   ======================================================================== */

export async function configureWarpAction(
  _p: ActionState,
  fd: FormData,
): Promise<ActionState> {
  return act(async () => {
    await requireRole("operator");
    const interfaceName = str(fd, "interfaceName");
    const privateKey = str(fd, "privateKey");
    const peerCount = Number(str(fd, "peerCount") || "0");
    const peers: Array<{ publicKey: string; endpoint: string }> = [];
    for (let i = 0; i < peerCount; i++) {
      const pk = str(fd, `peer${i}PublicKey`);
      const ep = str(fd, `peer${i}Endpoint`);
      if (pk && ep) peers.push({ publicKey: pk, endpoint: ep });
    }
    const iface = await configureWarp({ interfaceName, privateKey, peers });
    refresh();
    return {
      message: `WARP interface ${iface.name} configured with ${iface.peers} peer(s).`,
    };
  });
}

/* ========================================================================
   BPB
   ======================================================================== */

export async function updateBpbPolicyAction(
  _p: ActionState,
  fd: FormData,
): Promise<ActionState> {
  return act(async () => {
    await requireRole("operator");
    const nodeId = int(fd, "nodeId");
    const bandwidthLimit = int(fd, "bandwidthLimit");
    const priority = int(fd, "priority");
    const r = await updateBpbPolicy({ nodeId, bandwidthLimit, priority });
    refresh();
    return {
      message: `BPB policy for node ${r.nodeId}: limit=${r.bandwidthLimit}kbps, priority=${r.priority}.`,
    };
  });
}

/* ========================================================================
   Capability gating
   ======================================================================== */

export async function checkCapabilityAction(
  _p: ActionState,
  fd: FormData,
): Promise<ActionState> {
  return act(async () => {
    await requireRole("viewer");
    const key = str(fd, "key");
    const result = await checkM2Capability(key);
    return {
      message: `${key}: admissible=${result.admissible}, gated=${result.gated}, evidence=${result.evidence ?? "none"}`,
    };
  });
}
