"use server";

import { revalidatePath } from "next/cache";
import { actorOf, requireRole } from "@/lib/auth";
import { act, int, str, type ActionState } from "@/lib/action-helpers";
import {
  createInbound,
  createNode,
  quarantineNode,
  reissueEnrollment,
  rotateNodeSecrets,
  setInboundEnabled,
  setNodeStatus,
  updateInbound,
  updateNodeAddress,
} from "@/lib/nodes";
import { probeNodeNow } from "@/lib/health";
import { ProblemError } from "@/lib/problem";

const refresh = () => revalidatePath("/", "layout");

export async function createNodeAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const r = await createNode(
      actorOf(me),
      { name: str(fd, "name"), address: str(fd, "address"), provider: str(fd, "provider"), asn: str(fd, "asn"), region: str(fd, "region") },
      str(fd, "idemKey"),
    );
    refresh();
    return {
      message: r.token ? `Node registered. Run the agent installer with this one-time token (valid 1 hour).` : "Node already registered (idempotent replay).",
      secret: r.token ? { label: "Enrollment token", value: r.token } : undefined,
    };
  });
}

export async function reissueEnrollAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const t = await reissueEnrollment(actorOf(me), int(fd, "nodeId"));
    refresh();
    return { message: "Previous identity revoked; node must re-enroll.", secret: { label: "Enrollment token", value: t } };
  });
}

export async function nodeStatusAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const status = str(fd, "status") === "draining" ? "draining" : "active";
    await setNodeStatus(actorOf(me), int(fd, "nodeId"), status);
    refresh();
    return { message: status === "draining" ? "Node draining: removed from new subscriptions." : "Node restored." };
  });
}

export async function updateAddressAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    await updateNodeAddress(actorOf(me), int(fd, "nodeId"), str(fd, "address"));
    refresh();
    return { message: "Address updated; subscriptions now reference the new address." };
  });
}

export async function quarantineAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const confirmVal = str(fd, "confirm");
    if (confirmVal && confirmVal !== "QUARANTINE") {
      throw new ProblemError(422, "Validation failed", "Type QUARANTINE to confirm");
    }
    const n = await quarantineNode(actorOf(me), int(fd, "nodeId"));
    refresh();
    return { message: `Node quarantined and its identity revoked. ${n} installed credentials should be rotated.` };
  });
}

export async function rotateSecretsAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const nodeId = int(fd, "nodeId");
    const n = await rotateNodeSecrets(actorOf(me), nodeId);
    refresh();
    return { message: `Rotated ${n} credentials and Reality keys, and staged rotation; submit an independently approved proposal to publish.` };
  });
}

export async function probeAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    await requireRole("operator");
    const r = await probeNodeNow(int(fd, "nodeId"));
    refresh();
    return { message: r.message };
  });
}

/** Direct structural publication is forbidden without independent approval. */
export async function publishAction(_p: ActionState, _fd: FormData): Promise<ActionState> {
  return act(async () => {
    await requireRole("owner");
    throw new ProblemError(403, "Forbidden", "Direct publication is disabled; submit a signed proposal for independent second-owner approval.");
  });
}

export async function createInboundAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const nodeId = int(fd, "nodeId");
    const [runtime, protocol] = str(fd, "capability").split("|");
    await createInbound(
      actorOf(me),
      { nodeId, name: str(fd, "name"), runtime, protocol, port: int(fd, "port"), sni: str(fd, "sni") || "www.cloudflare.com" },
      str(fd, "idemKey"),
    );
    refresh();
    return { message: "Endpoint staged. Submit a signed proposal for independent second-owner approval before publication." };
  });
}

export async function updateInboundAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const inboundId = int(fd, "inboundId");
    await updateInbound(actorOf(me), inboundId, int(fd, "port"), str(fd, "sni"));
    // Changes are staged until an independent approved signed publication.
    refresh();
    return { message: "Endpoint updated and staged; submit an independently approved proposal to publish." };
  });
}

export async function toggleInboundAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const inboundId = int(fd, "inboundId");
    await setInboundEnabled(actorOf(me), inboundId, str(fd, "enabled") === "1");
    const nodeId = int(fd, "nodeId");
    // Changes are staged until an independent approved signed publication.
    refresh();
    return { message: "Endpoint status updated and staged; submit an independently approved proposal to publish." };
  });
}
