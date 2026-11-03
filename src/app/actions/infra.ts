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
import { publishStructural } from "@/lib/revisions";
import { db } from "@/db";
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
    if (str(fd, "confirm") !== "QUARANTINE") throw new ProblemError(422, "Validation failed", "Type QUARANTINE to confirm");
    const n = await quarantineNode(actorOf(me), int(fd, "nodeId"));
    refresh();
    return { message: `Node quarantined and its identity revoked. ${n} installed credentials should be rotated.` };
  });
}

export async function rotateSecretsAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const n = await rotateNodeSecrets(actorOf(me), int(fd, "nodeId"));
    refresh();
    return { message: `Rotated ${n} credentials and Reality keys. Publish a revision on healthy nodes if needed.` };
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

export async function publishAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const nodeId = int(fd, "nodeId");
    const rollback = int(fd, "rollbackOf");
    const rev = await db.transaction((tx) =>
      publishStructural(tx, nodeId, actorOf(me), Number.isFinite(rollback) && rollback > 0 ? { rollbackOfSequence: rollback } : {}),
    );
    refresh();
    return { message: rev ? `Published immutable revision #${rev.sequence} (${rev.disruption}).` : "No changes to publish." };
  });
}

export async function createInboundAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const [runtime, protocol] = str(fd, "capability").split("|");
    await createInbound(
      actorOf(me),
      { nodeId: int(fd, "nodeId"), name: str(fd, "name"), runtime, protocol, port: int(fd, "port"), sni: str(fd, "sni") },
      str(fd, "idemKey"),
    );
    refresh();
    return { message: "Inbound created and credentials provisioned for existing users. Publish a revision to deploy it." };
  });
}

export async function updateInboundAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    await updateInbound(actorOf(me), int(fd, "inboundId"), int(fd, "port"), str(fd, "sni"));
    refresh();
    return { message: "Inbound updated (unpublished)." };
  });
}

export async function toggleInboundAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    await setInboundEnabled(actorOf(me), int(fd, "inboundId"), str(fd, "enabled") === "1");
    refresh();
    return { message: "Inbound state changed (unpublished)." };
  });
}
