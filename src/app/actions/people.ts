"use server";

import { revalidatePath } from "next/cache";
import { actorOf, requireRole } from "@/lib/auth";
import { act, int, str, type ActionState } from "@/lib/action-helpers";
import { createPlan, createUser, mutateUserStatus, rotateEndpoint, rotateSubscriptionToken, updateUser } from "@/lib/users";
import { drainOutbox } from "@/lib/outbox";

const refresh = () => revalidatePath("/", "layout");

function subUrl(token: string) {
  const base = process.env.OMNI_PUBLIC_URL?.replace(/\/$/, "") ?? "";
  return `${base}/sub/${token}`;
}

const dateOrNull = (s: string) => (s ? new Date(s) : null);

export async function createPlanAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const gb = Number(fd.get("quotaGb"));
    await createPlan(actorOf(me), {
      name: str(fd, "name"),
      quotaGb: Number.isFinite(gb) && gb > 0 ? gb : null,
      enforcement: str(fd, "enforcement"),
      idemKey: str(fd, "idemKey"),
    });
    refresh();
    return { message: "Plan created." };
  });
}

export async function createUserAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const r = await createUser(
      actorOf(me),
      { name: str(fd, "name"), email: str(fd, "email") || null, planId: int(fd, "planId"), expiresAt: dateOrNull(str(fd, "expiresAt")) },
      str(fd, "idemKey"),
    );
    refresh();
    return {
      message: r.token ? "User created and provisioned on all eligible endpoints." : "User already created (idempotent replay).",
      secret: r.token ? { label: "Subscription URL (shown once)", value: subUrl(r.token), hint: "Append ?format=singbox|mihomo|uri to force a format." } : undefined,
    };
  });
}

export async function updateUserAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    await updateUser(
      actorOf(me),
      int(fd, "userId"),
      { name: str(fd, "name"), email: str(fd, "email") || null, planId: int(fd, "planId"), expiresAt: dateOrNull(str(fd, "expiresAt")) },
      int(fd, "version"),
    );
    await drainOutbox();
    refresh();
    return { message: "User updated." };
  });
}

export async function userStatusAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const status = str(fd, "status") === "active" ? "active" : "suspended";
    await mutateUserStatus(actorOf(me), int(fd, "userId"), status, "admin");
    refresh();
    return { message: status === "active" ? "User resumed; resume events queued for nodes." : "User suspended; suspend events queued for nodes." };
  });
}

export async function rotateTokenAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const t = await rotateSubscriptionToken(actorOf(me), int(fd, "userId"));
    refresh();
    return { message: "Previous subscription URL revoked.", secret: { label: "New subscription URL (shown once)", value: subUrl(t) } };
  });
}

export async function rotateEndpointAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    await rotateEndpoint(actorOf(me), int(fd, "principalId"));
    refresh();
    return { message: "Credential replaced. The retired credential is never reused." };
  });
}
