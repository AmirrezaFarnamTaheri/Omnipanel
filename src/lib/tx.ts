import { db } from "@/db";

export type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];
export type Actor = { label: string; adminId?: number; role?: string; correlationId?: string };

export const SYSTEM: Actor = { label: "system" };
