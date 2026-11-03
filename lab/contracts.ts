import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { planIngress } from "../src/lib/ingress";

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const root = path.resolve(__dirname, "..");
export const schemas = ["desired-state", "canonical-endpoint", "lab-evidence", "runtime-registry", "client-registry", "metering-registry"] as const;
export type SchemaName = typeof schemas[number];
for (const name of schemas) {
  const schema = JSON.parse(fs.readFileSync(path.join(root, "contracts", `${name}.schema.json`), "utf8"));
  ajv.addSchema(schema, name);
}

export function validateContract(name: SchemaName, value: unknown): string[] {
  const validate = ajv.getSchema(name)!;
  if (validate(value)) return [];
  // Do not return input values: manifests and evidence may contain sensitive data.
  return (validate.errors ?? []).map((error) => `${error.instancePath || "/"}: ${error.keyword}`);
}

export type DesiredState = {
  manifest: {
    nodeId: string;
    issuedAt: string;
    expiresAt: string;
    requiredCapabilities: string[];
    components: {
      id: string; dependsOn: string[];
      listeners: { address: string; port: number; transport: "tcp" | "udp"; ipv6Only: boolean }[];
    }[];
  };
};

/** Contract preflight, NOT a signature, capability, identity or epoch verifier. */
export function validateDesiredState(value: unknown): string[] {
  const errors = validateContract("desired-state", value);
  if (errors.length) return errors;
  const { manifest } = value as DesiredState;
  if (Date.parse(manifest.expiresAt) <= Date.parse(manifest.issuedAt)) errors.push("manifest: expiry must follow issue time");
  const ids = new Set(manifest.components.map((component) => component.id));
  if (ids.size !== manifest.components.length) errors.push("components: duplicate id");
  const active = new Set<string>(), visited = new Set<string>();
  const visit = (id: string) => {
    if (active.has(id)) { errors.push("components: dependency cycle"); return; }
    if (visited.has(id)) return;
    active.add(id);
    for (const dependency of manifest.components.find((component) => component.id === id)!.dependsOn) {
      if (!ids.has(dependency)) errors.push("components: unknown dependency");
      else visit(dependency);
    }
    active.delete(id); visited.add(id);
  };
  ids.forEach(visit);
  try {
    const plan = planIngress(manifest.components.flatMap((component) => component.listeners.map((listener) => ({
      ...listener, nodeId: manifest.nodeId, owner: component.id,
    }))));
    if (!plan.valid) errors.push("components: effective socket overlap");
  } catch { errors.push("components: invalid listener"); }
  return errors;
}
