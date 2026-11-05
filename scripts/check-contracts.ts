import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { schemas, validateContract, validateDesiredState } from "../lab/contracts";
const root = path.resolve(__dirname, "..");
for (const [schema, file] of [
  ["runtime-registry", "capabilities/runtime.json"],
  ["client-registry", "capabilities/clients.json"],
  ["metering-registry", "capabilities/metering.json"],
] as const) {
  const errors = validateContract(schema, JSON.parse(fs.readFileSync(path.join(root, file), "utf8")));
  if (errors.length) throw new Error(`${file}: ${errors.join(", ")}`);
}
const errors = validateDesiredState(JSON.parse(fs.readFileSync(path.join(root, "testdata/contracts/desired-state.json"), "utf8")));
if (errors.length) throw new Error(`Structural fixture: ${errors.join(", ")}`);
console.log(`${schemas.length} strict schemas compiled; registries and unsigned contract fixture validated. Not connectivity evidence.`);

const api = JSON.parse(fs.readFileSync(path.join(root, "contracts/openapi.yaml"), "utf8"));
if (api.openapi !== "3.1.0" || api.components.securitySchemes.nodeMTLS.type !== "mutualTLS") throw new Error("Invalid candidate API security/version");
const apiSchemas = new Ajv2020({ strict: true });
addFormats(apiSchemas);
for (const schema of Object.values(api.components.schemas)) apiSchemas.compile(schema as object);
function checkReferences(value: unknown): void {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (key === "$ref" && typeof child === "string") {
      if (child.startsWith("#/components/schemas/")) {
        if (!api.components.schemas[child.slice("#/components/schemas/".length)]) throw new Error("Unknown API schema reference");
      } else if (child !== "./desired-state.schema.json") throw new Error("Unexpected API external reference");
    } else checkReferences(child);
  }
}
checkReferences(api);
console.log("Candidate API schemas and references checked; no server implementation or full OpenAPI conformance claimed.");
