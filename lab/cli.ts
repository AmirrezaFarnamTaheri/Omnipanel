import path from "node:path";
import { runLab } from "./gate";

try {
  const root = path.resolve(__dirname, "..");
  const report = runLab(root, path.resolve(process.env.OMNI_LAB_EVIDENCE_DIR ?? path.join(root, ".data/lab-evidence")));
  console.log(JSON.stringify(report, null, 2));
  if (report.status !== "passed") process.exitCode = 2;
} catch {
  // Do not leak file contents, user-controlled JSON or credential-bearing paths.
  console.error("Lab gate blocked: invalid registry or unreadable/malformed evidence. See lab/README.md.");
  process.exitCode = 2;
}
