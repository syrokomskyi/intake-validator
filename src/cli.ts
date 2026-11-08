/**
<MODULE_CONTRACT>
<purpose>intake-validate CLI (RFC-1540): validate one werkstatt:intake/v2 bundle with the published rules and print the same payload as werkstatt's onboarding.intake.validate, plus the validator package version.</purpose>
<non-goals><item>No --id: onboarding ids are a werkstatt workshop concept.</item></non-goals>
</MODULE_CONTRACT>
*/
import { readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { createDefaultIO } from "@warpgogol/werkstatt-shared/kernel/workspace-io";
import { resolveIntakeExportSha256, validateIntakeBundle } from "./rules.ts";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  name: string;
  version: string;
};

export interface CliOutcome {
  exitCode: 0 | 1 | 2;
  stdout: string;
  stderr: string;
}

export async function runCli(argv: string[], cwd: string = process.cwd()): Promise<CliOutcome> {
  let bundle: string | undefined;
  let budgetRaw: string | undefined;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--bundle") bundle = argv[++i];
    else if (a === "--cost-budget-usd") budgetRaw = argv[++i];
    else if (a === "--json") json = true;
    else return { exitCode: 2, stdout: "", stderr: `[intake-validate] unknown argument ${a}\n` };
  }
  if (!bundle) {
    return { exitCode: 2, stdout: "", stderr: "[intake-validate] --bundle <dir> is required\n" };
  }
  const costBudgetUsd = budgetRaw === undefined ? 5 : Number(budgetRaw);
  if (!Number.isFinite(costBudgetUsd) || costBudgetUsd < 0) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `[intake-validate] --cost-budget-usd must be a non-negative number (got '${budgetRaw}')\n`,
    };
  }
  const bundleDir = isAbsolute(bundle) ? bundle : resolve(cwd, bundle);
  const { io } = createDefaultIO();
  const exportInfo = await resolveIntakeExportSha256(io);
  if (exportInfo === null) {
    return {
      exitCode: 2,
      stdout: "",
      stderr:
        "[intake-validate] intake.schema.generated.yaml is absent from the installed @warpgogol/werkstatt-shared package\n",
    };
  }
  const result = await validateIntakeBundle(bundleDir, io, {
    exportSha256: exportInfo.sha256,
    costBudgetUsd,
    bundleLabel: bundle,
  });
  const payload = { ...result, validator: { package: pkg.name, version: pkg.version } };
  const errors = result.diagnostics.filter((d) => d.severity === "error").length;
  const warnings = result.diagnostics.filter((d) => d.severity === "warning").length;
  const text = json
    ? `${JSON.stringify(payload, null, 2)}\n`
    : `${result.diagnostics.map((d) => `${d.severity} ${d.rule}: ${d.message}`).join("\n")}${result.diagnostics.length ? "\n" : ""}[intake-validate] ${result.systemId ?? bundle}: ${result.status} (${errors} errors, ${warnings} warnings)\n`;
  return { exitCode: result.status === "pass" ? 0 : 1, stdout: text, stderr: "" };
}
