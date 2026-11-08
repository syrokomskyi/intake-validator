/**
 * RFC-1540 AC-7 / AC-11 — monorepo-bound parity (excluded from the
 * standalone extract): the published bin and werkstatt's in-process call of
 * the same rules agree on every committed fixture bundle, and the bundled
 * family export is byte-equal to werkstatt's site copy.
 */
import { execFile } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { createDefaultIO } from "@warpgogol/werkstatt-shared/kernel/workspace-io";
import {
  bundledFamilyQuestionsPath,
  resolveIntakeExportSha256,
  validateIntakeBundle,
} from "./index.ts";

const run = promisify(execFile);
const pkgRoot = resolve(import.meta.dirname, "..");
const repoRoot = resolve(pkgRoot, "../..");
const fixturesRoot = join(repoRoot, "packages/werkstatt-engine/src/intake/fixtures");
const bundles = readdirSync(fixturesRoot, { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name)
  .sort();

describe("intake-validate bin ↔ werkstatt parity (RFC-1540)", () => {
  it("finds the committed fixture bundles", () => {
    expect(bundles).toEqual(expect.arrayContaining(["valid-minimal", "de-domain", "latin-only"]));
  });

  for (const name of bundles) {
    it(`AC-7: ${name} — same status and diagnostics from the bin and the werkstatt call`, async () => {
      const bundleDir = join(fixturesRoot, name);
      const { io } = createDefaultIO();
      const exportInfo = await resolveIntakeExportSha256(io);
      expect(exportInfo).not.toBeNull();
      const werkstatt = await validateIntakeBundle(bundleDir, io, {
        exportSha256: exportInfo!.sha256,
        bundleLabel: bundleDir,
        workspaceRoot: repoRoot,
      });

      let stdout: string;
      try {
        ({ stdout } = await run(
          process.execPath,
          [join(pkgRoot, "bin/intake-validate.mjs"), "--bundle", bundleDir, "--json"],
          { cwd: pkgRoot },
        ));
      } catch (err) {
        stdout = (err as { stdout: string }).stdout; // exit 1 on a failing bundle still prints JSON
      }
      const bin = JSON.parse(stdout) as typeof werkstatt & { validator: { package: string } };
      expect(bin.validator.package).toBe("@warpgogol/intake-validator");
      expect(bin.status).toBe(werkstatt.status);
      expect(bin.diagnostics).toEqual(werkstatt.diagnostics);
    }, 60_000);
  }

  it("AC-11: the bundled family export is byte-equal to werkstatt's site copy", () => {
    const site = join(
      repoRoot,
      "packages/werkstatt-site/src/onboarding/family-visitor-questions.generated.yaml",
    );
    expect(readFileSync(bundledFamilyQuestionsPath()!)).toEqual(readFileSync(site));
  });
});
