/*
<MODULE_CONTRACT>

<purpose>RFC-1281/RFC-1328/RFC-1342/RFC-1345/RFC-1346/RFC-1353/RFC-1357/RFC-1368: onboarding.intake.validate —
deterministic INTAKE-01…34 validation of a werkstatt:intake/v2 hand-over
bundle (INTAKE-CONTRACT + AMD-005 + AMD-007 + AMD-009 + AMD-010 + AMD-011 + AMD-012). Rule order is fixed:
INTAKE-01 (manifest/hash integrity) and INTAKE-02 (envelope schema, unknown or
retired major fails closed — v1 is rejected here after the v2 cut) run first;
INTAKE-03…34 run only when both produced no errors. All file access goes
through WorkspaceIO; hashing is node:crypto sha256.</purpose>
<non-goals>
  <item>Do not vendor PBP entity shapes — INTAKE-03 delegates to pbpSchemaById (DNA-103).</item>
  <item>Do not write files — the command is read-only; the bundle is immutable on arrival.</item>
</non-goals>
</MODULE_CONTRACT>
<KEY_DECISIONS>
  <item>contractSnapshot is compared to the sha256 of the vendored export resolved via import.meta.resolve("@warpgogol/werkstatt-shared/onboarding/intake.schema.generated.yaml")</item>
  <item>Verbatim substring checks (INTAKE-05) run against text-typed evidence items only (text/*, application/json, message/rfc822); a binary-only source is an error,.</item>
</KEY_DECISIONS>
<CHANGE_SUMMARY>
  <item>RFC-1328/AMD-005: INTAKE-12…15 — anchored internal-marker + assessment-vocabulary scan on published free text (name/statement/summary/description), locale-native statementByLocale coverage, WebP-only rasters, closed palette vocabulary; envelope-only fields stripped before the strict pbp parse (INTAKE-03).</item>
  <item>RFC-1353: steps 1-2 — intake faq block contract + INTAKE-26..29

werkstatt-shared: intakeFaqTopicSchema/intakeFaqEntrySchema (status conditionals
per INTAKE-02), faqEntryTier(), envelope faq: block, provenance.familyQuestionsSnapshot;
schema export regenerated (additive +152 lines) and fixtures re-stamped via
contract.ripple.apply. werkstatt-engine: INTAKE-26 (uniqueness, placement in
pageSetIntent|faq, visitorQuestionRef against the vendored export),
INTAKE-27 (locale coverage), INTAKE-28 ({{pbp:..}} tokens + no restated
identifying literals), INTAKE-29 (answered=>evidenceRefs); INTAKE-04/05/16/17/19
extended to faq entries (gap.blocks inverse covers faq ids). Tests-Skipped:
scoped gate deferred to the step-3 commit; intake suite 100/100 green.</item>
  <item>RFC-1485: sweep compass headers — engine</item>
  <item>RFC-1495: steps 2-3 - workshop paths resolver and call-site migration</item>
  <item>RFC-1540: publish the intake rules as @warpgogol/intake-validator</item>
  <history>ADR-0114, RFC-1281, RFC-1324, RFC-1342, RFC-1345, RFC-1346, RFC-1357, RFC-1368, RFC-1408, RFC-1410</history>
</CHANGE_SUMMARY>
*/

import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import YAML from "yaml";

import { pbpSchemaById } from "@warpgogol/pbp/entities";
import { biomeAxesSchema, biomePaletteSchema } from "@warpgogol/werkstatt-shared/ontology";
import { sniffMediaType } from "@warpgogol/werkstatt-shared/media/sniff-media-type";
import {
  INTAKE_SCHEMA_ID,
  canonicalIntentPageId,
  intakeEnvelopeSchema,
  faqEntryTier,
  LAYOUT_VOCABULARY,
  type IntakeEnvelope,
} from "@warpgogol/werkstatt-shared/onboarding/intake";
import type { WorkspaceIO } from "@warpgogol/werkstatt-shared/kernel/workspace-io";

/**
 * RFC-1540: the family visitor-question export shipped inside this package
 * (data/, written by werkstatt's family.questions.export). The last candidate
 * when no workspace copy exists — the standalone bin always resolves it.
 */
export function bundledFamilyQuestionsPath(): string | null {
  try {
    const url = new URL("../data/family-visitor-questions.generated.yaml", import.meta.url);
    return url.protocol === "file:" ? fileURLToPath(url) : null;
  } catch {
    return null; // non-file module URL (some test loaders) — the workspace candidates still apply
  }
}

export const INTAKE_RULE_IDS = [
  "INTAKE-01",
  "INTAKE-02",
  "INTAKE-03",
  "INTAKE-04",
  "INTAKE-05",
  "INTAKE-06",
  "INTAKE-07",
  "INTAKE-08",
  "INTAKE-09",
  "INTAKE-10",
  "INTAKE-11",
  "INTAKE-12",
  "INTAKE-13",
  "INTAKE-14",
  "INTAKE-15",
  "INTAKE-16",
  "INTAKE-17",
  "INTAKE-18",
  "INTAKE-19",
  "INTAKE-20",
  "INTAKE-21",
  "INTAKE-22",
  "INTAKE-23",
  "INTAKE-24",
  "INTAKE-25",
  "INTAKE-26",
  "INTAKE-27",
  "INTAKE-28",
  "INTAKE-29",
  "INTAKE-30",
  "INTAKE-31",
  "INTAKE-32",
  "INTAKE-33",
  "INTAKE-34",
] as const;

export type IntakeRuleId = (typeof INTAKE_RULE_IDS)[number];

/**
 * AMD-005/RFC-1328: evidence-ledger id shape plus the internal-assessment
 * vocabulary (evidence-source kinds, publishability gates) in free text.
 * Anchored — bare words ("source", "gap") never match.
 */
const INTERNAL_MARKER_RE =
  /\b(?:SRC|CLM|GAP|OPD|DEF|CHK|AST)-\d+|\b(?:internal_only|client-statement|after_proof)\b/;

/** Free-text fields INTAKE-12 scans on published entities (AMD-005). */
const PBP_FREE_TEXT_FIELDS = ["name", "statement", "summary", "description"] as const;

/**
 * AMD-005/RFC-1328: `visual.palette` keys must come from the canonical biome
 * palette vocabulary (`biomePaletteSchema.shape` keys — DNA-103 single source)
 * plus `background`, which aliases into the site background upstream
 * (`biome.from-intake` INTAKE_PALETTE_ALIASES).
 */
const CLOSED_PALETTE_KEYS: ReadonlySet<string> = new Set([
  ...Object.keys(biomePaletteSchema.shape),
  "background",
]);

export interface IntakeDiagnostic {
  rule: IntakeRuleId;
  severity: "error" | "warning";
  message: string;
  /** Bundle-relative file path, or JSON pointer into intake.json. */
  path?: string;
  /** Structured facts a rule emits alongside the message (INTAKE-34: asset/declared/detected). */
  facts?: Record<string, string>;
}

export interface IntakeValidateResult {
  command: "onboarding.intake.validate";
  status: "pass" | "fail";
  bundle: string;
  intakeId: string | null;
  systemId: string | null;
  contractSnapshot: { expected: string; actual: string | null };
  diagnostics: IntakeDiagnostic[];
}

export interface IntakeValidateOptions {
  /** sha256:<64hex> of the validator's own intake.schema.generated.yaml. */
  exportSha256: string;
  /** Budget ceiling for the INTAKE-11 warning. Default 5 USD. */
  costBudgetUsd?: number;
  /** Display form of the bundle path for the result payload. */
  bundleLabel?: string;
  /**
   * RFC-1353: explicit path of the vendored family visitor-question export —
   * hermetic test fixtures override; production resolves workspace-relative.
   */
  familyQuestionsPath?: string;
  /** Workspace root for the export's default resolution paths. */
  workspaceRoot?: string;
}

const EVIDENCE_SOURCE_SCHEMA = "pbp/evidence-source@1";
const CLAIM_SCHEMA = "pbp/claim@1";
const PBP_REF_RE = /^pbp\/([a-z][a-z0-9-]*)@(\d+):(.+)$/;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;

const ASSET_MEDIA_BY_EXT: Record<string, string> = {
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  webp: "image/webp",
  avif: "image/avif",
  mp4: "video/mp4",
  webm: "video/webm",
  pdf: "application/pdf",
};

function sha256Of(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function toPosix(p: string): string {
  return p.replace(/\\/g, "/");
}

/** Resolve `pbp/<type>@<v>:<id>` (PBP ref) or a bare `<id>` to { schema, id }. */
function resolveEntityRef(ref: string): { schema: string | null; id: string } {
  const m = PBP_REF_RE.exec(ref);
  if (m) return { schema: `pbp/${m[1]}@${m[2]}`, id: m[3] };
  return { schema: null, id: ref };
}

function isTextMediaType(mediaType: string | undefined): boolean {
  return (
    !!mediaType &&
    (mediaType.startsWith("text/") ||
      mediaType === "application/json" ||
      mediaType === "message/rfc822")
  );
}

/** RFC-1368's enumerated binary class — INTAKE-34's unknown-signature gate. */
function isBinaryMediaClass(mediaType: string | undefined): boolean {
  return (
    !!mediaType &&
    (mediaType.startsWith("image/") ||
      mediaType.startsWith("video/") ||
      mediaType.startsWith("font/") ||
      mediaType === "application/pdf")
  );
}

/**
 * sha256 of the vendored schema export as installed — resolved through the
 * package export map so the validator always hashes the artifact a producer
 * would vendor. Null when the file is absent (export not run / not vendored).
 */
export async function resolveIntakeExportSha256(
  io: WorkspaceIO,
): Promise<{ sha256: string; path: string } | null> {
  let url: string;
  try {
    url = import.meta
      .resolve("@warpgogol/werkstatt-shared/onboarding/intake.schema.generated.yaml");
  } catch {
    return null;
  }
  const path = fileURLToPath(url);
  if (!(await io.exists(path))) return null;
  const bytes = await io.readFileBytes(path);
  return { sha256: `sha256:${sha256Of(bytes)}`, path };
}

async function listBundleFiles(bundleDir: string, io: WorkspaceIO): Promise<string[]> {
  const entries = await io.glob("**/*", { cwd: bundleDir });
  const files: string[] = [];
  for (const rel of entries) {
    const stat = await io.stat(join(bundleDir, rel));
    if (stat.isFile) files.push(toPosix(rel));
  }
  return files.sort();
}

// --- RFC-1353/AMD-011: faq block helpers -------------------------------------

export interface FamilyVisitorQuestion {
  id: string;
  prompt: string;
  placement: "home" | "within-one-hop";
  families: string[];
}

/**
 * Load the vendored family visitor-question export the validator resolves
 * `visitorQuestionRef` against (INTAKE-26). Resolution order: an explicit
 * override (hermetic test fixtures), the workspace's generated file, the
 * vendored spec mirror, then the copy bundled in this package (RFC-1540). Null when none exists — bundles without
 * family-question entries never need it; bundles that do fail INTAKE-26
 * fail-closed.
 */
export async function loadFamilyQuestionsExport(
  io: WorkspaceIO,
  workspaceRoot: string,
  overridePath?: string,
): Promise<Map<string, FamilyVisitorQuestion>> {
  const candidates = overridePath
    ? [overridePath]
    : [
        join(
          workspaceRoot,
          "packages/werkstatt-site/src/onboarding/family-visitor-questions.generated.yaml",
        ),
        join(
          workspaceRoot,
          "docs/specs/werkstatt-onboarding/schemas/family-visitor-questions.generated.yaml",
        ),
        ...[bundledFamilyQuestionsPath()].filter((p): p is string => p !== null),
      ];
  for (const path of candidates) {
    if (!(await io.exists(path))) continue;
    try {
      const parsed = YAML.parse(await io.readFile(path)) as {
        questions?: Array<FamilyVisitorQuestion>;
      };
      const byId = new Map<string, FamilyVisitorQuestion>();
      for (const q of parsed?.questions ?? []) {
        if (typeof q?.id === "string") byId.set(q.id, q);
      }
      return byId;
    } catch {
      return new Map();
    }
  }
  return new Map();
}

/** Does the dotted field path exist on the entity (arrays indexed numerically)? */
function pbpFieldExists(entity: Record<string, unknown>, fieldPath: string): boolean {
  let cursor: unknown = entity;
  for (const segment of fieldPath.split(".")) {
    if (cursor === null || typeof cursor !== "object") return false;
    if (Array.isArray(cursor)) {
      const index = Number(segment);
      if (!Number.isInteger(index) || index < 0 || index >= cursor.length) return false;
      cursor = cursor[index];
      continue;
    }
    const record = cursor as Record<string, unknown>;
    if (!(segment in record)) return false;
    cursor = record[segment];
  }
  return cursor !== undefined;
}

/**
 * Identifying string values under the given field keys — the literals
 * INTAKE-28 forbids restating in faq answer text (they must ride
 * `{{pbp:…}}` tokens so a client-side edit never desynchronises them).
 */
function* identifyingValues(value: unknown, fields: ReadonlySet<string>): Generator<string> {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) yield* identifyingValues(item, fields);
    return;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (typeof child === "string") {
      if (fields.has(key)) yield child;
    } else {
      yield* identifyingValues(child, fields);
    }
  }
}

/**
 * Validate one intake bundle directory. Pure over `io` — no ambient fs.
 * INTAKE-03…11 run only when INTAKE-01 and INTAKE-02 produced no errors.
 */
export async function validateIntakeBundle(
  bundleDir: string,
  io: WorkspaceIO,
  options: IntakeValidateOptions,
): Promise<IntakeValidateResult> {
  const diagnostics: IntakeDiagnostic[] = [];
  const error = (
    rule: IntakeRuleId,
    message: string,
    path?: string,
    facts?: Record<string, string>,
  ): void => {
    diagnostics.push({
      rule,
      severity: "error",
      message,
      ...(path ? { path } : {}),
      ...(facts ? { facts } : {}),
    });
  };
  const warn = (
    rule: IntakeRuleId,
    message: string,
    path?: string,
    facts?: Record<string, string>,
  ): void => {
    diagnostics.push({
      rule,
      severity: "warning",
      message,
      ...(path ? { path } : {}),
      ...(facts ? { facts } : {}),
    });
  };

  const result: IntakeValidateResult = {
    command: "onboarding.intake.validate",
    status: "pass",
    bundle: options.bundleLabel ?? bundleDir,
    intakeId: null,
    systemId: null,
    contractSnapshot: { expected: options.exportSha256, actual: null },
    diagnostics,
  };

  // ---------------------------------------------------------------------
  // INTAKE-01 — MANIFEST.sha256 covers every file, hashes match, no strays
  // ---------------------------------------------------------------------
  let manifestClean = true;
  if (!(await io.exists(bundleDir))) {
    error("INTAKE-01", `bundle directory does not exist: ${bundleDir}`, bundleDir);
    manifestClean = false;
  } else {
    const manifestPath = join(bundleDir, "MANIFEST.sha256");
    if (!(await io.exists(manifestPath))) {
      error("INTAKE-01", "MANIFEST.sha256 is missing from the bundle", "MANIFEST.sha256");
      manifestClean = false;
    } else {
      const manifest = await io.readFile(manifestPath);
      const listed = new Map<string, string>();
      for (const [lineNo, rawLine] of manifest.split("\n").entries()) {
        const line = rawLine.trim();
        if (line === "") continue;
        const m = /^([0-9a-f]{64})\s+\*?(.+)$/.exec(line);
        if (!m) {
          error(
            "INTAKE-01",
            `MANIFEST.sha256 line ${lineNo + 1} is malformed: '${line}'`,
            "MANIFEST.sha256",
          );
          manifestClean = false;
          continue;
        }
        const rel = toPosix(m[2].trim());
        if (listed.has(rel)) {
          error("INTAKE-01", `MANIFEST.sha256 lists '${rel}' twice`, "MANIFEST.sha256");
          manifestClean = false;
          continue;
        }
        listed.set(rel, m[1]);
      }

      // composition/ is RFC-1324 fixture compose material, not intake payload —
      // it is exempt from manifest coverage (a real operator bundle never carries it).
      const diskFiles = (await listBundleFiles(bundleDir, io)).filter(
        (f) => f !== "MANIFEST.sha256" && !f.startsWith("composition/"),
      );
      const diskSet = new Set(diskFiles);

      for (const [rel, expectedSha] of listed) {
        if (rel.startsWith("composition/")) continue;
        if (!diskSet.has(rel)) {
          error("INTAKE-01", `MANIFEST.sha256 lists '${rel}' but the file is absent`, rel);
          manifestClean = false;
          continue;
        }
        const actual = sha256Of(await io.readFileBytes(join(bundleDir, rel)));
        if (actual !== expectedSha) {
          error(
            "INTAKE-01",
            `hash mismatch for '${rel}': manifest ${expectedSha}, actual ${actual}`,
            rel,
          );
          manifestClean = false;
        }
      }
      for (const rel of diskFiles) {
        if (!listed.has(rel)) {
          error("INTAKE-01", `file '${rel}' is not listed in MANIFEST.sha256`, rel);
          manifestClean = false;
        }
      }
    }
  }

  // ---------------------------------------------------------------------
  // INTAKE-02 — intake.json parses and validates against werkstatt:intake/v2;
  // an unknown schema major fails closed with a single diagnostic
  // ---------------------------------------------------------------------
  let envelope: IntakeEnvelope | null = null;
  try {
    const raw = await io.readFile(join(bundleDir, "intake.json"));
    const parsed: unknown = JSON.parse(raw);
    const schemaField =
      parsed !== null && typeof parsed === "object"
        ? (parsed as Record<string, unknown>).schema
        : undefined;
    if (
      typeof schemaField === "string" &&
      /^werkstatt:intake\/v\d+$/.test(schemaField) &&
      schemaField !== INTAKE_SCHEMA_ID
    ) {
      error(
        "INTAKE-02",
        `unsupported intake schema '${schemaField}' — validator supports '${INTAKE_SCHEMA_ID}' only (unknown major fails closed)`,
        "/schema",
      );
    } else {
      const parsed_ = intakeEnvelopeSchema.safeParse(parsed);
      if (!parsed_.success) {
        for (const issue of parsed_.error.issues) {
          error("INTAKE-02", issue.message, `/${issue.path.map((p) => String(p)).join("/")}`);
        }
      } else {
        envelope = parsed_.data;
      }
    }
  } catch (cause) {
    error(
      "INTAKE-02",
      `intake.json is missing or not valid JSON: ${(cause as Error).message}`,
      "intake.json",
    );
  }

  if (envelope !== null) {
    result.intakeId = envelope.intakeId;
    result.systemId = envelope.systemId;
    result.contractSnapshot.actual = envelope.provenance.contractSnapshot;
  }

  // ---------------------------------------------------------------------
  // INTAKE-03…11 — only when INTAKE-01 + INTAKE-02 produced no errors
  // ---------------------------------------------------------------------
  const hasErrors = (): boolean => diagnostics.some((d) => d.severity === "error");
  if (manifestClean && envelope !== null && !hasErrors()) {
    const env = envelope;

    // --- shared lookup tables ------------------------------------------
    const entitiesById = new Map<string, { index: number; entity: Record<string, unknown> }>();
    const claimIds = new Set<string>();
    const gapIds = new Set(env.gaps.map((g) => g.id));
    const assetIds = new Set(env.assets.map((a) => a.id));
    // AMD-015/RFC-1408: appliesTo rulings may bind slotBrief ids too.
    const slotBriefIds = new Set((env.slotBriefs ?? []).map((b) => b.id));
    // RFC-1353/AMD-011: faq entry ids participate in gap.blocks inverse coverage.
    const faqEntryIds = new Set((env.faq?.entries ?? []).map((e) => e.id));

    // --- INTAKE-03: canonical PBP validation -----------------------------
    for (const [i, entity] of env.pbp.entries()) {
      if (entitiesById.has(entity.id)) {
        error("INTAKE-03", `duplicate pbp entity id '${entity.id}'`, `/pbp/${i}/id`);
      }
      entitiesById.set(entity.id, { index: i, entity: entity as Record<string, unknown> });
      if (entity.schema === CLAIM_SCHEMA) claimIds.add(entity.id);

      const canonical = pbpSchemaById[entity.schema];
      if (!canonical) {
        error(
          "INTAKE-03",
          `no canonical PBP schema registered for '${entity.schema}'`,
          `/pbp/${i}/schema`,
        );
        continue;
      }
      // AMD-005: statementByLocale/localeNeutral are envelope-level fields —
      // the frozen pbp/*@1 schemas never see them (strict parse).
      const {
        statementByLocale: _statementByLocale,
        localeNeutral: _localeNeutral,
        ...canonicalEntity
      } = entity as Record<string, unknown>;
      const r = canonical.safeParse(canonicalEntity);
      if (!r.success) {
        for (const issue of r.error.issues) {
          error(
            "INTAKE-03",
            `entity '${entity.id}': ${issue.message}`,
            `/pbp/${i}${issue.path.length > 0 ? `/${issue.path.map((p) => String(p)).join("/")}` : ""}`,
          );
        }
      }
    }

    const checkPbpRef = (ref: string, path: string): void => {
      const { id } = resolveEntityRef(ref);
      if (!entitiesById.has(id)) {
        error("INTAKE-04", `unresolved pbp entity ref '${ref}'`, path);
      }
    };
    const checkGapRef = (ref: string, path: string): void => {
      if (!gapIds.has(ref)) {
        error("INTAKE-04", `unresolved gap ref '${ref}'`, path);
      }
    };
    const checkEvidenceRef = (ref: string, path: string): void => {
      const { schema, id } = resolveEntityRef(ref);
      if (schema !== null && schema !== EVIDENCE_SOURCE_SCHEMA) {
        error(
          "INTAKE-04",
          `evidence ref '${ref}' points at schema '${schema}', not '${EVIDENCE_SOURCE_SCHEMA}'`,
          path,
        );
        return;
      }
      const target = entitiesById.get(id);
      if (!target) {
        error("INTAKE-04", `unresolved evidence-source ref '${ref}'`, path);
      } else if ((target.entity as { schema?: string }).schema !== EVIDENCE_SOURCE_SCHEMA) {
        error(
          "INTAKE-04",
          `ref '${ref}' resolves to '${(target.entity as { schema?: string }).schema}', not an evidence-source`,
          path,
        );
      }
    };

    // --- INTAKE-04: referential integrity ---------------------------------
    // annotation keys → pbp ids; annotation contents → gaps/evidence.
    for (const [entityId, annotation] of Object.entries(env.annotations)) {
      checkPbpRef(entityId, `/annotations/${entityId}`);
      for (const [j, ref] of (annotation.blockers ?? []).entries()) {
        checkGapRef(ref, `/annotations/${entityId}/blockers/${j}`);
      }
      for (const [j, vb] of (annotation.verbatim ?? []).entries()) {
        checkEvidenceRef(vb.sourceRef, `/annotations/${entityId}/verbatim/${j}/sourceRef`);
      }
    }
    // operatorDecision.appliesTo → pbp entity, gap, asset, or slotBrief ids
    // (AMD-015: slotBrief joined the target space for projected rulings).
    for (const [i, decision] of env.operatorDecisions.entries()) {
      for (const [j, ref] of (decision.appliesTo ?? []).entries()) {
        const { id } = resolveEntityRef(ref);
        if (
          !entitiesById.has(id) &&
          !gapIds.has(id) &&
          !assetIds.has(id) &&
          !slotBriefIds.has(id)
        ) {
          error(
            "INTAKE-04",
            `unresolved operatorDecision appliesTo ref '${ref}'`,
            `/operatorDecisions/${i}/appliesTo/${j}`,
          );
        }
      }
    }
    // gap.blocks → pbp ids or RFC-1353 faq entry ids; gap.evidenceRefs → evidence-source ids.
    for (const [i, gap] of env.gaps.entries()) {
      for (const [j, ref] of gap.blocks.entries()) {
        const { id } = resolveEntityRef(ref);
        if (!entitiesById.has(id) && !faqEntryIds.has(id)) {
          error("INTAKE-04", `unresolved pbp entity ref '${ref}'`, `/gaps/${i}/blocks/${j}`);
        }
      }
      for (const [j, ref] of (gap.evidenceRefs ?? []).entries()) {
        checkEvidenceRef(ref, `/gaps/${i}/evidenceRefs/${j}`);
      }
    }
    // voice sourceRefs → evidence-source; claimRefs → claim ids.
    for (const [i, item] of env.voice.verbatim.entries()) {
      checkEvidenceRef(item.sourceRef, `/voice/verbatim/${i}/sourceRef`);
      for (const [j, ref] of (item.claimRefs ?? []).entries()) {
        if (!claimIds.has(ref)) {
          error(
            "INTAKE-04",
            `unresolved claim ref '${ref}'`,
            `/voice/verbatim/${i}/claimRefs/${j}`,
          );
        }
      }
    }
    for (const [i, item] of env.voice.directives.entries()) {
      checkEvidenceRef(item.sourceRef, `/voice/directives/${i}/sourceRef`);
    }
    // classification evidenceRefs → evidence-source ids.
    for (const [i, locale] of env.classification.locales.entries()) {
      for (const [j, ref] of (locale.evidenceRefs ?? []).entries()) {
        checkEvidenceRef(ref, `/classification/locales/${i}/evidenceRefs/${j}`);
      }
    }
    for (const [i, intent] of env.classification.pageSetIntent.entries()) {
      for (const [j, ref] of intent.evidenceRefs.entries()) {
        checkEvidenceRef(ref, `/classification/pageSetIntent/${i}/evidenceRefs/${j}`);
      }
      for (const [j, ref] of (intent.entityRefs ?? []).entries()) {
        checkPbpRef(ref, `/classification/pageSetIntent/${i}/entityRefs/${j}`);
      }
    }
    // claim evidenceRefs → evidence-source ids; asset refs → assets/gaps/evidence.
    for (const [i, entity] of env.pbp.entries()) {
      if (entity.schema !== CLAIM_SCHEMA) continue;
      const refs = (entity as { evidenceRefs?: Record<string, { ref?: string }> }).evidenceRefs;
      for (const [key, entry] of Object.entries(refs ?? {})) {
        if (entry && typeof entry.ref === "string") {
          checkEvidenceRef(entry.ref, `/pbp/${i}/evidenceRefs/${key}/ref`);
        }
      }
    }
    for (const [i, asset] of env.assets.entries()) {
      for (const [j, ref] of (asset.rights.blockers ?? []).entries()) {
        checkGapRef(ref, `/assets/${i}/rights/blockers/${j}`);
      }
      if (asset.rights.evidenceRef) {
        checkEvidenceRef(asset.rights.evidenceRef, `/assets/${i}/rights/evidenceRef`);
      }
      // RFC-1345: depicts.entityRefs → pbp ids (claims included); the same
      // check covers mediaHints[].depicts on document assets.
      for (const [k, ref] of (asset.depicts?.entityRefs ?? []).entries()) {
        checkPbpRef(ref, `/assets/${i}/depicts/entityRefs/${k}`);
      }
      for (const [j, hint] of (asset.mediaHints ?? []).entries()) {
        for (const [k, ref] of (hint.depicts.entityRefs ?? []).entries()) {
          checkPbpRef(ref, `/assets/${i}/mediaHints/${j}/depicts/entityRefs/${k}`);
        }
      }
    }
    for (const [i, ref] of (env.visual.moodAssetRefs ?? []).entries()) {
      if (!assetIds.has(ref)) {
        error("INTAKE-04", `unresolved mood asset ref '${ref}'`, `/visual/moodAssetRefs/${i}`);
      }
    }
    // every evidence-source item sha256 → a sources/<sha256>.* file exists.
    for (const { entity } of entitiesById.values()) {
      if ((entity as { schema?: string }).schema !== EVIDENCE_SOURCE_SCHEMA) continue;
      const items = (
        entity as {
          items?: Record<string, { sha256?: string }>;
        }
      ).items;
      for (const [key, item] of Object.entries(items ?? {})) {
        if (!item.sha256) continue;
        const matches = await io.glob(`sources/${item.sha256}.*`, { cwd: bundleDir });
        if (matches.length === 0) {
          error(
            "INTAKE-04",
            `evidence item '${key}' of '${(entity as { id?: string }).id}' names sha256 ${item.sha256} but no sources/${item.sha256}.* exists`,
            `/pbp/${(entity as { id?: string }).id}/items/${key}/sha256`,
          );
        }
      }
    }

    // --- INTAKE-05: byte-exact verbatim quotes ----------------------------
    interface VerbatimCheck {
      text: string;
      sourceRef: string;
      path: string;
    }
    const verbatimChecks: VerbatimCheck[] = [];
    for (const [entityId, annotation] of Object.entries(env.annotations)) {
      for (const [j, vb] of (annotation.verbatim ?? []).entries()) {
        verbatimChecks.push({
          text: vb.text,
          sourceRef: vb.sourceRef,
          path: `/annotations/${entityId}/verbatim/${j}/text`,
        });
      }
    }
    for (const [i, item] of env.voice.verbatim.entries()) {
      verbatimChecks.push({
        text: item.text,
        sourceRef: item.sourceRef,
        path: `/voice/verbatim/${i}/text`,
      });
    }
    for (const [i, item] of env.voice.directives.entries()) {
      verbatimChecks.push({
        text: item.text,
        sourceRef: item.sourceRef,
        path: `/voice/directives/${i}/text`,
      });
    }
    // RFC-1353/AMD-011: faq entry verbatim rides the same byte-exact check.
    for (const [i, entry] of (env.faq?.entries ?? []).entries()) {
      for (const [j, vb] of (entry.verbatim ?? []).entries()) {
        verbatimChecks.push({
          text: vb.text,
          sourceRef: vb.sourceRef,
          path: `/faq/entries/${i}/verbatim/${j}/text`,
        });
      }
    }

    for (const check of verbatimChecks) {
      const { id } = resolveEntityRef(check.sourceRef);
      const target = entitiesById.get(id);
      // Unresolvable/wrong-type refs are already reported by INTAKE-04.
      if (!target || (target.entity as { schema?: string }).schema !== EVIDENCE_SOURCE_SCHEMA) {
        continue;
      }
      const items = (
        target.entity as {
          items?: Record<string, { sha256?: string; mediaType?: string }>;
        }
      ).items;
      const textItems = Object.values(items ?? {}).filter(
        (item) => item.sha256 && isTextMediaType(item.mediaType),
      );
      if (textItems.length === 0) {
        error(
          "INTAKE-05",
          `source '${check.sourceRef}' has no text-typed items — verbatim text cannot be substring-checked`,
          check.path,
        );
        continue;
      }
      let sawFile = false;
      let found = false;
      for (const item of textItems) {
        for (const rel of await io.glob(`sources/${item.sha256}.*`, { cwd: bundleDir })) {
          sawFile = true;
          const content = await io.readFile(join(bundleDir, rel));
          if (content.includes(check.text)) {
            found = true;
            break;
          }
        }
        if (found) break;
      }
      if (sawFile && !found) {
        error(
          "INTAKE-05",
          `verbatim text is not a byte-exact substring of any text-typed item of '${check.sourceRef}'`,
          check.path,
        );
      }
    }

    // --- INTAKE-06: retired into the schema (AMD-007) ----------------------
    // v2 enforces "draft ⇒ internal or blockers ≥1" on the envelope
    // superRefine — the violation surfaces as INTAKE-02 before this block
    // runs. The rule id stays declared for spec/reporting stability.

    // --- INTAKE-07: locales ----------------------------------------------
    const localeTags = env.classification.locales.map((l) => l.tag);
    if (new Set(localeTags).size !== localeTags.length) {
      error("INTAKE-07", "duplicate BCP 47 locale tags", "/classification/locales");
    }
    const primaries = env.classification.locales.filter((l) => l.role === "primary");
    if (primaries.length !== 1) {
      error(
        "INTAKE-07",
        `expected exactly one primary locale, found ${primaries.length}`,
        "/classification/locales",
      );
    }
    const allowedLangs = new Set(localeTags.flatMap((tag) => [tag, tag.split("-")[0]]));
    for (const [i, entity] of env.pbp.entries()) {
      if (entity.schema !== CLAIM_SCHEMA || entity.status !== "published") continue;
      const lang = (entity as { statementLang?: string }).statementLang;
      if (lang && !allowedLangs.has(lang)) {
        error(
          "INTAKE-07",
          `published claim '${entity.id}' statementLang '${lang}' is not among classification locales`,
          `/pbp/${i}/statementLang`,
        );
      }
    }

    // --- INTAKE-08: visual axes via the live biomeAxesSchema --------------
    const axesResult = biomeAxesSchema.safeParse(env.visual.axes);
    if (!axesResult.success) {
      for (const issue of axesResult.error.issues) {
        error(
          "INTAKE-08",
          `visual.axes: ${issue.message}`,
          `/visual/axes${issue.path.length > 0 ? `/${issue.path.map((p) => String(p)).join("/")}` : ""}`,
        );
      }
    }
    for (const [i, font] of env.visual.fonts.entries()) {
      if (!font.scripts || font.scripts.length === 0) {
        error(
          "INTAKE-08",
          `font '${font.family}' declares no ISO 15924 scripts`,
          `/visual/fonts/${i}/scripts`,
        );
      }
    }

    // --- INTAKE-09: asset files -------------------------------------------
    for (const [i, asset] of env.assets.entries()) {
      const assetPath = `/assets/${i}`;
      const fileAbs = join(bundleDir, asset.file);
      if (!(await io.exists(fileAbs))) {
        error("INTAKE-09", `asset file '${asset.file}' is missing`, `${assetPath}/file`);
        continue;
      }
      const bytes = await io.readFileBytes(fileAbs);
      const actualSha = `sha256:${sha256Of(bytes)}`;
      if (actualSha !== asset.sha256) {
        error(
          "INTAKE-09",
          `asset '${asset.id}' sha256 mismatch — declared ${asset.sha256}, actual ${actualSha}`,
          `${assetPath}/sha256`,
        );
      }
      const stem = asset.file.slice("assets/".length, asset.file.lastIndexOf("."));
      if (SHA256_RE.test(asset.sha256) && asset.sha256 !== `sha256:${stem}`) {
        error(
          "INTAKE-09",
          `asset '${asset.id}' sha256 does not equal its content-addressed name '${asset.file}'`,
          `${assetPath}/file`,
        );
      }
      const ext = asset.file.slice(asset.file.lastIndexOf(".") + 1);
      const expectedMedia = ASSET_MEDIA_BY_EXT[ext];
      if (expectedMedia && asset.mediaType !== expectedMedia) {
        error(
          "INTAKE-09",
          `asset '${asset.id}' mediaType '${asset.mediaType}' does not match '.${ext}' (expected '${expectedMedia}')`,
          `${assetPath}/mediaType`,
        );
      }
      // INTAKE-34 (RFC-1368): the declared mediaType is verified against the
      // payload's magic bytes — the claim, not the filename. Two claims stay
      // unfalsifiable: text/xml-family declarations against a markup signature
      // (`<svg`/`<?xml` detects markup, not svg-ness — an honest application/xml
      // label is not a mislabel), and declarations outside the enumerated
      // binary class against an unrecognized signature.
      const sniffed = sniffMediaType(bytes);
      const markupClaim =
        isTextMediaType(asset.mediaType) || /[/+]xml$/.test(asset.mediaType ?? "");
      if (sniffed === "image/svg+xml" && markupClaim) {
        // unfalsifiable — markup signature vs a markup-family declaration
      } else if (sniffed && sniffed !== asset.mediaType) {
        error(
          "INTAKE-34",
          `asset '${asset.id}' mediaType '${asset.mediaType}' does not match sniffed '${sniffed}'`,
          `${assetPath}/mediaType`,
          { asset: asset.id, declared: asset.mediaType, detected: sniffed },
        );
      } else if (!sniffed && isBinaryMediaClass(asset.mediaType)) {
        error(
          "INTAKE-34",
          `asset '${asset.id}' declares binary mediaType '${asset.mediaType}' but the payload signature is unrecognized`,
          `${assetPath}/mediaType`,
          { asset: asset.id, declared: asset.mediaType, detected: "unrecognized" },
        );
      }
      if (asset.origin === "generated" && !asset.generator) {
        error(
          "INTAKE-09",
          `asset '${asset.id}' is origin 'generated' but carries no generator provenance`,
          `${assetPath}/generator`,
        );
      }
      if (asset.rights.state === "licensed-stock" && !asset.rights.licence) {
        error(
          "INTAKE-09",
          `asset '${asset.id}' is 'licensed-stock' but declares no licence`,
          `${assetPath}/rights/licence`,
        );
      }
    }

    // --- INTAKE-10: provenance completeness --------------------------------
    if (env.provenance.contractSnapshot !== options.exportSha256) {
      error(
        "INTAKE-10",
        `provenance.contractSnapshot ${env.provenance.contractSnapshot} does not match the validator's schema export ${options.exportSha256} — producer must re-vendor intake.schema.generated.yaml`,
        "/provenance/contractSnapshot",
      );
    }
    for (const [i, input] of env.provenance.inputs.entries()) {
      // z.literal(false) makes clipped:true unreachable after INTAKE-02 —
      // kept as a defensive belt for future envelope loosening.
      if ((input as { clipped?: boolean }).clipped === true) {
        error(
          "INTAKE-10",
          `provenance.inputs[${i}] '${input.path}' was clipped (P1 forbids)`,
          `/provenance/inputs/${i}/clipped`,
        );
      }
    }
    if (env.provenance.quoteCheck.result !== "pass") {
      error(
        "INTAKE-10",
        `provenance.quoteCheck.result is '${env.provenance.quoteCheck.result}', expected 'pass'`,
        "/provenance/quoteCheck/result",
      );
    }

    // --- INTAKE-11: cost report — warnings only, never blocks --------------
    if (!(await io.exists(join(bundleDir, "cost-report.json")))) {
      warn("INTAKE-11", "cost-report.json is missing from the bundle", "cost-report.json");
    }
    const budget = options.costBudgetUsd ?? 5;
    if (env.provenance.cost.total > budget) {
      warn(
        "INTAKE-11",
        `provenance.cost.total $${env.provenance.cost.total} exceeds budget $${budget}`,
        "/provenance/cost/total",
      );
    }

    // --- INTAKE-12: public-safe free text on published entities (AMD-005) --
    // Anchored on the evidence-ledger id shape — bare words never match.
    for (const [i, entity] of env.pbp.entries()) {
      if (entity.status !== "published") continue;
      for (const field of PBP_FREE_TEXT_FIELDS) {
        const value = (entity as Record<string, unknown>)[field];
        if (typeof value === "string" && INTERNAL_MARKER_RE.test(value)) {
          error(
            "INTAKE-12",
            `published entity '${entity.id}' ${field} contains an internal marker`,
            `/pbp/${i}/${field}`,
          );
        }
      }
    }

    // --- INTAKE-13 + INTAKE-18: locale-native statements (AMD-005/AMD-007) --
    // The root statement field is the primary-locale value; statementByLocale
    // must cover the rest, unless the statement is locale-neutral. INTAKE-13
    // covers published entities; AMD-007 widens the same coverage to
    // `ceiling: preview` entities (INTAKE-18) so preview-tier content never
    // reaches a secondary-locale site with English statements.
    const nonPrimaryLocaleTags = env.classification.locales
      .filter((l) => l.role !== "primary")
      .map((l) => l.tag);
    for (const [i, entity] of env.pbp.entries()) {
      const isPreview = env.annotations[entity.id]?.ceiling === "preview";
      const rule: IntakeRuleId = entity.status === "published" ? "INTAKE-13" : "INTAKE-18";
      if (entity.status !== "published" && !isPreview) continue;
      if (entity.localeNeutral === true) continue;
      const e = entity as Record<string, unknown>;
      const carriesStatement =
        typeof e["statement"] === "string" || typeof e["summary"] === "string";
      if (!carriesStatement) continue;
      const byLocale = (e["statementByLocale"] ?? {}) as Record<string, unknown>;
      for (const tag of nonPrimaryLocaleTags) {
        if (typeof byLocale[tag] !== "string" || byLocale[tag] === "") {
          error(
            rule,
            `${entity.status === "published" ? "published" : "preview-tier"} entity '${entity.id}' has no statementByLocale value for site locale '${tag}' — localise the statement or mark localeNeutral`,
            `/pbp/${i}/statementByLocale`,
          );
        }
      }
    }

    // --- INTAKE-14: raster assets are WebP (AMD-005) -----------------------
    for (const [i, asset] of env.assets.entries()) {
      if (
        asset.mediaType.startsWith("image/") &&
        asset.mediaType !== "image/webp" &&
        asset.mediaType !== "image/svg+xml"
      ) {
        error(
          "INTAKE-14",
          `asset '${asset.id}' mediaType '${asset.mediaType}' is a raster type — the platform serves image/webp only`,
          `/assets/${i}/mediaType`,
        );
      }
    }

    // --- INTAKE-15: closed palette vocabulary (AMD-005) --------------------
    for (const key of Object.keys(env.visual.palette)) {
      if (!CLOSED_PALETTE_KEYS.has(key)) {
        error(
          "INTAKE-15",
          `visual.palette key '${key}' is outside the closed biome vocabulary — map it to a canonical key before emitting`,
          `/visual/palette/${key}`,
        );
      }
    }

    // --- INTAKE-16…20: typed claim-use/blocker edges (AMD-007) --------------
    const gapsById = new Map(env.gaps.map((g) => [g.id, g]));
    const entitiesBlockingGap = new Map<string, Set<string>>();
    for (const [entityId, annotation] of Object.entries(env.annotations)) {
      for (const gapId of annotation.blockers ?? []) {
        let set = entitiesBlockingGap.get(gapId);
        if (!set) {
          set = new Set();
          entitiesBlockingGap.set(gapId, set);
        }
        set.add(entityId);
      }
    }

    // --- INTAKE-16: scope-extension/operational gaps block nothing ---------
    // An open question about growing a set never blocks its established
    // members; process gaps (domain, billing) never gate publishable content.
    // RFC-1345: asset rights.blockers is a third blockers location — a
    // scope-extension/operational gap must not gate an asset either.
    const assetsBlockingGap = new Map<string, Set<string>>();
    for (const asset of env.assets) {
      for (const gapId of asset.rights.blockers ?? []) {
        let set = assetsBlockingGap.get(gapId);
        if (!set) {
          set = new Set();
          assetsBlockingGap.set(gapId, set);
        }
        set.add(asset.id);
      }
    }
    for (const [i, gap] of env.gaps.entries()) {
      if (gap.kind !== "scope-extension" && gap.kind !== "operational") continue;
      if (gap.blocks.length > 0) {
        error(
          "INTAKE-16",
          `${gap.kind} gap '${gap.id}' declares a non-empty blocks[] — it must not gate any entity`,
          `/gaps/${i}/blocks`,
        );
      }
      const blockedBy = entitiesBlockingGap.get(gap.id);
      if (blockedBy && blockedBy.size > 0) {
        error(
          "INTAKE-16",
          `${gap.kind} gap '${gap.id}' appears in blockers of ${[...blockedBy].sort().join(", ")} — it must not gate any entity`,
          `/gaps/${i}`,
        );
      }
      const blockedAssets = assetsBlockingGap.get(gap.id);
      if (blockedAssets && blockedAssets.size > 0) {
        error(
          "INTAKE-16",
          `${gap.kind} gap '${gap.id}' appears in rights.blockers of assets ${[...blockedAssets].sort().join(", ")} — it must not gate any asset`,
          `/gaps/${i}`,
        );
      }
    }

    // --- INTAKE-17: preview ceilings need rights/approval blockers only ----
    for (const [entityId, annotation] of Object.entries(env.annotations)) {
      const entity = entitiesById.get(entityId);
      if (!entity) continue; // unresolved key already reported by INTAKE-04
      if (
        annotation.internal === true &&
        annotation.ceiling !== undefined &&
        annotation.ceiling !== "draft"
      ) {
        error(
          "INTAKE-17",
          `internal entity '${entityId}' declares ceiling '${annotation.ceiling}' — internal entities stay draft`,
          `/annotations/${entityId}/ceiling`,
        );
      }
      if (annotation.ceiling !== "preview") continue;
      for (const gapId of annotation.blockers ?? []) {
        const gap = gapsById.get(gapId);
        if (!gap) continue; // unresolved ref already reported by INTAKE-04
        if (gap.kind !== "rights" && gap.kind !== "approval") {
          error(
            "INTAKE-17",
            `preview-tier entity '${entityId}' is blocked by ${gap.kind} gap '${gapId}' — preview requires rights/approval blockers only`,
            `/annotations/${entityId}/blockers`,
          );
        }
      }
    }

    // --- INTAKE-19: gap.blocks ⇔ annotation.blockers inverse ---------------
    // RFC-1353: refs resolving to faq entry ids are checked in the faq
    // block's own inverse pass — skipped here.
    for (const [i, gap] of env.gaps.entries()) {
      const expected = entitiesBlockingGap.get(gap.id) ?? new Set<string>();
      const declared = new Set(
        gap.blocks.map((ref) => resolveEntityRef(ref).id).filter((id) => !faqEntryIds.has(id)),
      );
      for (const ref of declared) {
        if (!expected.has(ref)) {
          error(
            "INTAKE-19",
            `gap '${gap.id}' blocks[] names '${ref}' but that entity's blockers do not contain the gap`,
            `/gaps/${i}/blocks`,
          );
        }
      }
      for (const ref of expected) {
        if (!declared.has(ref)) {
          error(
            "INTAKE-19",
            `entity '${ref}' is blocked by gap '${gap.id}' but the gap's blocks[] does not name it`,
            `/gaps/${i}/blocks`,
          );
        }
      }
    }

    // --- INTAKE-20: publication-tier rulings reflected in ceilings ---------
    // A grantsTier:preview ruling is mechanical — every entity it names that
    // is blocked only by rights/approval gaps MUST carry ceiling:preview.
    for (const [i, decision] of env.operatorDecisions.entries()) {
      if (decision.effect !== "publication-tier" || decision.grantsTier !== "preview") continue;
      for (const ref of decision.appliesTo ?? []) {
        const { id } = resolveEntityRef(ref);
        const target = entitiesById.get(id);
        if (!target) continue; // unresolved ref already reported by INTAKE-04
        // Only drafts can carry a ceiling to raise — published entities need
        // none, superseded are historical.
        if ((target.entity as { status?: string }).status !== "draft") continue;
        const annotation = env.annotations[id];
        const blockerKinds = (annotation?.blockers ?? [])
          .map((gapId) => gapsById.get(gapId)?.kind)
          .filter((k): k is NonNullable<typeof k> => k !== undefined);
        const onlyPublishableKinds = blockerKinds.every((k) => k === "rights" || k === "approval");
        if (onlyPublishableKinds && annotation?.ceiling !== "preview") {
          error(
            "INTAKE-20",
            `decision '${decision.id}' grants preview to '${id}' (rights/approval blockers only) but the entity's ceiling is '${annotation?.ceiling ?? "draft"}' — apply the ruling or remove it`,
            `/operatorDecisions/${i}/appliesTo`,
          );
        }
      }
    }

    // --- INTAKE-21…23: document-derived media (RFC-1345/AMD-009) -----------
    const assetsById = new Map(env.assets.map((a) => [a.id, a]));

    // --- INTAKE-21: derivedFrom.asset → a document asset, hash-matched ------
    // Extraction provenance must name a real bundle document whose content
    // hash equals sourceSha256 — a stale or fabricated chain is an error.
    for (const [i, asset] of env.assets.entries()) {
      const from = asset.derivedFrom;
      if (!from) continue;
      const source = assetsById.get(from.asset);
      if (!source) {
        error(
          "INTAKE-21",
          `asset '${asset.id}' derivedFrom.asset '${from.asset}' resolves to no asset in the bundle`,
          `/assets/${i}/derivedFrom/asset`,
        );
        continue;
      }
      if (source.kind !== "document") {
        error(
          "INTAKE-21",
          `asset '${asset.id}' derivedFrom.asset '${from.asset}' is kind '${source.kind}', not 'document'`,
          `/assets/${i}/derivedFrom/asset`,
        );
        continue;
      }
      if (source.sha256 !== from.sourceSha256) {
        error(
          "INTAKE-21",
          `asset '${asset.id}' derivedFrom.sourceSha256 does not equal source asset '${from.asset}' sha256`,
          `/assets/${i}/derivedFrom/sourceSha256`,
        );
      }
    }

    // --- INTAKE-22: extraction never upgrades or sheds rights --------------
    // An extracted asset inherits the source document's rights state AND
    // blockers verbatim — rights change only through gap closure, never
    // through extraction.
    for (const [i, asset] of env.assets.entries()) {
      const from = asset.derivedFrom;
      if (!from) continue;
      const source = assetsById.get(from.asset);
      if (!source || source.kind !== "document") continue; // INTAKE-21 owns
      if (asset.rights.state !== source.rights.state) {
        error(
          "INTAKE-22",
          `extracted asset '${asset.id}' rights.state '${asset.rights.state}' differs from source '${from.asset}' state '${source.rights.state}' — extraction never changes rights`,
          `/assets/${i}/rights/state`,
        );
      }
      const assetBlockers = [...(asset.rights.blockers ?? [])].sort();
      const sourceBlockers = [...(source.rights.blockers ?? [])].sort();
      if (
        assetBlockers.length !== sourceBlockers.length ||
        assetBlockers.some((b, j) => b !== sourceBlockers[j])
      ) {
        error(
          "INTAKE-22",
          `extracted asset '${asset.id}' rights.blockers ${JSON.stringify(asset.rights.blockers ?? [])} differ from source '${from.asset}' blockers ${JSON.stringify(source.rights.blockers ?? [])} — extraction never sheds or adds blockers`,
          `/assets/${i}/rights/blockers`,
        );
      }
    }

    // --- INTAKE-23: generated imagery never depicts reality -----------------
    // A generated asset may carry atmosphere/illustration/abstract only —
    // claiming it shows a represented product (or brand mark, people, place)
    // is the dp7 "cream jar among pink roses" defect this RFC forbids.
    const GENERATED_DEPICTS_KINDS = new Set(["atmosphere", "illustration", "abstract"]);
    for (const [i, asset] of env.assets.entries()) {
      if (asset.origin !== "generated" || !asset.depicts) continue;
      if (!GENERATED_DEPICTS_KINDS.has(asset.depicts.kind)) {
        error(
          "INTAKE-23",
          `generated asset '${asset.id}' declares depicts.kind '${asset.depicts.kind}' — generated imagery may only depict atmosphere, illustration, or abstract`,
          `/assets/${i}/depicts/kind`,
        );
      }
    }

    // --- INTAKE-24: generated assets are mood concepts only (RFC-1346) ------
    // Final illustrations are refused in the bundle — generation moved to the
    // post-approval asset.slot.fulfill command. What remains is the three G-V
    // concept mood images, each traceable to a chosen or rejected concept.
    const conceptIds = new Set([env.visual.conceptId, ...(env.visual.rejectedConceptIds ?? [])]);
    for (const [i, asset] of env.assets.entries()) {
      if (asset.origin !== "generated") continue;
      if (asset.kind !== "mood") {
        error(
          "INTAKE-24",
          `generated asset '${asset.id}' has kind '${asset.kind}' — v2 bundles carry generated assets only as concept mood images; final illustrations are produced by asset.slot.fulfill after visual-review approval`,
          `/assets/${i}/kind`,
        );
      }
      if (!asset.generator?.conceptId || !conceptIds.has(asset.generator.conceptId)) {
        error(
          "INTAKE-24",
          `generated asset '${asset.id}' does not reference the chosen or a rejected visual concept (generator.conceptId '${asset.generator?.conceptId ?? "<absent>"}')`,
          `/assets/${i}/generator/conceptId`,
        );
      }
    }

    // --- INTAKE-25: slotBriefs resolve to intents and real refs (RFC-1346) --
    // Every brief's intent names a classification.pageSetIntent entry;
    // preferredSources resolve to bundle asset ids; awaitingGap resolves to a
    // gap id. (The no-prompt/sources-or-gap conditional on
    // depicts-represented-product is contract-level — the schema owns it.)
    const pageIntentSet = new Set(env.classification.pageSetIntent.map((p) => p.intent));
    const assetIdSet = new Set(env.assets.map((a) => a.id));
    const gapIdSet = new Set(env.gaps.map((g) => g.id));
    for (const [i, brief] of (env.slotBriefs ?? []).entries()) {
      if (!pageIntentSet.has(brief.intent)) {
        error(
          "INTAKE-25",
          `slot brief '${brief.id}' names intent '${brief.intent}' — no classification.pageSetIntent entry carries that intent`,
          `/slotBriefs/${i}/intent`,
        );
      }
      for (const [j, source] of (brief.preferredSources ?? []).entries()) {
        if (!assetIdSet.has(source)) {
          error(
            "INTAKE-25",
            `slot brief '${brief.id}' preferredSources[${j}] '${source}' resolves to no asset in the bundle`,
            `/slotBriefs/${i}/preferredSources/${j}`,
          );
        }
      }
      if (brief.awaitingGap !== undefined && !gapIdSet.has(brief.awaitingGap)) {
        error(
          "INTAKE-25",
          `slot brief '${brief.id}' awaitingGap '${brief.awaitingGap}' resolves to no gap in the bundle`,
          `/slotBriefs/${i}/awaitingGap`,
        );
      }
    }

    // --- RFC-1357/AMD-012: first-fold art direction (INTAKE-30…33) ---------

    // --- INTAKE-30: layout vocabulary refused in image prose --------------
    // Image models render page-layout words literally (the dp7 rounded-corner
    // panel). The closed list is whole-word/whole-phrase, case-insensitive —
    // "a stack of paper cards" passes, "rounded corner" does not.
    const layoutPatterns = LAYOUT_VOCABULARY.map(
      (term) => new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i"),
    );
    const checkLayoutVocab = (text: string | undefined, where: string, path: string): void => {
      if (typeof text !== "string") return;
      for (const [t, re] of layoutPatterns.entries()) {
        if (re.test(text)) {
          error(
            "INTAKE-30",
            `${where} contains layout term '${LAYOUT_VOCABULARY[t]}' — prompts describe photography only; composition intent belongs to artDirection/slot framing`,
            path,
          );
        }
      }
    };
    for (const [i, brief] of (env.slotBriefs ?? []).entries()) {
      checkLayoutVocab(brief.prompt, `slot brief '${brief.id}' prompt`, `/slotBriefs/${i}/prompt`);
      for (const [j, c] of (brief.constraints ?? []).entries()) {
        checkLayoutVocab(
          c,
          `slot brief '${brief.id}' constraints[${j}]`,
          `/slotBriefs/${i}/constraints/${j}`,
        );
      }
    }
    checkLayoutVocab(
      env.visual.artDirection.firstFold.imageSubject,
      "artDirection.firstFold.imageSubject",
      "/visual/artDirection/firstFold/imageSubject",
    );
    checkLayoutVocab(
      env.visual.artDirection.imagery.style,
      "artDirection.imagery.style",
      "/visual/artDirection/imagery/style",
    );

    // --- INTAKE-31: slotRef resolves to the single first-fold brief --------
    // of the home intent (AMD-012). Brief ids must be unique — a last-wins
    // Map would let a same-id brief shadow the real target silently.
    const briefIdCounts = new Map<string, number>();
    for (const b of env.slotBriefs ?? []) {
      briefIdCounts.set(b.id, (briefIdCounts.get(b.id) ?? 0) + 1);
    }
    for (const [id, count] of briefIdCounts) {
      if (count > 1) {
        error(
          "INTAKE-31",
          `slot brief id '${id}' is declared ${count} times — brief ids must be unique`,
          "/slotBriefs",
        );
      }
    }
    const briefsById = new Map((env.slotBriefs ?? []).map((b) => [b.id, b]));
    // r2 W4: 'home' matches the intent's parenthesised latin alias too —
    // authored intents are localized ("главная (home)"), and the page-set
    // machinery elsewhere treats the alias as the canonical page id
    // (RFC-1410: the shared canonicalIntentPageId owns the convention).
    const intentIsHome = (intent: string): boolean =>
      canonicalIntentPageId(intent).trim().toLowerCase() === "home";
    const firstFoldHomeBriefs = (env.slotBriefs ?? []).filter(
      (b) => intentIsHome(b.intent) && b.placement.surface === "first-fold",
    );
    if (firstFoldHomeBriefs.length > 1) {
      error(
        "INTAKE-31",
        `${firstFoldHomeBriefs.length} slot briefs claim placement.surface 'first-fold' on intent 'home' (${firstFoldHomeBriefs.map((b) => b.id).join(", ")}) — exactly one is allowed`,
        "/slotBriefs",
      );
    }
    const slotRef = env.visual.artDirection.firstFold.slotRef;
    if (slotRef !== undefined) {
      const target = briefsById.get(slotRef);
      if (!target) {
        error(
          "INTAKE-31",
          `artDirection.firstFold.slotRef '${slotRef}' resolves to no slot brief in the bundle`,
          "/visual/artDirection/firstFold/slotRef",
        );
      } else if (target.placement.surface !== "first-fold" || !intentIsHome(target.intent)) {
        error(
          "INTAKE-31",
          `artDirection.firstFold.slotRef '${slotRef}' names brief '${target.id}' whose placement.surface is '${target.placement.surface}' on intent '${target.intent}' — the ref must resolve to the single first-fold brief of the 'home' intent`,
          "/visual/artDirection/firstFold/slotRef",
        );
      }
    }

    // --- INTAKE-32: mockAssetRef → kind:mood of the chosen concept ---------
    {
      const mock = assetsById.get(env.visual.artDirection.mockAssetRef);
      if (!mock) {
        error(
          "INTAKE-32",
          `artDirection.mockAssetRef '${env.visual.artDirection.mockAssetRef}' resolves to no asset in the bundle`,
          "/visual/artDirection/mockAssetRef",
        );
      } else {
        if (mock.kind !== "mood") {
          error(
            "INTAKE-32",
            `artDirection.mockAssetRef '${mock.id}' is kind '${mock.kind}', not 'mood' — the approved first-fold mock is a mood asset`,
            "/visual/artDirection/mockAssetRef",
          );
        }
        if (mock.generator?.conceptId !== env.visual.conceptId) {
          error(
            "INTAKE-32",
            `artDirection.mockAssetRef '${mock.id}' generator.conceptId '${mock.generator?.conceptId ?? "<absent>"}' differs from visual.conceptId '${env.visual.conceptId}' — the mock must belong to the chosen concept`,
            "/visual/artDirection/mockAssetRef",
          );
        }
      }
    }

    // --- INTAKE-33: slotRef iff composition ≠ text-only ---------------------
    if (env.visual.artDirection.firstFold.composition === "text-only") {
      if (env.visual.artDirection.firstFold.slotRef !== undefined) {
        error(
          "INTAKE-33",
          `artDirection.firstFold.composition is 'text-only' but declares slotRef '${env.visual.artDirection.firstFold.slotRef}' — a text-only fold has no slot`,
          "/visual/artDirection/firstFold/slotRef",
        );
      }
    } else if (env.visual.artDirection.firstFold.slotRef === undefined) {
      error(
        "INTAKE-33",
        `artDirection.firstFold.composition '${env.visual.artDirection.firstFold.composition}' declares no slotRef — the first-fold slot brief is required`,
        "/visual/artDirection/firstFold/slotRef",
      );
    }

    // --- RFC-1353/AMD-011: the faq block (INTAKE-26…29 + extended rules) ----
    const faq = env.faq;
    if (faq) {
      const faqPath = (suffix: string): string => `/faq${suffix}`;
      const topicsById = new Map(faq.topics.map((t) => [t.id, t]));
      const primaryLocale = env.classification.locales.find((l) => l.role === "primary")?.tag;
      const localeTagSet = new Set(env.classification.locales.map((l) => l.tag));
      const localeTags = env.classification.locales.map((l) => l.tag);
      const familyQuestionsById = await loadFamilyQuestionsExport(
        io,
        options.workspaceRoot ?? bundleDir,
        options.familyQuestionsPath,
      );

      // --- INTAKE-26: integrity + placement + visitorQuestionRef -----------
      const seenTopicIds = new Set<string>();
      for (const [i, topic] of faq.topics.entries()) {
        if (seenTopicIds.has(topic.id)) {
          error("INTAKE-26", `duplicate faq topic id '${topic.id}'`, faqPath(`/topics/${i}/id`));
        }
        seenTopicIds.add(topic.id);
        if (!pageIntentSet.has(topic.placement) && topic.placement !== "faq") {
          error(
            "INTAKE-26",
            `faq topic '${topic.id}' placement '${topic.placement}' is neither a classification.pageSetIntent intent nor 'faq'`,
            faqPath(`/topics/${i}/placement`),
          );
        }
      }
      const seenEntryIds = new Set<string>();
      for (const [i, entry] of faq.entries.entries()) {
        if (seenEntryIds.has(entry.id)) {
          error("INTAKE-26", `duplicate faq entry id '${entry.id}'`, faqPath(`/entries/${i}/id`));
        }
        seenEntryIds.add(entry.id);
        if (!topicsById.has(entry.topic)) {
          error(
            "INTAKE-26",
            `faq entry '${entry.id}' names topic '${entry.topic}' — no faq.topics entry carries that id`,
            faqPath(`/entries/${i}/topic`),
          );
        }
        if (entry.visitorQuestionRef !== undefined) {
          const question = familyQuestionsById.get(entry.visitorQuestionRef);
          if (!question) {
            error(
              "INTAKE-26",
              `faq entry '${entry.id}' visitorQuestionRef '${entry.visitorQuestionRef}' resolves to no question in the vendored family visitor-question export`,
              faqPath(`/entries/${i}/visitorQuestionRef`),
            );
          }
        }
      }

      // --- INTAKE-27: locale coverage --------------------------------------
      const checkLocaleMap = (
        map: Record<string, string>,
        what: string,
        path: string,
        requireAllLocales: boolean,
      ): void => {
        for (const tag of Object.keys(map)) {
          if (!localeTagSet.has(tag)) {
            error(
              "INTAKE-27",
              `${what} carries locale '${tag}' outside classification.locales`,
              path,
            );
          }
        }
        if (primaryLocale !== undefined && typeof map[primaryLocale] !== "string") {
          error("INTAKE-27", `${what} is missing the primary locale '${primaryLocale}'`, path);
        }
        if (requireAllLocales) {
          for (const tag of localeTags) {
            if (typeof map[tag] !== "string" || map[tag] === "") {
              error("INTAKE-27", `${what} is missing site locale '${tag}'`, path);
            }
          }
        }
      };
      for (const [i, topic] of faq.topics.entries()) {
        checkLocaleMap(
          topic.label,
          `faq topic '${topic.id}' label`,
          faqPath(`/topics/${i}/label`),
          false,
        );
      }
      for (const [i, entry] of faq.entries.entries()) {
        const tier = faqEntryTier(entry);
        const base = faqPath(`/entries/${i}`);
        checkLocaleMap(
          entry.question,
          `faq entry '${entry.id}' question`,
          `${base}/question`,
          tier !== "draft",
        );
        if (entry.answer) {
          checkLocaleMap(
            entry.answer,
            `faq entry '${entry.id}' answer`,
            `${base}/answer`,
            tier !== "draft",
          );
        }
      }

      // --- INTAKE-28: fact tokens + no restated identifying literals --------
      const IDENTIFYING_FIELDS = [
        "email",
        "phone",
        "telephone",
        "mobile",
        "url",
        "website",
        "domain",
        "street",
        "streetAddress",
        "postalCode",
        "zip",
        "vatId",
        "taxId",
        "registrationNumber",
        "registerNumber",
        "legalName",
        "companyName",
      ];
      const PBP_TOKEN_RE = /\{\{pbp:([^#}]+)#([^}]+)\}\}/g;
      for (const [i, entry] of faq.entries.entries()) {
        const base = faqPath(`/entries/${i}`);
        const entityRefIds = new Set((entry.entityRefs ?? []).map((r) => resolveEntityRef(r).id));
        const answerLocales = [entry.answer ?? {}, entry.proposedAnswer ?? {}];
        for (const localeMap of answerLocales) {
          for (const [tag, text] of Object.entries(localeMap)) {
            for (const m of text.matchAll(PBP_TOKEN_RE)) {
              const entityId = m[1]!;
              const fieldPath = m[2]!;
              if (!entityRefIds.has(entityId)) {
                error(
                  "INTAKE-28",
                  `faq entry '${entry.id}' ${tag} token '{{pbp:${entityId}#${fieldPath}}}' names an entity outside its entityRefs`,
                  `${base}/answer/${tag}`,
                );
                continue;
              }
              const entity = entitiesById.get(entityId)?.entity as
                Record<string, unknown> | undefined;
              if (!entity || !pbpFieldExists(entity, fieldPath)) {
                error(
                  "INTAKE-28",
                  `faq entry '${entry.id}' ${tag} token '{{pbp:${entityId}#${fieldPath}}}' names a field that does not exist on the entity`,
                  `${base}/answer/${tag}`,
                );
              }
            }
            for (const ref of entry.entityRefs ?? []) {
              const { id } = resolveEntityRef(ref);
              const entity = entitiesById.get(id)?.entity as Record<string, unknown> | undefined;
              if (!entity) continue; // unresolved ref already reported by INTAKE-04
              for (const value of identifyingValues(entity, new Set(IDENTIFYING_FIELDS))) {
                if (value.length >= 6 && text.toLowerCase().includes(value.toLowerCase())) {
                  error(
                    "INTAKE-28",
                    `faq entry '${entry.id}' ${tag} answer restates the identifying literal '${value}' of cited entity '${id}' — use a {{pbp:<id>#<field>}} token`,
                    `${base}/answer/${tag}`,
                  );
                }
              }
            }
          }
        }
      }

      // --- INTAKE-29: answered ⇒ evidence ----------------------------------
      for (const [i, entry] of faq.entries.entries()) {
        if (entry.status !== "answered") continue;
        if ((entry.evidenceRefs?.length ?? 0) === 0) {
          error(
            "INTAKE-29",
            `answered faq entry '${entry.id}' carries no evidenceRefs — an answer without a source is an invention`,
            faqPath(`/entries/${i}/evidenceRefs`),
          );
        }
      }

      // --- INTAKE-04 (faq): refs resolve ------------------------------------
      for (const [i, entry] of faq.entries.entries()) {
        const base = faqPath(`/entries/${i}`);
        for (const [j, ref] of (entry.evidenceRefs ?? []).entries()) {
          checkEvidenceRef(ref, `${base}/evidenceRefs/${j}`);
        }
        for (const [j, ref] of (entry.entityRefs ?? []).entries()) {
          checkPbpRef(ref, `${base}/entityRefs/${j}`);
        }
        for (const [j, ref] of (entry.blockers ?? []).entries()) {
          checkGapRef(ref, `${base}/blockers/${j}`);
        }
        for (const [j, vb] of (entry.verbatim ?? []).entries()) {
          checkEvidenceRef(vb.sourceRef, `${base}/verbatim/${j}/sourceRef`);
        }
      }

      // --- INTAKE-16/17/19 (faq): blocker-holder semantics ------------------
      const faqBlockingGap = new Map<string, Set<string>>();
      for (const entry of faq.entries) {
        for (const gapRef of entry.blockers ?? []) {
          let set = faqBlockingGap.get(gapRef);
          if (!set) {
            set = new Set();
            faqBlockingGap.set(gapRef, set);
          }
          set.add(entry.id);
        }
      }
      for (const [i, gap] of env.gaps.entries()) {
        if (gap.kind !== "scope-extension" && gap.kind !== "operational") continue;
        const blockedFaq = faqBlockingGap.get(gap.id);
        if (blockedFaq && blockedFaq.size > 0) {
          error(
            "INTAKE-16",
            `${gap.kind} gap '${gap.id}' appears in blockers of faq entries ${[...blockedFaq].sort().join(", ")} — it must not gate any entry`,
            `/gaps/${i}`,
          );
        }
      }
      for (const [i, entry] of faq.entries.entries()) {
        if (faqEntryTier(entry) !== "preview") continue;
        for (const gapRef of entry.blockers ?? []) {
          const gap = gapsById.get(gapRef);
          if (!gap) continue; // unresolved ref already reported by INTAKE-04
          if (gap.kind !== "rights" && gap.kind !== "approval") {
            error(
              "INTAKE-17",
              `preview-tier faq entry '${entry.id}' is blocked by ${gap.kind} gap '${gapRef}' — preview requires rights/approval blockers only`,
              faqPath(`/entries/${i}/blockers`),
            );
          }
        }
      }
      for (const [i, gap] of env.gaps.entries()) {
        const expectedFaq = faqBlockingGap.get(gap.id) ?? new Set<string>();
        const declaredFaq = new Set(
          gap.blocks.map((ref) => resolveEntityRef(ref).id).filter((id) => faqEntryIds.has(id)),
        );
        for (const id of declaredFaq) {
          if (!expectedFaq.has(id)) {
            error(
              "INTAKE-19",
              `gap '${gap.id}' blocks[] names faq entry '${id}' but that entry's blockers do not contain the gap`,
              `/gaps/${i}/blocks`,
            );
          }
        }
        for (const id of expectedFaq) {
          if (!declaredFaq.has(id)) {
            error(
              "INTAKE-19",
              `faq entry '${id}' is blocked by gap '${gap.id}' but the gap's blocks[] does not name it`,
              `/gaps/${i}/blocks`,
            );
          }
        }
      }
    }
  }

  result.status = diagnostics.some((d) => d.severity === "error") ? "fail" : "pass";
  return result;
}
