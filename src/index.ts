/**
<MODULE_CONTRACT>
<purpose>@warpgogol/intake-validator public API (RFC-1540) — the werkstatt:intake/v2 consumer rules (INTAKE-01…34) that werkstatt's onboarding.intake.validate and every producer's golden-conformance leg run.</purpose>
<non-goals>
  <item>No werkstatt workshop resolution (--id) — that stays in werkstatt-engine.</item>
</non-goals>
</MODULE_CONTRACT>
*/
export {
  bundledFamilyQuestionsPath,
  INTAKE_RULE_IDS,
  loadFamilyQuestionsExport,
  resolveIntakeExportSha256,
  validateIntakeBundle,
  type FamilyVisitorQuestion,
  type IntakeDiagnostic,
  type IntakeRuleId,
  type IntakeValidateOptions,
  type IntakeValidateResult,
} from "./rules.ts";
