// Copyright (c) 2026 Vincent de Boer
// SPDX-License-Identifier: MIT
// (flattenResources and outputGuard adapt Apache-2.0 code: see NOTICE)

// @vcjdeboer/opentofu: one OpenTofu configuration, held in the swamp
// repository's git tree, planned and applied through a sha-bound gate. Its
// methods:
//   version   `tofu version -json`; refuses any tofu or provider version
//             other than the pinned ones
//   validate  the configuration rules, then init -backend=false and validate
//             in a temporary data directory: no backend, no credential
//   init      init with the configured backend, -lockfile=readonly
//   plan      a saved plan outside the repository: exit kind, sha256 and an
//             address-and-action summary only (PlanRecord tofu-plan/1)
//   apply     a sha-bound apply of exactly the saved plan whose sha256 a
//             person typed after reading it (ApplyRecord tofu-apply/1)
//   output    the allowlisted, non-sensitive outputs and the state's
//             addresses (OutputRecord tofu-output/1)
// argv is fixed per method: no free-form argument, -target, -replace, -var,
// import, destroy or state subcommand. The model definition is the policy:
// pinned versions, the environment tofu gets, the configuration rules, the
// actions an apply may take and the outputs it may record. State and plan
// files, `tofu show` text and provider error bodies never enter a record or
// a log line. Deno.* lives only in _io.ts.
//
// flattenResources and the output redaction are adapted from
// @webframp/terraform 2026.10.14.1 (Apache-2.0; NOTICE): here a sensitive
// output is refused, never masked and recorded.
import { z } from "npm:zod@4.3.6";
import { createHash } from "node:crypto";
import * as io from "./_io.ts";

// ---- value objects
/** A plan's id: p<yyyymmdd>T<hhmmss>-<8 hex>, UTC. */
export const PlanId = z.string().regex(/^p\d{8}T\d{6}-[0-9a-f]{8}$/);
/** A lowercase hex sha256. */
export const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);
/** A full git commit id. */
export const Commit = z.string().regex(/^[0-9a-f]{40}$/);
const VERSION_RE = /^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$/;
/** A version pin, e.g. 1.13.1. */
export const Version = z.string().regex(VERSION_RE);
/** A fully qualified provider source, e.g. registry.opentofu.org/hashicorp/aws. */
export const ProviderSource = z.string().regex(
  /^[a-z0-9.-]+(:\d+)?\/[a-z0-9_-]+\/[a-z0-9_-]+$/,
);
// The global-argument fields below are written inline (z.string()...): the
// registry lists a model's global arguments from the source, field by field.
// a plain relative path: no ., .. or empty segment, no trailing slash, and
// none of git's pathspec magic or glob characters (* ? [ ] : \)
const REL_PATH_RE =
  /^(?!\/)(?!.*(^|\/)\.\.?(\/|$))(?!.*\/\/)(?!.*\/$)[^\0\n*?[\]:\\]+$/;
const REL_PATH_MSG =
  "a plain relative path (no . or .. segment, trailing slash or * ? [ ] : \\)";
const ABS_DIR_RE = /^\/[^\0\n:]*$/;
const ABS_DIR_MSG = "an absolute path without :";
const EnvKey = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
const OutputName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_-]*$/).max(100);

/** The configuration rules a definition can switch on (validate and plan run them). */
export const RULES = [
  "prevent-destroy",
  "no-provisioner",
  "no-external-data",
  "no-module",
  "no-var-files",
  "outputs-allowlisted",
] as const;
/** The plan actions refused unless a definition permits them. */
export const DESTRUCTIVE = ["delete", "replace", "forget"] as const;

const DEFAULT_TIMEOUT_SEC = { plan: 900, apply: 1800, other: 300 } as const;

// Environment keys the definition may not set: the ones the model sets
// itself, any TF_* (TF_VAR_* would be an input outside the repository, TF_LOG
// would echo values), the dynamic loader's, and those that redirect what tofu
// fetches or where it looks: GIT_* (module fetches run git), XDG_* (implied
// plugin directories), proxies, TLS trust, telemetry export and TMPDIR.
const RESERVED_ENV =
  /^(HOME|PATH|TMPDIR|CHECKPOINT_DISABLE|TF_.*|LD_.*|DYLD_.*|GIT_.*|XDG_.*|SSL_.*|OTEL_.*|.*_PROXY)$/i;

// ---- global arguments (the model definition is the policy)
/** The model definition's global arguments. */
export const GlobalArgsSchema = z.object({
  tofuBin: z.string().max(300).regex(
    /^\/[^\0\n:]*\/tofu$/,
    "an absolute path to a binary named tofu",
  )
    .describe("Absolute path of the tofu binary; nothing else on PATH is used"),
  tofuVersion: z.string().regex(VERSION_RE).describe(
    "The tofu version tofuBin must report",
  ),
  providers: z.record(ProviderSource, Version).default({})
    .describe(
      "Exactly the providers the configuration may use, source to version; any other is refused",
    ),
  configDir: z.string().min(1).max(300).regex(REL_PATH_RE, REL_PATH_MSG)
    .describe(
      "The configuration directory, relative to the swamp repository; it must be tracked by git",
    ),
  cliConfigFile: z.string().min(1).max(100).regex(
    /^(?!\.\.?$)[^/\0\n*?[\]:\\]+$/,
    "a file name directly in configDir",
  )
    .optional()
    .describe(
      "A CLI configuration file directly in configDir (TF_CLI_CONFIG_FILE); without one tofu gets /dev/null, never ~/.tofurc",
    ),
  providerMirror: z.string().max(300).regex(ABS_DIR_RE, ABS_DIR_MSG).optional()
    .describe(
      "An unpacked filesystem mirror; when set, cliConfigFile must name only it and the lock's h1 must be the mirror's",
    ),
  env: z.record(EnvKey, z.string().max(4096)).default({})
    .describe(
      "The only extra environment tofu gets (e.g. AWS_PROFILE, AWS_REGION); values may be vault expressions",
    ),
  extraPath: z.array(z.string().max(300).regex(ABS_DIR_RE, ABS_DIR_MSG)).max(8)
    .default([])
    .describe(
      "Directories added to tofu's PATH after tofuBin's own (e.g. for a credential helper)",
    ),
  outputs: z.array(OutputName).max(100).default([])
    .describe(
      "The outputs the output method records; each must exist and be non-sensitive",
    ),
  expectedAddresses: z.array(z.string().max(300)).max(500).default([])
    .describe(
      "Managed resource addresses the state must hold; the output record lists the missing ones",
    ),
  rules: z.array(z.enum(RULES)).default([])
    .describe("Configuration rules checked by validate and plan"),
  permitActions: z.array(z.enum(DESTRUCTIVE)).default([])
    .describe(
      "Destructive actions an apply may take; by default a plan with any delete, replace or forget is refused",
    ),
  allowMixedImport: z.boolean().default(false)
    .describe(
      "Whether a plan that imports may also create or update; by default an import plan may only import",
    ),
  planMaxAgeMinutes: z.number().int().min(1).max(10080).default(240)
    .describe("The age after which a saved plan is refused"),
  timeouts: z.object({
    plan: z.number().int().min(10).max(86400).optional(),
    apply: z.number().int().min(10).max(86400).optional(),
    other: z.number().int().min(10).max(86400).optional(),
  }).strict().default({}).describe(
    "Seconds per tofu run (plan 900, apply 1800, other 300)",
  ),
}).strict().superRefine((g, c) => {
  for (const k of Object.keys(g.env)) {
    if (RESERVED_ENV.test(k)) {
      c.addIssue({
        code: "custom",
        path: ["env", k],
        message:
          `${k} may not be set: the model sets it or it would steer tofu`,
      });
    }
  }
  if (g.providerMirror !== undefined && g.cliConfigFile === undefined) {
    c.addIssue({
      code: "custom",
      path: ["cliConfigFile"],
      message:
        "providerMirror needs a cliConfigFile that installs only from it",
    });
  }
  if (g.outputs.length !== new Set(g.outputs).size) {
    c.addIssue({
      code: "custom",
      path: ["outputs"],
      message: "duplicate output",
    });
  }
});
/** Parsed global arguments, defaults applied. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// Method arguments: swamp hands a method the global arguments beside its own
// inputs, so a schema accepts the global-argument keys (each must equal the
// definition's value: checked by sameGlobals) and refuses every other unknown
// key.
const GLOBAL_KEYS = Object.keys(GlobalArgsSchema.shape);
/** A method-argument schema that refuses any key it does not name. */
export function closedArgs<T extends z.ZodRawShape>(shape: T) {
  const known = new Set([...Object.keys(shape), ...GLOBAL_KEYS]);
  return z.object(shape).passthrough().superRefine((v, c) => {
    for (const k of Object.keys(v)) {
      if (!known.has(k)) {
        c.addIssue({ code: "custom", message: `unknown input ${k}` });
      }
    }
  });
}
// Key-order independent JSON, for comparing structured global arguments.
const canon = (v: unknown): string =>
  JSON.stringify(
    v,
    (_k, x) => (x && typeof x === "object" && !Array.isArray(x)
      ? Object.fromEntries(
        Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
      )
      : x),
  );
/** Refuse a method input that overrides a global argument with another value. */
export function sameGlobals(raw: unknown, g: GlobalArgs): void {
  const r = (raw ?? {}) as Record<string, unknown>;
  for (const k of GLOBAL_KEYS) {
    if (
      k in r && r[k] !== undefined &&
      canon(r[k]) !== canon((g as Record<string, unknown>)[k])
    ) {
      throw new Error(`refused: input ${k} differs from the model definition`);
    }
  }
}
/** The arguments of a method that takes none. */
export const NoArgs = closedArgs({});
/** apply's arguments: the plan and the sha256 its reader typed. */
export const ApplyArgs = closedArgs({ planId: PlanId, planSha256: Sha256 });

// ---- records
const Diagnostic = z.object({
  severity: z.enum(["error", "warning"]),
  summary: z.string().max(200),
}).strict();
type DiagnosticT = z.infer<typeof Diagnostic>;
const Counts = z.object({
  import: z.number().int().min(0),
  create: z.number().int().min(0),
  update: z.number().int().min(0),
  replace: z.number().int().min(0),
  delete: z.number().int().min(0),
  forget: z.number().int().min(0),
}).strict();
/** A plan's change counts per kind. */
export type CountsT = z.infer<typeof Counts>;
const Change = z.object({
  address: z.string().max(300),
  actions: z.array(z.string().max(20)).max(3),
  importing: z.boolean(),
}).strict();
/** One resource change of a plan: address and actions, never values. */
export type ChangeT = z.infer<typeof Change>;
const Versions = z.record(z.string().max(120), z.string().max(40));

/** tofu-version/1 */
export const VersionRecord = z.object({
  schema: z.literal("tofu-version/1"),
  tofuVersion: z.string().max(40),
  providerVersions: Versions,
  ok: z.boolean(),
  problems: z.array(z.string().max(300)).max(20),
  at: z.string(),
}).strict();

/** tofu-validate/1 */
export const ValidateRecord = z.object({
  schema: z.literal("tofu-validate/1"),
  commit: Commit.nullable(),
  configDirty: z.boolean(),
  configDigest: Sha256,
  ruleProblems: z.array(z.string().max(300)).max(200),
  initExit: z.number().int().nullable(),
  valid: z.boolean(),
  diagnostics: z.array(Diagnostic).max(20),
  at: z.string(),
}).strict();

/** tofu-init/1 */
export const InitRecord = z.object({
  schema: z.literal("tofu-init/1"),
  commit: Commit,
  configDigest: Sha256,
  exitCode: z.number().int().nullable(),
  aborted: z.boolean(),
  at: z.string(),
}).strict();

/** tofu-plan/1 */
export const PlanRecord = z.object({
  schema: z.literal("tofu-plan/1"),
  planId: PlanId,
  commit: Commit,
  configDigest: Sha256,
  tofuVersion: z.string(),
  providerVersions: Versions,
  exitCode: z.number().int().nullable(),
  exitKind: z.enum(["no-changes", "changes", "error"]),
  planSha256: Sha256.nullable(),
  counts: Counts,
  summary: z.array(Change).max(200),
  summaryCut: z.boolean(),
  diagnostics: z.array(Diagnostic).max(20),
  createdAt: z.string(),
  finishedAt: z.string(),
}).strict();
/** A parsed tofu-plan/1 record. */
export type PlanRecordT = z.infer<typeof PlanRecord>;

/** Why an apply was refused before tofu ran. */
export const REFUSALS = [
  "no-plan",
  "not-changes",
  "sha-mismatch",
  "file-missing",
  "file-changed",
  "commit-changed",
  "config-dirty",
  "config-changed",
  "stale",
  "destructive",
  "import-not-clean",
  "already-applied",
  "plan-unreadable",
  "version",
  "repository",
] as const;
/** One of REFUSALS. */
export type Refusal = (typeof REFUSALS)[number];

/** tofu-apply/1 */
export const ApplyRecord = z.object({
  schema: z.literal("tofu-apply/1"),
  planId: PlanId,
  planSha256: Sha256,
  result: z.enum(["applied", "refused", "failed"]),
  refusal: z.enum(REFUSALS).nullable(),
  exitCode: z.number().int().nullable(),
  countsApplied: Counts.nullable(),
  diagnostics: z.array(Diagnostic).max(20),
  startedAt: z.string(),
  finishedAt: z.string(),
}).strict();

const OutputValue = z.union([z.string().max(1000), z.number(), z.boolean()]);
/** tofu-output/1 */
export const OutputRecord = z.object({
  schema: z.literal("tofu-output/1"),
  outputs: z.record(z.string(), OutputValue),
  unlisted: z.number().int().min(0),
  stateAddresses: z.array(z.string().max(300)).max(500),
  expectedMissing: z.array(z.string().max(300)),
  at: z.string(),
}).strict();

// ---- method context (the parts this model uses)
type Handle = { name: string };
/** The swamp method context this model uses. */
export type TofuCtx = {
  repoDir: string;
  globalArgs: unknown;
  definition?: { id: string; name: string };
  signal?: AbortSignal;
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<Handle>;
  readResource?: (name: string) => Promise<Record<string, unknown> | null>;
  logger?: {
    info: (m: string, p?: Record<string, unknown>) => void;
    warn: (m: string, p?: Record<string, unknown>) => void;
  };
};

/** The data name of a plan's record. */
export const planDataName = (id: string): string =>
  `tofu-plan-${id.toLowerCase()}`;
/** The data name of an apply's record. */
export const applyDataName = (id: string): string =>
  `tofu-apply-${id.toLowerCase()}`;
/** The data name of the output record. */
export const OUTPUT_DATA = "tofu-output";

// ---- where a model keeps its plans and tofu's data directory: one private
// directory per model definition, outside the repository
/** The private root of one model definition. */
export const modelHome = (home: string, defId: string): string => {
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(defId)) {
    throw new Error("the model definition id is not a plain identifier");
  }
  return `${home}/.swamp-opentofu/${defId}`;
};
/** The saved plans' directory. */
export const planDir = (root: string): string => `${root}/plans`;
/** tofu's data directory (TF_DATA_DIR). */
export const dataDir = (root: string): string => `${root}/data`;
/** The file of one saved plan. */
export const planFile = (root: string, id: string): string =>
  `${planDir(root)}/${id}.tfplan`;
/** The directory part of a path. */
export const dirOf = (p: string): string => p.slice(0, p.lastIndexOf("/"));

/**
 * The child's whole environment: the definition's env (left out for
 * validate, which needs no credential) and the model's own keys.
 */
export function childEnv(
  g: GlobalArgs,
  repoDir: string,
  home: string,
  tfDataDir: string,
  withEnv = true,
): Record<string, string> {
  return {
    ...(withEnv ? g.env : {}),
    HOME: home,
    PATH: [dirOf(g.tofuBin), ...g.extraPath, "/usr/bin", "/bin"].join(":"),
    TF_DATA_DIR: tfDataDir,
    TF_CLI_CONFIG_FILE: g.cliConfigFile === undefined
      ? "/dev/null"
      : `${repoDir}/${g.configDir}/${g.cliConfigFile}`,
    TF_IN_AUTOMATION: "1",
    TF_INPUT: "0",
    CHECKPOINT_DISABLE: "1",
  };
}

// ---- fixed argv per method (no input reaches argv except the plan file
// path, which the model builds from a validated PlanId)
/** The fixed argv of every tofu run. */
export const argv = {
  version: (g: GlobalArgs): string[] => [g.tofuBin, "version", "-json"],
  validateInit: (
    g: GlobalArgs,
  ): string[] => [
    g.tofuBin,
    "init",
    "-backend=false",
    "-input=false",
    "-lockfile=readonly",
    "-no-color",
  ],
  validate: (
    g: GlobalArgs,
  ): string[] => [g.tofuBin, "validate", "-json", "-no-color"],
  init: (
    g: GlobalArgs,
  ): string[] => [
    g.tofuBin,
    "init",
    "-input=false",
    "-lockfile=readonly",
    "-no-color",
  ],
  plan: (
    g: GlobalArgs,
    file: string,
  ): string[] => [
    g.tofuBin,
    "plan",
    "-input=false",
    "-detailed-exitcode",
    "-json",
    "-no-color",
    `-out=${file}`,
  ],
  show: (
    g: GlobalArgs,
    file: string,
  ): string[] => [g.tofuBin, "show", "-json", file],
  showState: (g: GlobalArgs): string[] => [g.tofuBin, "show", "-json"],
  apply: (
    g: GlobalArgs,
    file: string,
  ): string[] => [
    g.tofuBin,
    "apply",
    "-input=false",
    "-json",
    "-no-color",
    file,
  ],
  output: (g: GlobalArgs): string[] => [g.tofuBin, "output", "-json"],
};

// ---- version check
/** Problems with `tofu version -json` against the pins; needProvider after init. */
export function versionProblems(
  raw: string,
  g: GlobalArgs,
  needProvider: boolean,
): { problems: string[]; tofu: string; providers: Record<string, string> } {
  let v: { terraform_version?: unknown; provider_selections?: unknown };
  try {
    v = JSON.parse(raw);
  } catch {
    return { problems: ["version: not json"], tofu: "", providers: {} };
  }
  const tofu = typeof v.terraform_version === "string"
    ? v.terraform_version.slice(0, 40)
    : "";
  const providers: Record<string, string> = {};
  if (v.provider_selections && typeof v.provider_selections === "object") {
    for (
      const [k, val] of Object.entries(
        v.provider_selections as Record<string, unknown>,
      )
    ) {
      if (typeof val === "string") {
        providers[k.slice(0, 120)] = val.slice(0, 40);
      }
    }
  }
  const problems: string[] = [];
  if (tofu !== g.tofuVersion) {
    problems.push(
      `tofu ${tofu || "unknown"} is not the pinned ${g.tofuVersion}`,
    );
  }
  for (const [src, pin] of Object.entries(g.providers)) {
    const got = providers[src];
    if (got !== undefined && got !== pin) {
      problems.push(`provider ${src} ${got} is not the pinned ${pin}`);
    }
    if (needProvider && got === undefined) {
      problems.push(`provider ${src} is not installed: run init first`);
    }
  }
  const others = Object.keys(providers).filter((k) => !(k in g.providers));
  if (others.length) {
    problems.push(`providers not pinned: ${others.join(", ")}`);
  }
  return { problems, tofu, providers };
}

// ---- the plan summary: addresses, actions and importing flags only, read
// from `tofu show -json` of the saved plan; never before/after values
type RawChange = {
  address?: unknown;
  mode?: unknown;
  change?: { actions?: unknown; importing?: unknown };
};
/** Counts and an address-and-action summary of a plan's `show -json`. */
export function summarize(
  showJson: string,
): { counts: CountsT; summary: ChangeT[]; cut: boolean } {
  const p = JSON.parse(showJson) as { resource_changes?: RawChange[] };
  const counts: CountsT = {
    import: 0,
    create: 0,
    update: 0,
    replace: 0,
    delete: 0,
    forget: 0,
  };
  const summary: ChangeT[] = [];
  for (const rc of p.resource_changes ?? []) {
    if (rc.mode !== "managed" || typeof rc.address !== "string") continue;
    const actions = Array.isArray(rc.change?.actions)
      ? rc.change!.actions.filter((a): a is string => typeof a === "string")
      : [];
    const importing = rc.change?.importing !== undefined &&
      rc.change?.importing !== null;
    if (importing) counts.import++;
    const has = (a: string) => actions.includes(a);
    if (has("forget")) counts.forget++;
    else if (has("delete") && has("create")) counts.replace++;
    else if (has("delete")) counts.delete++;
    else if (has("create")) counts.create++;
    else if (has("update")) counts.update++;
    if (actions.length === 1 && actions[0] === "no-op" && !importing) continue;
    summary.push({
      address: rc.address.slice(0, 300),
      actions: actions.slice(0, 3).map((a) => a.slice(0, 20)),
      importing,
    });
  }
  return { counts, summary: summary.slice(0, 200), cut: summary.length > 200 };
}

/** 0 is no-changes, 2 changes, anything else error; an import is always a change. */
export function exitKind(
  code: number | null,
  counts: CountsT,
): "no-changes" | "changes" | "error" {
  if (code === 2) return "changes";
  if (code === 0) {
    return Object.values(counts).some((n) => n > 0) ? "changes" : "no-changes";
  }
  return "error";
}

/** Each diagnostic's severity and summary from a -json UI stream (never its detail). */
export function diagnostics(stream: string): DiagnosticT[] {
  const out: DiagnosticT[] = [];
  for (const line of stream.split("\n")) {
    if (!line.startsWith("{")) continue;
    let o: {
      type?: unknown;
      diagnostic?: { severity?: unknown; summary?: unknown };
    };
    try {
      o = JSON.parse(line);
    } catch {
      continue;
    }
    if (o.type !== "diagnostic" || !o.diagnostic) continue;
    const sev = o.diagnostic.severity === "error" ? "error" : "warning";
    out.push({
      severity: sev,
      summary: String(o.diagnostic.summary ?? "").slice(0, 200),
    });
    if (out.length >= 20) break;
  }
  return out;
}

/** valid and the diagnostics' summaries from `tofu validate -json`. */
export function validateResult(
  stdout: string,
): { valid: boolean; diagnostics: DiagnosticT[] } {
  try {
    const v = JSON.parse(stdout) as {
      valid?: unknown;
      diagnostics?: { severity?: unknown; summary?: unknown }[];
    };
    return {
      valid: v.valid === true,
      diagnostics: (v.diagnostics ?? []).slice(0, 20).map((d) => ({
        severity: d.severity === "error"
          ? "error" as const
          : "warning" as const,
        summary: String(d.summary ?? "").slice(0, 200),
      })),
    };
  } catch {
    return {
      valid: false,
      diagnostics: [{ severity: "error", summary: "validate: not json" }],
    };
  }
}

// ---- the apply guard (pure)
/** The first reason to refuse an apply, or null. */
export function applyGuard(i: {
  rec: PlanRecordT | null;
  typedSha: string;
  fileSha: string | null;
  head: string;
  clean: boolean;
  digest: string;
  now: Date;
  maxAgeMs: number;
  permit: readonly string[];
  allowMixedImport: boolean;
}): Refusal | null {
  const r = i.rec;
  if (r === null) return "no-plan";
  if (r.exitKind !== "changes" || r.planSha256 === null) return "not-changes";
  if (i.typedSha !== r.planSha256) return "sha-mismatch";
  const age = i.now.getTime() - Date.parse(r.createdAt);
  const stale = !(age >= 0 && age <= i.maxAgeMs);
  // plan removes stale plan files, so a missing one past its age is stale
  if (i.fileSha === null) return stale ? "stale" : "file-missing";
  if (i.fileSha !== r.planSha256) return "file-changed";
  if (i.head !== r.commit) return "commit-changed";
  if (!i.clean) return "config-dirty";
  if (i.digest !== r.configDigest) return "config-changed";
  if (stale) return "stale";
  if (DESTRUCTIVE.some((k) => r.counts[k] > 0 && !i.permit.includes(k))) {
    return "destructive";
  }
  if (
    !i.allowMixedImport && r.counts.import > 0 &&
    r.counts.create + r.counts.update > 0
  ) return "import-not-clean";
  return null;
}

// ---- outputs: record the allowlisted ones; refuse a missing, sensitive or
// non-scalar one (adapted from @webframp/terraform's get_outputs, which masks)
/** The allowlisted outputs of `tofu output -json`, or the reason to refuse. */
export function outputGuard(
  raw: string,
  allow: readonly string[],
): { outputs: Record<string, string | number | boolean>; unlisted: number } | {
  problem: string;
} {
  let o: Record<string, { sensitive?: unknown; value?: unknown }>;
  try {
    o = JSON.parse(raw);
  } catch {
    return { problem: "output: not json" };
  }
  if (!o || typeof o !== "object" || Array.isArray(o)) {
    return { problem: "output: not an object" };
  }
  const names = Object.keys(o);
  const missing = allow.filter((n) => !names.includes(n));
  if (missing.length) {
    return { problem: `outputs missing: ${missing.join(", ")}` };
  }
  const outputs: Record<string, string | number | boolean> = {};
  for (const n of allow) {
    if (o[n].sensitive !== false) {
      return { problem: `output ${n} is sensitive` };
    }
    const v = o[n].value;
    if (typeof v === "string") outputs[n] = v.slice(0, 1000);
    else if (
      (typeof v === "number" && Number.isFinite(v)) || typeof v === "boolean"
    ) outputs[n] = v;
    else return { problem: `output ${n} is not a string, number or boolean` };
  }
  return { outputs, unlisted: names.filter((n) => !allow.includes(n)).length };
}

// flattenResources, adapted from @webframp/terraform 2026.10.14.1
// (terraform.ts; Apache-2.0): every resource of nested modules. Only the
// managed resources' addresses leave this module.
type RawModule = {
  address?: string;
  resources?: { address?: unknown; mode?: unknown }[];
  child_modules?: RawModule[];
};
/** Every resource of a state module and its child modules. */
export function flattenResources(
  mod: RawModule,
): { address: unknown; mode: unknown }[] {
  const out: { address: unknown; mode: unknown }[] = [...(mod.resources ?? [])]
    .map((r) => ({ address: r.address, mode: r.mode }));
  for (const child of mod.child_modules ?? []) {
    out.push(...flattenResources(child));
  }
  return out;
}
/** The managed resource addresses of a state's `show -json`, sorted. */
export function stateAddresses(showStateJson: string): string[] {
  const s = JSON.parse(showStateJson) as {
    values?: { root_module?: RawModule };
  };
  if (!s.values?.root_module) return [];
  return flattenResources(s.values.root_module)
    .filter((r) => r.mode === "managed" && typeof r.address === "string")
    .map((r) => (r.address as string).slice(0, 300))
    .sort()
    .slice(0, 500);
}

// ---- the configuration rules (pure, on file texts; validate and plan run
// them)
/** An HCL block: its kind, labels and body (strings replaced by tokens). */
export type Block = { kind: string; labels: string[]; body: string };

// A string token in scanned text: a quote, §, the string's index, a quote
// (§ cannot occur outside a string in HCL, and strings are all tokens).
const TOKEN = /^"§(\d+)"$/;

// The end of the string literal opening at i (index of its closing quote),
// or -1: escapes, $${ and %%{ literals, and ${...} / %{...} templates whose
// expressions may hold strings and braces of their own.
function stringEnd(text: string, i: number): number {
  let j = i + 1;
  while (j < text.length) {
    const c = text[j];
    if (c === "\\") j += 2;
    else if (c === '"') return j;
    else if (c === "\n") return -1;
    else if (text.startsWith("$${", j) || text.startsWith("%%{", j)) j += 3;
    else if ((c === "$" || c === "%") && text[j + 1] === "{") {
      let depth = 1;
      j += 2;
      while (j < text.length && depth > 0) {
        if (text[j] === '"') {
          const e = stringEnd(text, j);
          if (e < 0) return -1;
          j = e;
        } else if (text[j] === "{") depth++;
        else if (text[j] === "}") depth--;
        j++;
      }
      if (depth > 0) return -1;
    } else j++;
  }
  return -1;
}

/**
 * Scan HCL text: comments dropped, every string literal and heredoc replaced
 * by a token (its text kept in strings), so no brace, # or keyword inside a
 * string counts. problems names what the scan could not account for; the
 * rules fail closed on any. Enough for the rules, not a full parser.
 */
export function hclScan(text: string): {
  clean: string;
  strings: string[];
  problems: string[];
} {
  let clean = "";
  const strings: string[] = [];
  const problems: string[] = [];
  const token = (s: string) => {
    strings.push(s);
    return `"§${strings.length - 1}"`;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const here = c === "<" && text[i + 1] === "<"
      ? /^<<-?([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\r?\n/.exec(text.slice(i))
      : null;
    if (c === '"') {
      const j = stringEnd(text, i);
      if (j < 0) {
        problems.push("an unterminated string");
        break;
      }
      clean += token(text.slice(i + 1, j));
      i = j;
    } else if (here) {
      const bodyAt = i + here[0].length;
      const end = new RegExp(`(^|\\n)[ \\t]*${here[1]}[ \\t]*(\\r?\\n|$)`).exec(
        text.slice(bodyAt),
      );
      if (!end) {
        problems.push(`an unterminated heredoc ${here[1]}`);
        break;
      }
      const stop = bodyAt + end.index + end[0].length;
      const body = text.slice(bodyAt, bodyAt + end.index);
      clean += token(body) +
        "\n".repeat((text.slice(i, stop).match(/\n/g) ?? []).length);
      i = stop - 1;
    } else if (c === "#" || (c === "/" && text[i + 1] === "/")) {
      while (i < text.length && text[i] !== "\n") i++;
      clean += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end < 0) {
        problems.push("an unterminated comment");
        break;
      }
      clean += "\n".repeat((text.slice(i, end).match(/\n/g) ?? []).length) +
        " ";
      i = end + 1;
    } else clean += c;
  }
  return { clean, strings, problems };
}

// The blocks directly in scanned text (top level of it), what lies outside
// them, and whether every block closed.
function blocksIn(
  clean: string,
  strings: string[],
): { blocks: Block[]; rest: string; balanced: boolean } {
  const blocks: Block[] = [];
  const head =
    /(^|\n)[ \t]*([A-Za-z_][A-Za-z0-9_-]*)((?:[ \t]+(?:"§\d+"|[A-Za-z_][A-Za-z0-9_-]*))*)[ \t]*\{/g;
  let m: RegExpExecArray | null;
  let from = 0;
  let rest = "";
  let balanced = true;
  while ((m = head.exec(clean)) !== null) {
    if (m.index < from) continue;
    rest += clean.slice(from, m.index);
    let depth = 1;
    let j = head.lastIndex;
    for (; j < clean.length && depth > 0; j++) {
      if (clean[j] === "{") depth++;
      else if (clean[j] === "}") depth--;
    }
    if (depth > 0) balanced = false;
    const labels = m[3].trim() === "" ? [] : m[3].trim().split(/[ \t]+/).map(
      (l) => {
        const t = TOKEN.exec(l);
        return t ? strings[Number(t[1])] : l;
      },
    );
    blocks.push({
      kind: m[2],
      labels,
      body: clean.slice(head.lastIndex, j - 1),
    });
    from = j;
    head.lastIndex = j;
  }
  rest += clean.slice(from);
  if (/[{}]/.test(rest)) balanced = false;
  return { blocks, rest, balanced };
}

/** The top-level blocks of an HCL text (string contents replaced by tokens in bodies). */
export function hclBlocks(text: string): Block[] {
  const s = hclScan(text);
  return blocksIn(s.clean, s.strings).blocks;
}

/** The configuration files OpenTofu reads (and the rules therefore must). */
const CONFIG_FILE = /\.(tf|tofu)$/;

/** The switched-on rules' problems with the configuration's top-level files. */
export function configProblems(
  files: Record<string, string>,
  g: Pick<GlobalArgs, "rules" | "outputs">,
): string[] {
  const on = (r: (typeof RULES)[number]) => g.rules.includes(r);
  const problems: string[] = [];
  const names = Object.keys(files).sort();
  if (on("no-var-files")) {
    for (const n of names) {
      if (
        /\.tfvars(\.json)?$|(^|_)override\.(tf|tofu)(\.json)?$|\.(tf|tofu)\.json$/
          .test(n)
      ) {
        problems.push(
          `${n}: no tfvars, override or JSON configuration file (rule no-var-files)`,
        );
      }
    }
  }
  if (g.rules.length === 0) return problems;
  type FileBlock = Block & { file: string; strings: string[] };
  const blocks: FileBlock[] = [];
  for (const n of names.filter((n) => CONFIG_FILE.test(n))) {
    // fail closed: a file the scanner cannot fully account for is a problem
    const s = hclScan(files[n]);
    const b = blocksIn(s.clean, s.strings);
    for (const p of s.problems) {
      problems.push(`${n}: ${p}; the rules cannot read it`);
    }
    if (!b.balanced) {
      problems.push(`${n}: unbalanced braces; the rules cannot read it`);
    }
    if (b.rest.trim() !== "") {
      problems.push(`${n}: text outside any block; the rules cannot read it`);
    }
    for (const x of b.blocks) {
      blocks.push({ ...x, file: n, strings: s.strings });
    }
  }
  const inner = (b: FileBlock) => blocksIn(b.body, b.strings).blocks;
  for (const r of blocks.filter((b) => b.kind === "resource")) {
    const addr = `${r.labels[0]}.${r.labels[1]}`;
    const nested = inner(r);
    if (
      on("prevent-destroy") &&
      !nested.some((l) =>
        l.kind === "lifecycle" &&
        /(^|\n)[ \t]*prevent_destroy[ \t]*=[ \t]*true[ \t]*(\n|$)/.test(l.body)
      )
    ) {
      problems.push(
        `${addr}: lifecycle prevent_destroy = true is missing (rule prevent-destroy)`,
      );
    }
    if (on("no-provisioner") && nested.some((l) => l.kind === "provisioner")) {
      problems.push(`${addr}: provisioner (rule no-provisioner)`);
    }
  }
  if (on("no-external-data")) {
    for (
      const d of blocks.filter((b) =>
        b.kind === "data" && b.labels[0] === "external"
      )
    ) {
      problems.push(
        `data.external.${
          d.labels[1]
        }: external data source (rule no-external-data)`,
      );
    }
  }
  if (on("no-module")) {
    for (const m of blocks.filter((b) => b.kind === "module")) {
      problems.push(`module.${m.labels[0]}: module block (rule no-module)`);
    }
  }
  if (on("outputs-allowlisted")) {
    const outputs = blocks.filter((b) => b.kind === "output");
    const declared = outputs.map((o) => o.labels[0]).sort();
    if (declared.join(",") !== [...g.outputs].sort().join(",")) {
      problems.push(
        `outputs must be exactly: ${
          g.outputs.join(", ") || "(none)"
        } (rule outputs-allowlisted)`,
      );
    }
    for (const o of outputs) {
      if (!/(^|\n)\s*sensitive\s*=\s*false/.test(o.body)) {
        problems.push(
          `output ${
            o.labels[0]
          }: sensitive = false is missing (rule outputs-allowlisted)`,
        );
      }
    }
  }
  return problems;
}

/**
 * The CLI configuration file: never dev_overrides (it bypasses the lock);
 * with a provider mirror, one provider_installation with one
 * filesystem_mirror at it and nothing else.
 */
export function cliConfigProblems(text: string, mirror?: string): string[] {
  if (mirror === undefined) {
    return /dev_overrides/.test(hclScan(text).clean)
      ? ["cliConfigFile: no dev_overrides (it bypasses the lock file)"]
      : [];
  }
  const blocks = hclBlocks(text);
  const problems: string[] = [];
  if (blocks.length !== 1 || blocks[0].kind !== "provider_installation") {
    return [
      "cliConfigFile: exactly one provider_installation block and nothing else",
    ];
  }
  const inner = hclBlocks(blocks[0].body);
  if (inner.length !== 1 || inner[0].kind !== "filesystem_mirror") {
    problems.push(
      "cliConfigFile: exactly one filesystem_mirror (no direct, network_mirror or dev_overrides)",
    );
  }
  const path = text.match(/(^|\n)\s*path\s*=\s*"([^"]+)"/);
  if (!path || path[2] !== mirror) {
    problems.push(`cliConfigFile: the mirror path is not ${mirror}`);
  }
  if (
    /dev_overrides|network_mirror|direct\s*\{|plugin_cache_dir|credentials|host\s+"/
      .test(text.replace(/#[^\n]*/g, ""))
  ) {
    problems.push(
      "cliConfigFile: no dev_overrides, network_mirror, direct, plugin_cache_dir, credentials or host",
    );
  }
  return problems;
}

/** The h1 hash of a provider package: sha256 over the sorted "<sha256>  <path>\n" lines, base64. */
export function h1Hash(files: { name: string; sha256: string }[]): string {
  const lines = [...files].sort((
    a,
    b,
  ) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)).map((f) =>
    `${f.sha256}  ${f.name}\n`
  ).join("");
  return "h1:" + createHash("sha256").update(lines).digest("base64");
}

/** .terraform.lock.hcl: exactly the pinned providers at their versions; with h1s, each listed. */
export function lockProblems(
  lock: string | undefined,
  pins: Record<string, string>,
  h1s?: Record<string, string>,
): string[] {
  const want = Object.keys(pins).sort();
  if (lock === undefined) {
    return want.length ? [".terraform.lock.hcl is missing: commit it"] : [];
  }
  const blocks = hclBlocks(lock).filter((b) => b.kind === "provider");
  const problems: string[] = [];
  const got = blocks.map((b) => b.labels[0]).sort();
  if (got.join(",") !== want.join(",")) {
    problems.push(
      `.terraform.lock.hcl: providers must be exactly ${
        want.join(", ") || "(none)"
      }`,
    );
  }
  // the lock's hashes are strings (hclBlocks blanks their braces only), so
  // read version and hashes from the raw text of each block
  for (const b of blocks) {
    const src = b.labels[0];
    if (!(src in pins)) continue;
    const at = lock.search(
      new RegExp(
        `(^|\\n)[ \\t]*provider[ \\t]+"${
          src.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")
        }"`,
      ),
    );
    const next = lock.slice(at + 1).search(/\n[ \t]*provider[ \t]+"/);
    const text = at < 0
      ? ""
      : lock.slice(at, next < 0 ? undefined : at + 1 + next);
    const v = text.match(/(^|\n)\s*version\s*=\s*"([^"]+)"/);
    if (!v || v[2] !== pins[src]) {
      problems.push(`.terraform.lock.hcl: ${src} must be at ${pins[src]}`);
    }
    if (h1s && h1s[src] !== undefined && !text.includes(`"${h1s[src]}"`)) {
      problems.push(
        `.terraform.lock.hcl: ${src}'s h1 hash is not the mirror's`,
      );
    }
  }
  return problems;
}

// ---- the repository state a plan binds to
/** HEAD, whether configDir is clean, a digest of its tracked files, and their top-level texts. */
export async function repoState(
  repoDir: string,
  configDir: string,
): Promise<
  {
    head: string;
    clean: boolean;
    digest: string;
    files: Record<string, string>;
  }
> {
  const head = (await io.run(["git", "rev-parse", "HEAD"], repoDir)).stdout
    .trim();
  const st = await io.run([
    "git",
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
    "--ignored=matching",
    "--",
    configDir,
  ], repoDir);
  // -v tags each entry (H normal; lowercase assume-unchanged, S skip-worktree:
  // git status would call those clean while their contents differ); -s gives
  // the mode (120000 symlink, 160000 submodule: not bound by the digest)
  const ls = await io.run([
    "git",
    "--literal-pathspecs",
    "ls-files",
    "-z",
    "-v",
    "-s",
    "--",
    configDir,
  ], repoDir);
  if (ls.code !== 0 || !/^[0-9a-f]{40}$/.test(head)) {
    throw new Error(
      "git: cannot read HEAD or the tracked files of the configuration (is configDir committed in a git repository?)",
    );
  }
  const paths: string[] = [];
  for (const entry of ls.stdout.split("\0").filter((e) => e !== "")) {
    const m = /^(\S) (\d{6}) [0-9a-f]+ (\d)\t(.+)$/s.exec(entry);
    if (!m) {
      throw new Error(
        "git: cannot read the tracked files of the configuration",
      );
    }
    const [, tag, mode, , path] = m;
    if (tag !== "H") {
      throw new Error(
        `git: ${path} is marked assume-unchanged, skip-worktree or unmerged (tag ${tag}); clear it first`,
      );
    }
    if (mode !== "100644" && mode !== "100755") {
      throw new Error(
        `git: ${path} is a ${
          mode === "120000"
            ? "symlink"
            : mode === "160000"
            ? "submodule"
            : `mode ${mode} entry`
        }; the configuration must hold regular files only`,
      );
    }
    paths.push(path);
  }
  paths.sort();
  if (paths.length === 0) {
    throw new Error(`git: ${configDir} has no tracked files`);
  }
  const h = createHash("sha256");
  const files: Record<string, string> = {};
  for (const p of paths) {
    const bytes = await io.readBytes(`${repoDir}/${p}`);
    h.update(p).update("\0").update(String(bytes.length)).update("\0").update(
      bytes,
    );
    const rel = p.slice(configDir.length + 1);
    if (!rel.includes("/")) files[rel] = new TextDecoder().decode(bytes);
  }
  return {
    head,
    clean: st.code === 0 && st.stdout.trim() === "",
    digest: h.digest("hex"),
    files,
  };
}

/** The working tree's top-level files of the configuration (what validate checks). */
export async function workingFiles(
  repoDir: string,
  configDir: string,
): Promise<Record<string, string>> {
  const files: Record<string, string> = {};
  for (const n of await io.listFiles(`${repoDir}/${configDir}`)) {
    files[n] = await io.readText(`${repoDir}/${configDir}/${n}`);
  }
  return files;
}

// ---- method plumbing
function args(ctx: TofuCtx): GlobalArgs {
  return GlobalArgsSchema.parse(ctx.globalArgs);
}
function root(ctx: TofuCtx): string {
  const id = ctx.definition?.id;
  if (!id) throw new Error("the method context names no model definition");
  return modelHome(io.home(), id);
}
const timeout = (g: GlobalArgs, k: "plan" | "apply" | "other") =>
  g.timeouts[k] ?? DEFAULT_TIMEOUT_SEC[k];
function abortSignal(ctx: TofuCtx, sec: number): AbortSignal {
  const t = AbortSignal.timeout(sec * 1000);
  return ctx.signal ? AbortSignal.any([t, ctx.signal]) : t;
}
async function tofu(
  ctx: TofuCtx,
  g: GlobalArgs,
  argvv: string[],
  tfData: string,
  sec: number,
  withEnv = true,
) {
  return await io.spawn(argvv, {
    cwd: `${ctx.repoDir}/${g.configDir}`,
    env: childEnv(g, ctx.repoDir, io.home(), tfData, withEnv),
    signal: abortSignal(ctx, sec),
  });
}
async function checkVersion(
  ctx: TofuCtx,
  g: GlobalArgs,
  tfData: string,
  needProvider: boolean,
  withEnv = true,
) {
  const r = await tofu(
    ctx,
    g,
    argv.version(g),
    tfData,
    timeout(g, "other"),
    withEnv,
  );
  const v = versionProblems(r.code === 0 ? r.stdout : "", g, needProvider);
  if (r.code !== 0) v.problems.unshift(`tofu version exit ${r.code}`);
  return v;
}
const iso = () => io.now().toISOString();

/** A new PlanId for a time and 8 hex characters. */
export function newPlanId(d: Date, hex: string): string {
  const s = d.toISOString();
  return `p${s.slice(0, 4)}${s.slice(5, 7)}${s.slice(8, 10)}T${
    s.slice(11, 13)
  }${s.slice(14, 16)}${s.slice(17, 19)}-${hex}`;
}

/**
 * The saved plan files (`<planId>.tfplan`) among names that apply would
 * refuse as stale at now: at least maxAgeMs plus the second a PlanId
 * truncates from the record's createdAt old. Other names, and plans dated
 * after now, are kept.
 */
export function stalePlanFiles(
  names: readonly string[],
  now: Date,
  maxAgeMs: number,
): string[] {
  return names.filter((n) => {
    const m =
      /^p(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})-[0-9a-f]{8}\.tfplan$/
        .exec(n);
    if (!m) return false;
    const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
    return now.getTime() - t >= maxAgeMs + 1000;
  });
}

/** The command a person runs to read a saved plan before typing its sha256. */
export function showCommand(
  g: GlobalArgs,
  repoDir: string,
  home: string,
  modelRoot: string,
  file: string,
): string {
  // the definition's env is left out: its values may be credentials, and
  // reading a saved plan needs none
  const e = childEnv(g, repoDir, home, dataDir(modelRoot), false);
  const q = shellQuote;
  return `cd ${q(`${repoDir}/${g.configDir}`)} && env -i HOME=${
    q(e.HOME)
  } PATH=${q(e.PATH)} TF_DATA_DIR=${q(e.TF_DATA_DIR)} TF_CLI_CONFIG_FILE=${
    q(e.TF_CLI_CONFIG_FILE)
  } ${q(g.tofuBin)} show ${q(file)}`;
}

/** A POSIX shell single-quoted word. */
export const shellQuote = (s: string): string =>
  /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;

// The rules on a set of top-level files, with the mirror's checks when set.
async function allProblems(
  g: GlobalArgs,
  files: Record<string, string>,
): Promise<string[]> {
  const problems = configProblems(files, g);
  let h1s: Record<string, string> | undefined;
  if (g.cliConfigFile !== undefined) {
    const text = files[g.cliConfigFile];
    if (text === undefined) {
      problems.push(
        `cliConfigFile ${g.cliConfigFile} is missing from ${g.configDir}`,
      );
    } else problems.push(...cliConfigProblems(text, g.providerMirror));
  }
  if (g.providerMirror !== undefined) {
    h1s = {};
    for (const [src, ver] of Object.entries(g.providers)) {
      const pkg = `${g.providerMirror}/${src}/${ver}/${io.platform()}`;
      if (!(await io.exists(pkg))) {
        problems.push(`the provider package ${pkg} is missing from the mirror`);
        continue;
      }
      const names = await io.listFilesDeep(pkg);
      h1s[src] = h1Hash(
        await Promise.all(
          names.map(async (name) => ({
            name,
            sha256: await io.sha256File(`${pkg}/${name}`),
          })),
        ),
      );
    }
  }
  problems.push(
    ...lockProblems(files[".terraform.lock.hcl"], g.providers, h1s),
  );
  return problems;
}

// ---- methods
/** version: record the tofu and provider versions; throw unless pinned. */
export async function versionMethod(ctx: TofuCtx, raw: unknown) {
  NoArgs.parse(raw ?? {});
  const g = args(ctx);
  sameGlobals(raw, g);
  const r = root(ctx);
  await io.privateDir(r);
  const v = await checkVersion(ctx, g, dataDir(r), false);
  const rec = VersionRecord.parse({
    schema: "tofu-version/1",
    tofuVersion: v.tofu,
    providerVersions: v.providers,
    ok: v.problems.length === 0,
    problems: v.problems.slice(0, 20).map((p) => p.slice(0, 300)),
    at: iso(),
  });
  const handle = await ctx.writeResource("version", "tofu-version", rec);
  if (v.problems.length) throw new Error(`refused: ${v.problems.join("; ")}`);
  return { dataHandles: [handle] };
}

/** validate: the rules on the working tree, then init -backend=false and validate in a throwaway data directory, without the definition's env. */
export async function validateMethod(ctx: TofuCtx, raw: unknown) {
  NoArgs.parse(raw ?? {});
  const g = args(ctx);
  sameGlobals(raw, g);
  const rs = await repoState(ctx.repoDir, g.configDir);
  const problems = await allProblems(
    g,
    await workingFiles(ctx.repoDir, g.configDir),
  );
  const tmp = await io.makeTempDir("swamp-opentofu-validate-");
  let initExit: number | null = null;
  let res = { valid: false, diagnostics: [] as DiagnosticT[] };
  // no backend and no credential: the definition's env is left out
  const run = (a: string[]) => tofu(ctx, g, a, tmp, timeout(g, "other"), false);
  try {
    problems.push(...(await checkVersion(ctx, g, tmp, false, false)).problems);
    if (problems.length === 0) {
      // -backend=false: no backend; -lockfile=readonly: a hash mismatch
      // fails, never rewrites the lock
      const init = await run(argv.validateInit(g));
      initExit = init.code;
      if (init.code === 0) {
        problems.push(
          ...(await checkVersion(ctx, g, tmp, true, false)).problems,
        );
        res = validateResult((await run(argv.validate(g))).stdout);
      } else problems.push(`init -backend=false exit ${init.code}`);
    }
  } finally {
    await io.removeQuiet(tmp, true);
  }
  const rec = ValidateRecord.parse({
    schema: "tofu-validate/1",
    commit: rs.head,
    configDirty: !rs.clean,
    configDigest: rs.digest,
    ruleProblems: problems.slice(0, 200).map((p) => p.slice(0, 300)),
    initExit,
    valid: problems.length === 0 && res.valid,
    diagnostics: res.diagnostics,
    at: iso(),
  });
  const handle = await ctx.writeResource("validate", "tofu-validate", rec);
  if (!rec.valid) {
    throw new Error(
      `validate failed: ${problems.length} rule problem(s), ${
        res.diagnostics.filter((d) => d.severity === "error").length
      } tofu error(s)`,
    );
  }
  return { dataHandles: [handle] };
}

async function preflight(ctx: TofuCtx, g: GlobalArgs) {
  const rs = await repoState(ctx.repoDir, g.configDir);
  if (!rs.clean) {
    throw new Error(
      `refused: ${g.configDir} has uncommitted, untracked or ignored files`,
    );
  }
  const problems = await allProblems(g, rs.files);
  if (problems.length) throw new Error(`refused: ${problems.join("; ")}`);
  const r = root(ctx);
  await io.privateDir(r);
  await io.privateDir(dataDir(r));
  return { rs, r };
}

/** init: the configured backend, -lockfile=readonly, on a clean committed configuration. */
export async function initMethod(ctx: TofuCtx, raw: unknown) {
  NoArgs.parse(raw ?? {});
  const g = args(ctx);
  sameGlobals(raw, g);
  const { rs, r } = await preflight(ctx, g);
  const v = await checkVersion(ctx, g, dataDir(r), false);
  if (v.problems.length) throw new Error(`refused: ${v.problems.join("; ")}`);
  const run = await tofu(ctx, g, argv.init(g), dataDir(r), timeout(g, "other"));
  const rec = InitRecord.parse({
    schema: "tofu-init/1",
    commit: rs.head,
    configDigest: rs.digest,
    exitCode: run.code,
    aborted: run.aborted,
    at: iso(),
  });
  const handle = await ctx.writeResource("init", "tofu-init", rec);
  if (run.code !== 0) {
    throw new Error(
      `init exit ${run.code}${
        run.aborted ? " (aborted)" : ""
      }; a state lock left behind needs tofu force-unlock`,
    );
  }
  return { dataHandles: [handle] };
}

/** plan: a saved plan file outside the repository; the record holds its sha256 and summary, never values. */
export async function planMethod(ctx: TofuCtx, raw: unknown) {
  NoArgs.parse(raw ?? {});
  const g = args(ctx);
  sameGlobals(raw, g);
  const { rs, r } = await preflight(ctx, g);
  const v = await checkVersion(ctx, g, dataDir(r), true);
  if (v.problems.length) throw new Error(`refused: ${v.problems.join("; ")}`);
  await io.privateDir(planDir(r));
  // a stale plan can never be applied, and its file holds values: remove it
  const stale = stalePlanFiles(
    await io.listFiles(planDir(r)),
    io.now(),
    g.planMaxAgeMinutes * 60_000,
  );
  for (const n of stale) await io.removeQuiet(`${planDir(r)}/${n}`);
  if (stale.length) {
    ctx.logger?.info("plan: removed {n} stale saved plan file(s)", {
      n: stale.length,
    });
  }
  const createdAt = io.now();
  const planId = newPlanId(createdAt, io.randomHex(4));
  const file = planFile(r, planId);
  const run = await tofu(
    ctx,
    g,
    argv.plan(g, file),
    dataDir(r),
    timeout(g, "plan"),
  );
  let counts: CountsT = {
    import: 0,
    create: 0,
    update: 0,
    replace: 0,
    delete: 0,
    forget: 0,
  };
  let summary: ChangeT[] = [];
  let cut = false;
  let sha: string | null = null;
  let code = run.code;
  if ((code === 0 || code === 2) && (await io.exists(file))) {
    await io.chmod600(file);
    const before = await io.sha256File(file);
    const show = await tofu(
      ctx,
      g,
      argv.show(g, file),
      dataDir(r),
      timeout(g, "plan"),
    );
    try {
      if (show.code !== 0 || show.stdoutCut) throw new Error("show");
      ({ counts, summary, cut } = summarize(show.stdout));
      // the summary must describe the bytes the sha names
      if ((await io.sha256File(file)) !== before) throw new Error("changed");
      sha = before;
    } catch {
      code = 1;
    }
  } else if (code === 0 || code === 2) code = 1;
  const kind = exitKind(code, counts);
  if (kind !== "changes") {
    await io.removeQuiet(file);
    sha = null;
  }
  const rec = PlanRecord.parse({
    schema: "tofu-plan/1",
    planId,
    commit: rs.head,
    configDigest: rs.digest,
    tofuVersion: v.tofu,
    providerVersions: v.providers,
    exitCode: run.code,
    exitKind: kind,
    planSha256: sha,
    counts,
    summary,
    summaryCut: cut,
    diagnostics: diagnostics(run.stdout),
    createdAt: createdAt.toISOString(),
    finishedAt: iso(),
  });
  const handle = await ctx.writeResource("plan", planDataName(planId), rec);
  if (kind === "error") {
    throw new Error(
      `plan ${planId}: exit kind error (exit ${run.code}${
        run.aborted ? ", aborted" : ""
      }); see the record's diagnostics`,
    );
  }
  if (kind === "changes") {
    ctx.logger?.info(
      "plan {planId}: changes {counts}; read it with: {show}; then apply --input planId={planId} --input planSha256={sha}",
      {
        planId,
        counts: JSON.stringify(counts),
        show: showCommand(g, ctx.repoDir, io.home(), r, file),
        sha,
      },
    );
  } else ctx.logger?.info("plan {planId}: no changes", { planId });
  return { dataHandles: [handle] };
}

/**
 * apply: exactly the saved plan whose sha256 was typed, or a recorded
 * refusal. The plan file is copied into a fresh private directory (never
 * through a symlink); the copy is hashed, summarized again with
 * `tofu show -json` (the record's counts are not trusted) and applied.
 */
export async function applyMethod(ctx: TofuCtx, raw: unknown) {
  const a = ApplyArgs.parse(raw);
  const g = args(ctx);
  sameGlobals(raw, g);
  const startedAt = iso();
  const r = root(ctx);
  const prior = ctx.readResource
    ? ApplyRecord.safeParse(await ctx.readResource(applyDataName(a.planId)))
    : null;
  if (prior?.success && prior.data.result === "applied") {
    // refused without a record: the applied record stays the latest
    throw new Error(`apply ${a.planId} refused: already-applied`);
  }
  const found = ctx.readResource
    ? await ctx.readResource(planDataName(a.planId))
    : null;
  const parsed = found ? PlanRecord.safeParse(found) : null;
  const rec = parsed?.success && parsed.data.planId === a.planId
    ? parsed.data
    : null;
  const write = async (
    result: "applied" | "refused" | "failed",
    o: {
      refusal?: Refusal;
      exitCode?: number | null;
      counts?: CountsT;
      diagnostics?: DiagnosticT[];
    } = {},
  ) =>
    await ctx.writeResource(
      "apply",
      applyDataName(a.planId),
      ApplyRecord.parse({
        schema: "tofu-apply/1",
        planId: a.planId,
        planSha256: a.planSha256,
        result,
        refusal: o.refusal ?? null,
        exitCode: o.exitCode ?? null,
        countsApplied: result === "applied" ? o.counts ?? null : null,
        diagnostics: o.diagnostics ?? [],
        startedAt,
        finishedAt: iso(),
      }),
    );
  const refuse = async (refusal: Refusal, why = ""): Promise<never> => {
    await write("refused", { refusal });
    throw new Error(`apply ${a.planId} refused: ${refusal}${why}`);
  };
  const file = planFile(r, a.planId);
  const tmp = await io.makeTempDir("swamp-opentofu-apply-");
  try {
    await io.privateDir(r);
    await io.privateDir(planDir(r));
    const copy = `${tmp}/${a.planId}.tfplan`;
    const fileSha = (await io.copyRegularFile(file, copy))
      ? await io.sha256File(copy)
      : null;
    let rs: Awaited<ReturnType<typeof repoState>>;
    try {
      rs = await repoState(ctx.repoDir, g.configDir);
    } catch (e) {
      return await refuse("repository", ` (${(e as Error).message})`);
    }
    const guardOf = (p: PlanRecordT | null) =>
      applyGuard({
        rec: p,
        typedSha: a.planSha256,
        fileSha,
        head: rs.head,
        clean: rs.clean,
        digest: rs.digest,
        now: io.now(),
        maxAgeMs: g.planMaxAgeMinutes * 60_000,
        permit: g.permitActions,
        allowMixedImport: g.allowMixedImport,
      });
    const first = guardOf(rec);
    if (first !== null) return await refuse(first);
    const v = await checkVersion(ctx, g, dataDir(r), true);
    if (v.problems.length) {
      return await refuse("version", ` (${v.problems.join("; ")})`);
    }
    // the counts that decide come from the copy itself, not the record
    const show = await tofu(
      ctx,
      g,
      argv.show(g, copy),
      dataDir(r),
      timeout(g, "plan"),
    );
    let counts: CountsT;
    try {
      if (show.code !== 0 || show.stdoutCut) throw new Error("show");
      counts = summarize(show.stdout).counts;
    } catch {
      return await refuse("plan-unreadable");
    }
    const second = guardOf({ ...rec!, counts });
    if (second !== null) return await refuse(second);
    if ((await io.sha256File(copy)) !== fileSha) {
      return await refuse("file-changed");
    }
    // tofu's own stale-plan check (the state serial) stays the last guard
    const run = await tofu(
      ctx,
      g,
      argv.apply(g, copy),
      dataDir(r),
      timeout(g, "apply"),
    );
    await io.removeQuiet(file);
    const handle = await write(run.code === 0 ? "applied" : "failed", {
      exitCode: run.code,
      counts,
      diagnostics: diagnostics(run.stdout),
    });
    if (run.code !== 0) {
      throw new Error(
        `apply ${a.planId} exit ${run.code}${
          run.aborted ? " (aborted)" : ""
        }; see the record's diagnostics, then plan again`,
      );
    }
    return { dataHandles: [handle] };
  } finally {
    await io.removeQuiet(tmp, true);
  }
}

/** output: the allowlisted non-sensitive outputs and the state's managed addresses. */
export async function outputMethod(ctx: TofuCtx, raw: unknown) {
  NoArgs.parse(raw ?? {});
  const g = args(ctx);
  sameGlobals(raw, g);
  const r = root(ctx);
  const v = await checkVersion(ctx, g, dataDir(r), true);
  if (v.problems.length) throw new Error(`refused: ${v.problems.join("; ")}`);
  const out = await tofu(
    ctx,
    g,
    argv.output(g),
    dataDir(r),
    timeout(g, "other"),
  );
  if (out.code !== 0) throw new Error(`output exit ${out.code}`);
  const guarded = outputGuard(out.stdout, g.outputs);
  if ("problem" in guarded) throw new Error(`refused: ${guarded.problem}`);
  const st = await tofu(
    ctx,
    g,
    argv.showState(g),
    dataDir(r),
    timeout(g, "other"),
  );
  if (st.code !== 0 || st.stdoutCut) {
    throw new Error(`show (state) exit ${st.code}`);
  }
  const addrs = stateAddresses(st.stdout);
  const rec = OutputRecord.parse({
    schema: "tofu-output/1",
    outputs: guarded.outputs,
    unlisted: guarded.unlisted,
    stateAddresses: addrs,
    expectedMissing: g.expectedAddresses.filter((d) => !addrs.includes(d)),
    at: iso(),
  });
  return { dataHandles: [await ctx.writeResource("output", OUTPUT_DATA, rec)] };
}

const spec = (description: string, schema: z.ZodType) => ({
  description,
  schema,
  lifetime: "infinite" as const,
  garbageCollection: 50,
});
/** The @vcjdeboer/opentofu model type. */
export const model = {
  type: "@vcjdeboer/opentofu",
  version: "2026.10.23.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.10.23.1",
      description:
        "plan removes stale saved plan files; global arguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    version: spec(
      "tofu-version/1: the tofu version and provider selections, checked against the pins",
      VersionRecord,
    ),
    validate: spec(
      "tofu-validate/1: the configuration rules and tofu validate after init -backend=false; no backend, no credential",
      ValidateRecord,
    ),
    init: spec(
      "tofu-init/1: init with the configured backend, -lockfile=readonly",
      InitRecord,
    ),
    plan: spec(
      "tofu-plan/1: one saved plan: exit kind, sha256, counts and an address-and-action summary, never values",
      PlanRecord,
    ),
    apply: spec(
      "tofu-apply/1: a sha-bound apply of one saved plan: applied, refused (with its reason) or failed",
      ApplyRecord,
    ),
    output: spec(
      "tofu-output/1: the allowlisted non-sensitive outputs and the state's managed addresses",
      OutputRecord,
    ),
  },
  methods: {
    version: {
      description:
        "tofu version -json; refuses any tofu or provider version other than the pinned ones",
      arguments: NoArgs,
      execute: (a: unknown, ctx: TofuCtx) => versionMethod(ctx, a),
    },
    validate: {
      description:
        "The definition's configuration rules, the lock file against the provider pins (and the mirror's h1), then init -backend=false and validate in a temporary data directory: no backend, no credential",
      arguments: NoArgs,
      execute: (a: unknown, ctx: TofuCtx) => validateMethod(ctx, a),
    },
    init: {
      description:
        "init with the configured backend and -lockfile=readonly, on a clean committed configuration",
      arguments: NoArgs,
      execute: (a: unknown, ctx: TofuCtx) => initMethod(ctx, a),
    },
    plan: {
      description:
        "A saved plan in ~/.swamp-opentofu/<definition>/plans (0600): exit kind, sha256, counts and an address-and-action summary recorded; logs the tofu show command to read it; first removes saved plan files older than planMaxAgeMinutes",
      arguments: NoArgs,
      execute: (a: unknown, ctx: TofuCtx) => planMethod(ctx, a),
    },
    apply: {
      description:
        "Apply a private copy of exactly the saved plan planId whose sha256 is given; refused (and recorded) on a sha, commit or configuration mismatch, a stale plan, a version change, a destructive action not permitted (read from the plan file itself), an import plan that also creates or updates, or a plan already applied",
      arguments: ApplyArgs,
      execute: (a: unknown, ctx: TofuCtx) => applyMethod(ctx, a),
    },
    output: {
      description:
        "Record the allowlisted non-sensitive outputs and the state's managed addresses; refuses a missing or sensitive allowlisted output",
      arguments: NoArgs,
      execute: (a: unknown, ctx: TofuCtx) => outputMethod(ctx, a),
    },
  },
};
