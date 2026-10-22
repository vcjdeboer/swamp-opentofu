// Copyright (c) 2026 Vincent de Boer
// SPDX-License-Identifier: MIT

// Tests of @vcjdeboer/opentofu: pure tests of the summary, the apply guard,
// the output guard, the configuration rules, the lock check and the argv;
// then the methods against a fake tofu (a POSIX sh script in a temporary
// directory) in a temporary git repository. With TOFU_BIN set to a real tofu,
// an end-to-end test plans and applies a terraform_data resource with the
// local backend (no provider, no network, no cloud).
import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1.0.13";
import {
  ApplyArgs,
  applyDataName,
  applyGuard,
  argv,
  childEnv,
  cliConfigProblems,
  configProblems,
  exitKind,
  type GlobalArgs,
  GlobalArgsSchema,
  h1Hash,
  hclBlocks,
  lockProblems,
  model,
  modelHome,
  newPlanId,
  OUTPUT_DATA,
  outputGuard,
  planDataName,
  type PlanRecordT,
  sameGlobals,
  shellQuote,
  stateAddresses,
  summarize,
  type TofuCtx,
  versionProblems,
} from "./opentofu.ts";
import { platform, privateDir } from "./_io.ts";

const AWS = "registry.opentofu.org/hashicorp/aws";
const CANARY = "CANARY-7f3e9a1b-value-never-recorded";
const SHA = "a".repeat(64);
const COMMIT = "b".repeat(40);
const DEF_ID = "0b6f7c1e-5d0a-4c55-9a5e-1f2a3b4c5d6e";

const LOCK = `# This file is maintained automatically by "tofu init".
# Manual edits may be lost in future updates.

provider "${AWS}" {
  version     = "6.65.0"
  constraints = "6.65.0"
  hashes = [
    "h1:AAAA=",
    "zh:0123",
  ]
}
`;
const CONFIG: Record<string, string> = {
  "main.tf": `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.65.0"
    }
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"
  lifecycle {
    prevent_destroy = true
  }
}

output "bucket_arn" {
  value     = aws_s3_bucket.logs.arn
  sensitive = false
}
`,
  ".terraform.lock.hcl": LOCK,
};

const g: GlobalArgs = GlobalArgsSchema.parse({
  tofuBin: "/opt/tofu/bin/tofu",
  tofuVersion: "1.13.1",
  providers: { [AWS]: "6.65.0" },
  configDir: "infra",
  outputs: ["bucket_arn"],
  expectedAddresses: ["aws_s3_bucket.logs"],
  rules: [
    "prevent-destroy",
    "no-provisioner",
    "no-external-data",
    "no-module",
    "no-var-files",
    "outputs-allowlisted",
  ],
  env: { AWS_PROFILE: "deploy", AWS_REGION: "eu-west-1" },
});

// ---- pure: the plan summary
const showJson = (
  changes: {
    address: string;
    actions: string[];
    importing?: boolean;
    mode?: string;
  }[],
) =>
  JSON.stringify({
    format_version: "1.2",
    resource_changes: changes.map((c) => ({
      address: c.address,
      mode: c.mode ?? "managed",
      change: {
        actions: c.actions,
        before: { secret: CANARY },
        after: { secret: CANARY, tags: { x: CANARY } },
        after_unknown: {},
        ...(c.importing ? { importing: { id: CANARY } } : {}),
      },
    })),
    prior_state: {
      values: {
        root_module: { resources: [{ values: { password: CANARY } }] },
      },
    },
    configuration: { root_module: {} },
  });

Deno.test("summarize: counts every kind; no-ops are left out; no value reaches the summary", () => {
  const s = summarize(showJson([
    { address: "aws_instance.a", actions: ["no-op"], importing: true },
    { address: "aws_iam_role.a", actions: ["update"] },
    { address: "aws_s3_bucket.a", actions: ["create"] },
    { address: "aws_security_group.a", actions: ["delete", "create"] },
    { address: "aws_iam_policy.a", actions: ["create", "delete"] },
    { address: "aws_iam_instance_profile.a", actions: ["delete"] },
    { address: "aws_s3_bucket_policy.a", actions: ["forget"] },
    { address: "aws_s3_bucket.unchanged", actions: ["no-op"] },
    { address: "data.aws_vpc.default", actions: ["read"], mode: "data" },
  ]));
  assertEquals(s.counts, {
    import: 1,
    create: 1,
    update: 1,
    replace: 2,
    delete: 1,
    forget: 1,
  });
  assertEquals(s.summary.length, 7);
  assertEquals(s.cut, false);
  assert(!JSON.stringify(s).includes(CANARY));
  assertEquals(s.summary[0], {
    address: "aws_instance.a",
    actions: ["no-op"],
    importing: true,
  });
});

Deno.test("exitKind: 0/2/1; an import is a change even at exit 0", () => {
  const zero = {
    import: 0,
    create: 0,
    update: 0,
    replace: 0,
    delete: 0,
    forget: 0,
  };
  assertEquals(exitKind(0, zero), "no-changes");
  assertEquals(exitKind(2, zero), "changes");
  assertEquals(exitKind(1, zero), "error");
  assertEquals(exitKind(null, zero), "error");
  assertEquals(exitKind(0, { ...zero, import: 10 }), "changes");
});

// ---- pure: the apply guard
const plan = (o: Partial<PlanRecordT> = {}): PlanRecordT => ({
  schema: "tofu-plan/1",
  planId: "p20261019T200000-0123abcd",
  commit: COMMIT,
  configDigest: SHA,
  tofuVersion: "1.13.1",
  providerVersions: {},
  exitCode: 2,
  exitKind: "changes",
  planSha256: SHA,
  counts: { import: 0, create: 1, update: 0, replace: 0, delete: 0, forget: 0 },
  summary: [],
  summaryCut: false,
  diagnostics: [],
  createdAt: "2026-10-19T20:00:00.000Z",
  finishedAt: "2026-10-19T20:01:00.000Z",
  ...o,
});
const guard = (o: Partial<Parameters<typeof applyGuard>[0]> = {}) =>
  applyGuard({
    rec: plan(),
    typedSha: SHA,
    fileSha: SHA,
    head: COMMIT,
    clean: true,
    digest: SHA,
    now: new Date("2026-10-19T21:00:00Z"),
    maxAgeMs: 4 * 3600_000,
    permit: [],
    allowMixedImport: false,
    ...o,
  });

Deno.test("applyGuard: applies a matching plan; refuses every mismatch", () => {
  assertEquals(guard(), null);
  assertEquals(guard({ rec: null }), "no-plan");
  assertEquals(
    guard({ rec: plan({ exitKind: "no-changes", planSha256: null }) }),
    "not-changes",
  );
  assertEquals(guard({ typedSha: "c".repeat(64) }), "sha-mismatch");
  assertEquals(guard({ fileSha: null }), "file-missing");
  assertEquals(guard({ fileSha: "d".repeat(64) }), "file-changed");
  assertEquals(guard({ head: "e".repeat(40) }), "commit-changed");
  assertEquals(guard({ clean: false }), "config-dirty");
  assertEquals(guard({ digest: "f".repeat(64) }), "config-changed");
  assertEquals(guard({ now: new Date("2026-10-20T00:00:01Z") }), "stale");
  assertEquals(guard({ now: new Date("2026-10-19T19:00:00Z") }), "stale");
  assertEquals(
    guard({ now: new Date("2026-10-20T00:00:01Z"), maxAgeMs: 5 * 3600_000 }),
    null,
  );
});

Deno.test("applyGuard: delete, replace and forget refused unless permitted; an import plan only imports unless allowed", () => {
  const c = {
    import: 0,
    create: 0,
    update: 0,
    replace: 0,
    delete: 0,
    forget: 0,
  };
  for (const k of ["delete", "replace", "forget"] as const) {
    assertEquals(
      guard({ rec: plan({ counts: { ...c, [k]: 1 } }) }),
      "destructive",
    );
    assertEquals(
      guard({ rec: plan({ counts: { ...c, [k]: 1 } }), permit: [k] }),
      null,
    );
  }
  assertEquals(
    guard({
      rec: plan({ counts: { ...c, delete: 1, replace: 1 } }),
      permit: ["delete"],
    }),
    "destructive",
  );
  assertEquals(guard({ rec: plan({ counts: { ...c, import: 3 } }) }), null);
  assertEquals(
    guard({ rec: plan({ counts: { ...c, import: 3, update: 1 } }) }),
    "import-not-clean",
  );
  assertEquals(
    guard({ rec: plan({ counts: { ...c, import: 3, create: 1 } }) }),
    "import-not-clean",
  );
  assertEquals(
    guard({
      rec: plan({ counts: { ...c, import: 3, create: 1 } }),
      allowMixedImport: true,
    }),
    null,
  );
});

// ---- pure: outputs and state
const outputs = (
  o: Record<string, { sensitive: boolean; value: unknown }> = {},
) =>
  JSON.stringify({
    bucket_arn: {
      sensitive: false,
      type: "string",
      value: "arn:aws:s3:::example-logs",
    },
    ...o,
  });

Deno.test("outputGuard: the allowlisted ones; unlisted counted, never recorded; sensitive or non-scalar refused", () => {
  const ok = outputGuard(
    outputs({ other: { sensitive: true, value: CANARY } }),
    ["bucket_arn"],
  );
  assert("outputs" in ok);
  assertEquals(ok.outputs, { bucket_arn: "arn:aws:s3:::example-logs" });
  assertEquals(ok.unlisted, 1);
  assert(!JSON.stringify(ok).includes(CANARY));
  const sens = outputGuard(
    outputs({ bucket_arn: { sensitive: true, value: CANARY } }),
    ["bucket_arn"],
  );
  assert("problem" in sens && !sens.problem.includes(CANARY));
  assert("problem" in outputGuard(outputs(), ["bucket_arn", "missing"]));
  assert(
    "problem" in
      outputGuard(outputs({ m: { sensitive: false, value: { k: CANARY } } }), [
        "m",
      ]),
  );
  const n = outputGuard(
    outputs({
      n: { sensitive: false, value: 3 },
      b: { sensitive: false, value: true },
    }),
    ["n", "b"],
  );
  assert("outputs" in n && n.outputs.n === 3 && n.outputs.b === true);
  assert("problem" in outputGuard("not json", []));
});

Deno.test("stateAddresses: managed addresses of nested modules only (flattenResources)", () => {
  const s = JSON.stringify({
    values: {
      root_module: {
        resources: [{
          address: "aws_s3_bucket.logs",
          mode: "managed",
          values: { x: CANARY },
        }, { address: "data.aws_vpc.default", mode: "data" }],
        child_modules: [{
          address: "module.m",
          resources: [{ address: "module.m.aws_s3_bucket.b", mode: "managed" }],
        }],
      },
    },
  });
  assertEquals(stateAddresses(s), [
    "aws_s3_bucket.logs",
    "module.m.aws_s3_bucket.b",
  ]);
  assertEquals(stateAddresses(JSON.stringify({ format_version: "1.0" })), []);
});

// ---- pure: version
Deno.test("versionProblems: refuses another tofu, another or unpinned provider; pinned providers needed after init", () => {
  const v = (t: string, p: Record<string, string> = {}) =>
    JSON.stringify({ terraform_version: t, provider_selections: p });
  assertEquals(versionProblems(v("1.13.1"), g, false).problems, []);
  assertEquals(
    versionProblems(v("1.13.1", { [AWS]: "6.65.0" }), g, true).problems,
    [],
  );
  assertEquals(versionProblems(v("1.13.2"), g, false).problems.length, 1);
  assertEquals(
    versionProblems(v("1.13.1", { [AWS]: "6.64.0" }), g, false).problems.length,
    1,
  );
  assertEquals(versionProblems(v("1.13.1"), g, true).problems.length, 1);
  assertEquals(
    versionProblems(
      v("1.13.1", { [AWS]: "6.65.0", "registry.opentofu.org/x/y": "1.0.0" }),
      g,
      true,
    ).problems.length,
    1,
  );
});

// ---- pure: global arguments, inputs, argv, environment
Deno.test("global arguments: closed; reserved env keys, relative-path escapes and a mirror without a CLI config refused", () => {
  const base = {
    tofuBin: "/opt/tofu/bin/tofu",
    tofuVersion: "1.13.1",
    configDir: "infra",
  };
  const d = GlobalArgsSchema.parse(base);
  assertEquals(d.rules, []);
  assertEquals(d.permitActions, []);
  assertEquals(d.planMaxAgeMinutes, 240);
  assertThrows(() => GlobalArgsSchema.parse({ ...base, extra: 1 }));
  assertThrows(() => GlobalArgsSchema.parse({ ...base, tofuBin: "tofu" }));
  assertThrows(() =>
    GlobalArgsSchema.parse({ ...base, configDir: "../elsewhere" })
  );
  assertThrows(() => GlobalArgsSchema.parse({ ...base, configDir: "/abs" }));
  assertThrows(() => GlobalArgsSchema.parse({ ...base, configDir: "a/./b" }));
  for (
    const k of [
      "PATH",
      "HOME",
      "TF_VAR_x",
      "TF_LOG",
      "DYLD_INSERT_LIBRARIES",
      "LD_PRELOAD",
      "CHECKPOINT_DISABLE",
    ]
  ) {
    assertThrows(
      () => GlobalArgsSchema.parse({ ...base, env: { [k]: "x" } }),
      Error,
      k,
    );
  }
  assertThrows(
    () => GlobalArgsSchema.parse({ ...base, providerMirror: "/mirror" }),
    Error,
    "cliConfigFile",
  );
  assertThrows(() =>
    GlobalArgsSchema.parse({ ...base, providers: { aws: "6.65.0" } })
  );
  assertThrows(() =>
    GlobalArgsSchema.parse({ ...base, rules: ["no-such-rule"] })
  );
});

Deno.test("inputs are closed and patterned; global-argument inputs must equal the definition", () => {
  ApplyArgs.parse({ planId: "p20261019T200000-0123abcd", planSha256: SHA });
  assertThrows(() =>
    ApplyArgs.parse({ planId: "../../etc/passwd", planSha256: SHA })
  );
  assertThrows(() =>
    ApplyArgs.parse({
      planId: "p20261019T200000-0123abcd",
      planSha256: "A".repeat(64),
    })
  );
  assertThrows(() =>
    ApplyArgs.parse({
      planId: "p20261019T200000-0123abcd",
      planSha256: SHA,
      target: "x",
    })
  );
  ApplyArgs.parse({
    planId: "p20261019T200000-0123abcd",
    planSha256: SHA,
    ...g,
  });
  sameGlobals({ ...g }, g);
  sameGlobals({ env: { AWS_REGION: "eu-west-1", AWS_PROFILE: "deploy" } }, g);
  assertThrows(
    () => sameGlobals({ tofuBin: "/tmp/evil/bin/tofu" }, g),
    Error,
    "differs",
  );
  assertThrows(
    () => sameGlobals({ permitActions: ["delete"] }, g),
    Error,
    "differs",
  );
  assertThrows(
    () =>
      sameGlobals(
        { env: { AWS_PROFILE: "admin", AWS_REGION: "eu-west-1" } },
        g,
      ),
    Error,
    "differs",
  );
  assertEquals(
    newPlanId(new Date("2026-10-19T20:15:03Z"), "0123abcd"),
    "p20261019T201503-0123abcd",
  );
  assertEquals(
    planDataName("p20261019T201503-0123abcd"),
    "tofu-plan-p20261019t201503-0123abcd",
  );
  assertEquals(
    applyDataName("p20261019T201503-0123abcd"),
    "tofu-apply-p20261019t201503-0123abcd",
  );
  assertEquals(modelHome("/h", DEF_ID), `/h/.swamp-opentofu/${DEF_ID}`);
  assertThrows(() => modelHome("/h", "../x"));
});

Deno.test("argv: fixed; validate never initialises a backend; init is -lockfile=readonly", () => {
  assert(argv.validateInit(g).includes("-backend=false"));
  assert(argv.validateInit(g).includes("-lockfile=readonly"));
  assert(argv.init(g).includes("-lockfile=readonly"));
  const all = [
    argv.version(g),
    argv.validateInit(g),
    argv.validate(g),
    argv.init(g),
    argv.plan(g, "/p/x.tfplan"),
    argv.show(g, "/p/x.tfplan"),
    argv.showState(g),
    argv.apply(g, "/p/x.tfplan"),
    argv.output(g),
  ];
  for (const a of all) {
    assertEquals(a[0], g.tofuBin);
    for (const w of a) {
      assert(
        !/^-(target|replace|var|var-file|auto-approve|destroy)/.test(w) &&
          !["import", "destroy", "state", "force-unlock", "console"].includes(
            w,
          ),
        w,
      );
    }
  }
  assertEquals(argv.apply(g, "/p/x.tfplan").at(-1), "/p/x.tfplan");
});

Deno.test("childEnv: the definition's env plus the model's keys; no CLI config means /dev/null, never ~/.tofurc", () => {
  const e = childEnv(g, "/repo", "/home/u", "/d");
  assertEquals(e.AWS_PROFILE, "deploy");
  assertEquals(e.TF_CLI_CONFIG_FILE, "/dev/null");
  assertEquals(e.PATH, "/opt/tofu/bin:/usr/bin:/bin");
  const m = childEnv(
    { ...g, cliConfigFile: "tofurc", extraPath: ["/opt/aws/bin"] },
    "/repo",
    "/home/u",
    "/d",
  );
  assertEquals(m.TF_CLI_CONFIG_FILE, "/repo/infra/tofurc");
  assertEquals(m.PATH, "/opt/tofu/bin:/opt/aws/bin:/usr/bin:/bin");
});

// ---- pure: the configuration rules
Deno.test("configProblems: the example passes; no rule switched on means no problem", () => {
  assertEquals(configProblems(CONFIG, g), []);
  const loose = {
    ...CONFIG,
    "x.auto.tfvars": "a = 1\n",
    "m.tf": 'module "m" {\n  source = "./m"\n}\n',
  };
  assertEquals(configProblems(loose, { rules: [], outputs: [] }), []);
});

Deno.test("configProblems: each rule bites", () => {
  const f = CONFIG;
  const mut = (from: string | RegExp, to: string) => ({
    ...f,
    "main.tf": f["main.tf"].replace(from, to),
  });
  const has = (files: Record<string, string>, re: RegExp) =>
    configProblems(files, g).some((p) => re.test(p));
  assert(
    has(
      mut("prevent_destroy = true", "prevent_destroy = false"),
      /aws_s3_bucket\.logs: lifecycle/,
    ),
  );
  assert(
    has(
      mut(/sensitive = false/, "sensitive = true"),
      /sensitive = false is missing/,
    ),
  );
  assert(
    has({
      ...f,
      "x.tf": 'output "extra" {\n  value = 1\n  sensitive = false\n}\n',
    }, /outputs must be exactly/),
  );
  assert(has({ ...f, "x.auto.tfvars": "a = 1\n" }, /no tfvars/));
  assert(has({ ...f, "x_override.tf": "" }, /no tfvars, override/));
  assert(has({ ...f, "x.tf.json": "{}" }, /\.tf\.json/));
  assert(
    has({
      ...f,
      "x.tf":
        'resource "null_resource" "x" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n  lifecycle {\n    prevent_destroy = true\n  }\n}\n',
    }, /provisioner/),
  );
  assert(
    has(
      { ...f, "x.tf": 'data "external" "x" {\n  program = ["sh"]\n}\n' },
      /external data source/,
    ),
  );
  assert(
    has(
      { ...f, "x.tf": 'module "m" {\n  source = "./m"\n}\n' },
      /module block/,
    ),
  );
  // a brace inside a string or a comment does not end a block
  assertEquals(
    hclBlocks(
      'resource "a" "b" {\n  x = "${f({})}" # }\n  lifecycle {\n    prevent_destroy = true\n  }\n}\n',
    ).length,
    1,
  );
});

Deno.test("configProblems: the scanner fails closed; .tofu files, unquoted labels, heredocs and strings", () => {
  const has = (files: Record<string, string>, re: RegExp) =>
    configProblems({ ...CONFIG, ...files }, g).some((p) => re.test(p));
  const bare = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n';
  // OpenTofu reads .tofu files: the rules do too
  assert(has({ "extra.tofu": bare }, /aws_s3_bucket\.b: lifecycle/));
  assert(has({ "x.tofu.json": "{}" }, /JSON configuration/));
  assert(has({ "override.tofu": "" }, /no tfvars, override/));
  // identifier labels are labels
  assert(
    has(
      { "x.tf": 'resource aws_s3_bucket b {\n  bucket = "x"\n}\n' },
      /aws_s3_bucket\.b: lifecycle/,
    ),
  );
  assert(has({ "x.tf": 'module m {\n  source = "./m"\n}\n' }, /module block/));
  // a # or a brace inside a heredoc neither ends a line nor a block
  const heredoc =
    'resource "aws_s3_bucket" "h" {\n  policy = <<EOT\ncolor: #fff }\nEOT\n  lifecycle {\n    prevent_destroy = true\n  }\n}\n\nmodule "m" {\n  source = "./m"\n}\n';
  const hp = configProblems({ ...CONFIG, "h.tf": heredoc }, g);
  assert(!hp.some((p) => /aws_s3_bucket\.h/.test(p)), hp.join("; "));
  assert(hp.some((p) => /module\.m: module block/.test(p)), hp.join("; "));
  // keywords inside strings and templates do not count
  const str =
    'resource "aws_s3_bucket" "s" {\n  bucket = "${lower("a}")} lifecycle { prevent_destroy = true }"\n}\n';
  assert(has({ "s.tf": str }, /aws_s3_bucket\.s: lifecycle/));
  // what the scanner cannot account for is a problem, never a pass
  assert(has({ "u.tf": bare.replace(/\}\n$/, "") }, /unbalanced braces/));
  assert(
    has(
      { "u.tf": 'resource "a" "b" {\n  x = "open\n}\n' },
      /unterminated string/,
    ),
  );
  assert(
    has(
      { "u.tf": "x = <<EOT\nnever closed\n" },
      /unterminated heredoc|outside any block/,
    ),
  );
  assert(has({ "u.tf": "locals_without_braces = 1\n" }, /outside any block/));
});

Deno.test("global arguments: configDir is a plain path; redirecting env keys refused; the show command is quoted", () => {
  const base = { tofuBin: "/opt/tofu/bin/tofu", tofuVersion: "1.13.1" };
  for (const d of ["infra/", "infra//x", "inf*", ":(glob)infra", "a\\b"]) {
    assertThrows(
      () => GlobalArgsSchema.parse({ ...base, configDir: d }),
      Error,
      undefined,
      d,
    );
  }
  GlobalArgsSchema.parse({ ...base, configDir: "deploy/prod-eu" });
  for (
    const k of [
      "GIT_SSH_COMMAND",
      "XDG_DATA_HOME",
      "HTTPS_PROXY",
      "https_proxy",
      "SSL_CERT_FILE",
      "OTEL_EXPORTER_OTLP_ENDPOINT",
      "TMPDIR",
    ]
  ) {
    assertThrows(
      () =>
        GlobalArgsSchema.parse({ ...base, configDir: "i", env: { [k]: "x" } }),
      Error,
      k,
    );
  }
  assertThrows(() =>
    GlobalArgsSchema.parse({
      ...base,
      configDir: "i",
      cliConfigFile: "sub/tofurc",
    })
  );
  assertEquals(shellQuote("/plain/path"), "/plain/path");
  assertEquals(shellQuote("/vs code/it's"), `'/vs code/it'\\''s'`);
  assertEquals(
    cliConfigProblems(
      'provider_installation {\n  dev_overrides {\n    "hashicorp/aws" = "/tmp"\n  }\n}\n',
    ).length,
    1,
  );
  assertEquals(
    cliConfigProblems(
      '# dev_overrides in a comment\nplugin_cache_dir = "/x"\n',
    ),
    [],
  );
});

Deno.test("lockProblems: exactly the pinned providers at their versions; the mirror's h1 when given", () => {
  assertEquals(lockProblems(LOCK, g.providers), []);
  assertEquals(lockProblems(LOCK, g.providers, { [AWS]: "h1:AAAA=" }), []);
  assert(
    lockProblems(LOCK, g.providers, { [AWS]: "h1:BBBB=" }).some((p) =>
      /h1/.test(p)
    ),
  );
  assert(
    lockProblems(LOCK, { [AWS]: "6.66.0" }).some((p) =>
      /must be at 6\.66\.0/.test(p)
    ),
  );
  assert(
    lockProblems(LOCK, {}).some((p) => /providers must be exactly/.test(p)),
  );
  assert(lockProblems(undefined, g.providers).some((p) => /missing/.test(p)));
  assertEquals(lockProblems(undefined, {}), []);
  const two = LOCK +
    `\nprovider "registry.opentofu.org/hashicorp/random" {\n  version = "3.7.2"\n  hashes = ["h1:CCCC="]\n}\n`;
  assertEquals(
    lockProblems(two, {
      ...g.providers,
      "registry.opentofu.org/hashicorp/random": "3.7.2",
    }, { "registry.opentofu.org/hashicorp/random": "h1:CCCC=" }),
    [],
  );
  assert(
    lockProblems(two, {
      ...g.providers,
      "registry.opentofu.org/hashicorp/random": "3.7.1",
    }).length === 1,
  );
});

Deno.test("h1Hash: the dirhash Hash1 of a package (sorted relative paths)", () => {
  const files = [{ name: "b", sha256: "1".repeat(64) }, {
    name: "a/x",
    sha256: "2".repeat(64),
  }];
  assertEquals(h1Hash(files), h1Hash([...files].reverse()));
  assert(h1Hash(files).startsWith("h1:"));
});

Deno.test("cliConfigProblems: only one filesystem mirror at the pinned path", () => {
  const t =
    `provider_installation {\n  filesystem_mirror {\n    path    = "/mirror"\n    include = ["registry.opentofu.org/*/*"]\n  }\n}\n`;
  assertEquals(cliConfigProblems(t, "/mirror"), []);
  assert(cliConfigProblems(t, "/other").length > 0);
  assert(
    cliConfigProblems(
      t.replace(
        "filesystem_mirror {",
        'dev_overrides {\n    "hashicorp/aws" = "/tmp"\n  }\n  filesystem_mirror {',
      ),
      "/mirror",
    ).length > 0,
  );
  assert(
    cliConfigProblems(
      t.replace("filesystem_mirror", "network_mirror"),
      "/mirror",
    ).length > 0,
  );
  assert(
    cliConfigProblems(t + '\nhost "example.com" {\n}\n', "/mirror").length > 0,
  );
});

// ---- the methods against a fake tofu
const FAKE = `#!/bin/sh
d=$(cd "$(dirname "$0")/.." && pwd)/fake
printf '%s\\n' "$*" >> "$d/calls.log"
env > "$d/env.log"
case "$1" in
  version) cat "$d/version.json" ;;
  init) exit "$(cat "$d/init.exit" 2>/dev/null || echo 0)" ;;
  validate) cat "$d/validate.json" ;;
  plan)
    for a in "$@"; do case "$a" in -out=*) out="\${a#-out=}" ;; esac; done
    if [ -f "$d/plan.sleep" ]; then trap 'exit 130' INT; sleep 20 & wait; exit 0; fi
    code=$(cat "$d/plan.exit")
    if [ "$code" = 0 ] || [ "$code" = 2 ]; then printf 'PLANBYTES-%s' "$$" > "$out"; fi
    cat "$d/plan.stream" 2>/dev/null
    exit "$code" ;;
  show) if [ $# -ge 3 ]; then cat "$d/show.json"; else cat "$d/state.json"; fi ;;
  apply) for a in "$@"; do last="$a"; done; printf '%s\\n' "$last" > "$d/applied"; exit "$(cat "$d/apply.exit" 2>/dev/null || echo 0)" ;;
  output) cat "$d/output.json" ;;
esac
`;

async function git(dir: string, ...a: string[]) {
  const o = await new Deno.Command("git", {
    args: a,
    cwd: dir,
    stdout: "null",
    stderr: "null",
  }).output();
  if (o.code !== 0) throw new Error(`git ${a.join(" ")}`);
}

async function fixture(
  config: Record<string, string> = CONFIG,
  globals: Record<string, unknown> = {},
) {
  const root = await Deno.makeTempDir({ prefix: "swamp-opentofu-test-" });
  const repo = `${root}/repo`;
  await Deno.mkdir(`${repo}/infra`, { recursive: true });
  for (const [n, t] of Object.entries(config)) {
    await Deno.writeTextFile(`${repo}/infra/${n}`, t);
  }
  await git(repo, "init", "-q");
  await git(repo, "add", "-A");
  await git(
    repo,
    "-c",
    "user.email=t@t",
    "-c",
    "user.name=t",
    "commit",
    "-q",
    "-m",
    "fixture",
  );
  await Deno.mkdir(`${root}/tofu/bin`, { recursive: true });
  await Deno.mkdir(`${root}/tofu/fake`);
  await Deno.writeTextFile(`${root}/tofu/bin/tofu`, FAKE, { mode: 0o755 });
  const fake = (n: string, t: string) =>
    Deno.writeTextFile(`${root}/tofu/fake/${n}`, t);
  await fake(
    "version.json",
    JSON.stringify({
      terraform_version: "1.13.1",
      provider_selections: { [AWS]: "6.65.0" },
    }),
  );
  const home = `${root}/home`;
  await Deno.mkdir(home);
  const store = new Map<string, Record<string, unknown>>();
  const logs: string[] = [];
  const ctx = (signal?: AbortSignal): TofuCtx => ({
    repoDir: repo,
    globalArgs: { ...g, tofuBin: `${root}/tofu/bin/tofu`, ...globals },
    definition: { id: DEF_ID, name: "infra" },
    signal,
    writeResource: (_spec, name, data) => {
      store.set(name, structuredClone(data));
      return Promise.resolve({ name });
    },
    readResource: (name) => Promise.resolve(store.get(name) ?? null),
    logger: {
      info: (m, p) => logs.push(m + JSON.stringify(p ?? {})),
      warn: (m, p) => logs.push(m + JSON.stringify(p ?? {})),
    },
  });
  const plans = `${home}/.swamp-opentofu/${DEF_ID}/plans`;
  return {
    root,
    repo,
    home,
    plans,
    fake,
    store,
    logs,
    ctx,
    calls: async () =>
      (await Deno.readTextFile(`${root}/tofu/fake/calls.log`)).trim().split(
        "\n",
      ),
  };
}

// Each method test runs with HOME at the fixture's; a canary variable in the
// parent must never reach tofu.
async function withEnv(home: string, fn: () => Promise<void>) {
  const saved = Deno.env.get("HOME");
  Deno.env.set("HOME", home);
  Deno.env.set("SWAMP_OPENTOFU_PARENT_CANARY", CANARY);
  Deno.env.set("AWS_PROFILE_PARENT_CANARY", CANARY);
  try {
    await fn();
  } finally {
    Deno.env.delete("SWAMP_OPENTOFU_PARENT_CANARY");
    Deno.env.delete("AWS_PROFILE_PARENT_CANARY");
    if (saved !== undefined) Deno.env.set("HOME", saved);
  }
}
const methods = model.methods;
const T = { sanitizeOps: false, sanitizeResources: false };
const sha256 = async (path: string) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", await Deno.readFile(path)),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");

Deno.test("privateDir: a missing directory is made 0700; an existing wider one is refused naming its mode and chmod 700", async () => {
  const tmp = await Deno.makeTempDir();
  try {
    const made = `${tmp}/home/.swamp-opentofu`;
    await privateDir(made);
    assertEquals((await Deno.stat(made)).mode! & 0o777, 0o700);
    const wide = `${tmp}/wide`;
    await Deno.mkdir(wide);
    await Deno.chmod(wide, 0o755);
    await assertRejects(
      () => privateDir(wide),
      Error,
      `${wide} is not a 0700 directory (mode 0755): run chmod 700 ${wide}`,
    );
    assertEquals(
      (await Deno.stat(wide)).mode! & 0o777,
      0o755,
      "an existing directory is never changed",
    );
  } finally {
    await Deno.remove(tmp, { recursive: true });
  }
});

Deno.test({
  ...T,
  name:
    "plan exit 2: changes recorded with sha256 and summary only; plan file 0600 outside the repo; only the definition's env reaches tofu",
  fn: async () => {
    const f = await fixture();
    await f.fake("plan.exit", "2");
    await f.fake(
      "plan.stream",
      JSON.stringify({
        type: "diagnostic",
        diagnostic: { severity: "warning", summary: "w", detail: CANARY },
      }) + "\n",
    );
    await f.fake(
      "show.json",
      showJson([{ address: "aws_s3_bucket.logs", actions: ["create"] }]),
    );
    await withEnv(f.home, async () => {
      await methods.plan.execute({}, f.ctx());
    });
    const [name, rec] = [...f.store.entries()][0];
    assert(name.startsWith("tofu-plan-p"));
    assertEquals(rec.exitKind, "changes");
    assertEquals((rec.counts as Record<string, number>).create, 1);
    const file = `${f.plans}/${rec.planId}.tfplan`;
    assertEquals((await Deno.stat(file)).mode! & 0o777, 0o600);
    assertEquals((await Deno.stat(f.plans)).mode! & 0o777, 0o700);
    assertEquals(rec.planSha256, await sha256(file));
    assert(
      !JSON.stringify(rec).includes(CANARY) &&
        !f.logs.join("\n").includes(CANARY),
    );
    assert(f.logs.join("\n").includes(`show ${file}`));
    const env = await Deno.readTextFile(`${f.root}/tofu/fake/env.log`);
    assert(
      !env.includes(CANARY),
      "the parent's environment never reaches tofu",
    );
    assert(
      env.includes("TF_IN_AUTOMATION=1") &&
        env.includes("TF_CLI_CONFIG_FILE=/dev/null"),
    );
    assert(
      env.includes("AWS_PROFILE=deploy") &&
        env.includes("AWS_REGION=eu-west-1"),
    );
  },
});

Deno.test({
  ...T,
  name:
    "plan exit 0: no-changes removes the file; exit 0 with imports is changes; exit 1 is recorded then thrown",
  fn: async () => {
    const f = await fixture();
    await f.fake("plan.exit", "0");
    await f.fake(
      "show.json",
      showJson([{ address: "aws_s3_bucket.logs", actions: ["no-op"] }]),
    );
    await withEnv(f.home, async () => {
      await methods.plan.execute({}, f.ctx());
      let rec = [...f.store.values()].at(-1)!;
      assertEquals(rec.exitKind, "no-changes");
      assertEquals(rec.planSha256, null);
      assertEquals([...Deno.readDirSync(f.plans)].length, 0);
      await f.fake(
        "show.json",
        showJson([{
          address: "aws_s3_bucket.logs",
          actions: ["no-op"],
          importing: true,
        }]),
      );
      f.store.clear();
      await methods.plan.execute({}, f.ctx());
      rec = [...f.store.values()].at(-1)!;
      assertEquals(rec.exitKind, "changes");
      await f.fake("plan.exit", "1");
      f.store.clear();
      await assertRejects(
        () => methods.plan.execute({}, f.ctx()),
        Error,
        "exit kind error",
      );
      rec = [...f.store.values()].at(-1)!;
      assertEquals(rec.exitKind, "error");
      assertEquals(rec.planSha256, null);
    });
  },
});

Deno.test({
  ...T,
  name:
    "apply: the exact saved plan file on the right sha; refusals recorded, tofu apply never called",
  fn: async () => {
    const f = await fixture();
    await f.fake("plan.exit", "2");
    await f.fake(
      "show.json",
      showJson([{ address: "aws_s3_bucket.logs", actions: ["create"] }]),
    );
    await withEnv(f.home, async () => {
      await methods.plan.execute({}, f.ctx());
      const rec = [...f.store.values()][0];
      const id = rec.planId as string;
      await assertRejects(
        () =>
          methods.apply.execute(
            { planId: id, planSha256: "c".repeat(64) },
            f.ctx(),
          ),
        Error,
        "sha-mismatch",
      );
      assertEquals(f.store.get(applyDataName(id))!.refusal, "sha-mismatch");
      assert(!(await f.calls()).some((c) => c.startsWith("apply")));
      await assertRejects(
        () =>
          methods.apply.execute({
            planId: "p20261019T000000-00000000",
            planSha256: SHA,
          }, f.ctx()),
        Error,
        "no-plan",
      );
      // a changed configuration after the plan
      await Deno.writeTextFile(`${f.repo}/infra/extra.tf`, "# x\n");
      await assertRejects(
        () =>
          methods.apply.execute({
            planId: id,
            planSha256: rec.planSha256 as string,
          }, f.ctx()),
        Error,
        "config-dirty",
      );
      await Deno.remove(`${f.repo}/infra/extra.tf`);
      await methods.apply.execute({
        planId: id,
        planSha256: rec.planSha256 as string,
      }, f.ctx());
      const file = `${f.plans}/${id}.tfplan`;
      // tofu applied a private copy of the file, not the file by its path
      const applied = (await Deno.readTextFile(`${f.root}/tofu/fake/applied`))
        .trim();
      assert(
        new RegExp(`/swamp-opentofu-apply-[^/]+/${id}\\.tfplan$`).test(applied),
        applied,
      );
      assertEquals(f.store.get(applyDataName(id))!.result, "applied");
      await assertRejects(() => Deno.stat(file), Deno.errors.NotFound);
      await assertRejects(() => Deno.stat(applied), Deno.errors.NotFound);
      assertEquals(
        (await f.calls()).filter((c) => c.startsWith("apply")).length,
        1,
      );
      // a retry is refused without overwriting the applied record
      await assertRejects(
        () =>
          methods.apply.execute({
            planId: id,
            planSha256: rec.planSha256 as string,
          }, f.ctx()),
        Error,
        "already-applied",
      );
      assertEquals(f.store.get(applyDataName(id))!.result, "applied");
    });
  },
});

Deno.test({
  ...T,
  name:
    "apply: the counts come from the plan file, not the record; a symlinked plan file is refused",
  fn: async () => {
    const f = await fixture();
    await f.fake("plan.exit", "2");
    await f.fake(
      "show.json",
      showJson([{ address: "aws_s3_bucket.logs", actions: ["create"] }]),
    );
    await withEnv(f.home, async () => {
      await methods.plan.execute({}, f.ctx());
      const rec = [...f.store.values()][0];
      const id = rec.planId as string;
      // the record says create, the file (as tofu shows it) deletes
      await f.fake(
        "show.json",
        showJson([{ address: "aws_s3_bucket.logs", actions: ["delete"] }]),
      );
      await assertRejects(
        () =>
          methods.apply.execute({
            planId: id,
            planSha256: rec.planSha256 as string,
          }, f.ctx()),
        Error,
        "destructive",
      );
      assert(!(await f.calls()).some((c) => c.startsWith("apply")));
      // the plan file replaced by a symlink to identical bytes
      const file = `${f.plans}/${id}.tfplan`;
      await Deno.rename(file, `${f.root}/elsewhere.tfplan`);
      await Deno.symlink(`${f.root}/elsewhere.tfplan`, file);
      await assertRejects(
        () =>
          methods.apply.execute({
            planId: id,
            planSha256: rec.planSha256 as string,
          }, f.ctx()),
        Error,
        "file-missing",
      );
    });
  },
});

Deno.test({
  ...T,
  name:
    "repository: skip-worktree and symlink entries refuse; validate gets no credential",
  fn: async () => {
    const f = await fixture();
    await f.fake(
      "validate.json",
      JSON.stringify({ valid: true, diagnostics: [] }),
    );
    await withEnv(f.home, async () => {
      await methods.validate.execute({}, f.ctx());
      const env = await Deno.readTextFile(`${f.root}/tofu/fake/env.log`);
      assert(!env.includes("AWS_PROFILE"), "validate runs without env");
      await git(f.repo, "update-index", "--skip-worktree", "infra/main.tf");
      await assertRejects(
        () => methods.plan.execute({}, f.ctx()),
        Error,
        "skip-worktree",
      );
      await git(f.repo, "update-index", "--no-skip-worktree", "infra/main.tf");
      await Deno.symlink("/etc/hosts", `${f.repo}/infra/link.tf`);
      await git(f.repo, "add", "infra/link.tf");
      await git(
        f.repo,
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-qm",
        "l",
      );
      await assertRejects(
        () => methods.plan.execute({}, f.ctx()),
        Error,
        "symlink",
      );
    });
  },
});

Deno.test({
  ...T,
  name:
    "apply: a replace is refused by default and applied when the definition permits it",
  fn: async () => {
    for (const permit of [[], ["replace"]]) {
      const f = await fixture(CONFIG, { permitActions: permit });
      await f.fake("plan.exit", "2");
      await f.fake(
        "show.json",
        showJson([{
          address: "aws_s3_bucket.logs",
          actions: ["delete", "create"],
        }]),
      );
      await withEnv(f.home, async () => {
        await methods.plan.execute({}, f.ctx());
        const rec = [...f.store.values()][0];
        const go = () =>
          methods.apply.execute({
            planId: rec.planId,
            planSha256: rec.planSha256,
          }, f.ctx());
        if (permit.length === 0) await assertRejects(go, Error, "destructive");
        else await go();
      });
    }
  },
});

Deno.test({
  ...T,
  name:
    "refusals before any tofu plan: a dirty configuration, a broken rule, another tofu version",
  fn: async () => {
    const f = await fixture();
    await f.fake("plan.exit", "2");
    await withEnv(f.home, async () => {
      await Deno.writeTextFile(`${f.repo}/infra/x.auto.tfvars`, "a = 1\n");
      await assertRejects(
        () => methods.plan.execute({}, f.ctx()),
        Error,
        "uncommitted",
      );
      await Deno.remove(`${f.repo}/infra/x.auto.tfvars`);
      await Deno.writeTextFile(
        `${f.repo}/infra/main.tf`,
        CONFIG["main.tf"].replace(
          "prevent_destroy = true",
          "prevent_destroy = false",
        ),
      );
      await git(
        f.repo,
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-qam",
        "x",
      );
      await assertRejects(
        () => methods.plan.execute({}, f.ctx()),
        Error,
        "prevent_destroy",
      );
      await Deno.writeTextFile(`${f.repo}/infra/main.tf`, CONFIG["main.tf"]);
      await git(
        f.repo,
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-qam",
        "y",
      );
      await f.fake(
        "version.json",
        JSON.stringify({
          terraform_version: "1.12.0",
          provider_selections: {},
        }),
      );
      await assertRejects(
        () => methods.plan.execute({}, f.ctx()),
        Error,
        "not the pinned",
      );
      await assertRejects(
        () => methods.version.execute({}, f.ctx()),
        Error,
        "not the pinned",
      );
      assertEquals(f.store.get("tofu-version")!.ok, false);
    });
    const calls = await f.calls().catch(() => [] as string[]);
    assert(!calls.some((c) => c.startsWith("plan")), "no plan ran");
    assertThrows(() => ApplyArgs.parse({}));
  },
});

Deno.test({
  ...T,
  name:
    "ctx.signal stops a running tofu (SIGINT); the plan is recorded as error",
  fn: async () => {
    const f = await fixture();
    await f.fake("plan.sleep", "1");
    await withEnv(f.home, async () => {
      const c = new AbortController();
      // abort once tofu plan runs (not during the version check)
      const poll = setInterval(async () => {
        const calls = await f.calls().catch(() => [] as string[]);
        if (calls.some((l) => l.startsWith("plan"))) {
          clearInterval(poll);
          setTimeout(() => c.abort(), 200);
        }
      }, 50);
      const t0 = Date.now();
      await assertRejects(
        () => methods.plan.execute({}, f.ctx(c.signal)),
        Error,
        "aborted",
      );
      assert(Date.now() - t0 < 10_000);
      assertEquals([...f.store.values()].at(-1)!.exitKind, "error");
    });
  },
});

Deno.test({
  ...T,
  name:
    "output: the allowlisted ones with the state's addresses; a sensitive one is refused, not recorded",
  fn: async () => {
    const f = await fixture();
    await f.fake(
      "output.json",
      outputs({ secret: { sensitive: true, value: CANARY } }),
    );
    await f.fake(
      "state.json",
      JSON.stringify({
        values: {
          root_module: {
            resources: [{
              address: "aws_s3_bucket.logs",
              mode: "managed",
              values: { s: CANARY },
            }],
          },
        },
      }),
    );
    await withEnv(f.home, async () => {
      await methods.output.execute({}, f.ctx());
      const rec = f.store.get(OUTPUT_DATA)!;
      assertEquals(rec.outputs, { bucket_arn: "arn:aws:s3:::example-logs" });
      assertEquals(rec.unlisted, 1);
      assertEquals(rec.expectedMissing, []);
      assert(!JSON.stringify(rec).includes(CANARY));
      f.store.clear();
      await f.fake(
        "output.json",
        outputs({ bucket_arn: { sensitive: true, value: CANARY } }),
      );
      await assertRejects(
        () => methods.output.execute({}, f.ctx()),
        Error,
        "sensitive",
      );
      assertEquals(f.store.size, 0);
    });
  },
});

Deno.test({
  ...T,
  name:
    "validate: the rules, then init -backend=false -lockfile=readonly and validate in a temporary data directory",
  fn: async () => {
    const f = await fixture();
    await f.fake(
      "validate.json",
      JSON.stringify({
        valid: true,
        error_count: 0,
        warning_count: 0,
        diagnostics: [],
      }),
    );
    await withEnv(f.home, async () => {
      await methods.validate.execute({}, f.ctx());
      const rec = f.store.get("tofu-validate")!;
      assertEquals(rec.valid, true);
      assertEquals(rec.ruleProblems, []);
      const calls = await f.calls();
      assert(
        calls.includes(
          "init -backend=false -input=false -lockfile=readonly -no-color",
        ),
      );
      assert(
        !calls.some((c) =>
          c.startsWith("init") && !c.includes("-backend=false")
        ),
      );
      const env = await Deno.readTextFile(`${f.root}/tofu/fake/env.log`);
      assert(/TF_DATA_DIR=\S*swamp-opentofu-validate-/.test(env));
      // a broken rule in the working tree fails validate, recorded
      await Deno.writeTextFile(
        `${f.repo}/infra/main.tf`,
        CONFIG["main.tf"].replace("prevent_destroy = true", ""),
      );
      await assertRejects(
        () => methods.validate.execute({}, f.ctx()),
        Error,
        "rule problem",
      );
      assertEquals(f.store.get("tofu-validate")!.configDirty, true);
    });
  },
});

Deno.test({
  ...T,
  name:
    "validate with a provider mirror: the CLI config and the lock's h1 are checked against the mirror",
  fn: async () => {
    const mirror = await Deno.makeTempDir({ prefix: "swamp-opentofu-mirror-" });
    const pkg = `${mirror}/${AWS}/6.65.0/${platform()}`;
    await Deno.mkdir(pkg, { recursive: true });
    await Deno.writeTextFile(`${pkg}/terraform-provider-aws_v6.65.0`, "binary");
    const h1 = h1Hash([{
      name: "terraform-provider-aws_v6.65.0",
      sha256: await sha256(`${pkg}/terraform-provider-aws_v6.65.0`),
    }]);
    const tofurc =
      `provider_installation {\n  filesystem_mirror {\n    path = "${mirror}"\n  }\n}\n`;
    const config = {
      ...CONFIG,
      tofurc,
      ".terraform.lock.hcl": LOCK.replace("h1:AAAA=", h1),
    };
    const f = await fixture(config, {
      providerMirror: mirror,
      cliConfigFile: "tofurc",
    });
    await f.fake(
      "validate.json",
      JSON.stringify({ valid: true, diagnostics: [] }),
    );
    await withEnv(f.home, async () => {
      await methods.validate.execute({}, f.ctx());
      assert(
        (await Deno.readTextFile(`${f.root}/tofu/fake/env.log`)).includes(
          `TF_CLI_CONFIG_FILE=${f.repo}/infra/tofurc`,
        ),
      );
      await Deno.writeTextFile(
        `${pkg}/terraform-provider-aws_v6.65.0`,
        "tampered",
      );
      await assertRejects(
        () => methods.validate.execute({}, f.ctx()),
        Error,
        "rule problem",
      );
      assert(
        (f.store.get("tofu-validate")!.ruleProblems as string[]).some((p) =>
          /h1/.test(p)
        ),
      );
    });
  },
});

// ---- end to end with a real tofu (TOFU_BIN), local backend, no provider
const TOFU_BIN = Deno.env.get("TOFU_BIN");
Deno.test({
  ...T,
  name:
    "end to end (TOFU_BIN): validate, init, plan, apply, output; a replace is refused",
  ignore: !TOFU_BIN,
  fn: async () => {
    const ver = JSON.parse(
      new TextDecoder().decode(
        (await new Deno.Command(TOFU_BIN!, { args: ["version", "-json"] })
          .output()).stdout,
      ),
    );
    const state = await Deno.makeTempDir({ prefix: "swamp-opentofu-state-" });
    const main = (v: string) =>
      `terraform {\n  backend "local" {\n    path = "${state}/terraform.tfstate"\n  }\n}\n\nresource "terraform_data" "marker" {\n  input = "${v}"\n  triggers_replace = ["${v}"]\n}\n\noutput "marker" {\n  value     = terraform_data.marker.output\n  sensitive = false\n}\n`;
    const f = await fixture({ "main.tf": main("one") }, {
      tofuBin: TOFU_BIN,
      tofuVersion: ver.terraform_version,
      providers: {},
      outputs: ["marker"],
      expectedAddresses: ["terraform_data.marker"],
      rules: [
        "no-provisioner",
        "no-external-data",
        "no-module",
        "no-var-files",
        "outputs-allowlisted",
      ],
      env: {},
    });
    await withEnv(f.home, async () => {
      await methods.version.execute({}, f.ctx());
      await methods.validate.execute({}, f.ctx());
      await methods.init.execute({}, f.ctx());
      await methods.plan.execute({}, f.ctx());
      const p = [...f.store.values()].find((r) => r.schema === "tofu-plan/1")!;
      assertEquals(p.exitKind, "changes");
      assertEquals((p.counts as Record<string, number>).create, 1);
      await methods.apply.execute({
        planId: p.planId,
        planSha256: p.planSha256,
      }, f.ctx());
      assertEquals(
        f.store.get(applyDataName(p.planId as string))!.result,
        "applied",
      );
      await methods.output.execute({}, f.ctx());
      assertEquals(f.store.get(OUTPUT_DATA)!.outputs, { marker: "one" });
      assertEquals(f.store.get(OUTPUT_DATA)!.expectedMissing, []);
      // a second plan: no changes
      f.store.clear();
      await methods.plan.execute({}, f.ctx());
      assertEquals([...f.store.values()][0].exitKind, "no-changes");
      // a changed trigger replaces the resource: refused by default
      await Deno.writeTextFile(`${f.repo}/infra/main.tf`, main("two"));
      await git(
        f.repo,
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-qam",
        "two",
      );
      f.store.clear();
      await methods.plan.execute({}, f.ctx());
      const p2 = [...f.store.values()][0];
      assertEquals((p2.counts as Record<string, number>).replace, 1);
      await assertRejects(
        () =>
          methods.apply.execute({
            planId: p2.planId,
            planSha256: p2.planSha256,
          }, f.ctx()),
        Error,
        "destructive",
      );
      // the state never left the configuration directory's backend, and no record holds it
      for (const r of f.store.values()) {
        assert(!JSON.stringify(r).includes('"input"'));
      }
    });
  },
});
