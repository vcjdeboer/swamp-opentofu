# @vcjdeboer/opentofu

Plan and apply [OpenTofu](https://opentofu.org) from [swamp](https://swamp-club.com)
through a **sha-bound gate**: `plan` saves a plan and logs its sha256 beside
the command that shows it; `apply` takes that sha256 back and applies exactly
those bytes, and only if nothing they were planned against has moved. Reading
the plan before passing the sha256 on is the reviewer's step (a person, or an
agent whose approval your workflow requires); the gate makes sure what gets
applied is what was reviewed.

```
validate ─▶ init ─▶ plan ─▶ (read it, copy its sha256) ─▶ apply ─▶ output
```

## Why another Terraform/OpenTofu extension?

[`@webframp/terraform`](https://github.com/webframp/swamp-extensions) reads
state (`list_resources`, `read_state`, `get_outputs`). It is the right tool for
looking at infrastructure. This extension is for **changing** it safely:

|                         | `@webframp/terraform`             | `@vcjdeboer/opentofu`                                                                                         |
| ----------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Methods                 | read state, list resources, outputs | version, validate, init, plan, apply, output                                                                |
| Apply                   | —                                 | exactly one saved plan, bound to its sha256, the git commit and a digest of the configuration                 |
| Destructive changes     | —                                 | delete, replace and forget refused unless the definition permits them, judged from the plan file itself      |
| What reaches swamp data | full state, sensitive values masked | never state, plan contents or before/after values: counts, addresses and diagnostic summaries only         |
| Outputs                 | all, sensitive masked             | an allowlist; a sensitive allowlisted output is refused, not masked                                           |
| Versions                | whatever `terraform`/`tofu` is on PATH | the pinned tofu binary and provider versions; optionally an h1-checked filesystem mirror                   |
| Inputs                  | free                              | fixed argv: no `-target`, `-replace`, `-var`, `destroy`, `import` or `state`                                   |
| Environment             | inherited                         | cleared: tofu gets only what the definition declares                                                          |

## Quick start

```bash
swamp extension pull @vcjdeboer/opentofu
swamp model create @vcjdeboer/opentofu infra \
  --global-arg tofuBin=/opt/homebrew/bin/tofu \
  --global-arg tofuVersion=1.13.1 \
  --global-arg configDir=infra
```

Then edit `models/@vcjdeboer/opentofu/infra.yaml` to declare the policy, e.g.:

```yaml
globalArguments:
  tofuBin: /opt/homebrew/bin/tofu
  tofuVersion: 1.13.1
  configDir: infra                      # relative to the swamp repo, committed in git
  providers:                            # exactly these, at these versions
    registry.opentofu.org/hashicorp/aws: 6.65.0
  env:                                  # the only environment tofu gets
    AWS_PROFILE: deploy
    AWS_REGION: eu-west-1
  outputs: [bucket_arn]                 # recorded by `output`; must be non-sensitive
  expectedAddresses: [aws_s3_bucket.logs]
  rules: [prevent-destroy, no-provisioner, no-external-data, no-module, no-var-files, outputs-allowlisted]
  permitActions: []                     # add delete / replace / forget to allow them
  planMaxAgeMinutes: 240
```

Commit the configuration (including `.terraform.lock.hcl`), then:

```bash
swamp model method run infra validate   # rules + tofu validate, no backend, no credential
swamp model method run infra init
swamp model method run infra plan       # logs the planId, its sha256 and the `tofu show` command to read it
swamp model method run infra apply \
  --input planId=p20261022T190048-514e7cfb \
  --input planSha256=65439bcf77b4918129423aed93d6818e5eeb0996aab9d3ccd796ca69523d7862
swamp model method run infra output
```

Read a record with CEL, e.g. in a workflow:

```
data.latest("infra", "tofu-output").attributes.outputs.bucket_arn
```

## Methods

| method     | runs                                                                                     | record (data name)                     |
| ---------- | ---------------------------------------------------------------------------------------- | -------------------------------------- |
| `version`  | `tofu version -json`                                                                     | `tofu-version` (tofu-version/1)        |
| `validate` | the rules on the working tree, the lock against the pins, then `init -backend=false -lockfile=readonly` and `validate -json` in a temporary data directory, without the definition's `env` | `tofu-validate` (tofu-validate/1) |
| `init`     | `init -input=false -lockfile=readonly` with the configured backend                       | `tofu-init` (tofu-init/1)              |
| `plan`     | `plan -detailed-exitcode -json -out=<file>`, then `show -json <file>` parsed in memory   | `tofu-plan-<planid>` (tofu-plan/1)     |
| `apply`    | a private copy of the saved plan: hashed, `show -json` summarized again, then `apply -json <copy>` | `tofu-apply-<planid>` (tofu-apply/1)   |
| `output`   | `output -json`, then `show -json` (state) for its managed addresses                      | `tofu-output` (tofu-output/1)          |

## Global arguments (the policy)

| key                 | default     | meaning |
| ------------------- | ----------- | ------- |
| `tofuBin`           | required    | absolute path of a binary named `tofu`; PATH is never searched |
| `tofuVersion`       | required    | the version `tofuBin` must report |
| `configDir`         | required    | the configuration directory, a plain path relative to the swamp repository, tracked by git |
| `providers`         | `{}`        | provider source → version; any other provider, or another version, is refused |
| `cliConfigFile`     | none        | a CLI config file directly in `configDir`, never with `dev_overrides`; without one tofu gets `/dev/null`, never `~/.tofurc` |
| `providerMirror`    | none        | an unpacked filesystem mirror; `cliConfigFile` must then install only from it, and the lock's `h1` must equal the mirror package's |
| `env`               | `{}`        | the extra environment tofu gets for init, plan, apply and output (credentials, region); `${{ vault.get(...) }}` works here. Refused: `PATH`, `HOME`, `TMPDIR`, `TF_*`, `LD_*`, `DYLD_*`, `GIT_*`, `XDG_*`, `SSL_*`, `OTEL_*`, `*_PROXY` |
| `extraPath`         | `[]`        | directories added to tofu's PATH (e.g. a credential helper) |
| `outputs`           | `[]`        | outputs `output` records; each must exist, be non-sensitive and be a string, number or boolean |
| `expectedAddresses` | `[]`        | managed addresses the state must hold; the output record lists the missing ones |
| `rules`             | `[]`        | configuration rules, see below |
| `permitActions`     | `[]`        | any of `delete`, `replace`, `forget` an apply may take |
| `allowMixedImport`  | `false`     | whether a plan that imports may also create or update |
| `planMaxAgeMinutes` | `240`       | a saved plan older than this is refused |
| `timeouts`          | `{}`        | seconds per run: `plan` (900), `apply` (1800), `other` (300) |

### Rules

Checked by `validate` (working tree) and `plan` (the committed files), on the
top-level `.tf` and `.tofu` files of `configDir`:

- `prevent-destroy`: every resource has `lifecycle { prevent_destroy = true }`
- `no-provisioner`: no `provisioner` block
- `no-external-data`: no `data "external"`
- `no-module`: no `module` block (the rules do not read module directories)
- `no-var-files`: no `*.tfvars`, override or JSON configuration file (`*.tf.json`, `*.tofu.json`)
- `outputs-allowlisted`: the declared outputs are exactly `outputs`, each `sensitive = false`

The rules read HCL with a small scanner, not a full parser. It understands
strings, templates, heredocs, comments and quoted or bare labels, and it
fails closed: a file it cannot fully account for (unbalanced braces, an
unterminated string, text outside any block) is a rule problem, never a
pass. Still, the rules are a guard rail for a configuration you control, not
a sandbox for one you don't.

## What it guarantees

- **Sha-bound apply.** apply copies the plan file (never through a symlink)
  into a fresh private directory and works only on that copy. Refused,
  recorded with its reason and `tofu apply` never started, unless: the plan
  record exists with exit kind `changes`; the given `planSha256` equals the
  recorded one and the copy's; HEAD is the recorded commit; `configDir` is
  clean with the recorded digest; the plan is no older than
  `planMaxAgeMinutes`; the pinned versions hold; and the copy itself, read
  again with `tofu show -json` (the record's counts are not trusted), holds no
  delete, replace or forget outside `permitActions` and (unless
  `allowMixedImport`) imports only, if it imports at all. tofu's own
  stale-plan check stays the last guard. The plan file is removed after the
  apply runs; a retry of an applied plan is refused without touching its
  record.
- **Plans bind to git, for `configDir`.** init, plan and apply refuse unless
  `configDir` is committed and clean (no untracked or ignored file), and
  every tracked file in it is a plain file (no symlink, no submodule, nothing
  marked assume-unchanged or skip-worktree). What tofu reads from outside
  `configDir` (a local module in `../modules`, `file("../x")`, remote modules,
  the backend's state) is not part of the digest: keep what must be bound
  inside `configDir`. Keep local state outside it
  (`backend "local" { path = "../state/terraform.tfstate" }`) or use a
  remote backend.
- **Private files.** Plans and tofu's data directory live in
  `~/.swamp-opentofu/<definition id>/` (0700, plan files 0600). An existing
  directory with group or other bits is refused, never changed.
- **Closed inputs.** The only method inputs are apply's `planId`
  (`^p\d{8}T\d{6}-[0-9a-f]{8}$`) and `planSha256` (64 hex). A global
  argument passed as an input must equal the definition's value.
- **Closed environment.** The child gets `env` (not for validate) plus
  `HOME`, `PATH` (tofuBin's directory, `extraPath`, `/usr/bin`, `/bin`),
  `TF_DATA_DIR`, `TF_CLI_CONFIG_FILE`, `TF_IN_AUTOMATION=1`, `TF_INPUT=0`,
  `CHECKPOINT_DISABLE=1`. Nothing of swamp's own environment reaches tofu.
  `HOME` is your real home, so what tofu and providers read from it still
  applies (e.g. `~/.aws/config` for `AWS_PROFILE`, `~/.terraform.d`); the
  lock file's hashes still bind every provider.
- **Never in a record or log:** state, the plan file, `tofu show` text,
  before/after values, stderr (only counted), the definition's `env` values,
  diagnostic details. Each diagnostic keeps its severity and the first 200
  characters of its summary, which can name the failing resource or the
  account a provider error mentions.
- **Cancellation.** On a timeout or a cancelled run tofu gets SIGINT, then
  SIGKILL after 30 s. A state lock left behind needs `tofu force-unlock`.

## Development

```bash
deno test --no-config --allow-read --allow-write --allow-run --allow-env --allow-sys=uid extensions/models/opentofu/
# also plan and apply a terraform_data resource with a real tofu (local backend, no network):
TOFU_BIN=$(which tofu) deno test --no-config --allow-read --allow-write --allow-run --allow-env --allow-sys=uid extensions/models/opentofu/
```

## Licence

AGPL-3.0-or-later (LICENSE). Two functions are adapted from
`@webframp/terraform` (Apache-2.0); see NOTICE.
