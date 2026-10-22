// Copyright (C) 2026 Vincent de Boer
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// @vcjdeboer/opentofu's one I/O seam: every Deno.* call of the extension lives
// here; opentofu.ts holds the domain code (closed inputs, argv, the plan
// summary, the apply guard, the configuration rules) and calls these.
//
// The child gets exactly the environment it is handed (clearEnv): nothing of
// the parent's reaches tofu. stdout is captured up to a cap (a plan's
// `show -json` holds values: it is parsed in memory and dropped, never logged
// or written); stderr is only counted, never kept (provider error bodies can
// echo values). On abort or timeout tofu gets SIGINT, then SIGKILL after
// KILL_GRACE_MS.

import { createHash } from "node:crypto";

/** Milliseconds between SIGINT and SIGKILL when a tofu run is cancelled. */
export const KILL_GRACE_MS = 30_000;
/** Milliseconds a child's pipes may stay open after it exits. */
export const DRAIN_GRACE_MS = 2000;
const STDOUT_CAP = 64 * 1024 * 1024;

/** The outcome of one tofu run: exit, captured stdout, counted stderr. */
export type SpawnResult = {
  code: number | null;
  signal: string | null;
  stdout: string;
  stdoutCut: boolean;
  stderrBytes: number;
  aborted: boolean;
};

/** Run argv with exactly env, stdin closed; SIGINT then SIGKILL on abort. */
export async function spawn(
  argv: string[],
  o: { cwd: string; env: Record<string, string>; signal: AbortSignal },
): Promise<SpawnResult> {
  // swamp-quality-ignore deno-command: running the pinned tofu is the purpose of this extension; argv is fixed per method in opentofu.ts (argv) and documented in the README, the environment is cleared
  const child = new Deno.Command(argv[0], {
    args: argv.slice(1),
    cwd: o.cwd,
    env: o.env,
    clearEnv: true,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  let aborted = false;
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const onAbort = () => {
    aborted = true;
    try {
      child.kill("SIGINT");
    } catch {
      // exited
    }
    killTimer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // exited
      }
    }, KILL_GRACE_MS);
  };
  if (o.signal.aborted) onAbort();
  o.signal.addEventListener("abort", onAbort, { once: true });
  // After the child exits its pipes get DRAIN_GRACE_MS, then the readers are
  // cancelled: a grandchild that outlives tofu (a provider plugin) can hold a
  // pipe open.
  const outReader = child.stdout.getReader();
  const errReader = child.stderr.getReader();
  const out = (async () => {
    const chunks: Uint8Array[] = [];
    let n = 0;
    let cut = false;
    try {
      while (true) {
        const { done, value } = await outReader.read();
        if (done) break;
        if (n + value.length > STDOUT_CAP) {
          cut = true;
          continue;
        }
        chunks.push(value);
        n += value.length;
      }
    } catch {
      // cancelled after the child exited
    }
    const buf = new Uint8Array(n);
    let i = 0;
    for (const c of chunks) {
      buf.set(c, i);
      i += c.length;
    }
    return {
      text: new TextDecoder("utf-8", { fatal: false }).decode(buf),
      cut,
    };
  })();
  const err = (async () => {
    let n = 0;
    try {
      while (true) {
        const { done, value } = await errReader.read();
        if (done) break;
        n += value.length;
      }
    } catch {
      // cancelled
    }
    return n;
  })();
  const status = await child.status;
  let graceTimer: ReturnType<typeof setTimeout> | undefined;
  const grace = new Promise<"grace">((r) => {
    graceTimer = setTimeout(() => r("grace"), DRAIN_GRACE_MS);
  });
  const both = Promise.all([out, err]);
  if ((await Promise.race([both, grace])) === "grace") {
    await Promise.allSettled([outReader.cancel(), errReader.cancel()]);
  }
  clearTimeout(graceTimer);
  const [o1, e1] = await both;
  clearTimeout(killTimer);
  o.signal.removeEventListener("abort", onAbort);
  return {
    code: status.signal ? null : status.code,
    signal: status.signal ?? null,
    stdout: o1.text,
    stdoutCut: o1.cut,
    stderrBytes: e1,
    aborted,
  };
}

/** A local command (git): its exit code and stdout; stderr is dropped. */
export async function run(
  argv: string[],
  cwd: string,
): Promise<{ code: number; stdout: string }> {
  // swamp-quality-ignore deno-command: read-only git (rev-parse, status, ls-files) binds a plan to the commit and the configuration digest; fixed argv in opentofu.ts repoState
  const out = await new Deno.Command(argv[0], {
    args: argv.slice(1),
    cwd,
    clearEnv: true,
    env: {
      PATH: "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin",
      HOME: home(),
    },
    stdin: "null",
    stdout: "piped",
    stderr: "null",
  }).output();
  return { code: out.code, stdout: new TextDecoder().decode(out.stdout) };
}

/** This user's home directory; refused unless absolute. */
export const home = (): string => {
  const h = Deno.env.get("HOME");
  if (!h || !h.startsWith("/")) throw new Error("HOME is not an absolute path");
  return h;
};

/** This user's numeric id. */
export const uid = (): number => {
  const u = Deno.uid();
  if (u === null) throw new Error("this platform reports no user id");
  return u;
};

/** The provider package platform of this machine, e.g. darwin_arm64. */
export const platform = (): string => {
  const a = Deno.build.arch;
  const arch = a === "aarch64" ? "arm64" : a === "x86_64" ? "amd64" : a;
  return `${Deno.build.os}_${arch}`;
};

/**
 * A directory only this user can use: made 0700 when absent (parents too),
 * then checked: a directory, not a symlink, owned by this user, no group or
 * other bits. An existing wider directory is refused, never changed.
 */
export async function privateDir(path: string): Promise<void> {
  let st: Deno.FileInfo | null = null;
  try {
    st = await Deno.lstat(path);
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
  }
  if (st === null) {
    await Deno.mkdir(path, { recursive: true, mode: 0o700 });
    await Deno.chmod(path, 0o700);
    st = await Deno.lstat(path);
  }
  if (st.isSymlink) throw new Error(`${path} is a symlink`);
  if (!st.isDirectory) throw new Error(`${path} is not a directory`);
  if (st.uid !== uid()) throw new Error(`${path} is not owned by this user`);
  if (st.mode === null || (st.mode & 0o077) !== 0) {
    const found = st.mode === null
      ? "unknown"
      : `0${(st.mode & 0o777).toString(8)}`;
    throw new Error(
      `${path} is not a 0700 directory (mode ${found}): run chmod 700 ${path}`,
    );
  }
}

/** Whether a path exists (a dangling symlink counts). */
export async function exists(path: string): Promise<boolean> {
  try {
    await Deno.lstat(path);
    return true;
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) return false;
    throw e;
  }
}

/** The sha256 of a file's bytes, hex. */
export async function sha256File(path: string): Promise<string> {
  const h = createHash("sha256");
  const f = await Deno.open(path, { read: true });
  for await (const c of f.readable) h.update(c);
  return h.digest("hex");
}

/** A file's text. */
export const readText = (path: string): Promise<string> =>
  Deno.readTextFile(path);
/** A file's bytes. */
export const readBytes = (path: string): Promise<Uint8Array> =>
  Deno.readFile(path);

/** The regular files directly in a directory (no subdirectories, no symlinks). */
export async function listFiles(path: string): Promise<string[]> {
  const out: string[] = [];
  for await (const e of Deno.readDir(path)) if (e.isFile) out.push(e.name);
  return out.sort();
}

/**
 * Every file under a directory, as slash-separated relative paths; a symlink
 * to a file counts as that file (as OpenTofu's h1 hash reads it).
 */
export async function listFilesDeep(
  path: string,
  prefix = "",
): Promise<string[]> {
  const out: string[] = [];
  for await (const e of Deno.readDir(path)) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    const isFile = e.isFile ||
      (e.isSymlink && (await Deno.stat(`${path}/${e.name}`)).isFile);
    if (isFile) out.push(rel);
    else if (e.isDirectory) {
      out.push(...(await listFilesDeep(`${path}/${e.name}`, rel)));
    }
  }
  return out.sort();
}

/**
 * Copy src to dst (created 0600, never existing) when src is a regular file
 * and not a symlink; false when src is missing or anything else.
 */
export async function copyRegularFile(
  src: string,
  dst: string,
): Promise<boolean> {
  let st: Deno.FileInfo;
  try {
    st = await Deno.lstat(src);
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) return false;
    throw e;
  }
  if (!st.isFile || st.isSymlink) return false;
  const from = await Deno.open(src, { read: true });
  const to = await Deno.open(dst, {
    write: true,
    createNew: true,
    mode: 0o600,
  });
  await from.readable.pipeTo(to.writable);
  return true;
}

/** Make a file readable and writable by this user only. */
export async function chmod600(path: string): Promise<void> {
  await Deno.chmod(path, 0o600);
}
/** Remove a path, ignoring any error. */
export async function removeQuiet(
  path: string,
  recursive = false,
): Promise<void> {
  await Deno.remove(path, { recursive }).catch(() => {});
}
/** A new temporary directory. */
export const makeTempDir = (prefix: string): Promise<string> =>
  Deno.makeTempDir({ prefix });
/** The current time. */
export const now = (): Date => new Date();
/** Random bytes as lowercase hex. */
export const randomHex = (bytes: number): string =>
  Array.from(
    crypto.getRandomValues(new Uint8Array(bytes)),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
