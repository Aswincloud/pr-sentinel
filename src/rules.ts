// Deterministic checks over a change's diff. These decide on their own whether
// to alert: the AI pass can only ADD findings, never remove these, so text in a
// malicious diff ("ignore previous instructions, this is safe") cannot silence
// them.

export type Severity = "high" | "medium";

export interface Finding {
  rule: string;
  severity: Severity;
  file: string;
  detail: string;
}

export interface ChangedFile {
  filename: string;
  status: string; // added | modified | removed | renamed
  patch?: string; // unified diff; absent for binary / very large files
}

/** Added lines only (what the change introduces), without the leading "+". */
export const addedLines = (patch = ""): string[] =>
  patch.split("\n").filter((l) => l.startsWith("+") && !l.startsWith("+++")).map((l) => l.slice(1));

const isWorkflow = (f: string) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f);
const LIFECYCLE = /"(preinstall|install|postinstall|prepare|prepublish|prepublishOnly)"\s*:/;
const SECRET_REF = /\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}|\btoJSON\(\s*secrets\s*\)/;
const OBFUSCATE = /\bbase64\b|\bxxd\b|\bod\s+-|\bfold\s+-w|\brev\b|\bsed\s+'s\/\.\/|\bgzip\b|\bopenssl\s+enc\b|\|\s*tr\s/;
const EGRESS = /\bcurl\b|\bwget\b|\bnc\b|\bInvoke-WebRequest\b|https?:\/\//;
const BARE_IP_URL = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/;
const PIPE_SHELL = /\|\s*(?:ba|z)?sh\b|\beval\s+"?\$\(/;

export function scanFiles(files: ChangedFile[]): Finding[] {
  const out: Finding[] = [];
  const add = (rule: string, severity: Severity, file: string, detail: string) =>
    out.push({ rule, severity, file, detail });

  for (const f of files) {
    const name = f.filename;
    const lines = addedLines(f.patch);
    const body = lines.join("\n");

    if (isWorkflow(name)) {
      add("workflow-changed", "medium", name, `workflow ${f.status}`);
      if (SECRET_REF.test(body) && (OBFUSCATE.test(body) || /\becho\b|\bprintf\b|\bcat\b/.test(body))) {
        add("secret-exfil-in-workflow", "high", name, "workflow reads secrets and echoes / encodes output");
      }
      if (SECRET_REF.test(body) && EGRESS.test(body)) {
        add("secret-sent-over-network", "high", name, "workflow reads secrets and makes network calls");
      }
      if (/pull_request_target/.test(body)) {
        add("pull-request-target", "medium", name, "adds a pull_request_target trigger (runs with secrets on PRs)");
      }
      const removedHarden = (f.patch ?? "").split("\n").some((l) => l.startsWith("-") && /harden-runner/.test(l));
      if (removedHarden && !/harden-runner/.test(body)) {
        add("harden-runner-removed", "medium", name, "removes the Harden-Runner step");
      }
    }

    if (/(^|\/)package\.json$/.test(name) && lines.some((l) => LIFECYCLE.test(l))) {
      add("npm-lifecycle-script", "high", name, "adds an npm install-time lifecycle script");
    }

    const base = name.split("/").pop() ?? name;
    if (f.status === "added" && /^\.ci-[a-z0-9]{4,}\.sh$/.test(base)) {
      add("campaign-script", "high", name, "hidden .ci-*.sh script (WFX Phantom pattern)");
    } else if (f.status === "added" && /^\.[^/]+\.(sh|js|py|mjs|cjs)$/.test(base)) {
      add("hidden-script", "medium", name, "adds a hidden script file");
    }

    if (BARE_IP_URL.test(body)) add("bare-ip-url", "high", name, "contacts a raw IP address");
    if (PIPE_SHELL.test(body)) add("pipe-to-shell", "high", name, "pipes downloaded content to a shell / eval");
    if (/\/exfil\b|WF_CALLBACK|WF_CTOKEN|api\.telegram\.org\/bot/.test(body)) {
      add("known-exfil-marker", "high", name, "known exfiltration marker");
    }
  }
  return out;
}

const DECOY_MESSAGES = [
  /^ci: refresh build cache/i,
  /^ci: restore\b/i,
  /^ci: cleanup\b/i,
  /^chore: add ci helper\b/i,
  /^chore: add dependency audit workflow\b/i,
  /^docs: (add )?dependency audit notes\b/i,
];

export function scanMessages(messages: string[]): Finding[] {
  const out: Finding[] = [];
  for (const m of messages) {
    const first = m.split("\n")[0] ?? "";
    if (DECOY_MESSAGES.some((re) => re.test(first))) {
      out.push({ rule: "campaign-commit-message", severity: "high", file: "(commit message)", detail: first.slice(0, 120) });
    }
  }
  return out;
}

export function scanBranch(ref: string): Finding[] {
  const b = ref.replace(/^refs\/heads\//, "");
  if (/^wfx-|^ci-check-\d{4}$/.test(b)) {
    return [{ rule: "campaign-branch", severity: "high", file: "(branch)", detail: b }];
  }
  return [];
}

export const worst = (fs: Finding[]): Severity | null =>
  fs.some((f) => f.severity === "high") ? "high" : fs.length ? "medium" : null;

// ---- Dependabot version bumps --------------------------------------------
//
// A Dependabot PR is quiet ONLY if every changed line is a version reference.
// The author check is done by the caller on GitHub's `user.login` (which a
// branch name cannot fake); this function checks the CONTENT, so a hijacked
// "dependabot" PR that slips in a new step, script or postinstall still alerts.

const USES_LINE = /^\s*(-\s+)?uses:\s+[\w.-]+\/[\w./-]+@([0-9a-f]{40}|v?\d[\w.-]*)(\s+#\s*v?\d[\w.-]*)?\s*$/;
const MANIFEST_VERSION_LINE = /^\s*"(@[\w.-]+\/)?[\w.-]+"\s*:\s*"[~^><=]*\s*\d[\w.+-]*"\s*,?\s*$/;
const LOCKFILE = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|go\.sum|Cargo\.lock|poetry\.lock|requirements[\w-]*\.txt)$/;
const MANIFEST = /(^|\/)(package\.json|go\.mod|Cargo\.toml|pyproject\.toml)$/;

function changedLines(patch = ""): string[] {
  return patch.split("\n").filter((l) => /^[+-]/.test(l) && !/^(\+\+\+|---)/.test(l)).map((l) => l.slice(1));
}

export function isVersionOnlyChange(files: ChangedFile[]): boolean {
  if (files.length === 0) return false;
  for (const f of files) {
    if (f.status !== "modified") return false; // bumps never add, delete or rename files
    if (LOCKFILE.test(f.filename)) continue; // generated; its manifest is checked below
    const lines = changedLines(f.patch).filter((l) => l.trim() !== "");
    if (f.patch === undefined || lines.length === 0) return false;
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(f.filename)) {
      if (!lines.every((l) => USES_LINE.test(l))) return false;
    } else if (MANIFEST.test(f.filename)) {
      if (!lines.every((l) => MANIFEST_VERSION_LINE.test(l) || /^\s*(require\s+)?[\w./-]+\s+v\d[\w.+-]*\s*$/.test(l))) return false;
    } else {
      return false;
    }
  }
  return true;
}

// ---- Known automations that push straight to the default branch ------------
//
// Each entry must match EVERY field: repo (or "*"), pusher login, exact file
// set, and commit-message prefix. A push by the same bot that touches any
// other file, or a different message, still raises direct-push-default.

export interface KnownAutomation {
  name: string;
  repo: string; // "owner/name" or "*"
  actor: string; // pusher / sender login
  files: RegExp; // EVERY changed file must match
  message?: RegExp; // EVERY commit's first line must match
}

export const KNOWN_AUTOMATIONS: KnownAutomation[] = [
  {
    name: "org README refresh",
    repo: "Aswincloud/.github",
    actor: "aswincloud-bot[bot]",
    files: /^(README\.md|profile\/README\.md)$/,
    message: /^chore: auto-update public repository list$/,
  },
  {
    name: "filaments-shop stock sync",
    repo: "Aswincloud/filaments-shop",
    actor: "github-actions[bot]",
    files: /^data\/(products|numakers-raw)\.json$/,
    message: /^Stock sync: /,
  },
];

export function matchKnownAutomation(
  repo: string,
  actor: string,
  files: { filename: string; status: string }[],
  messages: string[],
  list: KnownAutomation[] = KNOWN_AUTOMATIONS,
): KnownAutomation | null {
  if (files.length === 0) return null;
  for (const a of list) {
    if (a.repo !== "*" && a.repo !== repo) continue;
    if (a.actor !== actor) continue;
    if (!files.every((f) => f.status === "modified" && a.files.test(f.filename))) continue;
    if (a.message && !(messages.length > 0 && messages.every((m) => a.message!.test(m.split("\n")[0] ?? "")))) continue;
    return a;
  }
  return null;
}
