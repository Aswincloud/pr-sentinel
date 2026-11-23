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
