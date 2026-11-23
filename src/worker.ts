// pr-sentinel: scans every pull request and every push across the org and
// alerts Slack immediately when a change looks like an attack.
//
// Fed by an org webhook (events: pull_request, push). It never runs code from
// the change: it reads the diff as text through a short-lived, read-only
// GitHub App token, applies deterministic rules, then asks Workers AI for a
// second opinion. Rules alert on their own; the AI can only add.

import { verifySignature } from "./webhook.ts";
import { isVersionOnlyChange, matchKnownAutomation, scanBranch, scanFiles, scanMessages, worst, type ChangedFile, type Finding } from "./rules.ts";
import { aiReview, type AiBinding, type AiVerdict } from "./ai.ts";
import { appJwt, importPkcs8, mintInstallationToken } from "./github.ts";

export interface Env {
  WEBHOOK_SECRET: string;
  SLACK_WEBHOOK_URL: string;
  APP_PRIVATE_KEY: string;
  APP_ID: string;
  APP_INSTALLATION_ID: string;
  ORG: string;
  AI: AiBinding;
}

const API = "https://api.github.com";
const UA = "aswincloud-pr-sentinel";

interface Change {
  kind: "pull_request" | "push";
  repo: string; // owner/name
  title: string;
  url: string;
  actor: string;
  ref: string;
  messages: string[];
  files: ChangedFile[];
  forced?: boolean;
  toDefault?: boolean;
}

async function readToken(env: Env, repo: string): Promise<string> {
  const jwt = await appJwt(env.APP_ID, await importPkcs8(env.APP_PRIVATE_KEY));
  const t = await mintInstallationToken(jwt, env.APP_INSTALLATION_ID, [repo], { contents: "read", pull_requests: "read", metadata: "read" });
  return t.token;
}

async function gh<T>(token: string, path: string): Promise<T> {
  const r = await fetch(`${API}${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": UA, "X-GitHub-Api-Version": "2022-11-28" },
  });
  if (!r.ok) throw new Error(`GitHub ${path} -> ${r.status}`);
  return (await r.json()) as T;
}

async function loadChange(env: Env, event: string, p: any): Promise<Change | null> {
  const repoFull: string = p.repository?.full_name ?? "";
  const repoName: string = p.repository?.name ?? "";
  if (!repoFull.startsWith(`${env.ORG}/`)) return null;

  if (event === "pull_request") {
    if (!["opened", "synchronize", "reopened", "ready_for_review"].includes(p.action)) return null;
    const pr = p.pull_request;
    const token = await readToken(env, repoName);
    const files = await gh<ChangedFile[]>(token, `/repos/${repoFull}/pulls/${pr.number}/files?per_page=100`);
    const commits = await gh<{ commit: { message: string } }[]>(token, `/repos/${repoFull}/pulls/${pr.number}/commits?per_page=100`);
    return {
      kind: "pull_request", repo: repoFull, title: `PR #${pr.number}: ${pr.title}`, url: pr.html_url,
      actor: pr.user?.login ?? "?", ref: pr.head?.ref ?? "", messages: [pr.title, ...commits.map((c) => c.commit.message)], files,
    };
  }

  if (event === "push") {
    if (p.deleted || !p.after || /^0+$/.test(p.after)) return null;
    const ref: string = p.ref ?? "";
    if (!ref.startsWith("refs/heads/") || ref.startsWith("refs/heads/gh-readonly-queue/")) return null;
    const token = await readToken(env, repoName);
    const base = p.forced || !p.before || /^0+$/.test(p.before) ? null : p.before;
    let files: ChangedFile[] = [];
    if (base) {
      const cmp = await gh<{ files?: ChangedFile[] }>(token, `/repos/${repoFull}/compare/${base}...${p.after}`);
      files = cmp.files ?? [];
    } else {
      const c = await gh<{ files?: ChangedFile[] }>(token, `/repos/${repoFull}/commits/${p.after}`);
      files = c.files ?? [];
    }
    const defaultBranch = p.repository?.default_branch ?? "main";
    return {
      kind: "push", repo: repoFull, title: `push to ${ref.replace("refs/heads/", "")}`,
      url: p.compare ?? `https://github.com/${repoFull}/commit/${p.after}`, actor: p.pusher?.name ?? p.sender?.login ?? "?",
      ref, messages: (p.commits ?? []).map((c: { message: string }) => c.message), files,
      forced: Boolean(p.forced), toDefault: ref === `refs/heads/${defaultBranch}`,
    };
  }
  return null;
}

// Pushes to the default branch that don't come from a merged PR are worth a look
// on their own: merges arrive through the merge queue (gh-readonly-queue/*) and
// carry "(#NN)" in the message.
function directPushFindings(c: Change): Finding[] {
  if (c.kind !== "push" || !c.toDefault) return [];
  const out: Finding[] = [];
  if (c.forced) out.push({ rule: "force-push-default", severity: "high", file: "(branch)", detail: `force push to ${c.ref}` });
  const viaPr = c.messages.length > 0 && c.messages.every((m) => /\(#\d+\)\s*$/.test(m.split("\n")[0] ?? ""));
  const known = matchKnownAutomation(c.repo, c.actor, c.files, c.messages);
  if (!viaPr && !known) out.push({ rule: "direct-push-default", severity: "medium", file: "(branch)", detail: "commit on the default branch not from a merged PR" });
  return out;
}

export function buildDiff(files: ChangedFile[]): string {
  return files.map((f) => `--- ${f.filename} (${f.status})\n${f.patch ?? "[no textual diff]"}`).join("\n");
}

const escapeSlack = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function slackMessage(c: Change, findings: Finding[], ai: AiVerdict | null, level: "high" | "medium") {
  const icon = level === "high" ? ":rotating_light:" : ":warning:";
  const lines = findings.slice(0, 12).map((f) => `• *${f.rule}* — ${escapeSlack(f.detail)} \`${escapeSlack(f.file)}\``);
  if (findings.length > 12) lines.push(`• …and ${findings.length - 12} more`);
  const aiLine = ai ? `*AI (${ai.risk})*: ${escapeSlack(ai.reason)}` : "*AI*: unavailable";
  return {
    text: `${icon} ${level.toUpperCase()} risk change in ${c.repo}`,
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `${icon} *${level.toUpperCase()} risk* — <${c.url}|${escapeSlack(c.repo)} ${escapeSlack(c.title)}>\nby *${escapeSlack(c.actor)}* on \`${escapeSlack(c.ref)}\`` } },
      { type: "section", text: { type: "mrkdwn", text: [...lines, aiLine].join("\n") || aiLine } },
    ],
  };
}

async function process(env: Env, event: string, payload: any): Promise<void> {
  const c = await loadChange(env, event, payload);
  if (!c) return;
  const findings = [...scanFiles(c.files), ...scanMessages(c.messages), ...scanBranch(c.ref), ...directPushFindings(c)];
  const ai = c.files.length ? await aiReview(env.AI, c.title, buildDiff(c.files)) : null;
  if (ai && ai.risk !== "low") findings.push({ rule: "ai-flag", severity: ai.risk, file: "(diff)", detail: ai.reason });
  let level = worst(findings);
  // Quiet genuine Dependabot version bumps: real dependabot[bot] author (GitHub's
  // user.login, not a branch name), version-only diff, no high finding, AI not
  // worried. Anything else in a Dependabot PR still alerts.
  const dependabotBump = c.kind === "pull_request" && c.actor === "dependabot[bot]" && level !== "high"
    && (!ai || ai.risk === "low") && isVersionOnlyChange(c.files);
  if (dependabotBump) level = null;
  console.log(JSON.stringify({ event: "scanned", dependabot_bump: dependabotBump || undefined, kind: c.kind, repo: c.repo, ref: c.ref, actor: c.actor, files: c.files.length, level, rules: findings.map((f) => f.rule), ai: ai?.risk ?? null }));
  if (!level) return;
  const r = await fetch(env.SLACK_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(slackMessage(c, findings, ai, level)) });
  if (!r.ok) console.log(JSON.stringify({ event: "slack_failed", status: r.status, repo: c.repo }));
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/health") return new Response("ok");
    if (url.pathname !== "/webhook" || req.method !== "POST") return new Response("not found", { status: 404 });
    const body = await req.text();
    if (!(await verifySignature(env.WEBHOOK_SECRET, body, req.headers.get("X-Hub-Signature-256")))) {
      return new Response("bad signature", { status: 401 });
    }
    const event = req.headers.get("X-GitHub-Event") ?? "";
    if (event === "ping") return new Response("pong");
    let payload: unknown;
    try { payload = JSON.parse(body); } catch { return new Response("bad json", { status: 400 }); }
    // Acknowledge fast (GitHub times out at 10 s); scan in the background.
    ctx.waitUntil(process(env, event, payload).catch((e) => console.log(JSON.stringify({ event: "scan_failed", reason: (e as Error).message }))));
    return new Response("accepted", { status: 202 });
  },
} satisfies ExportedHandler<Env>;
