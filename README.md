# pr-sentinel

Scans **every pull request and every push** in the Aswincloud org and posts to
Slack the moment a change looks like an attack.

```
GitHub org webhook (pull_request, push) ──HMAC──▶ pr-sentinel Worker
   │ fetch the diff with a 1-hour, read-only App token   (never runs the code)
   │ 1. deterministic rules  → alert on their own
   │ 2. Workers AI review    → can only ADD findings
   ▼
Slack #security-alerts
```

## What it flags

| Rule | Severity | Catches |
|---|---|---|
| `campaign-script`, `known-exfil-marker`, `campaign-commit-message`, `campaign-branch` | high | WFX Phantom (2026-11-11): `.ci-*.sh`, `WF_CALLBACK`, `ci: restore`, `wfx-docs` |
| `npm-lifecycle-script` | high | new `postinstall` / `preinstall` / `prepare` |
| `secret-exfil-in-workflow` | high | workflow reads `secrets.*` and echoes / base64 / splits it (portfolio #256) |
| `secret-sent-over-network` | high | workflow reads secrets and calls curl/wget/http |
| `bare-ip-url`, `pipe-to-shell` | high | raw-IP URLs, `curl … \| sh`, `eval $(…)` |
| `force-push-default` | high | force push to the default branch |
| `workflow-changed`, `pull-request-target`, `harden-runner-removed`, `hidden-script` | medium | anything touching CI or adding hidden scripts |
| `direct-push-default` | medium | commit on the default branch not from a merged PR (except the App's README refresh) |
| `ai-flag` | from AI | Workers AI's second opinion (`@cf/meta/llama-3.3-70b-instruct-fp8-fast`) |

The diff is untrusted: the AI is told so, its output is parsed as strict JSON,
and nothing it says removes a rule finding.

## Setup

Secrets (Worker secrets only): `WEBHOOK_SECRET`, `SLACK_WEBHOOK_URL`,
`APP_PRIVATE_KEY` (PKCS#8, same App as token-broker). Org webhook:
`https://pr-sentinel.aswincloud.com/webhook`, content type JSON, events
**Pull requests** + **Pushes**, secret = `WEBHOOK_SECRET`.

## Limits

An alarm, not a lock: it alerts after the change exists. Pair it with branch
rules and protected environments to *prevent* misuse.

Live test: this line exists only to trigger a pull_request event.
