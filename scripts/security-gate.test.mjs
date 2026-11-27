import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import {
  buildPrompt,
  chatCompletionsUrl,
  codexConfig,
  collectExcerpts,
  decide,
  detectAuthorFamilies,
  familyOfModel,
  exportedServerActions,
  gitleaksFindings,
  installCli,
  installScriptFindings,
  isSensitive,
  parseAiVerdict,
  parsePatterns,
  parseUnifiedDiff,
  redact,
  renderReport,
  scanRepository,
  selectReviewers,
  serverActionFindings,
  splitSql,
  sqlFindings,
  VERDICT_SCHEMA,
  workflowFindings,
} from "./security-gate.mjs";

// Run by .github/workflows/self-check.yml: `node --test scripts/`.

const PAULLORBER = parsePatterns(`
proxy.ts
lib/supabase-server.ts
lib/auth*
lib/hosts.ts
app/**/actions.ts
app/api/**
app/auth/**
app/login/**
supabase/**
.github/**
.claude/**
vercel.json
next.config.ts
package.json
package-lock.json
scripts/**
`);

const lines = (...texts) => texts.map((text, i) => ({ line: i + 1, text }));
const all = (text) => new Set(text.split("\n").map((_, i) => i + 1));
const rules = (findings) => findings.map((f) => f.rule);

test("sensitive paths match files, parents and ** segments", () => {
  for (const path of ["proxy.ts", "lib/auth.ts", "lib/auth-passkey.ts", "lib/auth/session.ts", "app/actions.ts", "app/finance/deep/actions.ts", "app/api/status/route.ts", "supabase/migrations/1.sql", ".github/workflows/ci.yml", ".claude/settings.json", "package-lock.json", "scripts/a/b.mjs"]) {
    assert.equal(isSensitive(path, PAULLORBER), true, path);
  }
  for (const path of ["README.md", "app/page.tsx", "lib/hosts.test.ts", "app/finance/page.tsx", "lib/author.ts.bak/x", "components/actions.ts", "next.config.mjs"]) {
    if (path === "lib/author.ts.bak/x") continue; // lib/auth* deliberately covers lib/author*
    assert.equal(isSensitive(path, PAULLORBER), false, path);
  }
});

test("parsePatterns ignores comments and blanks", () => {
  assert.deepEqual(parsePatterns("a\n# b\n c # d\n,e"), ["a", "c", "e"]);
});

test("parseUnifiedDiff tracks added line numbers per file", () => {
  const diff = [
    "diff --git a/x.sql b/x.sql",
    "new file mode 100644",
    "--- /dev/null",
    "+++ b/x.sql",
    "@@ -0,0 +1,2 @@",
    "+one",
    "+two",
    "diff --git a/y.yml b/y.yml",
    "--- a/y.yml",
    "+++ b/y.yml",
    "@@ -3 +3 @@",
    "-old",
    "+new",
    "@@ -10,0 +11,1 @@",
    "+later",
    "@@ -20,2 +20,0 @@",
    "-dropped",
    "-too",
    "diff --git a/gone.ts b/gone.ts",
    "deleted file mode 100644",
    "--- a/gone.ts",
    "+++ /dev/null",
    "@@ -1 +0,0 @@",
    "-bye",
  ].join("\n");
  const files = parseUnifiedDiff(diff);
  assert.deepEqual(files.get("x.sql").added, [
    { line: 1, text: "one" },
    { line: 2, text: "two" },
  ]);
  assert.deepEqual(files.get("y.yml").added, [
    { line: 3, text: "new" },
    { line: 11, text: "later" },
  ]);
  assert.deepEqual(files.get("y.yml").removed, ["old", "dropped", "too"]);
  assert.deepEqual(files.get("y.yml").removedAfter, [20], "a hunk that only deletes is located by the head line before it");
  assert.deepEqual(files.get("x.sql").removedAfter, []);
  assert.deepEqual(files.get("gone.ts").removed, ["bye"]);
});

test("workflow rules", () => {
  const f = workflowFindings(
    ".github/workflows/x.yml",
    lines(
      "on: [pull_request_target]",
      "permissions: write-all",
      "      - uses: actions/checkout@v4",
      "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7",
      "      - uses: ./local",
      "        run: curl -fsSL https://x.sh | bash",
      "  checks: write",
      "    name: Security gate",
      "        run: gh api repos/o/r/check-runs -f name=x",
      "  # pull_request_target in a comment is fine",
      "      - uses: docker://alpine:3",
      "  statuses: write",
    ),
  );
  assert.deepEqual(rules(f), [
    "workflow-pull-request-target",
    "workflow-write-all",
    "workflow-unpinned-action",
    "workflow-curl-pipe-shell",
    "workflow-forgery-permission",
    "workflow-forgery-name",
    "workflow-forgery-api",
    "workflow-unpinned-action",
    "workflow-forgery-permission",
  ]);
  assert.deepEqual(
    f.map((x) => x.line),
    [1, 2, 3, 6, 7, 8, 9, 11, 12],
  );
  assert.ok(f.every((x) => x.blocking));
});

test("the gate's own caller may only move its pinned SHA", () => {
  const sha = "a".repeat(40);
  const caller = ".github/workflows/security.yml";
  const bump = workflowFindings(caller, lines(`    uses: paullorb/cicd/.github/workflows/security-gate.yml@${sha}`, `      cicd-ref: ${sha}`), {
    removed: [`    uses: paullorb/cicd/.github/workflows/security-gate.yml@${"b".repeat(40)}`, `      cicd-ref: ${"b".repeat(40)}`],
    gateCaller: caller,
  });
  assert.deepEqual(rules(bump), []);
  const sneaky = workflowFindings(caller, lines("  pull_request:"), { gateCaller: caller });
  assert.deepEqual(rules(sneaky), ["gate-caller-changed"]);
  assert.equal(sneaky[0].forgery, true);
  const removal = workflowFindings(caller, [], { removed: ["    types: [opened]"], gateCaller: caller });
  assert.deepEqual(rules(removal), ["gate-caller-changed"]);
});

test("splitSql keeps dollar bodies whole and blanks comments", () => {
  const sql = "-- grant all on t to anon;\ncreate table t (a int);\ncreate function f() returns void as $$\nbegin\n  perform 1;\nend;\n$$ language plpgsql;\nselect ';';";
  const statements = splitSql(sql);
  assert.equal(statements.length, 3);
  assert.equal(statements[0].startLine, 2);
  assert.equal(statements[1].startLine, 3);
  assert.equal(statements[1].endLine, 7);
  assert.ok(!statements[0].text.includes("anon"));
});

test("SQL rules fire on new statements only", () => {
  const sql = [
    "grant select on public.notes to anon, authenticated;", // 1
    "grant usage on schema public to anon;", // 2
    "grant select on public.notes to service_role;", // 3
    "create or replace function f() returns void language sql security definer as $$ select 1 $$;", // 4
    "create function g() returns void language sql security definer set search_path = '' as $$ select 1 $$;", // 5
    "alter table notes disable row level security;", // 6
    "create policy p on notes for select to authenticated using (true);", // 7
    "create policy q on notes for update to service_role using (true) with check (true);", // 8
    "-- disable row level security in a comment", // 9
    "alter default privileges in schema public grant select on tables to public;", // 10
    "grant execute on function f() to authenticated;", // 11
    "revoke all on public.notes from anon;", // 12
  ].join("\n");
  const f = sqlFindings("supabase/migrations/1.sql", sql, all(sql));
  assert.deepEqual(
    f.map((x) => `${x.line}:${x.rule}`),
    ["1:sql-grant-open-role", "4:sql-definer-search-path", "6:sql-disable-rls", "7:sql-policy-true", "10:sql-grant-open-role"],
  );
  assert.deepEqual(sqlFindings("x.sql", sql, new Set([3])), []);
});

test("SQL rules see a grant inside a DO block", () => {
  const sql = "do $$\nbegin\n  grant select on public.t to anon;\nend\n$$;";
  assert.deepEqual(rules(sqlFindings("x.sql", sql, new Set([3]))), ["sql-grant-open-role"]);
});

const ACTIONS = `"use server";

import { getOwner } from "@/lib/supabase-server";

export type State = { error: string | null };

export async function guarded(id: string): Promise<{ error: string | null }> {
  const owner = await getOwner();
  if (!owner) return { error: "no" };
  return { error: null };
}

export async function open(form: FormData): Promise<State> {
  const value = \`\${form.get("x")} }\`;
  return { error: value };
}

// security-gate: public-action the login form posts here before a session exists
export async function login(form: FormData) {
  return null;
}

export const arrow = async (id: string) => {
  await getOwnerRequiresMfa();
};

export const expression = async () => fetchSomething();

export default async function main({ a }: { a: string }): Promise<void> {
  helper();
}

function helper() {
  return getOwner();
}
`;

test("exportedServerActions finds every exported async function and its body", () => {
  const actions = exportedServerActions(ACTIONS);
  assert.deepEqual(
    actions.map((a) => a.name),
    ["guarded", "open", "login", "arrow", "expression", "main"],
  );
  assert.match(actions[0].body, /getOwner/);
  assert.doesNotMatch(actions[1].body, /getOwner/);
  assert.doesNotMatch(actions[5].body, /getOwner/);
});

test("server actions without the owner check block; marked ones are noted", () => {
  const f = serverActionFindings("app/x/actions.ts", ACTIONS, all(ACTIONS), "\\bgetOwner\\w*\\s*\\(");
  assert.deepEqual(
    f.map((x) => `${x.rule}:${x.blocking}`),
    ["server-action-no-owner:true", "server-action-public:false", "server-action-no-owner:true", "server-action-no-owner:true"],
  );
  assert.deepEqual(serverActionFindings("a.ts", ACTIONS, new Set([1, 2, 3]), "getOwner"), []);
  assert.deepEqual(serverActionFindings("a.ts", ACTIONS.replace('"use server";', ""), all(ACTIONS), "getOwner"), []);
});

test("deleting an action's owner check is a change to that action", () => {
  const guard = "\\bgetOwner\\w*\\s*\\(";
  const lines = ACTIONS.split("\n");
  const open = lines.indexOf("export async function open(form: FormData): Promise<State> {") + 1;
  const none = new Set();
  // Lines deleted after the action's first, or before its last line: inside it.
  assert.deepEqual(rules(serverActionFindings("a.ts", ACTIONS, none, guard, [open])), ["server-action-no-owner"]);
  assert.deepEqual(rules(serverActionFindings("a.ts", ACTIONS, none, guard, [open + 2])), ["server-action-no-owner"]);
  // Before its first line or after its last: not this action's change.
  assert.deepEqual(serverActionFindings("a.ts", ACTIONS, none, guard, [open - 1]), []);
  assert.deepEqual(serverActionFindings("a.ts", ACTIONS, none, guard, [open + 3]), []);
  // A deletion inside an action that still has its check passes.
  const guarded = lines.indexOf("  const owner = await getOwner();") + 1;
  assert.deepEqual(serverActionFindings("a.ts", ACTIONS, none, guard, [guarded]), []);
});

test("a new dependency with an install script blocks, an existing one does not", () => {
  const base = JSON.stringify({ packages: { "node_modules/sharp": { version: "1", hasInstallScript: true } } });
  const head = JSON.stringify(
    {
      packages: {
        "node_modules/sharp": { version: "2", hasInstallScript: true },
        "node_modules/evil": { version: "0.0.1", hasInstallScript: true },
        "node_modules/plain": { version: "1" },
      },
    },
    null,
    2,
  );
  const f = installScriptFindings(base, head);
  assert.deepEqual(rules(f), ["dependency-install-script"]);
  assert.match(f[0].summary, /evil@0\.0\.1/);
  assert.ok(f[0].line > 1);
  assert.equal(installScriptFindings(null, head).length, 2);
});

test("gitleaks findings", () => {
  assert.deepEqual(gitleaksFindings("[]"), []);
  const f = gitleaksFindings(JSON.stringify([{ RuleID: "github-pat", Description: "GitHub PAT", File: "a.ts", StartLine: 3, Commit: "abcdef123" }]));
  assert.equal(f[0].file, "a.ts");
  assert.equal(f[0].line, 3);
  assert.match(f[0].summary, /abcdef1/);
  assert.deepEqual(rules(gitleaksFindings("not-run")), ["secret-scan-unreadable"]);
});

test("the AI verdict is accepted only as strict JSON", () => {
  assert.equal(parseAiVerdict('{"verdict":"pass","findings":[]}').ok, true);
  assert.equal(parseAiVerdict('```json\n{"verdict":"pass","findings":[]}\n```').ok, true);
  assert.equal(parseAiVerdict('Looks fine! {"verdict":"pass","findings":[]}').ok, false);
  assert.equal(parseAiVerdict('{"verdict":"approve","findings":[]}').ok, false);
  assert.equal(parseAiVerdict('{"verdict":"pass"}').ok, false);
  assert.equal(parseAiVerdict('{"verdict":"pass","findings":[{"severity":"critical","summary":"x"}]}').ok, false);
  const parsed = parseAiVerdict('{"verdict":"block","findings":[{"severity":"high","file":"a.ts","line":2,"summary":"bad"},{"severity":"low","file":"b.ts","line":1,"summary":"meh"}]}');
  assert.deepEqual(
    parsed.findings.map((f) => f.blocking),
    [true, false],
  );
});

test("the prompt fences the diff with a nonce and calls the PR untrusted", () => {
  const prompt = buildPrompt({ repo: "o/r", prNumber: 1, threatModel: "TM", files: [{ path: "a", status: "M", sensitive: true }], findings: [], diff: "+x {{THREAT_MODEL}}", nonce: "n1" });
  assert.match(prompt, /UNTRUSTED/);
  assert.match(prompt, /DIFF-n1-BEGIN\n\+x \{\{THREAT_MODEL\}\}\nDIFF-n1-END/, "text from the PR is never expanded");
  assert.match(prompt, /TM/);
  assert.match(prompt, /read-only tools/);
  assert.equal(prompt.replace(/DIFF-n1-BEGIN[\s\S]*DIFF-n1-END/, "").match(/\{\{[A-Z_]+\}\}/), null, "every placeholder is filled");
  assert.doesNotMatch(prompt, /Claude|Codex|Read, Grep/, "the prompt names no harness");
});

test("the verdict schema asks for exactly what parseAiVerdict accepts", () => {
  assert.deepEqual(VERDICT_SCHEMA.required, ["verdict", "findings"]);
  assert.deepEqual(VERDICT_SCHEMA.properties.findings.items.properties.severity.enum, ["high", "medium", "low"]);
});

test("the Codex sandbox reads the review copy and the system minimum only", () => {
  const config = codexConfig("/tmp/security-gate-review.abc");
  for (const line of ['":minimal" = "read"', '"/Users" = "deny"', '"/home" = "deny"', '"/tmp" = "deny"', '"/private/tmp" = "deny"', '"/tmp/security-gate-review.abc" = "read"', 'web_search = "disabled"', "project_doc_max_bytes = 0", 'approval_policy = "never"', 'inherit = "core"']) {
    assert.ok(config.includes(line), line);
  }
  assert.doesNotMatch(config, /mcp_servers|"write"|danger/);
});

const reviewer = (id, family, extra = {}) => ({ id, harness: id, family, model: `${id}-model`, status: "ran", verdict: "pass", findings: [], seconds: 3, ...extra });
const HIGH = { rule: "ai-review", severity: "high", blocking: true, file: "a.ts", line: 1, summary: "h" };
const MEDIUM = { rule: "ai-review", severity: "medium", blocking: false, file: "a.ts", line: 2, summary: "m" };

test("decide: block on any high, AI trouble never blocks, a missing scan fails closed", () => {
  const scan = { files: [{ path: "a", sensitive: false }], findings: [], sensitive: false, authorFamilies: [] };
  assert.equal(decide({ scan, ai: null }).conclusion, "success");
  assert.match(decide({ scan, ai: null }).title, /No sensitive paths/);

  const sensitive = { ...scan, sensitive: true };
  const none = decide({ scan: sensitive, ai: { reviewers: [{ id: "claude", status: "unconfigured", missing: ["CLAUDE_CODE_OAUTH_TOKEN"] }] } });
  assert.equal(none.conclusion, "success");
  assert.match(none.warnings[0], /AI review skipped: no reviewer is configured/);
  assert.match(none.title, /AI review skipped/);

  const allDown = decide({ scan: sensitive, ai: { reviewers: [reviewer("claude", "anthropic", { status: "unavailable", reason: "timeout" }), reviewer("codex", "openai", { status: "unavailable", reason: "401" })] } });
  assert.equal(allDown.conclusion, "success");
  assert.match(allDown.warnings[0], /AI review skipped: every configured reviewer was unavailable \(claude \(claude-model\): timeout; codex \(codex-model\): 401\)/);

  const medium = decide({ scan: sensitive, ai: { reviewers: [reviewer("claude", "anthropic", { verdict: "block", findings: [MEDIUM] })] } });
  assert.equal(medium.conclusion, "success");
  assert.match(medium.warnings[0], /answered "block" without a high-severity finding/);
  assert.match(medium.title, /reviewed by 1 AI reviewer — passed/);

  // One dissenting reviewer is enough: prompt injection has to fool them all.
  const oneHigh = decide({ scan: sensitive, ai: { reviewers: [reviewer("claude", "anthropic"), reviewer("codex", "openai", { verdict: "block", findings: [HIGH] })] } });
  assert.equal(oneHigh.conclusion, "failure");
  assert.equal(oneHigh.findings[0].rule, "ai · codex");

  const deterministic = decide({ scan: { ...sensitive, findings: [{ blocking: true, severity: "high", summary: "x" }] }, ai: { reviewers: [] } });
  assert.equal(deterministic.conclusion, "failure");

  assert.equal(decide({ scan: null, ai: null, jobStatus: "failure" }).conclusion, "failure");
  assert.equal(decide({ scan: null, ai: null, jobStatus: "cancelled" }).conclusion, "cancelled");
});

test("cross-review: a model family never alone judges its own PR when another is configured", () => {
  const claudePr = { files: [{ path: "a", sensitive: true }], findings: [], sensitive: true, authorFamilies: [{ family: "anthropic", evidence: "Claude in commit abc1234" }] };
  // Another family answered: pass.
  assert.equal(decide({ scan: claudePr, ai: { reviewers: [reviewer("claude", "anthropic"), reviewer("codex", "openai")] } }).conclusion, "success");
  // Another family is configured but did not answer while the author's own did: blocked.
  const own = decide({ scan: claudePr, ai: { reviewers: [reviewer("claude", "anthropic"), reviewer("codex", "openai", { status: "unavailable", reason: "timeout" })] } });
  assert.equal(own.conclusion, "failure");
  assert.equal(own.findings[0].rule, "cross-review-missing");
  // Only the author's family is configured: pass with a visible note.
  const same = decide({ scan: claudePr, ai: { reviewers: [reviewer("claude", "anthropic"), reviewer("codex", "openai", { status: "unconfigured", missing: ["CODEX_API_KEY"] })] } });
  assert.equal(same.conclusion, "success");
  assert.match(same.warnings.join("\n"), /Cross-review: .* reviewed by its own family only/);
  // Every reviewer unavailable: the deterministic layer decides, as before.
  const down = decide({ scan: claudePr, ai: { reviewers: [reviewer("claude", "anthropic", { status: "unavailable", reason: "x" }), reviewer("codex", "openai", { status: "unavailable", reason: "y" })] } });
  assert.equal(down.conclusion, "success");
  assert.match(down.warnings[0], /AI review skipped/);
  // No harness detected (a human PR): any reviewer will do.
  assert.equal(decide({ scan: { ...claudePr, authorFamilies: [] }, ai: { reviewers: [reviewer("claude", "anthropic"), reviewer("codex", "openai", { status: "unavailable", reason: "x" })] } }).conclusion, "success");
  // Written with both families: a third family is needed only if configured.
  const both = { ...claudePr, authorFamilies: [{ family: "anthropic", evidence: "a" }, { family: "openai", evidence: "b" }] };
  assert.equal(decide({ scan: both, ai: { reviewers: [reviewer("claude", "anthropic"), reviewer("codex", "openai")] } }).conclusion, "success");
  assert.equal(decide({ scan: both, ai: { reviewers: [reviewer("claude", "anthropic"), reviewer("openai-compatible", "google", { status: "unavailable", reason: "x" })] } }).conclusion, "failure");
});

test("the author's harness comes from trailers, identities and the branch", () => {
  const commit = (message, extra = {}) => ({ sha: "0123456789", authorName: "Paul", authorEmail: "p@example.com", committerName: "Paul", committerEmail: "p@example.com", message, ...extra });
  const families = (commits, headRef) => detectAuthorFamilies({ commits, headRef }).map((a) => a.family).sort();
  assert.deepEqual(families([commit("fix\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n")]), ["anthropic"]);
  assert.deepEqual(families([commit("fix\n\nCo-authored-by: Claude Fable 5.2 <noreply@anthropic.com>")]), ["anthropic"]);
  assert.deepEqual(families([commit("fix\n\nCo-authored-by: Codex <noreply@openai.com>")]), ["openai"]);
  assert.deepEqual(families([commit("fix", { authorName: "chatgpt-codex-connector[bot]", authorEmail: "x@users.noreply.github.com" })]), ["openai"]);
  assert.deepEqual(families([commit("fix\n\nCo-authored-by: gemini-code-assist[bot] <x@users.noreply.github.com>")]), ["google"]);
  assert.deepEqual(families([commit("a\n\nCo-Authored-By: Claude <noreply@anthropic.com>"), commit("b\n\nCo-authored-by: Codex <noreply@openai.com>")]), ["anthropic", "openai"]);
  assert.deepEqual(families([commit("plain human commit")]), []);
  assert.deepEqual(families([commit("mentions claude in prose and Co-authored-by: Paul")]), [], "only a trailer line counts, not prose");
  assert.deepEqual(families([commit("x")], "claude/fix-login"), ["anthropic"]);
  assert.deepEqual(families([commit("x")], "codex/fix-login"), ["openai"]);
  assert.match(detectAuthorFamilies({ commits: [commit("x\n\nCo-authored-by: Codex <noreply@openai.com>")] })[0].evidence, /Codex in commit 0123456/);
});

test("reviewers are enabled by their credentials and ordered by SECURITY_REVIEWERS", () => {
  const ids = (env) => selectReviewers(env).reviewers.map((r) => `${r.id}:${r.configured ? "on" : "off"}`);
  assert.deepEqual(ids({}), ["claude:off", "codex:off", "openai-compatible:off"]);
  assert.deepEqual(ids({ CODEX_API_KEY: "k", CLAUDE_CODE_OAUTH_TOKEN: "t" }), ["claude:on", "codex:on", "openai-compatible:off"]);
  assert.deepEqual(ids({ SECURITY_REVIEWERS: "codex, claude", CODEX_API_KEY: "k" }), ["codex:on", "claude:off"]);
  assert.deepEqual(ids({ REVIEW_API_KEY: "k", REVIEW_API_BASE: "https://x" }), ["claude:off", "codex:off", "openai-compatible:off"], "the API reviewer also needs its model");
  const api = selectReviewers({ REVIEW_API_KEY: "k", REVIEW_API_BASE: "https://x", REVIEW_API_MODEL: "gemini-3-pro" }).reviewers[2];
  assert.equal(api.configured, true);
  assert.equal(api.family, "google");
  assert.deepEqual(selectReviewers({}).reviewers[2].missing, ["REVIEW_API_KEY", "REVIEW_API_BASE", "REVIEW_API_MODEL"]);
  const odd = selectReviewers({ SECURITY_REVIEWERS: "gemini,codex" });
  assert.deepEqual(odd.unknown, ["gemini"]);
  assert.match(decide({ scan: { files: [], findings: [], sensitive: true }, ai: { reviewers: odd.reviewers.map((r) => ({ ...r, status: "unconfigured" })), unknown: odd.unknown } }).warnings[0], /names `gemini`, which this gate does not know/);
});

test("model families", () => {
  assert.equal(familyOfModel("claude-opus-5-5"), "anthropic");
  assert.equal(familyOfModel("gpt-6.2-sol"), "openai");
  assert.equal(familyOfModel("openai/o4-mini"), "openai");
  assert.equal(familyOfModel("gemini-3-pro"), "google");
  assert.equal(familyOfModel("models/gemini-2.5-flash"), "google");
  assert.equal(familyOfModel("meta-llama/llama-4"), "meta");
  assert.equal(familyOfModel("qwen3-coder"), "alibaba");
  assert.equal(familyOfModel("something-new"), "other");
});

test("the API reviewer only talks https (or http to loopback)", () => {
  assert.equal(chatCompletionsUrl("https://generativelanguage.googleapis.com/v1beta/openai/"), "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions");
  assert.equal(chatCompletionsUrl("http://localhost:11434/v1"), "http://localhost:11434/v1/chat/completions");
  assert.equal(chatCompletionsUrl("http://example.com/v1"), null);
  assert.equal(chatCompletionsUrl("https://user:pw@example.com/v1"), null);
  assert.equal(chatCompletionsUrl("file:///etc/passwd"), null);
  assert.equal(chatCompletionsUrl(""), null);
});

test("excerpts are bounded and skip deleted and binary files", () => {
  const dir = mkdtempSync(join(tmpdir(), "security-gate-excerpts-"));
  writeFileSync(join(dir, "big.ts"), "x".repeat(50));
  writeFileSync(join(dir, "auth.ts"), "secret check");
  writeFileSync(join(dir, "bin.png"), "a\0b");
  const out = collectExcerpts(dir, [
    { path: "big.ts", status: "M", sensitive: false },
    { path: "auth.ts", status: "M", sensitive: true },
    { path: "gone.ts", status: "D", sensitive: true },
    { path: "bin.png", status: "A", sensitive: true },
  ], { perFile: 20, total: 30 });
  assert.deepEqual(out.map((e) => [e.path, e.text.length, e.truncated]), [["auth.ts", 12, false], ["big.ts", 18, true]]);
  const prompt = buildPrompt({ repo: "o/r", prNumber: 1, threatModel: "", files: [], findings: [], diff: "+x", nonce: "n2", excerpts: out });
  assert.match(prompt, /You have no tools/);
  assert.match(prompt, /EXCERPTS-n2-BEGIN\n===== auth.ts\nsecret check/);
});

test("credentials never reach the report", () => {
  const value = redact({ reviewers: [{ reason: "bad key sk-0123456789abcdef", findings: [{ summary: "echoed sk-0123456789abcdef" }] }] }, ["sk-0123456789abcdef", undefined, "short"]);
  assert.doesNotMatch(JSON.stringify(value), /sk-0123/);
  assert.match(value.reviewers[0].reason, /\[redacted\]/);
});

test("renderReport names each reviewer, its model, verdict and findings", () => {
  const scan = { files: [{ path: "a", sensitive: false }], findings: [], sensitive: false };
  const body = renderReport({ decision: decide({ scan, ai: null }), scan, ai: null, headSha: "0123456789", runUrl: "" });
  assert.ok(body.startsWith("<!-- security-gate:sticky -->"));
  assert.match(body, /No sensitive paths — deterministic checks passed/);
  assert.match(body, /`0123456`/);

  const sensitive = { files: [{ path: "a", sensitive: true }], findings: [], sensitive: true, authorFamilies: [{ family: "anthropic", evidence: "x" }] };
  const ai = {
    reviewers: [
      reviewer("codex", "openai", { harness: "Codex", version: "0.169.0", model: "gpt-6.2-sol", verdict: "block", findings: [HIGH] }),
      reviewer("claude", "anthropic", { harness: "Claude Code", status: "unavailable", reason: "did not finish within 480s" }),
      { id: "openai-compatible", harness: "OpenAI-compatible API", family: "other", status: "unconfigured", missing: ["REVIEW_API_KEY", "REVIEW_API_BASE", "REVIEW_API_MODEL"] },
    ],
  };
  const report = renderReport({ decision: decide({ scan: sensitive, ai }), scan: sensitive, ai, headSha: "0123456789", runUrl: "" });
  assert.match(report, /\| Codex 0\.169\.0 \| `gpt-6\.2-sol` \| OpenAI \(GPT\/Codex\) \| 🛑 block, 1 finding \| 3s \|/);
  assert.match(report, /\| Claude Code \| `claude-model` \| Anthropic \(Claude\) \| unavailable: did not finish within 480s \|/);
  assert.match(report, /Not configured: openai-compatible \(REVIEW_API_KEY \+ REVIEW_API_BASE \+ REVIEW_API_MODEL\)/);
  assert.match(report, /<sub>ai · codex<\/sub>/);
  assert.match(report, /written with Anthropic \(Claude\)/);
});

test("scanRepository end to end on a scratch repository", () => {
  const dir = mkdtempSync(join(tmpdir(), "security-gate-test-"));
  const run = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" }).trim();
  const write = (path, text) => {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  };
  run("init", "-q", "-b", "main");
  run("config", "user.email", "t@example.com");
  run("config", "user.name", "t");
  write("README.md", "hi\n");
  write("supabase/migrations/1.sql", "create table t (a int);\nalter table t disable row level security;\n");
  run("add", ".");
  run("commit", "-qm", "base");
  const base = run("rev-parse", "HEAD");

  run("checkout", "-qb", "pr");
  write("README.md", "hi\nthere\n");
  run("commit", "-qam", "docs");
  const docs = run("rev-parse", "HEAD");
  const quiet = scanRepository({ repoDir: dir, baseSha: base, headSha: docs, patterns: PAULLORBER, guardPattern: "getOwner", gateCaller: "", gitleaksReport: "[]" });
  assert.equal(quiet.sensitive, false);
  assert.deepEqual(quiet.findings, []);

  write("supabase/migrations/2.sql", "grant select on t to anon;\n");
  write("lib/work/actions.ts", '"use server";\nexport async function x() {\n  return 1;\n}\n');
  run("add", ".");
  run("commit", "-qm", "risky\n\nCo-authored-by: Codex <noreply@openai.com>");
  const head = run("rev-parse", "HEAD");
  const loud = scanRepository({ repoDir: dir, baseSha: base, headSha: head, patterns: PAULLORBER, guardPattern: "getOwner", gateCaller: "", gitleaksReport: "[]" });
  assert.equal(loud.sensitive, true);
  assert.deepEqual(rules(loud.findings).sort(), ["server-action-no-owner", "sql-grant-open-role"]);
  assert.equal(loud.files.find((f) => f.path === "lib/work/actions.ts").sensitive, true, "a use-server file is sensitive wherever it lives");

  // A PR that only deletes the owner check adds no line, and is still judged.
  run("checkout", "-q", "main");
  write("lib/work/guarded.ts", '"use server";\nexport async function y() {\n  await getOwner();\n  return 1;\n}\n');
  run("add", ".");
  run("commit", "-qm", "guarded");
  const guardedBase = run("rev-parse", "HEAD");
  run("checkout", "-qb", "unguard");
  write("lib/work/guarded.ts", '"use server";\nexport async function y() {\n  return 1;\n}\n');
  run("commit", "-qam", "drop the check");
  const unguarded = scanRepository({ repoDir: dir, baseSha: guardedBase, headSha: run("rev-parse", "HEAD"), patterns: PAULLORBER, guardPattern: "getOwner", gateCaller: "", gitleaksReport: "[]" });
  assert.deepEqual(rules(unguarded.findings), ["server-action-no-owner"]);
  assert.deepEqual(quiet.authorFamilies, []);
  assert.deepEqual(loud.authorFamilies.map((a) => a.family), ["openai"], "the trailer of a PR commit names the author's harness");
});

test("a reviewer's CLI is installed outside the review copy, whatever the PR planted there", async () => {
  const root = mkdtempSync(join(tmpdir(), "security-gate-cli-"));
  const write = (path, text, mode) => {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
    if (mode) chmodSync(join(root, path), mode);
  };
  // The real package, standing in for the registry's.
  write("registry/gate-cli/package.json", JSON.stringify({ name: "gate-cli", version: "1.0.0", bin: { "gate-cli": "cli.js" } }));
  write("registry/gate-cli/cli.js", '#!/usr/bin/env node\nprocess.stdout.write("trusted");\n', 0o755);
  // The PR's copy: the same name and version, already "installed", and an
  // .npmrc that sends npm to a registry of its own.
  write("review/package.json", JSON.stringify({ name: "pr", version: "1.0.0", dependencies: { "gate-cli": "1.0.0" } }));
  write("review/.npmrc", "registry=http://127.0.0.1:9/\n");
  write("review/node_modules/gate-cli/package.json", JSON.stringify({ name: "gate-cli", version: "1.0.0", bin: { "gate-cli": "cli.js" } }));
  write("review/node_modules/gate-cli/cli.js", '#!/usr/bin/env node\nprocess.stdout.write("planted");\n', 0o755);
  write("review/node_modules/.bin/gate-cli", '#!/usr/bin/env node\nprocess.stdout.write("planted");\n', 0o755);
  mkdirSync(join(root, "home"));

  const env = { PATH: process.env.PATH, HOME: join(root, "home"), npm_config_cache: join(root, "home", ".npm"), npm_config_update_notifier: "false", npm_config_fund: "false", npm_config_audit: "false" };
  const cli = await installCli({ spec: join(root, "registry", "gate-cli"), bin: "gate-cli", home: join(root, "home"), env, timeoutMs: 120_000 });
  assert.equal(cli.error, undefined);
  assert.ok(cli.path.startsWith(join(root, "home") + "/"), "the executable lives in the gate's own directory");
  assert.equal(execFileSync(cli.path, [], { cwd: join(root, "review"), env, encoding: "utf8" }), "trusted");

  mkdirSync(join(root, "home2"));
  const missing = await installCli({ spec: join(root, "registry", "nothing-here"), bin: "gate-cli", home: join(root, "home2"), env: { ...env, HOME: join(root, "home2") }, timeoutMs: 120_000 });
  assert.match(missing.error, /^installing .* failed/);
  assert.equal(missing.path, undefined);
});
