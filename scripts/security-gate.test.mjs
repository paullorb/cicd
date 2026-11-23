import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import {
  buildPrompt,
  decide,
  exportedServerActions,
  gitleaksFindings,
  installScriptFindings,
  isSensitive,
  parseAiVerdict,
  parsePatterns,
  parseUnifiedDiff,
  renderReport,
  scanRepository,
  serverActionFindings,
  splitSql,
  sqlFindings,
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
  assert.deepEqual(files.get("y.yml").removed, ["old"]);
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
  const prompt = buildPrompt({ repo: "o/r", prNumber: 1, threatModel: "TM", files: [{ path: "a", status: "M", sensitive: true }], findings: [], diff: "+x", nonce: "n1" });
  assert.match(prompt, /UNTRUSTED/);
  assert.match(prompt, /DIFF-n1-BEGIN\n\+x\nDIFF-n1-END/);
  assert.match(prompt, /TM/);
});

test("decide: block on high only, AI trouble never blocks, a missing scan fails closed", () => {
  const scan = { files: [{ path: "a", sensitive: false }], findings: [], sensitive: false };
  assert.equal(decide({ scan, ai: null }).conclusion, "success");
  assert.match(decide({ scan, ai: null }).title, /No sensitive paths/);

  const sensitive = { ...scan, sensitive: true };
  const skipped = decide({ scan: sensitive, ai: { status: "skipped", reason: "no token" } });
  assert.equal(skipped.conclusion, "success");
  assert.match(skipped.warnings[0], /AI review skipped: no token/);

  const medium = decide({ scan: sensitive, ai: { status: "ran", verdict: "block", findings: [{ severity: "medium", blocking: false, summary: "m" }] } });
  assert.equal(medium.conclusion, "success");
  assert.equal(medium.warnings.length, 1);

  const high = decide({ scan: sensitive, ai: { status: "ran", verdict: "block", findings: [{ severity: "high", blocking: true, summary: "h" }] } });
  assert.equal(high.conclusion, "failure");

  const deterministic = decide({ scan: { ...sensitive, findings: [{ blocking: true, severity: "high", summary: "x" }] }, ai: { status: "skipped", reason: "r" } });
  assert.equal(deterministic.conclusion, "failure");

  assert.equal(decide({ scan: null, ai: null, jobStatus: "failure" }).conclusion, "failure");
  assert.equal(decide({ scan: null, ai: null, jobStatus: "cancelled" }).conclusion, "cancelled");
});

test("renderReport starts with the sticky marker", () => {
  const scan = { files: [{ path: "a", sensitive: false }], findings: [], sensitive: false };
  const body = renderReport({ decision: decide({ scan, ai: null }), scan, ai: null, headSha: "0123456789", runUrl: "" });
  assert.ok(body.startsWith("<!-- security-gate:sticky -->"));
  assert.match(body, /No sensitive paths — deterministic checks passed/);
  assert.match(body, /`0123456`/);
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
  run("commit", "-qm", "risky");
  const head = run("rev-parse", "HEAD");
  const loud = scanRepository({ repoDir: dir, baseSha: base, headSha: head, patterns: PAULLORBER, guardPattern: "getOwner", gateCaller: "", gitleaksReport: "[]" });
  assert.equal(loud.sensitive, true);
  assert.deepEqual(rules(loud.findings).sort(), ["server-action-no-owner", "sql-grant-open-role"]);
  assert.equal(loud.files.find((f) => f.path === "lib/work/actions.ts").sensitive, true, "a use-server file is sensitive wherever it lives");
});
