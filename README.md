# CI/CD pipeline

Private reusable GitHub Actions workflows serving multiple
[paullorb](https://github.com/paullorb) repositories at once.

This repository owns orchestration only; each application repository owns its
tests, scripts, Lighthouse/Playwright configuration, migrations, and product
code. Each caller pins this repository to an exact commit SHA and passes only
the secrets its workflow requires.

## Workflows

| Workflow | Caller | Trigger |
|---|---|---|
| `muk-ci.yml` | muk.events | pull requests and pushes to `main` (includes the advisory mobile Lighthouse budget) |
| `muk-browser-matrix.yml` | muk.events | weekly and manual |
| `muk-scheduled-checks.yml` | muk.events | daily and manual |
| `muk-sync-events.yml` | muk.events | hourly and manual |
| `muk-runner-watchdog.yml` | muk.events | every six hours and manual |
| `app-ci.yml` | paullorber | pull requests and pushes to `main` |
| `app-vercel.yml` | generic apps | Vercel production delivery (no previews) |
| `app-native-build.yml` | generic Capacitor apps | unsigned iOS and Android release artifacts; `build_ios` / `build_android` select platforms |
| `app-content-check-probe.yml` | generic apps | path-scoped, secret-bearing PR comment proof |
| `pr-overlap.yml` | any repo | pull requests; comments which other open PRs change the same files |
| `app-auto-merge.yml` | any repo | pull requests; arms auto-merge (squash) with the automation app's token |
| `app-supabase.yml` | any repo with `supabase/` | pushes to `main` and manual; applies migrations, then deploys edge functions |
| `security-gate.yml` | paullorber | `pull_request_target`; the required `Security gate` check on the PR head |

`app-ci.yml` is the generic entry point for a Next.js app (lint, audit, build,
and migration replay when migrations exist; no secrets). New repos should
start there and compose the additive deploy, native, or content-check
workflows they need. A bespoke product workflow is the exception, not the
onboarding path.

The small caller workflows remain in each application repository because
GitHub events and schedules belong to the caller. `actions/checkout` inside a
reusable workflow checks out the caller repository, not this one.

## Runner model

Every repo routes its jobs through one repository variable, `CI_LABELS`, so
routing can be flipped without a commit. What differs is only the pool a repo
falls back to when the variable is unset:

- **muk.events**: `["self-hosted","muk-ci"]`, the four repository-level
  runners on the Mac Studio (the `muk-*` workflows' default). The variable
  was `MUK_CI_LABELS` until 2026-11-21.
- **Every other repo**: `["self-hosted","app-ci"]`. Repository-level runners
  on a personal account serve exactly one repository, so the muk-ci pool is
  not reachable from other repos; instead each caller registers its own
  `app-ci` runner(s) on the same Mac Studio (`~/actions-runner-<repo>`, one
  LaunchAgent each — see "Adding a repository").

muk keeps `CI_LABELS` set explicitly to its pool, because the generic
workflows it calls (`app-auto-merge.yml`, `pr-overlap.yml`) default to
`app-ci`, a label none of its runners carry.

### Hosted minutes: what may spend them

The account's 3,000 hosted minutes a month are spent only by **private**
repositories (standard hosted runners are free for public ones), and every
private repo has its own runner, so hosted is the exception that has to
explain itself. Two things are hosted by design:

- **Dependabot's pull requests** run on `ubuntu-latest` whatever the variable
  says, in every routed job: a bumped package's install script or tests on a
  persistent box is the one blast radius a disposable VM is worth. In
  `muk-ci.yml` Dependabot's own run is only the handover (two short jobs; the
  header there says why), and the run that decides the PR is on the pool.
- **`muk-runner-watchdog.yml`**, once a day: the alarm for the runners cannot
  run on them.

Everything else is a finding. paullorber's `scripts/issue-keeper.mjs` reads
every private repo's workflows and label variables (and this repo's reusable
workflows, which bill their caller) once an hour and files a `for-paul` issue
for any hosted runner outside the allowlist in its
`scripts/lib/hosted-runners.mjs`; a new hosted job is added there, with its
reason and its monthly cost, in the PR that introduces it.

**Nothing fails over to hosted runners.** `muk-runner-watchdog.yml` used to
flip `CI_LABELS` to `["ubuntu-latest"]` when the pool was down; one such
day (2026-11-07) cost 263 minutes, because the variable routes every workflow
at once. A down runner is now a queue that waits, an alarm and a task (next
section). Setting `CI_LABELS` to `["ubuntu-latest"]` by
hand remains the escape hatch, as a decision to spend the quota; the keeper
files it as a finding and muk's watchdog sets muk's back once the pool is up.

Expected spend in muk with this in place, from November 2026's runs: about
30 minutes for the watchdog, about 50 for Dependabot's pull requests (2 per push for the handover, about 4 for the
auto-fix and impact jobs) and about 30 for Dependabot's own update jobs:
roughly 110 a month against November's 629. The other private repos billed
nothing in November because their Dependabot jobs waited for a `dependabot`
runner; once those run hosted, each update job is about 2 minutes and each
Dependabot push one `app-ci.yml` job.

## When the runners are down

Queued runs are not lost: they start by themselves when a runner comes back
(GitHub gives up on a job only after it has been queued for a day).

One command restarts every runner on the Mac Studio; it is safe to run when
they are already up:

```sh
for d in ~/actions-runner-*; do (cd "$d" && ./svc.sh start; ./svc.sh status | tail -2); done
```

What can go wrong, what notices, and what brings it back:

| Failure | Noticed by | Comes back by itself? | By hand |
| --- | --- | --- | --- |
| **Mac reboot or power cut** | muk's `runner-heartbeat` LaunchAgent stops pinging healthchecks.io (minutes); muk's daily hosted watchdog (email + `for-paul` issue) | A macOS update's own restart: yes, so far. A cold boot: no. Every runner is a LaunchAgent, so it starts at **login**, FileVault waits at the unlock screen, and the Mac does not power on after a power cut (`pmset autorestart` is 0). | Log in. All 13 runner agents, the keeper and the collector start with the session. `sudo pmset -a autorestart 1` makes a power cut end at the unlock screen instead of off. |
| **Runner process crash** | status.paullorber.com (each runner's listening / online state, every collector run); the keeper's queue issue after 45 minutes | The listener, on a retryable exit or a self-update: yes, `runsvc.sh` relaunches it after 5 seconds, up to 10 times in a row. After a terminal exit or the tenth retry, or when `runsvc.sh` itself dies: no, the plists `svc.sh install` writes have `RunAtLoad` and no `KeepAlive`. | `cd ~/actions-runner-<repo> && ./svc.sh start` (or the loop above). Logs: `~/Library/Logs/actions.runner.*/` and `_diag/Runner_*.log`. |
| **Runner offline while jobs queue** | paullorber's keeper, every 15 minutes: a run queued for over 45 minutes opens a `for-paul` issue in that repo, naming whether its runners are offline, busy or missing the label; closes itself when the queue moves | No failover. The runs wait. | The loop above. A run that asks for a label no runner carries (`muk-e2e`, or Dependabot's `dependabot` when "Dependabot on self-hosted runners" is on) waits for ever: fix the label or the setting. |
| **A stuck job holding a runner** | muk: `stuck-run-reaper.yml` cancels any run with a job past 75 minutes (every 30 minutes, itself on the pool). Elsewhere: the queue issue says "online and busy" | Every job has `timeout-minutes` (60 at most here, checked by `scripts/check-workflows.mjs`; muk pins its own), which the runner enforces. A runner too wedged to enforce it: only in muk, by the reaper. | `gh run cancel <id> -R paullorb/<repo>`, then `gh api -X POST repos/paullorb/<repo>/actions/runs/<id>/force-cancel` if it does not let go, then `./svc.sh stop && ./svc.sh start` in that runner's directory. |
| **Registration or token expiry** | The runner shows offline on the dashboard while its process is listening; `_diag/Runner_*.log` has the 401/403. `RUNNER_WATCHDOG_TOKEN`: the watchdog fails saying so, and muk's nightly "Credentials before they expire" warns ahead. | No. GitHub deletes a runner that has not connected for 14 days; a runner in use never expires. | Re-register in its directory: `./svc.sh stop; ./svc.sh uninstall; ./config.sh remove --token "$(gh api -X POST repos/paullorb/<repo>/actions/runners/remove-token --jq .token)"`, then the `config.sh` and `svc.sh install && ./svc.sh start` lines of "Adding a repository" with the same name and labels (muk's: `muk-ci`, and `muk-e2e` where it had it). |
| **Disk full** | muk's `runner-heartbeat` pings `/fail` under its free-disk threshold; the dashboard's disk bar and storage panel | No. | `du -sh ~/actions-runner-*/_work ~/actions-runner-*/_diag \| sort -h`; a runner's `_work` can be deleted while it is stopped. `docker system prune` for the lanes' images; `npm run worktrees:sweep -- --apply` in muk. |

Still open, and the owner's to close (each is a change on the Mac, which no
workflow here makes): `KeepAlive` in the runner plists, so launchd restarts a
`runsvc.sh` that died; `pmset autorestart 1`; and a runner for a private repo
that has none (`alteschersheimrc` selects hosted through `CI_LABELS` until
then).

Concurrent PRs from several repos are safe by construction: each repo's
runner(s) serve only that repo, migration-replay scratch databases are named
by repository and run id on the shared Homebrew PostgreSQL, and repo-scoped
concurrency groups (e.g. muk's `e2e-prod`) never cross repositories. The
fixed ports below are box-wide, though: a repo that starts a server in CI
picks a port no other repo's job uses (careteam's e2e uses `3300`).

Fixed ports on the Mac Studio:

- `3000`: interactive Codex, Claude, or human development
- `3100`: Playwright CI
- `3200`: Lighthouse CI

The Mac Studio also runs Homebrew `postgresql@17` as a service. Migration
checks replay each repo's `supabase/migrations/` onto a per-run scratch
database there (with a pg_cron stub extension the job reinstalls on every
run) instead of paying for a Supabase preview branch. See
`muk.events/docs/self-hosted-runners.md` for box setup.

Do not enable GitHub's remote npm cache on the persistent runners. The local
`~/.npm` cache survives jobs; the former Actions cache restored a 1.4 GB
archive in every cache-enabled job.

## The baseline every repo shares

A cloned paullorb repo is set up the same way wherever its product allows.
What "the same" means, and where each part lives:

| Part | Where | The same in every repo |
|---|---|---|
| CI | caller `ci.yml` → `app-ci.yml` | every pull request and every push to `main`; a bespoke job only where the product is not a Next.js app (hush, kairos, lacordobesa, muk) |
| Overlap comment | caller `pr-overlap.yml` → `pr-overlap.yml` | informational, never required |
| Auto-merge | caller `auto-merge.yml` → `app-auto-merge.yml` | squash, armed when a non-draft PR into `main` opens; never for forks; Dependabot's are armed by paullorber's issue keeper, not here |
| Supabase deploy | caller `supabase.yml` → `app-supabase.yml` | only in repos with `supabase/`; on when `SUPABASE_PROJECT_REF` is set |
| Pin | every `uses: paullorb/cicd/...@<SHA>` | one SHA per repo, the same in all of its callers |
| Repository settings | GitHub | auto-merge allowed, head branches deleted on merge, "Always suggest updating pull request branches" |
| `main` | ruleset "main protection" | no deletion, no force push, a pull request with 0 approvals, the repo's CI check required |
| Local branches and worktrees | paullorber's `repo-sweep` LaunchAgent (muk: its own `com.muk.sweep`) | removed once their work is proven merged |
| Agent rules | `AGENTS.md` (`CLAUDE.md` links to it), `.claude/settings.json`, `.claude/hooks/` | the "Working as an agent here" section and the three hooks, copied from paullorber |
| Dependabot | `.github/dependabot.yml` | weekly on Monday, grouped, npm (or pip) and GitHub Actions |

muk keeps its own pipeline (`muk-ci.yml` and the other `muk-*` workflows):
its deploy is ordered behind its own gates and is not worth re-plumbing. New
work there should still prefer the generic parts over a muk-only one.

### Auto-merge

`app-auto-merge.yml` arms the merge with the automation app's token
(`AUTOMATION_APP_ID`, `AUTOMATION_APP_PRIVATE_KEY`), else with the
`AUTO_MERGE_TOKEN` PAT. It does not fall back to `GITHUB_TOKEN` unless the
caller sets `github_token_fallback: true`, because a merge made under that
token starts no workflow: `main`'s CI and any deploy on push would not run.
A repo with neither secret gets a notice and paullorber's issue keeper arms
its pull requests from the Mac instead.

### Supabase deploy

`app-supabase.yml` applies `supabase/migrations/` and then deploys
`supabase/functions/` when `main` moves. It is switched on by settings, per
repository:

- `SUPABASE_PROJECT_REF` (repository variable): the project to deploy to.
  Unset means the job reports "nothing deployed" and stays green.
- `SUPABASE_ACCESS_TOKEN` (secret): needed in `shared` mode and for edge
  functions.
- `SUPABASE_DB_URL` (secret): needed in `push` mode.

`mode: shared` is for the `paullorber` project, whose ledger holds the
migrations of paullorber, careteam, hush and fuehrerschein: each missing file
is applied in one transaction with its ledger row. Never run
`supabase migration repair --status reverted` there; it deletes the other
repos' rows. `mode: push` is for a project one repo owns (lacordobesa) and
runs `supabase db push --include-all`.

Before switching it on for a repo whose migrations were applied by hand,
compare the ledger with the files: a file with no ledger row is applied again
on the first run.

### Security gate

`security-gate.yml` is the reviewer for pull requests that merge themselves.
The caller is a `pull_request_target` workflow, so the gate that judges a PR
is the base branch's copy, not one the PR can edit; the job checks the PR
head out as data and never installs, builds or runs anything from it. It
reports a check run named `Security gate` on the PR **head** SHA through the
Checks API and one sticky PR comment. (The job's own `<caller job> /
review` check also lands on the head SHA, as measured on paullorber#475, but
require the explicit `Security gate`: its name is fixed and it carries the
verdict.)

- **Deterministic rules** (`scripts/security-gate.mjs`, tested by
  `scripts/security-gate.test.mjs` in the self-check), on the lines the PR
  adds; every finding blocks:
  - migrations: a table grant to `anon`, `authenticated` or `public`;
    `security definer` without `set search_path`; `disable row level
    security`; a policy `using (true)` / `with check (true)` for anyone but
    `service_role`;
  - workflows: `pull_request_target`, `permissions: write-all`, a `uses:` not
    pinned to a 40-hex SHA, `curl | sh`, and the forgery guard (`checks:` or
    `statuses: write`, the Checks/status API, the words "Security gate"). A
    PR tripping the forgery guard is also turned into a draft, so a forged
    green check cannot merge it. The caller file itself may change only by
    moving its pinned SHA;
  - a `"use server"` file whose exported async function never calls the
    `server-action-guard` regex (`getOwner()` by default). A deliberate
    public action takes `// security-gate: public-action <why>` above it and
    is reported, not blocked. Any `"use server"` file counts as sensitive;
  - gitleaks (pinned binary) over the PR's own commits with the job's config,
    so a PR cannot add a `.gitleaks.toml` or `.gitleaksignore`; a false
    positive takes an inline `gitleaks:allow` comment;
  - a new `package-lock.json` entry with `hasInstallScript`.
- **AI review**, only when a file matches the caller's `sensitive-paths`
  (or is a `"use server"` file), by a team of reviewers rather than one
  vendor. Every reviewer gets the same contract: the diff, the sensitive file
  list and the caller's `threat-model` in one provider-neutral prompt
  (`scripts/security-gate-prompt.md`), a copy of the head under `/tmp` with
  no `.git`, no symlinks and none of the PR's agent configuration
  (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.claude/`, `.codex/`, `.gemini/`,
  `.mcp.json`, ... — they still reach the reviewers as diff), and
  `ai-timeout-seconds` (480). It must answer exactly
  `{"verdict":"pass"|"block","findings":[{"severity","file","line","summary"}]}`;
  anything else, an error or a timeout makes that reviewer "unavailable",
  never a pass. The reviewers run in parallel; each is enabled only by its
  own credential:

  | Reviewer | Enabled by | Runs as |
  |---|---|---|
  | `claude` | secret `CLAUDE_CODE_OAUTH_TOKEN` (`claude setup-token`); model `claude-model`, or the `CLAUDE_MODEL` variable | Claude Code `claude-code-version` in `--restricted` print mode: Read, Grep and Glob only, `dontAsk`, a throwaway `HOME`, `--strict-mcp-config`, deny rules outside its working directory |
  | `codex` | secret `CODEX_API_KEY` (an OpenAI API key; `codex exec` reads it from that variable); model: the `CODEX_MODEL` variable, else Codex's default | `codex exec` `codex-version` with a throwaway `CODEX_HOME` whose `config.toml` is the only config: a permission profile that reads the system minimum and the review copy only (home folders and temp directories denied, no writes, no network), `approval_policy = "never"`, AGENTS.md not loaded, web search, apps, plugins, hooks, memories and sub-agents off, `--ignore-rules --ephemeral`, and `--output-schema` for the verdict |
  | `openai-compatible` | secret `REVIEW_API_KEY` plus the variables `REVIEW_API_BASE` (e.g. `https://generativelanguage.googleapis.com/v1beta/openai`; plain `http` only to localhost) and `REVIEW_API_MODEL` | one `POST {base}/chat/completions` from the gate script, no tools: the diff plus excerpts of the changed head files (sensitive first, 24k characters each, 120k in all) |

  The two CLIs are installed at their pinned version into a fresh directory
  of the gate's own and run by absolute path, never with `npx` in the review
  copy: npm would read that copy's `.npmrc` and prefer a
  `node_modules/.bin/claude` planted in it. The install counts against the
  reviewer's `ai-timeout-seconds`.

  **Dependencies.** The gate compares `package-lock.json` before and after
  the PR itself and tells the reviewers what it found, outside the diff:
  - a different version of a package already in the tree is routine and not
    a finding by itself (Dependabot's one-week `cooldown` in the caller's
    `.github/dependabot.yml` is what keeps a hijacked release out; a
    lockfile regenerated by hand should use `npm install --before=<date>`
    to stay inside it);
  - a package **new to the tree**, direct or transitive, is listed on every
    report (`dependency-new-package`, never blocking by itself). A reviewer
    may rate it `high` only on evidence; an install script blocks as before;
  - the repository variable `SECURITY_GATE_ACCEPTED_PACKAGES` is the owner's
    accepted list: `name` or `name@version`, separated by commas or white
    space (`gh variable set SECURITY_GATE_ACCEPTED_PACKAGES --body
    "proxy-agent-negotiate@1.1.0"`). An accepted package leaves the list of
    new ones and is marked for the reviewers. It is a variable on purpose:
    no pull request can change it, so a sentence in a diff saying the owner
    agreed carries no weight and this does.

  The repository variable `SECURITY_REVIEWERS` (e.g. `codex,claude`)
  limits and orders them; unset, every enabled one runs. The team policy:
  - **any** reviewer's `high` finding blocks; medium and low are reported.
    Prompt injection has to fool every model to get through;
  - **cross-review**: the PR's author harness is read from its commits
    (`Co-Authored-By: Claude …` or `@anthropic.com`, `Co-authored-by: Codex
    <noreply@openai.com>` or the Codex bot, Gemini's trailer or bot) and a
    `claude/`, `codex/` or `gemini/` branch prefix. When a reviewer of
    another model family is configured, at least one of them must answer, or
    the gate blocks ("cross-review-missing", re-run it); with only the
    author's family configured it passes with a visible note;
  - no reviewer configured, or every one unavailable: the deterministic
    layer decides and the comment says "AI review skipped: …".

  The sticky comment lists each reviewer with its harness, version, model,
  family, verdict and time, and tags each AI finding with the reviewer that
  raised it. Credential values are scrubbed from everything a reviewer
  returns before it is posted. Secrets reach a reusable workflow only when
  the caller passes them (`secrets:` in its `uses:` job); repository
  variables are the caller's own, as with `CI_LABELS`, and need no caller
  change.
- **Required check**: add exactly `Security gate` to the repo's ruleset with
  `integration_id` 15368 (GitHub Actions), so a commit status or another
  app's check of that name does not count. Verify it reported on a real PR
  head first: a required check that never reports stops every merge.
- **Changing the caller** beyond its SHA (permissions, triggers, inputs) is
  blocked by design. The owner does it by hand: remove `Security gate` from
  the ruleset, merge, put it back.

## Adding a repository

0. Register an `app-ci` runner for the repo on the Mac Studio (a runner
   serves one repository, so this is per repo; the tarball version is the one
   the muk instances run):

   ```sh
   repo=<name>
   mkdir ~/actions-runner-$repo && cd ~/actions-runner-$repo
   tar xzf ~/Downloads/actions-runner-osx-arm64-<version>.tar.gz
   ./config.sh --url https://github.com/paullorb/$repo \
     --token "$(gh api -X POST repos/paullorb/$repo/actions/runners/registration-token --jq .token)" \
     --name "tostinn-mac-$repo" --labels app-ci --unattended
   ./svc.sh install && ./svc.sh start
   ```

   A second instance (`~/actions-runner-$repo-2`, name suffixed `-2`) is
   only worth it for a repo whose PRs run several jobs at once.
   Then `node ~/Developer/paullorber/scripts/runner-preflight.mjs` in the
   new checkout must pass before its first workflow is pushed: it fails until
   a runner with the label is registered and online and no workflow names a
   hosted runner outside the allowlist. A repo that starts without its
   runner spends hosted minutes from its first pull request (fahren: 181 in
   its first day, 2026-11-23).
1. Point a small caller workflow in the app repo at `app-ci.yml@<SHA>`.
2. Pass the caller's Node version file when it is not `.node-version`.
3. Add the `auto-merge.yml` caller, and the `supabase.yml` caller when the
   repo has `supabase/` ("The baseline every repo shares").
4. Compose `app-vercel.yml` for isolated Vercel delivery and
   `app-native-build.yml` for Capacitor artifacts. Secrets stay in the caller
   repository and are passed explicitly.
5. Keep event and path filters in the caller. A path-scoped caller can invoke
   `app-content-check-probe.yml`; its `expected_repository` guard prevents an
   accidental cross-project invocation.
6. Migration replays support two optional per-repo files:
   `scripts/ci-db-shim.sql` (objects that predate the migrations) and
   `scripts/ci-db-replay-skip.txt` (files recorded in a shared ledger but
   owned by another repo).

## Updating

1. Change and validate the reusable workflow here.
2. Commit and push it.
3. Update the pinned SHA in the corresponding caller workflow(s).
4. Open a pull request in the caller repo and verify the real called jobs
   before merging.

Deploy jobs remain ordered inside `muk-ci.yml`: quality, rules, migration
replay, and Playwright must pass before migrations deploy, followed by edge
functions. The three main-only deploy jobs name a caller environment
(`production-backend`, `Production`) with `deployment: false`, so deploy-only
secrets can move from the caller's repository store into an environment
restricted to `main`; until they do, the job reads the secret the caller
passes, as before.
The same holds for three jobs that run on a schedule: `quota` in
`muk-scheduled-checks.yml` names `Production` (the Vercel token and team id),
and `sweep` there and the job in `muk-browser-matrix.yml` name
`production-backend`, because they write to the database and must keep the
owner connection string when the caller's repo-level one becomes read-only.

Every job's `timeout-minutes` stays at or under 60
(`scripts/check-workflows.mjs`): muk.events' stuck-run reaper cancels any job
running past 75 minutes, and pins that threshold from its side.

## Operator scripts

`scripts/rotate-keys.py` rotates the Supabase secret keys and `MUK_CRON_SECRET`
across muk.events and paullorber in one pass (Vercel envs, redeploy, webhook
row, live probe). It lives here because it spans both repos; run it by hand
with `python3 scripts/rotate-keys.py`, then `--prune-paullorber` once the old
Preview deployments are rebuilt. It prints and stores no secrets.
