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

`app-ci.yml` is the generic entry point for a Next.js app with Supabase
migrations (lint, audit, build, migration replay; no secrets). New repos
should start there and only get a bespoke workflow when they outgrow it.

The small caller workflows remain in each application repository because
GitHub events and schedules belong to the caller. `actions/checkout` inside a
reusable workflow checks out the caller repository, not this one.

## Runner model

Two pools, chosen per caller repository via a repository variable so routing
can be flipped without a commit:

- **muk.events** uses `MUK_CI_LABELS`, normally `["self-hosted","muk-ci"]` —
  the three repository-level runners on the Mac Studio.
  `muk-runner-watchdog.yml` flips the variable to `["ubuntu-latest"]` when no
  runner is online, and back.
- **Every other repo** uses `CI_LABELS`, defaulting to `["ubuntu-latest"]`.
  Repository-level runners on a personal account serve exactly one
  repository, so the muk-ci pool is not reachable from other repos — and
  their volume is fine on hosted minutes.

Concurrent PRs from several repos are safe by construction: hosted jobs get
fresh VMs, muk jobs queue on the 3-slot pool, migration-replay scratch
databases are named by run id, and repo-scoped concurrency groups (e.g. muk's
`e2e-prod`) never cross repositories.

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

## Adding a repository

1. Point a small caller workflow in the app repo at `app-ci.yml@<SHA>`.
2. If the app needs env/secrets in CI, add `workflow_call` inputs/secrets to
   `app-ci.yml` (or give the repo its own `<repo>-ci.yml`) — don't grow
   implicit environment assumptions.
3. Migration replays support two optional per-repo files:
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
functions.
