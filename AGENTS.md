# cicd

Private reusable GitHub Actions workflows serving every paullorb repository.
This repo owns orchestration only; each app repo owns its tests, scripts and
product code, pins this repo to an exact commit SHA, and passes only the
secrets its workflow needs. The README is the reference.

- `app-ci.yml` is the onboarding path for a new repo; a bespoke product
  workflow is the exception. Prefer repo-neutral names, labels and capacity:
  nothing new is muk-only without flagging the tradeoff.
- Changing a reusable workflow is two PRs: this one, then the caller's SHA
  bump, verified against the real called jobs before it merges.
- A runner is work-conserving, never capped per repo; idle runners are waste.

## Working as an agent here — the same in every paullorb repo

- **Keep the context small.** Hand off to a fresh session once the context
  passes about 200k tokens; never open a 1M-window session for routine work.
  A turn at 500k costs five times a turn at 100k even when it is all cache
  reads (the 2026-10-07 cross-project token audit).
- **Sweep with a subagent, not from the main context.** A `grep`/`sed`/`cat`
  pass over the tree belongs in an Explore subagent that returns the
  conclusion; read a file yourself only when you are about to edit it.
- **Routine work runs on Sonnet.** Red PRs, Dependabot follow-ups, gate
  re-runs and canary triage do not need the most expensive model.
- **Work in a worktree, never the primary checkout**
  (`.claude/hooks/primary-checkout-guard.sh` refuses the edit). The session
  starts by listing the repo's red PRs (`.claude/hooks/red-prs.sh`); your own
  red PR comes before new work.
- **Report the verdict, not the mechanics**: "CI passed" is the whole report.
  Wait for an outcome once, do not poll for it.
- **Every change goes through a PR into `main` with auto-merge armed**; never
  merge by hand.
