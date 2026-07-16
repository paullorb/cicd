# muk.events CI/CD

Private reusable GitHub Actions workflows for
[`paullorb/muk.events`](https://github.com/paullorb/muk.events).

This repository is intentionally project-specific. It owns orchestration only;
the application repository continues to own its tests, scripts, Lighthouse
configuration, Playwright configuration, migrations, and product code.

## Workflows

| Workflow | Caller trigger |
|---|---|
| `ci.yml` | pull requests and pushes to `muk.events/main` |
| `lighthouse.yml` | pull requests and pushes to `muk.events/main` |
| `browser-matrix.yml` | weekly and manual |
| `scheduled-checks.yml` | daily and manual |
| `sync-events.yml` | hourly and manual |
| `runner-watchdog.yml` | every six hours and manual |

The small caller workflows remain in `muk.events/.github/workflows` because
GitHub events and schedules belong to the application repository. Each caller
pins this repository to an exact commit SHA and passes only its required
secrets. `actions/checkout` inside a reusable workflow checks out `muk.events`,
not this repository.

## Runner model

Jobs use the caller repository's `MUK_CI_LABELS` variable, normally
`["self-hosted","muk-ci"]`. The three repository-level runners remain attached
to `muk.events`; reusable workflows owned by the same account can use runners
available to their caller.

Ports are fixed for this project:

- `3000`: interactive Codex, Claude, or human development
- `3100`: Playwright CI
- `3200`: Lighthouse CI

Do not enable GitHub's remote npm cache on these persistent runners. The local
`~/.npm` cache survives jobs; the former Actions cache restored a 1.4 GB archive
in every cache-enabled job.

## Updating

1. Change and validate the reusable workflow here.
2. Commit and push it.
3. Update the pinned SHA in the corresponding `muk.events` caller.
4. Open a `muk.events` pull request and verify the real called jobs before
   merging.

Deploy jobs remain ordered inside `ci.yml`: quality, rules, and Playwright must
pass before migrations, followed by edge functions.
