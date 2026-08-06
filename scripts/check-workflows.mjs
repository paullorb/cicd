import { createRequire } from "node:module";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

// The self-check for this repo's reusable workflows, run by
// .github/workflows/self-check.yml. This repository has no application code
// and therefore no test suite, but its workflows ARE the product for every
// repo that calls them: an invalid one aborts with no jobs, no logs and a
// misleading event, which is exactly the failure a consumer cannot diagnose.
//
// It asserts four things:
//   1. Every workflow file parses as YAML and declares `on` and `jobs`.
//   2. Every job that is not a pure `uses:` caller declares runs-on, steps and
//      an explicit timeout — an untimed job on the self-hosted pool holds one
//      of the machine's few slots for six hours.
//   3. Every such job writes a "What this job is for" block to the run
//      summary. The owner reads run summaries, not YAML comments, and a job
//      that cannot say why it exists and what its red means is a check nobody
//      can act on. New jobs must carry one from the start, which is why this
//      is enforced rather than left to review.
//   4. Every action reference is pinned to a full 40-hex commit SHA — a
//      mutable tag on a privileged pipeline is somebody else's write access.
//
// The app-*.yml workflows serve a different project (paullorber) and are
// exempt from rule 3 only: their summaries are that project's call to make.
// Rules 1, 2 and 4 apply to every file here.

const WORKFLOW_DIR = ".github/workflows";
const SUMMARY_EXEMPT = /^app-/;

export function jobProblems(file, name, job, { requireSummary }) {
  const problems = [];
  if (job.uses) return problems; // a caller job delegates everything

  if (!job["runs-on"]) problems.push(`${file}: job "${name}" has no runs-on`);
  if (!Array.isArray(job.steps) || job.steps.length === 0) {
    problems.push(`${file}: job "${name}" has no steps`);
    return problems;
  }
  if (job["timeout-minutes"] === undefined) {
    problems.push(
      `${file}: job "${name}" has no timeout-minutes — a hung job holds a self-hosted slot for six hours`,
    );
  }
  if (
    requireSummary &&
    !job.steps.some((step) => String(step?.run ?? "").includes("GITHUB_STEP_SUMMARY"))
  ) {
    problems.push(
      `${file}: job "${name}" writes nothing to $GITHUB_STEP_SUMMARY — add a "What this job is for" step saying why the job exists and what green and red mean`,
    );
  }
  return problems;
}

export function pinProblems(file, source) {
  const problems = [];
  const uses = /^\s*(?:-\s*)?uses:\s*(\S+)/gm;
  for (const [, ref] of source.matchAll(uses)) {
    if (ref.startsWith("./")) continue; // local composite action
    if (!/@[0-9a-f]{40}$/.test(ref)) {
      problems.push(`${file}: "${ref}" is not pinned to a full 40-character commit SHA`);
    }
  }
  return problems;
}

export function checkWorkflows(dir, readFile, listFiles, parseYaml) {
  const files = listFiles(dir).filter((file) => /\.ya?ml$/.test(file));
  if (files.length === 0) return [`${dir} contains no workflow files`];

  const problems = [];
  for (const file of files) {
    const source = readFile(join(dir, file));
    let doc;
    try {
      doc = parseYaml(source);
    } catch (error) {
      problems.push(`${file}: is not valid YAML — ${error.message}`);
      continue;
    }
    // js-yaml resolves the bare key `on` to boolean true (YAML 1.1).
    if (doc?.on === undefined && doc?.true === undefined) {
      problems.push(`${file}: declares no triggers (on:)`);
    }
    const jobs = doc?.jobs ?? {};
    if (Object.keys(jobs).length === 0) {
      problems.push(`${file}: declares no jobs`);
      continue;
    }
    const requireSummary = !SUMMARY_EXEMPT.test(file);
    for (const [name, job] of Object.entries(jobs)) {
      problems.push(...jobProblems(file, name, job ?? {}, { requireSummary }));
    }
    problems.push(...pinProblems(file, source));
  }
  return problems;
}

function loadYaml() {
  // js-yaml is pinned EXACTLY in package.json and locked with an integrity
  // hash, and CI installs it with `npm ci --ignore-scripts`. It used to be
  // fetched on demand with `npm install js-yaml@5`, which was wrong twice
  // over: an unlocked major resolves to whatever is newest at run time, so a
  // broken upstream release fails commits that changed nothing, and without
  // --ignore-scripts a compromised package (or any of its transitive deps)
  // would run lifecycle scripts on a runner that already holds the checkout
  // and the job token. A security check must not be the least careful
  // installer in the pipeline.
  const require = createRequire(import.meta.url);
  try {
    return require("js-yaml").load;
  } catch {
    throw new Error(
      "js-yaml is not installed — run `npm ci --ignore-scripts` in this repo first.",
    );
  }
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) {
  const parseYaml = loadYaml();
  const problems = checkWorkflows(
    WORKFLOW_DIR,
    (path) => readFileSync(path, "utf8"),
    (dir) => readdirSync(dir),
    parseYaml,
  );
  if (problems.length === 0) {
    process.stdout.write("Every workflow parses, is timed, is SHA-pinned and explains itself.\n");
  } else {
    for (const problem of problems) process.stderr.write(`${problem}\n`);
    process.stderr.write(`\n${problems.length} workflow problem(s).\n`);
    process.exitCode = 1;
  }
}
