"""One-shot rotation of the Vercel secrets flagged "readable-secret".

    python3 scripts/rotate-keys.py   (from a cicd checkout; paths below are absolute)

1. New Supabase secret key per project -> Vercel as Sensitive
   (muk-events Production; paullorber Preview + Production + Development).
2. New MUK_CRON_SECRET -> Vercel as Sensitive.
3. Redeploy the current production deployment of both projects and wait.
4. Only if muk-events redeployed: write the cron secret into muk_private.system_webhooks.
5. Probe the release-reminder endpoint with {"events":[]} (rejected before any send):
   400 "No events" == live end to end.
6. Delete Supabase secret keys from earlier runs of this script (name prefix "rot_").
Nothing secret is printed or written to disk.
"""
import datetime, json, os, secrets, subprocess, sys, urllib.request, urllib.error

TEAM = "team_pf3Bww94XHZFleIsXXb8blP1"
VAUTH = json.load(open(os.path.expanduser("~/Library/Application Support/com.vercel.cli/auth.json")))["token"]
SBT = subprocess.check_output(["security", "find-generic-password", "-s", "Supabase CLI", "-w"]).decode().strip()
STAMP = datetime.date.today().strftime("%Y%m%d")
MUK = dict(ref="vffbfrwsfcauyambjimv", project="muk-events", dir=os.path.expanduser("~/Documents/GitHub/muk.events"))
PL = dict(ref="assoslkdxmcelmohlxwb", project="paullorber", dir=os.path.expanduser("~/Documents/GitHub/paullorber"))


def call(url, tok, method="GET", body=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            p = r.read(); return r.status, (p.decode() if raw else json.loads(p or b"{}"))
    except urllib.error.HTTPError as e:
        p = e.read(); return e.code, (p.decode() if raw else json.loads(p or b"{}"))


def vercel_set(project, key, value, target, vtype):
    """Delete every existing variable named `key` for exactly this target, then create it as `vtype`."""
    _, envs = call(f"https://api.vercel.com/v9/projects/{project}/env?teamId={TEAM}", VAUTH)
    for e in envs.get("envs", []):
        if e["key"] == key and e["target"] == [target]:
            st, _ = call(f"https://api.vercel.com/v9/projects/{project}/env/{e['id']}?teamId={TEAM}", VAUTH, "DELETE")
            print(f"  delete {project} {key} {target} -> {st}")
    st, res = call(f"https://api.vercel.com/v10/projects/{project}/env?teamId={TEAM}", VAUTH, "POST",
                   {"key": key, "value": value, "type": vtype, "target": [target]})
    ok = st in (200, 201)
    print(f"  create {project} {key} {target} ({vtype}) -> {st}", "" if ok else json.dumps(res)[:200])
    return ok


def sb_new_secret(ref, name):
    st, res = call(f"https://api.supabase.com/v1/projects/{ref}/api-keys?reveal=true", SBT, "POST",
                   {"type": "secret", "name": name, "description": f"Vercel, rotated {STAMP} by rotate-keys.py"})
    print(f"  supabase new secret key '{name}' -> {st}", "" if st in (200, 201) else json.dumps(res)[:300])
    return res.get("api_key")


def sb_delete_old_secrets(ref, keep_name):
    _, keys = call(f"https://api.supabase.com/v1/projects/{ref}/api-keys?reveal=false", SBT)
    for k in keys:
        if k.get("type") == "secret" and k["name"].startswith("rot_") and k["name"] != keep_name:
            st, _ = call(f"https://api.supabase.com/v1/projects/{ref}/api-keys/{k['id']}", SBT, "DELETE")
            print(f"  delete old supabase key '{k['name']}' -> {st}")


def redeploy(p):
    st, res = call(f"https://api.vercel.com/v6/deployments?teamId={TEAM}&app={p['project']}&target=production&state=READY&limit=1", VAUTH)
    deps = res.get("deployments", [])
    if not deps:
        print(f"== redeploy {p['project']}: no READY production deployment found ({st})"); return False
    url = "https://" + deps[0]["url"]
    print(f"== redeploy {p['project']} ({url})")
    r = subprocess.run(["vercel", "redeploy", url], cwd=p["dir"])
    print(f"  vercel redeploy exit code {r.returncode}")
    return r.returncode == 0


name = f"rot_{STAMP}"
print("== muk-events SUPABASE_SERVICE_ROLE_KEY")
k = sb_new_secret(MUK["ref"], name)
muk_srk_ok = bool(k) and vercel_set("muk-events", "SUPABASE_SERVICE_ROLE_KEY", k, "production", "sensitive")

print("== paullorber SUPABASE_SERVICE_ROLE_KEY (all targets)")
k = sb_new_secret(PL["ref"], name)
pl_srk_ok = bool(k) and all([
    vercel_set("paullorber", "SUPABASE_SERVICE_ROLE_KEY", k, "preview", "sensitive"),
    vercel_set("paullorber", "SUPABASE_SERVICE_ROLE_KEY", k, "production", "sensitive"),
    vercel_set("paullorber", "SUPABASE_SERVICE_ROLE_KEY", k, "development", "encrypted"),
])

print("== muk-events MUK_CRON_SECRET (Vercel side)")
new_cron = secrets.token_hex(32)
cron_ok = vercel_set("muk-events", "MUK_CRON_SECRET", new_cron, "production", "sensitive")

muk_deployed = redeploy(MUK)
pl_deployed = redeploy(PL)

if cron_ok and muk_deployed:
    print("== muk_private.system_webhooks")
    st, res = call(f"https://api.supabase.com/v1/projects/{MUK['ref']}/database/query", SBT, "POST", {
        "query": f"update muk_private.system_webhooks set secret='{new_cron}', updated_at=now(); "
                 f"select count(*) as rows_on_new_secret from muk_private.system_webhooks where secret='{new_cron}';"})
    print("  updated ->", st, json.dumps(res)[:200])
    print("== probe https://app.muk.events/api/cron/release-reminder")
    st, body = call("https://app.muk.events/api/cron/release-reminder", new_cron, "POST", {"events": []}, raw=True)
    print(f"  {st} {body[:120]}  ({'OK: new cron secret is live' if st == 400 else 'NOT OK: expected 400'})")
else:
    print("!! Skipped the webhook update: Vercel write or muk-events redeploy failed. Crons keep using the old")
    print("!! secret against the old deployment. Fix the failure and simply re-run this script.")
    sys.exit(1)

if muk_srk_ok and muk_deployed:
    sb_delete_old_secrets(MUK["ref"], name)
if pl_srk_ok and pl_deployed:
    sb_delete_old_secrets(PL["ref"], name)
print("== done")
