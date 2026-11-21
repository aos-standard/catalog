import json, subprocess, sys, datetime
ME = "Tetsurohhori"
def gh(*a):
    r = subprocess.run(["gh", "api", *a], capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else None
rows = []
for line in open(__import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "status_threads.txt")):
    run, repo, num = line.split()
    iss = gh(f"repos/{repo}/issues/{num}")
    if iss is None:
        rows.append({"run": run, "repo": repo, "num": num, "error": True}); continue
    is_pr = "pull_request" in iss
    merged = None
    if is_pr:
        pr = gh(f"repos/{repo}/pulls/{num}")
        merged = bool(pr and pr.get("merged_at"))
    comments = gh(f"repos/{repo}/issues/{num}/comments?per_page=100", "--paginate") or []
    mine = [c["created_at"] for c in comments if c["user"]["login"] == ME]
    last_mine = max(mine) if mine else None
    others_after = [c for c in comments if last_mine and c["created_at"] > last_mine and c["user"]["login"] != ME and not c["user"]["login"].endswith("[bot]") and c["user"]["type"] != "Bot"]
    rows.append({"run": run, "repo": repo, "num": int(num), "kind": "PR" if is_pr else "issue", "state": iss["state"],
                 "merged": merged, "closed_at": iss.get("closed_at"), "my_comments": len(mine), "last_mine": last_mine,
                 "others_after_my_last": len(others_after), "last_other_after": max((c["created_at"] for c in others_after), default=None)})
    print(rows[-1])
json.dump({"measured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "rows": rows}, open(sys.argv[1] if len(sys.argv) > 1 else "STATUS.json", "w"), indent=1)
