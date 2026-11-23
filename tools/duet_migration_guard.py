#!/usr/bin/env python3
"""Migration guard (planning prototype, v1.1, 2026-11-23; v1.1 skips its own governance files).

Static checks only. It never imports, executes or connects to anything in the tree it checks,
and it never runs a migration. Designed to run in CI from the protected base branch, reading the
pull-request tree as data.

  build  --tree BASELINE --out INVENTORY.json
  check  --tree CANDIDATE --inventory INVENTORY.json --auth AUTH.json --out RESULT.json

Guards
  G1  every file in migrations/versions matches its baseline SHA-256; the pinned revision must be present and
      unchanged; a new or removed migration file fails unless AUTH lists it with its hash.
  G2  revision graph parsed with ast (no import): one head, no branches, no missing parents.
      Reports the graph head and the highest authorized target separately.
  G3  upgrade invocations in executable files (outside migrations/versions): a site that is not
      in the baseline inventory fails when it has no target, head/heads, a relative or variable
      target, or a target (or prefix) that resolves beyond AUTH's authorized targets. A changed
      file that held baseline sites fails.
  G4  workflow files: a new or changed file under .github/workflows fails unless AUTH lists
      its hash; baseline workflows that run upgrades are reported as must-be-disabled.
  G5  AUTH must come from the base branch: a candidate that changes the authorization file is
      reported, and fails if it changes anything else in the same pull request.
Exit 0 = pass, 1 = fail, 2 = usage or internal error.
"""
import argparse, ast, hashlib, json, os, re, sys

MIG_DIR = "migrations/versions"
AUTH_PATH = "governance/migration_authorization.json"
INVENTORY_PATH = "governance/baseline_inventory.json"
EXEC_EXT = {".py", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".yml", ".yaml", ".toml", ".cfg",
            ".ini", ".json", ".mk"}
EXEC_NAMES = {"Procfile", "Dockerfile", "Makefile", "Justfile"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}

PATTERNS = [
    ("shell", re.compile(r"\bflask\s+db\s+upgrade\b(?:[ \t]+(?!&|\||;|#)([^\s;&|#]+))?")),
    ("shell", re.compile(r"\balembic\b(?:\s+-[cxn]\s+\S+)*\s+upgrade\b(?:[ \t]+(?!&|\||;|#)([^\s;&|#]+))?")),
    ("argv", re.compile(r"""["']db["']\s*,\s*["']upgrade["']\s*(?:,\s*([^\]\),]+))?""")),
    ("argv", re.compile(r"""\[\s*["']upgrade["']\s*(?:,\s*([^\]\),]+))?""")),
    ("api", re.compile(r"\bcommand\.upgrade\(\s*[^,()]+(?:\([^)]*\))?\s*,\s*([^,)]+)")),
    ("api", re.compile(r"\b(?:flask_migrate|migrate)\.upgrade\(\s*([^)]*)\)")),
]
FROM_IMPORT_UPGRADE = re.compile(r"from\s+flask_migrate\s+import\s+[^\n]*\bupgrade\b")
BARE_UPGRADE_CALL = re.compile(r"(?<![\w.])upgrade\(\s*([^)]*)\)")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def walk(tree):
    for root, dirs, files in os.walk(tree):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            full = os.path.join(root, name)
            if os.path.islink(full):
                continue
            yield os.path.relpath(full, tree).replace(os.sep, "/"), full


def is_exec(rel):
    base = rel.rsplit("/", 1)[-1]
    if rel.startswith(MIG_DIR + "/") or rel in (AUTH_PATH, INVENTORY_PATH):
        return False
    if base in EXEC_NAMES or base.startswith("Dockerfile") or base.startswith("docker-compose"):
        return True
    return os.path.splitext(base)[1].lower() in EXEC_EXT


def parse_revision(path):
    """Read revision and down_revision by ast; never import or execute the file."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        tree = ast.parse(f.read(), filename=path)
    out = {}
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets, value = [node.target.id], node.value
        for t in targets:
            if t in ("revision", "down_revision"):
                try:
                    out[t] = ast.literal_eval(value)
                except Exception:
                    out[t] = "<non-literal>"
    return out.get("revision"), out.get("down_revision")


def graph(tree):
    revs, errors = {}, []
    mdir = os.path.join(tree, MIG_DIR)
    for name in sorted(os.listdir(mdir)) if os.path.isdir(mdir) else []:
        if not name.endswith(".py") or name.startswith("__"):
            continue
        try:
            rev, down = parse_revision(os.path.join(mdir, name))
        except SyntaxError as e:
            errors.append(f"{name}: syntax error {e.lineno}")
            continue
        if not isinstance(rev, str):
            errors.append(f"{name}: revision is not a literal string")
            continue
        if rev in revs:
            errors.append(f"duplicate revision {rev}")
        revs[rev] = {"file": name, "down": down}
    parents = set()
    for rev, info in revs.items():
        downs = info["down"] if isinstance(info["down"], (list, tuple)) else [info["down"]]
        for d in downs:
            if d is None:
                continue
            if not isinstance(d, str):
                errors.append(f"{rev}: down_revision is not a literal")
            elif d not in revs:
                errors.append(f"{rev}: parent {d} missing")
            parents.add(d)
        if isinstance(info["down"], (list, tuple)) and len(info["down"]) > 1:
            errors.append(f"{rev}: merge revision")
    heads = sorted(r for r in revs if r not in parents)
    roots = sorted(r for r, i in revs.items() if i["down"] is None)
    order, cur = [], (heads[0] if len(heads) == 1 else None)
    while cur:
        order.append(cur)
        d = revs[cur]["down"]
        cur = d if isinstance(d, str) and d in revs else None
    order.reverse()
    return {"revisions": revs, "heads": heads, "roots": roots, "linear_order": order,
            "errors": errors}


def classify(raw, order, allowed):
    if raw is None or raw.strip() in ("", ")"):
        return "no_target", None
    t = raw.strip().strip("\"'` ").rstrip(",")
    kw = {}
    m = re.match(r"(?:revision|target)\s*=\s*(.+)", t)
    if m:
        t = m.group(1).strip().strip("\"'")
    if t in ("head", "heads", "@head") or t.endswith("@head") or t.endswith("@heads"):
        return "head", t
    if re.match(r"^[+-]\d+$", t) or "+" in t or t.startswith("-"):
        return "relative", t
    if not re.match(r"^[A-Za-z0-9_]+$", t) or re.match(r"^[a-z_][a-z0-9_]*$", t) and not any(
            r.startswith(t) for r in order):
        return "variable_or_unknown", t
    matches = [r for r in order if r.startswith(t)]
    if not matches:
        return "unknown_revision", t
    if len(matches) > 1:
        return "ambiguous_prefix", t
    return ("authorized_target" if matches[0] in allowed else "unauthorized_target"), matches[0]


def scan_sites(tree, rel, full, order, allowed):
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return []
    sites = []
    lines = text.splitlines()
    imports_upgrade = bool(FROM_IMPORT_UPGRADE.search(text)) and rel.endswith(".py")
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        pats = list(PATTERNS)
        if imports_upgrade and not stripped.startswith("def "):
            pats.append(("api", BARE_UPGRADE_CALL))
        seen = set()
        for kind, pat in pats:
            for m in pat.finditer(line):
                if m.start() in seen:
                    continue
                seen.add(m.start())
                raw = m.group(1) if m.lastindex else None
                cls, tgt = classify(raw, order, allowed)
                sites.append({"path": rel, "line": i, "kind": kind,
                              "text": re.sub(r"\s+", " ", m.group(0)).strip()[:160],
                              "class": cls, "target": tgt})
    return sites


def build(tree, out):
    g = graph(tree)
    allowed = set()
    mig = {}
    for rel, full in walk(tree):
        if rel.startswith(MIG_DIR + "/"):
            mig[rel] = sha(full)
    sites, site_files, workflows = [], {}, {}
    order = g["linear_order"]
    for rel, full in walk(tree):
        if rel.startswith(".github/workflows/"):
            workflows[rel] = sha(full)
        if is_exec(rel):
            s = scan_sites(tree, rel, full, order, allowed)
            if s:
                site_files[rel] = sha(full)
                sites.extend(s)
    inv = {"schema": "duet-migration-inventory-v1", "migration_files": mig, "graph": {
        "heads": g["heads"], "roots": g["roots"], "linear_order": order, "errors": g["errors"]},
        "baseline_upgrade_site_files": site_files, "baseline_upgrade_sites": sites,
        "baseline_workflows": workflows,
        "baseline_workflows_running_upgrades": sorted({s["path"] for s in sites
                                                        if s["path"].startswith(".github/workflows/")})}
    with open(out, "w") as f:
        json.dump(inv, f, indent=1, sort_keys=True)
    return inv


def check(tree, inv, auth, base_auth_sha=None):
    findings = []

    def fail(guard, code, detail):
        findings.append({"guard": guard, "result": "FAIL", "code": code, "detail": detail})

    def note(guard, code, detail):
        findings.append({"guard": guard, "result": "INFO", "code": code, "detail": detail})

    allowed_targets = set(auth.get("authorized_targets", []))
    allowed_new_migs = auth.get("authorized_new_migration_files", {})
    allowed_wf = auth.get("authorized_workflow_hashes", {})
    pinned = auth.get("pinned_unauthorized_revisions", [])

    # G1
    cur_mig = {rel: sha(full) for rel, full in walk(tree) if rel.startswith(MIG_DIR + "/")}
    for rel, h in inv["migration_files"].items():
        if rel not in cur_mig:
            fail("G1", "baseline_migration_removed", rel)
        elif cur_mig[rel] != h:
            fail("G1", "baseline_migration_modified", rel)
    for rel, h in cur_mig.items():
        if rel not in inv["migration_files"]:
            if allowed_new_migs.get(rel) == h:
                note("G1", "authorized_new_migration", rel)
            else:
                fail("G1", "unauthorized_new_migration_file", rel)
    for p in pinned:
        hit = [r for r in inv["migration_files"] if p in r]
        if hit and all(r in cur_mig and cur_mig[r] == inv["migration_files"][r] for r in hit):
            note("G1", "pinned_revision_preserved", p)

    # G2
    g = graph(tree)
    for e in g["errors"]:
        fail("G2", "graph_error", e)
    if len(g["heads"]) != 1:
        fail("G2", "multiple_or_no_heads", g["heads"])
    order = g["linear_order"]
    allowed = set()
    for t in allowed_targets:
        if t in order:
            allowed.update(order[:order.index(t) + 1])
        else:
            fail("G2", "authorized_target_not_in_graph", t)
    for p in pinned:
        for r in sorted(allowed):
            if r.startswith(p):
                fail("G2", "authorized_target_implies_pinned_revision",
                     {"pinned": r, "reason": "a target at or above it would apply it"})
    head = g["heads"][0] if len(g["heads"]) == 1 else None
    if head and head not in allowed:
        note("G2", "graph_head_not_authorized_as_target", head)
    if head and head not in inv["graph"]["heads"] and head not in allowed:
        fail("G2", "new_unauthorized_head", head)

    # G3
    base_sites = {}
    for s in inv["baseline_upgrade_sites"]:
        base_sites.setdefault(s["path"], set()).add((s["text"], s["class"] if s["class"] not in (
            "authorized_target", "unauthorized_target") else "explicit"))
    bad = ("no_target", "head", "relative", "variable_or_unknown", "unknown_revision",
           "ambiguous_prefix", "unauthorized_target")
    known_count = 0
    for rel, full in walk(tree):
        if not is_exec(rel):
            continue
        h = sha(full)
        if rel in inv["baseline_upgrade_site_files"]:
            if h == inv["baseline_upgrade_site_files"][rel]:
                known_count += 1
                continue
            fail("G3", "baseline_upgrade_site_file_modified", rel)
        for s in scan_sites(tree, rel, full, order, allowed):
            key_cls = s["class"] if s["class"] not in ("authorized_target", "unauthorized_target") else "explicit"
            known = (s["text"], key_cls) in base_sites.get(rel, set())
            if s["class"] in bad and not known:
                fail("G3", "unauthorized_upgrade_invocation",
                     {k: s[k] for k in ("path", "line", "text", "class", "target")})
            elif s["class"] == "authorized_target":
                note("G3", "authorized_target_invocation",
                     {k: s[k] for k in ("path", "line", "text", "target")})
    note("G3", "baseline_known_site_files_unchanged", known_count)

    # G4
    for rel, full in walk(tree):
        if not rel.startswith(".github/workflows/"):
            continue
        h = sha(full)
        if inv["baseline_workflows"].get(rel) == h:
            if rel in inv["baseline_workflows_running_upgrades"]:
                note("G4", "baseline_workflow_runs_upgrade_must_be_disabled", rel)
            continue
        if allowed_wf.get(rel) == h:
            note("G4", "authorized_workflow", rel)
        else:
            fail("G4", "unauthorized_workflow_change", rel)
    for rel in inv["baseline_workflows"]:
        if not os.path.exists(os.path.join(tree, rel)):
            note("G4", "baseline_workflow_removed", rel)

    # G5
    ap = os.path.join(tree, AUTH_PATH)
    if os.path.exists(ap) and base_auth_sha and sha(ap) != base_auth_sha:
        note("G5", "authorization_file_changed_in_candidate",
             "candidate copy ignored; base-branch copy used")

    failed = [f for f in findings if f["result"] == "FAIL"]
    return {"schema": "duet-migration-guard-result-v1", "pass": not failed,
            "fail_count": len(failed), "graph_head": head,
            "authorized_targets": sorted(allowed_targets), "findings": findings}


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build"); b.add_argument("--tree", required=True); b.add_argument("--out", required=True)
    c = sub.add_parser("check")
    for a in ("--tree", "--inventory", "--auth", "--out"):
        c.add_argument(a, required=True)
    c.add_argument("--base-auth-sha")
    c.add_argument("--changed-files", help="file listing paths changed in the PR (for G5)")
    args = ap.parse_args()
    if args.cmd == "build":
        inv = build(args.tree, args.out)
        print(json.dumps({"migration_files": len(inv["migration_files"]),
                          "heads": inv["graph"]["heads"],
                          "site_files": len(inv["baseline_upgrade_site_files"]),
                          "sites": len(inv["baseline_upgrade_sites"])}))
        return 0
    with open(args.inventory) as f:
        inv = json.load(f)
    with open(args.auth) as f:
        auth = json.load(f)
    res = check(args.tree, inv, auth, args.base_auth_sha)
    if args.changed_files:
        with open(args.changed_files) as f:
            changed = [l.strip() for l in f if l.strip()]
        if AUTH_PATH in changed and len(changed) > 1:
            res["findings"].append({"guard": "G5", "result": "FAIL",
                                    "code": "authorization_change_mixed_with_other_changes",
                                    "detail": len(changed)})
            res["pass"] = False
            res["fail_count"] += 1
    with open(args.out, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print(json.dumps({"pass": res["pass"], "fail_count": res["fail_count"],
                      "codes": sorted({x["code"] for x in res["findings"] if x["result"] == "FAIL"})}))
    return 0 if res["pass"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        print(f"guard internal error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
