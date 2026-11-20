#!/usr/bin/env python3
"""
db_rce_check.py
Vairav Technology CSOC - "Narrow Grants, Wide Engines" database RCE exposure check
(PostgreSQL CVE-2026-116331, MySQL CVE-2026-101786, Oracle Text CVE-2026-114819,
 Oracle REST Data Services CVE-2026-91609, ClickHouse - no CVE / no confirmed fix)

Read-only. Never sends exploit traffic. Host checks need no database login. Optional --sql runs
read-only catalog SELECTs (credentials come from your normal client config / environment).

Per host it checks:
  1. Engine versions vs fixed releases / affected ranges (PostgreSQL, MySQL, Oracle DB, ORDS, ClickHouse)
  2. Distro backport evidence for PostgreSQL (package changelog names the CVE) and stale running binaries
  3. Which database ports listen on non-loopback addresses
  4. Optional --sql: accounts with TEMPORARY / CREATE TEMPORARY TABLES rights, PostgreSQL user aggregates
     with a sort operator, ClickHouse setting constraints
  5. Optional --hunt: crash / SORTOP / setting-change messages in local logs and DB services that spawned shells

Exit codes: 0 no finding | 1 vulnerable, unsupported or restart required | 2 review / hardening gaps | 3 no database found
Usage: sudo python3 db_rce_check.py [--sql] [--hunt] [--json] [--no-color]
           [--oracle-version 19.29] [--ords-version 25.1.0] [--ords-url https://host/ords/]
           [--pg-host H --pg-port P --pg-user U] [--mysql-defaults-file F]
"""
import argparse, glob, gzip, json, os, re, shutil, socket, ssl, subprocess, sys, time, urllib.request

PG_FIXED = {14: 25, 15: 20, 16: 16, 17: 12, 18: 7}
CVE_PG = "CVE-2026-116331"
USE_COLOR = sys.stdout.isatty()


def c(t, code): return f"\033[{code}m{t}\033[0m" if USE_COLOR else t
G = lambda t: c(t, "32"); Y = lambda t: c(t, "33"); R = lambda t: c(t, "31;1"); CY = lambda t: c(t, "36")


def run(cmd, timeout=40, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 127, str(e)


def vt(text, pat=r"(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?"):
    m = re.search(pat, text)
    return tuple(int(x) for x in m.groups() if x is not None) if m else None


def uniq_exec(cands):
    seen = {}
    for p in cands:
        if p and os.path.isfile(p) and os.access(p, os.X_OK): seen[os.path.realpath(p)] = p
    return list(seen)


def proc_exes(name):
    out = []
    for e in glob.glob("/proc/[0-9]*/exe"):
        try:
            t = os.readlink(e).replace(" (deleted)", "")
            if os.path.basename(t) == name: out.append(t)
        except OSError: pass
    return out


def changelog_has(binpath, cve):
    if shutil.which("dpkg"):
        rc, o = run(["dpkg", "-S", binpath])
        if rc == 0:
            pkg = o.split(":")[0].strip()
            for fn in glob.glob(f"/usr/share/doc/{pkg}/changelog*"):
                try:
                    d = (gzip.open(fn, "rt", errors="ignore") if fn.endswith(".gz") else open(fn, errors="ignore")).read()
                    if cve in d: return True
                except OSError: pass
    if shutil.which("rpm"):
        rc, o = run(["rpm", "-qf", binpath])
        if rc == 0 and cve in run(["rpm", "-q", "--changelog", o.strip()])[1]: return True
    return False


def stale_master(binpath, argpat):
    """Return True if a running process using this binary started before the binary was replaced."""
    if not sys.platform.startswith("linux"): return None
    real = os.path.realpath(binpath); res = []
    for d in glob.glob("/proc/[0-9]*"):
        try:
            exe = os.readlink(d + "/exe"); deleted = exe.endswith(" (deleted)")
            if not deleted and os.path.realpath(exe) != real: continue
            cmd = open(d + "/cmdline", "rb").read().decode(errors="ignore").replace("\0", " ")
            if not re.search(argpat, cmd): continue
            res.append(deleted or os.stat(binpath).st_mtime > os.stat(d).st_ctime)
        except (OSError, ValueError): continue
    return any(res) if res else None


# ---------------------------------------------------------------- engines
def check_postgres(sql, a):
    cands = glob.glob("/usr/lib/postgresql/*/bin/postgres") + glob.glob("/usr/pgsql-*/bin/postgres") + \
        glob.glob("/opt/*/bin/postgres") + glob.glob("/usr/local/pgsql*/bin/postgres") + glob.glob("/opt/*/*/bin/postgres") + \
        [shutil.which("postgres"), shutil.which("postmaster")] + proc_exes("postgres")
    out = []
    for b in uniq_exec(cands):
        rc, o = run([b, "--version"]); v = vt(o)
        r = {"engine": "PostgreSQL", "binary": b, "version": ".".join(map(str, v[:2])) if v else None, "notes": [], "findings": []}
        if not v: r["verdict"] = "REVIEW"; r["notes"].append("version not parsed"); out.append(r); continue
        major, minor = v[0], v[1] if len(v) > 1 else 0
        bp = changelog_has(b, CVE_PG)
        if bp: r["notes"].append(f"package changelog names {CVE_PG} (backported fix)")
        if major in PG_FIXED:
            fixed = f"{major}.{PG_FIXED[major]}"
            ok = minor >= PG_FIXED[major] or bp
            r["verdict"] = "PATCHED" if ok else "VULNERABLE"
            r["notes"].append(f"fixed release for this branch: {fixed} (12 Nov 2026)")
        elif major < 14:
            r["verdict"] = "UNSUPPORTED"; r["notes"].append("end-of-life branch: no fixed release; upgrade to 18.7 / 17.12 / 16.16 / 15.20 / 14.25 or newer")
        else:
            r["verdict"] = "REVIEW"; r["notes"].append("branch not in the advisory; confirm it includes the November 2026 fixes")
        st = stale_master(b, r"postgres.*-D|postmaster")
        if st and r["verdict"] in ("PATCHED",): r["verdict"] = "RESTART-REQUIRED"; r["notes"].append("running postmaster is older than the binary on disk: restart PostgreSQL")
        out.append(r)
    if sql and out: out[0]["findings"] += pg_sql(a)
    return out


def psql(a, db, q):
    base = ["psql", "-X", "-At", "-F", "|", "-d", db, "-c", q]
    if a.pg_host: base[1:1] = ["-h", a.pg_host]
    if a.pg_port: base[1:1] = ["-p", str(a.pg_port)]
    if a.pg_user: base[1:1] = ["-U", a.pg_user]
    elif hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("runuser") and not a.pg_host:
        base = ["runuser", "-u", "postgres", "--"] + base
    return run(base)


def pg_sql(a):
    f = []
    if not shutil.which("psql"): return [("WARN", "psql not found: PostgreSQL SQL checks skipped")]
    rc, o = psql(a, "postgres", "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate")
    if rc != 0: return [("WARN", "could not connect with psql (set --pg-user/--pg-host, PGPASSWORD): " + o.strip().splitlines()[0][:120])]
    dbs = [x for x in o.split() if x]
    rc, o = psql(a, "postgres", "SELECT d.datname FROM pg_database d WHERE d.datallowconn AND NOT d.datistemplate AND (d.datacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(d.datacl) x WHERE x.grantee=0 AND x.privilege_type='TEMPORARY'))")
    for d in o.split(): f.append(("BAD", f"database {d}: TEMPORARY is granted to PUBLIC (every login role can create temp objects) -> REVOKE TEMPORARY ON DATABASE {d} FROM PUBLIC"))
    rc, o = psql(a, "postgres", "SELECT d.datname, pg_get_userbyid(x.grantee) FROM pg_database d, aclexplode(d.datacl) x WHERE x.privilege_type='TEMPORARY' AND x.grantee<>0 AND d.datallowconn AND NOT d.datistemplate")
    for ln in o.splitlines():
        if "|" in ln: dn, rn = ln.split("|", 1); f.append(("WARN", f"database {dn}: role {rn} has explicit TEMPORARY - confirm it is needed"))
    for d in dbs:
        rc, o = psql(a, d, "SELECT p.proname||' (owner '||pg_get_userbyid(p.proowner)||', sortop '||ag.aggsortop::regoperator||')' FROM pg_aggregate ag JOIN pg_proc p ON p.oid=ag.aggfnoid WHERE ag.aggsortop<>0 AND p.pronamespace NOT IN ('pg_catalog'::regnamespace)")
        for ln in o.splitlines():
            if ln.strip(): f.append(("BAD", f"database {d}: user-defined aggregate with a sort operator: {ln.strip()} - review owner"))
    if not f: f.append(("OK", "no PUBLIC TEMPORARY grants or user aggregates with SORTOP found"))
    return f


def check_mysql(sql, a):
    cands = [shutil.which("mysqld"), shutil.which("mariadbd"), "/usr/sbin/mysqld", "/usr/local/mysql/bin/mysqld", "/usr/libexec/mysqld",
             "/usr/sbin/mariadbd"] + glob.glob("/opt/*/bin/mysqld") + proc_exes("mysqld") + proc_exes("mariadbd")
    out = []
    for b in uniq_exec(cands):
        rc, o = run([b, "--version"]); first = o.strip().splitlines()[0] if o.strip() else ""
        r = {"engine": "MySQL", "binary": b, "version": None, "notes": [first], "findings": []}
        if "mariadb" in first.lower() or "mariadb" in os.path.basename(b).lower():
            r["engine"] = "MariaDB"; r["verdict"] = "NOT-LISTED"; r["notes"].append("MariaDB is not covered by the advisory"); out.append(r); continue
        v = vt(re.sub(r"^.*Ver\s+", "", first) if "Ver" in first else first, r"(\d+)\.(\d+)\.(\d+)")
        r["version"] = ".".join(map(str, v)) if v else None
        if not v: r["verdict"] = "REVIEW"; r["notes"].append("version not parsed")
        elif (26, 7, 0) <= v <= (26, 7, 1): r["verdict"] = "VULNERABLE"; r["notes"].append("CVE-2026-101786: affected range 26.7.0-26.7.1; apply the 20 Oct 2026 Oracle MySQL update")
        else:
            r["verdict"] = "OUTSIDE-RANGE"; r["notes"].append("not in the advisory's affected range (26.7.0-26.7.1); exact fixed build not published in reviewed sources - confirm against Oracle's October 2026 CPU")
        st = stale_master(b, r"mysqld")
        if st and r["verdict"] != "VULNERABLE": r["verdict"] = "RESTART-REQUIRED"; r["notes"].append("running mysqld is older than the binary on disk: restart MySQL")
        out.append(r)
    if sql and out and out[0]["engine"] == "MySQL": out[0]["findings"] += mysql_sql(a)
    return out


def mysql_sql(a):
    if not shutil.which("mysql"): return [("WARN", "mysql client not found: MySQL SQL checks skipped")]
    base = ["mysql"] + ([f"--defaults-file={a.mysql_defaults_file}"] if a.mysql_defaults_file else []) + ["-N", "-B", "-e"]
    q = ("SELECT GRANTEE, CONCAT('schema:', TABLE_SCHEMA) FROM information_schema.SCHEMA_PRIVILEGES WHERE PRIVILEGE_TYPE='CREATE TEMPORARY TABLES' "
         "UNION ALL SELECT GRANTEE, 'global' FROM information_schema.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='CREATE TEMPORARY TABLES'")
    rc, o = run(base + [q])
    if rc != 0: return [("WARN", "could not connect with mysql client (use --mysql-defaults-file): " + o.strip().splitlines()[0][:120])]
    f = []
    for ln in o.splitlines():
        if ln.strip():
            who, _, scope = ln.partition("\t")
            f.append(("WARN", f"account {who} can CREATE TEMPORARY TABLES ({scope}) - revoke where not needed"))
    return f or [("OK", "no account holds CREATE TEMPORARY TABLES")]


def check_oracle(a):
    out = []
    homes = set()
    if os.environ.get("ORACLE_HOME"): homes.add(os.environ["ORACLE_HOME"])
    if os.path.exists("/etc/oratab"):
        for ln in open("/etc/oratab", errors="ignore"):
            p = ln.strip().split(":")
            if len(p) >= 2 and not ln.startswith("#") and p[1].startswith("/"): homes.add(p[1])
    for e in proc_exes("oracle"):
        m = re.match(r"(.*)/bin/oracle$", e)
        if m: homes.add(m.group(1))
    vers = {}
    for h in sorted(homes):
        sp = os.path.join(h, "bin", "sqlplus")
        if os.path.isfile(sp):
            env = dict(os.environ, ORACLE_HOME=h, LD_LIBRARY_PATH=os.path.join(h, "lib"))
            rc, o = run([sp, "-V"], env=env); m = re.search(r"Version\s+(\d+)\.(\d+)\.(\d+)", o)
            if m: vers[h] = tuple(int(x) for x in m.groups())
    if a.oracle_version:
        v = vt(a.oracle_version, r"(\d+)\.(\d+)(?:\.(\d+))?"); vers["(--oracle-version)"] = v
    for h, v in vers.items():
        r = {"engine": "Oracle Database", "binary": h, "version": ".".join(map(str, v)), "notes": [], "findings": []}
        M, m = v[0], v[1]
        vuln = (M == 19 and m <= 32) or (M == 21 and m <= 24) or (M == 23 and (m, v[2] if len(v) > 2 else 0) >= (4, 0) and (m, v[2] if len(v) > 2 else 0) <= (26, 3))
        if vuln:
            r["verdict"] = "VULNERABLE"; r["notes"].append("CVE-2026-114819 (Oracle Text, CVSS 9.9): affected 19.3-19.32 / 21.3-21.24 / 23.4.0-23.26.3; apply the November 2026 CPU (17 Nov)")
            r["notes"].append("version comes from sqlplus -V (home's release update); confirm with 'opatch lspatches' and 'datapatch -verbose' - an interim patch may cover it")
        elif M in (19, 21, 23):
            r["verdict"] = "OUTSIDE-RANGE"; r["notes"].append("above the advisory's affected range; confirm the November 2026 CPU is in the home with opatch lspatches")
        else:
            r["verdict"] = "REVIEW"; r["notes"].append("release not covered by the advisory (likely out of support); confirm with Oracle")
        out.append(r)
    if not vers and (homes or glob.glob("/proc/[0-9]*/comm") and any(open(p).read().startswith("ora_pmon") for p in glob.glob("/proc/[0-9]*/comm") if os.access(p, os.R_OK))):
        out.append({"engine": "Oracle Database", "binary": ",".join(sorted(homes)) or "(running)", "version": None, "verdict": "REVIEW",
                    "notes": ["Oracle detected but version not read; run as the oracle user or pass --oracle-version"], "findings": []})
    return out


def check_ords(a):
    out = []; vers = []
    for b in uniq_exec([shutil.which("ords"), "/opt/oracle/ords/bin/ords", "/usr/local/bin/ords", "/u01/ords/bin/ords"] + glob.glob("/opt/*/ords/bin/ords")):
        rc, o = run([b, "--version"], timeout=60); m = re.search(r"(\d+)\.(\d+)\.(\d+)", o)
        vers.append((b, tuple(int(x) for x in m.groups()) if m else None))
    if a.ords_version: vers.append(("(--ords-version)", vt(a.ords_version, r"(\d+)\.(\d+)\.(\d+)")))
    for b, v in vers:
        r = {"engine": "Oracle REST Data Services", "binary": b, "version": ".".join(map(str, v)) if v else None, "notes": [], "findings": []}
        if not v: r["verdict"] = "REVIEW"; r["notes"].append("version not parsed")
        elif (24, 2, 0) <= v <= (26, 2, 1): r["verdict"] = "VULNERABLE"; r["notes"].append("CVE-2026-91609 (GraphQL): affected 24.2.0-26.2.1; apply the October 2026 CPU. Part of the unauthenticated Oracle chain")
        elif v < (24, 2, 0): r["verdict"] = "REVIEW"; r["notes"].append("older than the listed range; out of support - upgrade")
        else: r["verdict"] = "OUTSIDE-RANGE"; r["notes"].append("above the advisory's affected range")
        out.append(r)
    for w in glob.glob("/opt/**/ords.war", recursive=True)[:5] + glob.glob("/u01/**/ords.war", recursive=True)[:5]:
        out.append({"engine": "Oracle REST Data Services", "binary": w, "version": None, "verdict": "REVIEW", "findings": [],
                    "notes": ["ords.war found (Tomcat/WebLogic deployment): read its version with 'java -jar ords.war version' or pass --ords-version"]})
    return out


def check_clickhouse(sql, a):
    out = []
    for b in uniq_exec([shutil.which("clickhouse-server"), shutil.which("clickhouse"), "/usr/bin/clickhouse-server", "/usr/bin/clickhouse"] + proc_exes("clickhouse-server") + proc_exes("clickhouse")):
        rc, o = run([b, "--version"]); v = vt(o, r"(\d+)\.(\d+)\.(\d+)\.?(\d+)?")
        r = {"engine": "ClickHouse", "binary": b, "version": ".".join(map(str, v)) if v else None, "findings": [],
             "verdict": "NO-FIX", "notes": ["no CVE and no confirmed vendor fix; researcher tested 26.7.5.10 (shell obtained via format_binary_max_string_size = 0)"]}
        files = glob.glob("/etc/clickhouse-server/*.xml") + glob.glob("/etc/clickhouse-server/*.d/*.xml") + glob.glob("/etc/clickhouse-server/*.yaml") + glob.glob("/etc/clickhouse-server/*.d/*.yaml")
        hit = [fn for fn in files if "format_binary_max_string_size" in open(fn, errors="ignore").read()]
        r["findings"].append(("OK", "setting mentioned in config (review it is constrained read-only): " + ", ".join(hit)) if hit else
                             ("BAD", "no constraint on format_binary_max_string_size in config files - add <readonly/> constraint (Vairav interim suggestion)"))
        if sql:
            cli = shutil.which("clickhouse-client")
            if cli:
                rc, o = run([cli, "--query", "SELECT setting_name, min, max, writability FROM system.settings_profile_elements WHERE setting_name='format_binary_max_string_size' FORMAT TSV"])
                r["findings"].append(("OK", "constraint in access control: " + o.strip()) if rc == 0 and o.strip() else ("WARN", "no SQL-defined constraint found (or cannot connect)"))
                rc, o = run([cli, "--query", "SELECT count() FROM system.query_log WHERE query ILIKE '%format_binary_max_string_size%' AND query NOT ILIKE '%system.query_log%'"])
                if rc == 0 and o.strip().isdigit() and int(o.strip()) > 0: r["findings"].append(("BAD", f"{o.strip()} query_log entries mention format_binary_max_string_size - review who ran them"))
            else: r["findings"].append(("WARN", "clickhouse-client not found: SQL checks skipped"))
        out.append(r)
    return out


# ---------------------------------------------------------------- exposure, hunt, probe
PORTS = {5432: "PostgreSQL", 3306: "MySQL", 33060: "MySQL X", 1521: "Oracle listener", 8123: "ClickHouse HTTP", 9000: "ClickHouse native", 9440: "ClickHouse TLS", 8443: "HTTPS (ORDS?)"}


def listeners():
    res = set()
    if shutil.which("ss") or shutil.which("netstat"):
        rc, o = run(["ss", "-H", "-ltn"]) if shutil.which("ss") else run(["netstat", "-an"])
        for ln in o.splitlines():
            addr = next((p for p in ln.split() if re.search(r":\d+$", p)), None)
            if not addr: continue
            h, _, p = addr.rpartition(":")
            if p.isdigit() and int(p) in PORTS:
                h = h.strip("[]"); res.add((int(p), PORTS[int(p)], h, h not in ("127.0.0.1", "::1", "localhost")))
    else:  # Linux without ss/netstat: read /proc/net
        for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
            try: lines = open(fn).read().splitlines()[1:]
            except OSError: continue
            for ln in lines:
                f = ln.split()
                if len(f) > 3 and f[3] == "0A":
                    ip, hp = f[1].split(":"); p = int(hp, 16)
                    if p in PORTS:
                        lo = ip in ("0100007F", "00000000000000000000000001000000")
                        res.add((p, PORTS[p], "loopback" if lo else "all/other addresses", not lo))
    return sorted(res)


def hunt():
    pats = [("terminated by signal 11", "backend crash"), ("got signal 11", "mysqld crash"), ("format_binary_max_string_size", "ClickHouse setting"), ("SORTOP", "PostgreSQL aggregate option")]
    files = glob.glob("/var/log/postgresql/*") + glob.glob("/var/log/mysql/*") + glob.glob("/var/log/mysqld.log*") + glob.glob("/var/lib/mysql/*.err") + \
        glob.glob("/var/log/clickhouse-server/*.log") + glob.glob("/var/lib/pgsql/*/data/log/*") + glob.glob("/var/log/messages") + glob.glob("/var/log/syslog")
    hits = []
    for fn in files:
        if fn.endswith(".gz") or not os.path.isfile(fn): continue
        try:
            for i, ln in enumerate(open(fn, errors="ignore")):
                for p, why in pats:
                    if p.lower() in ln.lower() and not (p == "SORTOP" and "CREATE AGGREGATE" not in ln.upper()):
                        hits.append((fn, why, ln.strip()[:200]))
        except OSError: pass
    procs = []
    rc, o = run(["ps", "-eo", "pid,ppid,user,comm"])
    byid = {}; rows = []
    for ln in o.splitlines()[1:]:
        p = ln.split(None, 3)
        if len(p) == 4: byid[p[0]] = p[3]; rows.append(p)
    for pid, ppid, user, comm in rows:
        if comm in ("sh", "bash", "dash", "curl", "wget", "python", "python3", "perl", "nc", "ncat", "socat") and re.match(r"(postgres|postmaster|mysqld|mariadbd|clickhouse|oracle|tnslsnr)", byid.get(ppid, "")):
            procs.append((pid, byid[ppid], comm, user))
    return hits[:200], procs


def probe_ords(url):
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "vairav-db-check"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            return {"url": url, "status": r.status, "server": r.headers.get("Server")}
    except Exception as e:
        return {"url": url, "error": str(e)}


def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(description="Database engine RCE (Narrow Grants, Wide Engines) read-only exposure check")
    ap.add_argument("--sql", action="store_true"); ap.add_argument("--hunt", action="store_true")
    ap.add_argument("--json", action="store_true"); ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--oracle-version"); ap.add_argument("--ords-version"); ap.add_argument("--ords-url")
    ap.add_argument("--pg-host"); ap.add_argument("--pg-port", type=int); ap.add_argument("--pg-user"); ap.add_argument("--mysql-defaults-file")
    a = ap.parse_args()
    if a.no_color or a.json: USE_COLOR = False
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    inst = check_postgres(a.sql, a) + check_mysql(a.sql, a) + check_oracle(a) + check_ords(a) + check_clickhouse(a.sql, a)
    lst = listeners(); hh = hunt() if a.hunt else None; h = {"log_hits": hh[0], "shell_children": hh[1]} if hh else None; op = probe_ords(a.ords_url) if a.ords_url else None
    rep = {"host": socket.gethostname(), "time": time.strftime("%F %T"), "instances": inst, "listeners": lst, "hunt": h, "ords_probe": op}
    if a.json: print(json.dumps(rep, indent=2, default=str))
    else:
        print("=" * 68); print(f" Database RCE (Narrow Grants, Wide Engines) check - {rep['host']} - {rep['time']}"); print("=" * 68)
        if not root and sys.platform.startswith("linux"): print(Y("[!] Not root: process and log inspection may be incomplete (use sudo)."))
        if not inst: print(CY("[i] No PostgreSQL, MySQL, Oracle, ORDS or ClickHouse installation found."))
        col = {"PATCHED": G, "OUTSIDE-RANGE": G, "VULNERABLE": R, "UNSUPPORTED": R, "RESTART-REQUIRED": R, "NO-FIX": Y, "REVIEW": Y, "NOT-LISTED": CY}
        for i in inst:
            print(f"\n--- {i['engine']}  {i['version'] or ''}  ({i['binary']}) ---")
            for n in i["notes"]:
                if n: print("  " + n)
            for lvl, msg in i["findings"]:
                print("  " + {"OK": G, "WARN": Y, "BAD": R}[lvl](f"[{lvl}] ") + msg)
            print("  VERDICT: " + col[i["verdict"]](i["verdict"]))
        print("\n--- Database ports listening ---")
        for p, name, addr, ext in lst: print("  " + (R if ext else G)(f"{name:18} {addr}:{p}  " + ("NETWORK-REACHABLE: restrict to app servers/admin hosts" if ext else "loopback only")))
        if not lst: print("  none of the standard database ports found listening")
        if op: print("\n--- ORDS URL (reachability only) ---\n  " + (Y(f"{op['url']} reachable (HTTP {op['status']}) - confirm it is not exposed to untrusted networks; patch ORDS and Oracle") if "status" in op else f"{op['url']}: {op['error']}"))
        if h is not None:
            hits, procs = h["log_hits"], h["shell_children"]
            print("\n--- Hunt (local logs; review dates against 20 Oct 2026 onward) ---")
            for fn, why, ln in hits[:25]: print(Y(f"  {why}: {fn}: {ln}"))
            if len(hits) > 25: print(f"  ... {len(hits) - 25} more matches")
            for pid, par, comm, user in procs: print(R(f"  PID {pid}: {par} spawned {comm} (user {user})"))
            if not hits and not procs: print(G("  nothing suspicious found in local logs or process tree"))
        print("\nNote: heuristics only. Version and privilege checks cannot prove a host is safe. Patch, restart, and remove unneeded rights.")
    ver = [i["verdict"] for i in inst]
    if not ver: sys.exit(3)
    lvls = [l for i in inst for l, _ in i["findings"]]
    if any(v in ("VULNERABLE", "UNSUPPORTED", "RESTART-REQUIRED") for v in ver) or (h and h["shell_children"]): sys.exit(1)
    if any(v in ("REVIEW", "NO-FIX") for v in ver) or "BAD" in lvls or "WARN" in lvls or any(e for _, _, _, e in lst) or (h and h["log_hits"]): sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
