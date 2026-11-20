# 🗄️ Database RCE Toolkit "Narrow Grants, Wide Engines"

> **Vairav Technology Security Pvt. Ltd. · Cyber Security Operations Centre (CSOC)**

Read-only scripts that show whether a host runs a database engine exposed to the research by Zheng Yu (Depthfirst): **low-privilege database accounts can reach memory-corruption bugs in PostgreSQL, MySQL and ClickHouse**, and an **exposed ORDS endpoint** leads to unauthenticated code execution on Oracle Database.

---

## 🧭 Contents

- [🔬 What the scripts decide](#-what-the-scripts-decide)
- [🗂️ Package contents](#️-package-contents)
- [🪪 Requirements](#-requirements)
- [🐍 Script 1 Python](#-script-1--db_rce_checkpy)
- [🐧 Script 2 Bash (Linux)](#-script-2--db_rce_check_linuxsh)
- [🪟 Script 3 PowerShell (Windows)](#-script-3--db_rce_check_windowsps1)
- [🧮 Reading the results](#-reading-the-results)
- [📦 Fixed versions](#-fixed-versions)
- [🔐 Reduce object-creation rights](#-reduce-object-creation-rights)
- [🩹 Patch and restart](#-patch-and-restart)
- [🪛 Troubleshooting](#-troubleshooting)
- [🧷 Verify file integrity](#-verify-file-integrity)
- [🧪 Testing status](#-testing-status)

---

## 🔬 What the scripts decide

| Engine | Identifier | Flaw | Needs |
|---|---|---|---|
| 🐘 **PostgreSQL** | CVE-2026-116331 | Type confusion in min/max aggregate optimisation (user aggregate with `SORTOP`) CVSS 8.8 | Any login role that can create objects (default `TEMPORARY` privilege) |
| 🐬 **MySQL** | CVE-2026-101786 | Query-optimiser memory flaw | Account that can create temporary tables |
| 🏛️ **Oracle Database** | CVE-2026-114819 | Oracle Text flaw **CVSS 9.9** | Chained with ORDS: **no login** |
| 🌐 **Oracle REST Data Services** | CVE-2026-91609 | GraphQL interface flaw | Exposed ORDS endpoint |
| 🖱️ **ClickHouse** | *no CVE, no confirmed fix* | Integer-overflow write with `format_binary_max_string_size = 0` | Authenticated user who can change that setting |

Each script runs these checks:

| # | Check | Why it matters |
|---|---|---|
| 1️⃣ | 🏷️ **Engine versions** | Compared with fixed releases (PostgreSQL) or affected ranges (MySQL, Oracle, ORDS) from the advisory |
| 2️⃣ | 📦 **Backport evidence** | PostgreSQL package changelog naming CVE-2026-116331 (Debian/Ubuntu/RHEL) |
| 3️⃣ | 🔁 **Stale processes** | Running PostgreSQL or MySQL older than the installed binary restart needed |
| 4️⃣ | 🔌 **Listening ports** | 5432, 3306, 1521, 8123/9000/9440 and 8443 reachable beyond loopback |
| 5️⃣ | 🔑 **Privileges** *(Python, Bash, `--sql`)* | `TEMPORARY` granted to PUBLIC or roles, `CREATE TEMPORARY TABLES` accounts, PostgreSQL user aggregates with a sort operator, ClickHouse setting constraint |
| 6️⃣ | 🕵️ **Hunt** *(`--hunt`)* | Engine crash messages, `CREATE AGGREGATE … SORTOP`, setting changes, and database services that spawned shells |

> 🛑 **These scripts never send exploit traffic.** Do not try to reproduce the research on production systems.

---

## 🗂️ Package contents

```
db-rce-toolkit/
├── 📘 README.md                          ← this file
├── 🧷 SHA256SUMS.txt                     ← script checksums
└── 📁 scripts/
    ├── 🐍 db_rce_check.py                ← Linux / macOS (Python 3.8+), full feature set
    ├── 🐧 db_rce_check_linux.sh          ← Linux (bash), same checks, no Python needed
    └── 🪟 db_rce_check_windows.ps1       ← Windows (PowerShell 5.1+), version / process / port / hunt checks
```

| Script | Platform | 👁️ Read-only | 🔄 Restarts services | 🔑 `--sql` privilege checks | 🕵️ Hunt |
|---|---|:---:|:---:|:---:|:---:|
| 🐍 `db_rce_check.py` | Linux, macOS | ✔️ | ✖️ | ✔️ | ✔️ |
| 🐧 `db_rce_check_linux.sh` | Linux | ✔️ | ✖️ | ✔️ | ✔️ |
| 🪟 `db_rce_check_windows.ps1` | Windows | ✔️ | ✖️ | ✖️ (use Python) | ✔️ |

---

## 🪪 Requirements

| Platform | Needs |
|---|---|
| 🐧 Linux | `bash` or Python 3.8+; **root** (`sudo`) so processes and logs can be read; optional `psql`, `mysql`, `clickhouse-client`, `dpkg`/`rpm` |
| 🔑 `--sql` | A database login that can read catalogs (read-only `SELECT`s). Use your normal client config: `PGPASSWORD`, `~/.pgpass`, `--mysql-defaults-file`, or run as root and the script uses `runuser -u postgres` |
| 🪟 Windows | PowerShell 5.1+ run **as Administrator** |

```bash
unzip db-rce-toolkit.zip
cd db-rce-toolkit/scripts
chmod +x *.sh *.py
```

---

## 🐍 Script 1 `db_rce_check.py`

```bash
sudo python3 db_rce_check.py                              # host checks only, no DB login
sudo python3 db_rce_check.py --sql --hunt                 # + privilege checks and log hunt
python3 db_rce_check.py --sql --pg-host db1 --pg-user auditor      # remote PostgreSQL (PGPASSWORD set)
python3 db_rce_check.py --oracle-version 19.29 --ords-version 25.1.0 --ords-url https://host/ords/
sudo python3 db_rce_check.py --json > db_rce_$(hostname).json
```

| Option | Purpose |
|---|---|
| `--sql` | Read-only catalog checks (PostgreSQL, MySQL, ClickHouse) |
| `--hunt` | Search local logs and the process tree |
| `--pg-host/--pg-port/--pg-user` | Connection for PostgreSQL checks |
| `--mysql-defaults-file F` | MySQL credentials file |
| `--oracle-version` / `--ords-version` | Supply a version when the tool cannot be run (for example as a non-oracle user) |
| `--ords-url` | Reachability-only check of an ORDS URL |
| `--json` / `--no-color` | Machine-readable or plain output |

---

## 🐧 Script 2 `db_rce_check_linux.sh`

Same checks and options as the Python script, in plain bash.

```bash
sudo ./db_rce_check_linux.sh
sudo ./db_rce_check_linux.sh --sql --hunt --pg-user auditor
sudo ./db_rce_check_linux.sh --no-color | tee db_rce_$(hostname).txt        # save report
```

**Sample output**

```
--- PostgreSQL  16.15  (/usr/lib/postgresql/16/bin/postgres) ---
  fixed release for this branch: 16.16 (12 Nov 2026)
  [BAD] database appdb: TEMPORARY is granted to PUBLIC ... -> REVOKE TEMPORARY ON DATABASE appdb FROM PUBLIC
  [BAD] database appdb: user-defined aggregate with a sort operator: my_max (owner postgres, ...) - review owner
  VERDICT: VULNERABLE
--- Database ports listening ---
  PostgreSQL  0.0.0.0:5432  NETWORK-REACHABLE: restrict to app servers/admin hosts
```

---

## 🪟 Script 3 `db_rce_check_windows.ps1`

```powershell
powershell -ExecutionPolicy Bypass -File .\db_rce_check_windows.ps1 -Hunt
powershell -ExecutionPolicy Bypass -File .\db_rce_check_windows.ps1 -OracleVersion 19.29 -OrdsVersion 25.1.0 -OrdsUrl https://host/ords/
```

Finds PostgreSQL, MySQL/MariaDB, Oracle (registry homes, `sqlplus -V`), ORDS and ClickHouse; checks versions, stale processes, listeners and (with `-Hunt`) logs and shells spawned by database services. Privilege checks need SQL access, so run the Python script with `--sql` for those.

---

## 🧮 Reading the results

| Verdict | Meaning | Action |
|---|---|---|
| ✅ `PATCHED` | PostgreSQL is at or above the fixed minor release (or the changelog names the CVE) | None |
| 🟢 `OUTSIDE-RANGE` | MySQL, Oracle or ORDS version is above the advisory's affected range | Confirm the Oracle CPU in the home (`opatch lspatches`) exact fixed builds were not published |
| ❌ `VULNERABLE` | Version is in the affected range or below the fixed release | Patch and restart |
| 🔁 `RESTART-REQUIRED` | Fixed binary on disk, old process still running | Restart the service |
| 🛑 `UNSUPPORTED` | End-of-life PostgreSQL branch with no fix | Upgrade to a supported branch |
| ⚠️ `NO-FIX` | ClickHouse: no CVE and no confirmed vendor fix | Apply the setting constraint; follow up with the vendor |
| 🔍 `REVIEW` | Version not read, or release not covered by the advisory | Check manually |
| ℹ️ `NOT-LISTED` | MariaDB: not covered by the advisory | None |

Finding tags: 🟢 `[OK]` · 🟡 `[WARN]` review · 🔴 `[BAD]` fix.

**Exit codes:** `0` no finding · `1` vulnerable, unsupported or restart required (or a shell spawned by a database service) · `2` review, hardening gap, network-reachable database port or hunt hit · `3` no database found.

> ⚠️ A good result is a **version and configuration check**, not proof of safety. Oracle versions come from `sqlplus -V` (the home's release update): confirm patches with `opatch lspatches`.

---

## 📦 Fixed versions

| Product | Affected | Fixed |
|---|---|---|
| 🐘 PostgreSQL 18 / 17 / 16 / 15 / 14 | Before 18.7 / 17.12 / 16.16 / 15.20 / 14.25 | **18.7 / 17.12 / 16.16 / 15.20 / 14.25** (12 Nov 2026) |
| 🐬 MySQL Server and Cluster | 26.7.0 – 26.7.1 | Oracle MySQL update, 20 Oct 2026 |
| 🏛️ Oracle Database (Oracle Text) | 19.3–19.32, 21.3–21.24, 23.4.0–23.26.3 | Oracle CPU November 2026 (17 Nov) |
| 🌐 Oracle REST Data Services | 24.2.0 – 26.2.1 | Oracle CPU October 2026 (20 Oct) |
| 🖱️ ClickHouse | 26.7.5.10 tested | **No confirmed fix** |

> ℹ️ Fixed build numbers for MySQL and ORDS were not stated in the sources the advisory used; the scripts use the affected ranges and say so.

---

## 🔐 Reduce object-creation rights

Review what each account can **do**, not only what it can read. Test applications first some ORMs and reports use temporary tables.

```sql
-- 🐘 PostgreSQL
REVOKE TEMPORARY ON DATABASE appdb FROM PUBLIC;
GRANT  TEMPORARY ON DATABASE appdb TO app_role_that_needs_it;

-- 🐬 MySQL
REVOKE CREATE TEMPORARY TABLES ON appdb.* FROM 'report_user'@'%';
```

```xml
<!-- 🖱️ ClickHouse users.xml profile Vairav interim suggestion, not vendor guidance; test first -->
<profiles><default><constraints>
  <format_binary_max_string_size><readonly/></format_binary_max_string_size>
</constraints></default></profiles>
```

Also: 🔌 keep database listeners and ORDS off untrusted networks, 🧱 put ORDS behind a WAF and limit GraphQL, and 👥 separate reporting and vendor accounts from application accounts.

---

## 🩹 Patch and restart

1. 🏛️ **Oracle first:** apply the October (ORDS) and November (Oracle Text) 2026 CPUs. Account restrictions do not mitigate the unauthenticated chain.
2. 🐘 Upgrade **PostgreSQL** to the fixed minor release and **restart** (update binaries and restart together; rebuild extensions where required).
3. 🐬 Apply the **MySQL** October 2026 update.
4. 🖱️ **ClickHouse:** apply the setting constraint and ask the vendor for a fix timeline.
5. 🔎 Re-run the script and confirm `PATCHED` / `OUTSIDE-RANGE` with no `[BAD]` findings.

---

## 🪛 Troubleshooting

| Problem | Fix |
|---|---|
| `could not connect with psql` | Pass `--pg-user/--pg-host`, set `PGPASSWORD` or `~/.pgpass`, or run as root on the DB host (uses `runuser -u postgres`) |
| `could not connect with mysql client` | Use `--mysql-defaults-file` with a read-only account |
| Oracle shows `REVIEW` | Run as the `oracle` user, or pass `--oracle-version` (from `sqlplus -V`) |
| ORDS found only as `ords.war` | Run `java -jar ords.war version` and pass `--ords-version` |
| Version looks old on Ubuntu/Debian | Backported fix: the script checks the changelog for CVE-2026-116331 |
| `NETWORK-REACHABLE` port | Bind to loopback or restrict with a firewall to app servers and admin hosts |
| `Execution policy` error on Windows | Run with `-ExecutionPolicy Bypass` as shown above |

---

## 🧷 Verify file integrity

```bash
sha256sum -c SHA256SUMS.txt
```

---

## 🧪 Testing status

| Script | Status |
|---|---|
| 🐍 Python | Run against simulated PostgreSQL, MySQL, MariaDB, Oracle (`sqlplus -V`), ORDS and ClickHouse binaries across vulnerable and patched versions, listening sockets and a planted log entry |
| 🐧 Bash | Same scenarios as Python; output and exit codes matched |
| 🐘 PostgreSQL SQL checks | **Run against a live PostgreSQL 16 server** in both scripts: correctly flagged PUBLIC `TEMPORARY`, explicit grants and a user aggregate with `SORTOP` |
| 🐬 MySQL / 🖱️ ClickHouse SQL checks | Tested only against stand-in clients returning canned output **not validated on real servers** |
| 🪟 PowerShell | **Syntax-reviewed only** not executed. Test on one Windows host before wide use |
| 🏛️ Oracle / ORDS | Version logic tested with simulated `sqlplus` / `ords` output; not run against real Oracle homes |

---

*Vairav Technology Security Pvt. Ltd. · sales@vairavtech.com · vairavtech.com*
