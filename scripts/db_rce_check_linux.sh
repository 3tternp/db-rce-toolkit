#!/bin/bash
# =============================================================================
# db_rce_check_linux.sh
# Vairav Technology CSOC - "Narrow Grants, Wide Engines" database RCE exposure check
# PostgreSQL CVE-2026-116331 | MySQL CVE-2026-101786 | Oracle Text CVE-2026-114819
# Oracle REST Data Services CVE-2026-91609 | ClickHouse (no CVE, no confirmed fix)
#
# Read-only. Never sends exploit traffic. Host checks need no database login; --sql runs
# read-only catalog SELECTs using your normal client configuration / environment.
#
# Usage: sudo bash db_rce_check_linux.sh [--sql] [--hunt] [--no-color]
#          [--oracle-version 19.29] [--ords-version 25.1.0] [--ords-url https://host/ords/]
#          [--pg-host H] [--pg-port P] [--pg-user U] [--mysql-defaults-file F]
# Exit codes: 0 no finding | 1 vulnerable, unsupported or restart required | 2 review / hardening gaps | 3 no database found
# =============================================================================
SQL=0; HUNT=0; COLOR=1; ORAV=""; ORDSV=""; ORDSURL=""; PGH=""; PGP=""; PGU=""; MYDEF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --sql) SQL=1; shift ;; --hunt) HUNT=1; shift ;; --no-color) COLOR=0; shift ;;
    --oracle-version) ORAV="$2"; shift 2 ;; --ords-version) ORDSV="$2"; shift 2 ;; --ords-url) ORDSURL="$2"; shift 2 ;;
    --pg-host) PGH="$2"; shift 2 ;; --pg-port) PGP="$2"; shift 2 ;; --pg-user) PGU="$2"; shift 2 ;;
    --mysql-defaults-file) MYDEF="$2"; shift 2 ;;
    -h|--help) sed -n 2,15p "$0"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac
done
[ -t 1 ] || COLOR=0
if [ "$COLOR" -eq 1 ]; then G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31;1m'; C=$'\033[36m'; N=$'\033[0m'; else G=; Y=; R=; C=; N=; fi

WORST=0; FOUND=0
bump() { case "$1" in 1) WORST=1 ;; 2) [ "$WORST" -ne 1 ] && WORST=2 ;; esac; }
vn() { echo $(( (( ${1:-0}*10000 + ${2:-0} )*10000 + ${3:-0} )*10000 + ${4:-0} )); }
parse_ver() { echo "$1" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?(\.[0-9]+)?' | head -1; }
note() { echo "  $1"; }
verdict() { # engine version binary verdict
  local col; case "$4" in PATCHED|OUTSIDE-RANGE) col=$G ;; VULNERABLE|UNSUPPORTED|RESTART-REQUIRED) col=$R ;; NOT-LISTED) col=$C ;; *) col=$Y ;; esac
  echo "  VERDICT: ${col}$4${N}"
  case "$4" in VULNERABLE|UNSUPPORTED|RESTART-REQUIRED) bump 1 ;; REVIEW|NO-FIX) bump 2 ;; esac
}
head_line() { FOUND=1; echo; echo "--- $1  $2  ($3) ---"; }
finding() { case "$1" in OK) echo "  ${G}[OK]${N} $2" ;; WARN) echo "  ${Y}[WARN]${N} $2"; bump 2 ;; BAD) echo "  ${R}[BAD]${N} $2"; bump 2 ;; esac; }

declare -A SEEN
uniq_bins() { local p r; for p in "$@"; do [ -n "$p" ] && [ -x "$p" ] && [ -f "$p" ] || continue; r=$(readlink -f "$p"); [ -n "${SEEN[$r]}" ] && continue; SEEN[$r]=1; echo "$r"; done; }
proc_exes() { local e t; for e in /proc/[0-9]*/exe; do t=$(readlink "$e" 2>/dev/null) || continue; t=${t% (deleted)}; [ "$(basename "$t")" = "$1" ] && echo "$t"; done; }
changelog_has() { local pkg f; if command -v dpkg >/dev/null 2>&1 && pkg=$(dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1) && [ -n "$pkg" ]; then
    for f in /usr/share/doc/"$pkg"/changelog*; do [ -f "$f" ] && { zgrep -q "$2" "$f" 2>/dev/null || grep -q "$2" "$f" 2>/dev/null; } && return 0; done
  elif command -v rpm >/dev/null 2>&1 && pkg=$(rpm -qf "$1" 2>/dev/null | head -1) && [ -n "$pkg" ]; then rpm -q --changelog "$pkg" 2>/dev/null | grep -q "$2" && return 0; fi; return 1; }
stale_master() { # binary argpattern -> 0 if a running process is older than the binary
  local bin real pid exe mt st; real=$(readlink -f "$1"); mt=$(stat -c %Y "$real" 2>/dev/null)
  for pid in $(pgrep -f "$2" 2>/dev/null); do exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    case "$exe" in *"(deleted)") return 0 ;; esac; [ "$(readlink -f "$exe")" = "$real" ] || continue
    st=$(date -d "$(ps -o lstart= -p "$pid")" +%s 2>/dev/null); [ -n "$st" ] && [ -n "$mt" ] && [ "$mt" -gt "$st" ] && return 0; done; return 1; }

echo "===================================================================="
echo " Database RCE (Narrow Grants, Wide Engines) check - $(hostname) - $(date '+%F %T')"
echo "===================================================================="
[ "$(id -u)" -ne 0 ] && echo "${Y}[!] Not root: process and log inspection may be incomplete (use sudo).${N}"

# ------------------------------------------------------------ PostgreSQL
declare -A PGFIX=([14]=25 [15]=20 [16]=16 [17]=12 [18]=7)
pgq() { local db="$1" q="$2"; local -a a=(psql -X -At -F '|' -d "$db" -c "$q")
  [ -n "$PGH" ] && a=(psql -h "$PGH" "${a[@]:1}"); [ -n "$PGP" ] && a=("${a[0]}" -p "$PGP" "${a[@]:1}"); [ -n "$PGU" ] && a=("${a[0]}" -U "$PGU" "${a[@]:1}")
  if [ -z "$PGU" ] && [ -z "$PGH" ] && [ "$(id -u)" -eq 0 ] && command -v runuser >/dev/null 2>&1; then runuser -u postgres -- "${a[@]}" 2>&1; else "${a[@]}" 2>&1; fi; }
FIRST_PG=1
for b in $(uniq_bins /usr/lib/postgresql/*/bin/postgres /usr/pgsql-*/bin/postgres /opt/*/bin/postgres /usr/local/pgsql*/bin/postgres /opt/*/*/bin/postgres "$(command -v postgres)" "$(command -v postmaster)" $(proc_exes postgres)); do
  out=$("$b" --version 2>&1); v=$(parse_ver "$out"); major=${v%%.*}; minor=${v#*.}; minor=${minor%%.*}
  head_line PostgreSQL "${v:-?}" "$b"
  if [ -z "$v" ]; then note "version not parsed"; verdict PostgreSQL "$v" "$b" REVIEW; continue; fi
  bp=0; changelog_has "$b" CVE-2026-116331 && { bp=1; note "package changelog names CVE-2026-116331 (backported fix)"; }
  if [ -n "${PGFIX[$major]}" ]; then
    note "fixed release for this branch: $major.${PGFIX[$major]} (12 Nov 2026)"
    if [ "$minor" -ge "${PGFIX[$major]}" ] || [ "$bp" -eq 1 ]; then V=PATCHED; else V=VULNERABLE; fi
  elif [ "$major" -lt 14 ]; then V=UNSUPPORTED; note "end-of-life branch: no fixed release; upgrade to 18.7 / 17.12 / 16.16 / 15.20 / 14.25 or newer"
  else V=REVIEW; note "branch not in the advisory; confirm it includes the November 2026 fixes"; fi
  if [ "$V" = PATCHED ] && stale_master "$b" 'postgres.*-D|postmaster'; then V=RESTART-REQUIRED; note "running postmaster is older than the binary on disk: restart PostgreSQL"; fi
  if [ "$SQL" -eq 1 ] && [ "$FIRST_PG" -eq 1 ]; then FIRST_PG=0
    if ! command -v psql >/dev/null 2>&1; then finding WARN "psql not found: PostgreSQL SQL checks skipped"
    else
      dbs=$(pgq postgres "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate")
      if [ $? -ne 0 ] || echo "$dbs" | grep -qiE 'error|could not|fatal'; then finding WARN "could not connect with psql (set --pg-user/--pg-host, PGPASSWORD): $(echo "$dbs" | head -1 | cut -c1-120)"
      else
        n=0
        for d in $(pgq postgres "SELECT d.datname FROM pg_database d WHERE d.datallowconn AND NOT d.datistemplate AND (d.datacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(d.datacl) x WHERE x.grantee=0 AND x.privilege_type='TEMPORARY'))"); do
          finding BAD "database $d: TEMPORARY is granted to PUBLIC (every login role can create temp objects) -> REVOKE TEMPORARY ON DATABASE $d FROM PUBLIC"; n=1; done
        while IFS='|' read -r dn rn; do [ -n "$rn" ] && { finding WARN "database $dn: role $rn has explicit TEMPORARY - confirm it is needed"; n=1; }; done < <(pgq postgres "SELECT d.datname, pg_get_userbyid(x.grantee) FROM pg_database d, aclexplode(d.datacl) x WHERE x.privilege_type='TEMPORARY' AND x.grantee<>0 AND d.datallowconn AND NOT d.datistemplate")
        for d in $dbs; do
          while IFS= read -r ln; do [ -n "$ln" ] && { finding BAD "database $d: user-defined aggregate with a sort operator: $ln - review owner"; n=1; }; done < <(pgq "$d" "SELECT p.proname||' (owner '||pg_get_userbyid(p.proowner)||', sortop '||ag.aggsortop::regoperator||')' FROM pg_aggregate ag JOIN pg_proc p ON p.oid=ag.aggfnoid WHERE ag.aggsortop<>0 AND p.pronamespace NOT IN ('pg_catalog'::regnamespace)")
        done
        [ "$n" -eq 0 ] && finding OK "no PUBLIC TEMPORARY grants or user aggregates with SORTOP found"
      fi
    fi
  fi
  verdict PostgreSQL "$v" "$b" "$V"
done

# ------------------------------------------------------------ MySQL / MariaDB
FIRST_MY=1
for b in $(uniq_bins "$(command -v mysqld)" "$(command -v mariadbd)" /usr/sbin/mysqld /usr/local/mysql/bin/mysqld /usr/libexec/mysqld /usr/sbin/mariadbd /opt/*/bin/mysqld $(proc_exes mysqld) $(proc_exes mariadbd)); do
  first=$("$b" --version 2>&1 | head -1)
  if echo "$first $b" | grep -qi mariadb; then head_line MariaDB "" "$b"; note "$first"; note "MariaDB is not covered by the advisory"; verdict MariaDB "" "$b" NOT-LISTED; continue; fi
  v=$(echo "$first" | sed 's/^.*Ver[[:space:]]*//' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  head_line MySQL "${v:-?}" "$b"; note "$first"
  if [ -z "$v" ]; then V=REVIEW; note "version not parsed"
  else IFS=. read -r a1 a2 a3 <<<"$v"
    if [ "$(vn "$a1" "$a2" "$a3")" -ge "$(vn 26 7 0)" ] && [ "$(vn "$a1" "$a2" "$a3")" -le "$(vn 26 7 1)" ]; then V=VULNERABLE; note "CVE-2026-101786: affected range 26.7.0-26.7.1; apply the 20 Oct 2026 Oracle MySQL update"
    else V=OUTSIDE-RANGE; note "not in the advisory's affected range (26.7.0-26.7.1); exact fixed build not published in reviewed sources - confirm against Oracle's October 2026 CPU"; fi
    if [ "$V" != VULNERABLE ] && stale_master "$b" mysqld; then V=RESTART-REQUIRED; note "running mysqld is older than the binary on disk: restart MySQL"; fi
  fi
  if [ "$SQL" -eq 1 ] && [ "$FIRST_MY" -eq 1 ]; then FIRST_MY=0
    if ! command -v mysql >/dev/null 2>&1; then finding WARN "mysql client not found: MySQL SQL checks skipped"
    else
      args=(mysql); [ -n "$MYDEF" ] && args=(mysql "--defaults-file=$MYDEF"); args+=(-N -B -e)
      res=$("${args[@]}" "SELECT GRANTEE, CONCAT('schema:', TABLE_SCHEMA) FROM information_schema.SCHEMA_PRIVILEGES WHERE PRIVILEGE_TYPE='CREATE TEMPORARY TABLES' UNION ALL SELECT GRANTEE, 'global' FROM information_schema.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='CREATE TEMPORARY TABLES'" 2>&1)
      if [ $? -ne 0 ]; then finding WARN "could not connect with mysql client (use --mysql-defaults-file): $(echo "$res" | head -1 | cut -c1-120)"
      elif [ -z "$res" ]; then finding OK "no account holds CREATE TEMPORARY TABLES"
      else while IFS=$'\t' read -r who scope; do finding WARN "account $who can CREATE TEMPORARY TABLES ($scope) - revoke where not needed"; done <<<"$res"; fi
    fi
  fi
  verdict MySQL "$v" "$b" "$V"
done

# ------------------------------------------------------------ Oracle Database
declare -A HOMES
[ -n "$ORACLE_HOME" ] && HOMES[$ORACLE_HOME]=1
[ -f /etc/oratab ] && while IFS=: read -r s h rest; do case "$s" in \#*|"") ;; *) [ "${h#/}" != "$h" ] && HOMES[$h]=1 ;; esac; done < /etc/oratab
for e in $(proc_exes oracle); do h=${e%/bin/oracle}; [ "$h" != "$e" ] && HOMES[$h]=1; done
ORA_SEEN=0
oracle_eval() { # label version
  local v="$2" M m p V; IFS=. read -r M m p <<<"$v"; p=${p:-0}; ORA_SEEN=1
  head_line "Oracle Database" "$v" "$1"
  if { [ "$M" = 19 ] && [ "$m" -le 32 ]; } || { [ "$M" = 21 ] && [ "$m" -le 24 ]; } || { [ "$M" = 23 ] && [ "$(vn 23 "$m" "$p")" -ge "$(vn 23 4 0)" ] && [ "$(vn 23 "$m" "$p")" -le "$(vn 23 26 3)" ]; }; then
    V=VULNERABLE; note "CVE-2026-114819 (Oracle Text, CVSS 9.9): affected 19.3-19.32 / 21.3-21.24 / 23.4.0-23.26.3; apply the November 2026 CPU (17 Nov)"
    note "version comes from sqlplus -V (home's release update); confirm with 'opatch lspatches' and 'datapatch -verbose' - an interim patch may cover it"
  elif [ "$M" = 19 ] || [ "$M" = 21 ] || [ "$M" = 23 ]; then V=OUTSIDE-RANGE; note "above the advisory's affected range; confirm the November 2026 CPU is in the home with opatch lspatches"
  else V=REVIEW; note "release not covered by the advisory (likely out of support); confirm with Oracle"; fi
  verdict "Oracle Database" "$v" "$1" "$V"; }
for h in "${!HOMES[@]}"; do
  [ -x "$h/bin/sqlplus" ] || continue
  o=$(ORACLE_HOME="$h" LD_LIBRARY_PATH="$h/lib" "$h/bin/sqlplus" -V 2>&1); v=$(echo "$o" | grep -oE 'Version[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  [ -n "$v" ] && oracle_eval "$h" "$v"
done
[ -n "$ORAV" ] && oracle_eval "(--oracle-version)" "$ORAV"
if [ "$ORA_SEEN" -eq 0 ] && { [ ${#HOMES[@]} -gt 0 ] || pgrep -f '^ora_pmon' >/dev/null 2>&1; }; then
  head_line "Oracle Database" "" "${!HOMES[*]}"; note "Oracle detected but version not read; run as the oracle user or pass --oracle-version"; verdict "Oracle Database" "" "" REVIEW; fi

# ------------------------------------------------------------ ORDS
ords_eval() { local v="$2" V; head_line "Oracle REST Data Services" "${v:-?}" "$1"
  if [ -z "$v" ]; then V=REVIEW; note "version not parsed"; IFS=. read -r a b c <<<"0.0.0"
  else IFS=. read -r a b c <<<"$v"; n=$(vn "$a" "$b" "$c")
    if [ "$n" -ge "$(vn 24 2 0)" ] && [ "$n" -le "$(vn 26 2 1)" ]; then V=VULNERABLE; note "CVE-2026-91609 (GraphQL): affected 24.2.0-26.2.1; apply the October 2026 CPU. Part of the unauthenticated Oracle chain"
    elif [ "$n" -lt "$(vn 24 2 0)" ]; then V=REVIEW; note "older than the listed range; out of support - upgrade"
    else V=OUTSIDE-RANGE; note "above the advisory's affected range"; fi; fi
  verdict "Oracle REST Data Services" "$v" "$1" "$V"; }
for b in $(uniq_bins "$(command -v ords)" /opt/oracle/ords/bin/ords /usr/local/bin/ords /u01/ords/bin/ords /opt/*/ords/bin/ords); do
  ords_eval "$b" "$(timeout 60 "$b" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"; done
[ -n "$ORDSV" ] && ords_eval "(--ords-version)" "$ORDSV"
for w in $(find /opt /u01 -maxdepth 5 -name ords.war 2>/dev/null | head -5); do
  head_line "Oracle REST Data Services" "" "$w"; note "ords.war found (Tomcat/WebLogic deployment): read its version with 'java -jar ords.war version' or pass --ords-version"; verdict ORDS "" "$w" REVIEW; done

# ------------------------------------------------------------ ClickHouse
FIRST_CH=1
for b in $(uniq_bins "$(command -v clickhouse-server)" "$(command -v clickhouse)" /usr/bin/clickhouse-server /usr/bin/clickhouse $(proc_exes clickhouse-server) $(proc_exes clickhouse)); do
  v=$("$b" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
  head_line ClickHouse "${v:-?}" "$b"; note "no CVE and no confirmed vendor fix; researcher tested 26.7.5.10 (shell obtained via format_binary_max_string_size = 0)"
  hit=$(grep -lsE 'format_binary_max_string_size' /etc/clickhouse-server/*.xml /etc/clickhouse-server/*.d/*.xml /etc/clickhouse-server/*.yaml /etc/clickhouse-server/*.d/*.yaml 2>/dev/null | tr '\n' ' ')
  if [ -n "$hit" ]; then finding OK "setting mentioned in config (review it is constrained read-only): $hit"
  else finding BAD "no constraint on format_binary_max_string_size in config files - add <readonly/> constraint (Vairav interim suggestion)"; fi
  if [ "$SQL" -eq 1 ] && [ "$FIRST_CH" -eq 1 ]; then FIRST_CH=0
    if command -v clickhouse-client >/dev/null 2>&1; then
      r=$(clickhouse-client --query "SELECT setting_name, min, max, writability FROM system.settings_profile_elements WHERE setting_name='format_binary_max_string_size' FORMAT TSV" 2>/dev/null)
      [ -n "$r" ] && finding OK "constraint in access control: $r" || finding WARN "no SQL-defined constraint found (or cannot connect)"
      n=$(clickhouse-client --query "SELECT count() FROM system.query_log WHERE query ILIKE '%format_binary_max_string_size%' AND query NOT ILIKE '%system.query_log%'" 2>/dev/null)
      [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null && finding BAD "$n query_log entries mention format_binary_max_string_size - review who ran them"
    else finding WARN "clickhouse-client not found: SQL checks skipped"; fi
  fi
  verdict ClickHouse "$v" "$b" NO-FIX
done

# ------------------------------------------------------------ listeners
echo; echo "--- Database ports listening ---"
declare -A PN=([5432]="PostgreSQL" [3306]="MySQL" [33060]="MySQL X" [1521]="Oracle listener" [8123]="ClickHouse HTTP" [9000]="ClickHouse native" [9440]="ClickHouse TLS" [8443]="HTTPS (ORDS?)")
NEXT=0; LIST=""
if command -v ss >/dev/null 2>&1; then LIST=$(ss -H -ltn | awk '{print $4}' | sed -E 's/^(.*):([0-9]+)$/\1 \2/')
elif command -v netstat >/dev/null 2>&1; then LIST=$(netstat -an | awk '/LISTEN/ {print $4}' | sed -E 's/^(.*):([0-9]+)$/\1 \2/')
else for f in /proc/net/tcp /proc/net/tcp6; do [ -r "$f" ] && while read -r _ la _ st _; do [ "$st" = 0A ] || continue; ip=${la%%:*}; hp=${la##*:}
    case "$ip" in 0100007F|00000000000000000000000001000000) a=127.0.0.1 ;; *) a=other ;; esac; LIST+="$a $((16#$hp))"$'\n'; done < "$f"; done; fi
SEENP=""; while read -r addr port; do [ -n "$port" ] && [ -n "${PN[$port]}" ] || continue; case " $SEENP " in *" $addr:$port "*) continue ;; esac; SEENP+=" $addr:$port"
  case "$addr" in 127.0.0.1|"[::1]"|::1) echo "  ${G}${PN[$port]}  $addr:$port  loopback only${N}" ;; *) echo "  ${R}${PN[$port]}  $addr:$port  NETWORK-REACHABLE: restrict to app servers/admin hosts${N}"; NEXT=1 ;; esac; done <<<"$LIST"
[ -z "$SEENP" ] && echo "  none of the standard database ports found listening"
[ "$NEXT" -eq 1 ] && bump 2

# ------------------------------------------------------------ ORDS URL
if [ -n "$ORDSURL" ]; then echo; echo "--- ORDS URL (reachability only) ---"
  code=$(curl -sk -o /dev/null -m 8 -w '%{http_code}' "$ORDSURL" 2>/dev/null)
  if [ -n "$code" ] && [ "$code" != 000 ]; then echo "  ${Y}$ORDSURL reachable (HTTP $code) - confirm it is not exposed to untrusted networks; patch ORDS and Oracle${N}"; bump 2; else echo "  $ORDSURL: not reachable from this host"; fi; fi

# ------------------------------------------------------------ hunt
if [ "$HUNT" -eq 1 ]; then echo; echo "--- Hunt (local logs; review dates against 20 Oct 2026 onward) ---"; HITS=0
  FILES=$(ls /var/log/postgresql/* /var/log/mysql/* /var/log/mysqld.log* /var/lib/mysql/*.err /var/log/clickhouse-server/*.log /var/lib/pgsql/*/data/log/* /var/log/messages /var/log/syslog 2>/dev/null | grep -v '\.gz$')
  for f in $FILES; do [ -f "$f" ] || continue
    m=$(grep -iE 'terminated by signal 11|got signal 11|format_binary_max_string_size|CREATE AGGREGATE.*SORTOP' "$f" 2>/dev/null | head -5)
    [ -n "$m" ] && { HITS=1; while IFS= read -r l; do echo "  ${Y}$f: ${l:0:200}${N}"; done <<<"$m"; }; done
  SH=$(ps -eo pid,ppid,user,comm | awk 'NR==FNR{if(NR>1)c[$1]=$4;next} FNR>1 && $4 ~ /^(sh|bash|dash|curl|wget|python3?|perl|nc|ncat|socat)$/ && c[$2] ~ /^(postgres|postmaster|mysqld|mariadbd|clickhouse|oracle|tnslsnr)/ {print "  PID "$1": "c[$2]" spawned "$4" (user "$3")"}' <(ps -eo pid,ppid,user,comm) <(ps -eo pid,ppid,user,comm))
  [ -n "$SH" ] && { echo "${R}$SH${N}"; bump 1; }
  [ "$HITS" -eq 1 ] && bump 2
  [ "$HITS" -eq 0 ] && [ -z "$SH" ] && echo "  ${G}nothing suspicious found in local logs or process tree${N}"; fi

echo; echo "Note: heuristics only. Version and privilege checks cannot prove a host is safe. Patch, restart, and remove unneeded rights."
[ "$FOUND" -eq 0 ] && { echo "${C}[i] No PostgreSQL, MySQL, Oracle, ORDS or ClickHouse installation found.${N}"; exit 3; }
exit $WORST
