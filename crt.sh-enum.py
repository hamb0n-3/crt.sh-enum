#!/usr/bin/env python3
# jr: crt.sh client with logging + enum progress + strict AND/OR targets

from __future__ import annotations
import argparse
import csv
import datetime as dt
import json
import logging
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple, Set

# ---------------------------
# hard-coded settings (tweak)
# ---------------------------
BASE_URL: str = "https://crt.sh/"
DEFAULT_OUTPUT_DIR: Path = Path("reports")
DEFAULT_MAX_WORKERS: int = 4
DEFAULT_TIMEOUT: int = 30
DEFAULT_RETRIES: int = 3
RETRY_BACKOFF_SECS: float = 1.5
DEDUPE_BY_CERT: bool = True
INCLUDE_EXPIRED: bool = True
REQUEST_HEADERS: Dict[str, str] = {"User-Agent": "Mozilla/1.1 ()"}

# enum presets
ENUM_KEYWORDS: List[str] = [
    "dev","stage","staging","test","qa","uat","int","prod","preprod","sandbox","alpha","beta",
    "admin","portal","sso","okta","auth","login","idp","oauth","vault",
    "api","gateway","edge","cdn","static","assets","files","repo","git","gitlab","bitbucket",
    "k8s","kubernetes","grafana","kibana","monitor","elastic","es","metrics",
    "mail","smtp","imap","mx","owa","webmail","rdp","citrix","vpn","fw",
    "jira","confluence","jenkins","sonarqube","nexus",
    "db","mysql","mssql","postgres","pg","oracle","mongo","redis",
    "billing","payments","pay","checkout","shop","store","backup","legacy"
]
ENUM_PATTERNS_PER_TARGET: List[str] = [
    "%{T}%", "%. {T}".replace(" ",""), "%.api.{T}%", "%.admin.{T}%", "%.auth.{T}%", "%.login.{T}%"
]

CSV_FIELDS: List[str] = [
    "name","common_name","issuer_name","crtsh_id",
    "not_before","not_after","logged_at","is_expired",
    "source_query","input_group","input_term"
]

# ---------------------------
# libs (requests/tqdm optional)
# ---------------------------
try:
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:
    import urllib.request
    _HAS_REQUESTS = False

try:
    from tqdm import tqdm  # type: ignore
    _HAS_TQDM = True
except Exception:
    _HAS_TQDM = False

# ---------------------------
# logging
# ---------------------------
def setup_logging(out_dir: Path, base: str, level: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    log_path = out_dir / f"{base}-{ts}.log"

    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    for h in list(logger.handlers):
        logger.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(getattr(logging, level.upper(), logging.INFO))
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(getattr(logging, level.upper(), logging.INFO))
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    logging.info("logging initialized")
    return log_path

# ---------------------------
# helpers
# ---------------------------
def to_lazy_like(term: str) -> str:
    s = (term or "").strip()
    if not s:
        return "%"
    s = s.replace("*", "%")
    if "%" not in s:
        s = f"%{s}%"
    return s

def build_crtsh_url(q: str, include_expired: bool, dedupe: bool) -> str:
    params = {"q": q, "output": "json"}
    if dedupe:
        params["deduplicate"] = "Y"
    if not include_expired:
        params["exclude"] = "expired"
    return f"{BASE_URL}?{urllib.parse.urlencode(params)}"

def now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _http_get_json(url: str, timeout: int) -> Any:
    if _HAS_REQUESTS:
        r = requests.get(url, headers=REQUEST_HEADERS, timeout=timeout)
        r.raise_for_status()
        return json.loads(r.text)
    else:
        req = urllib.request.Request(url, headers=REQUEST_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)

# ---------------------------
# fetching
# ---------------------------
def fetch_crtsh_once(q: str, timeout: int) -> List[Dict[str, Any]]:
    url = build_crtsh_url(q, INCLUDE_EXPIRED, DEDUPE_BY_CERT)
    logging.debug(f"http GET: {url}")
    return _http_get_json(url, timeout=timeout)

def fetch_crtsh(q: str, timeout: int, retries: int) -> List[Dict[str, Any]]:
    attempt = 0
    while True:
        try:
            return fetch_crtsh_once(q, timeout)
        except Exception as e:
            attempt += 1
            logging.warning(f"query failed (attempt {attempt}): {q} :: {e}")
            if attempt > retries:
                logging.error(f"giving up on: {q}")
                return []
            time.sleep(RETRY_BACKOFF_SECS * attempt)

# ---------------------------
# normalize
# ---------------------------
def flatten_records(raw: List[Dict[str, Any]], source_query: str,
                    input_group: int, input_term: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in raw:
        name_val = (item.get("name_value") or "").strip()
        names = [n.strip() for n in name_val.splitlines() if n.strip()] or [""]
        for nm in names:
            not_before = item.get("not_before")
            not_after = item.get("not_after")
            is_expired = False
            try:
                if not_after:
                    is_expired = dt.datetime.fromisoformat(
                        not_after.replace("Z", "+00:00")
                    ) < dt.datetime.now(dt.timezone.utc)
            except Exception:
                pass
            rows.append({
                "name": nm,
                "common_name": item.get("common_name"),
                "issuer_name": item.get("issuer_name"),
                "crtsh_id": item.get("id"),
                "not_before": not_before,
                "not_after": not_after,
                "logged_at": item.get("entry_timestamp"),
                "is_expired": is_expired,
                "source_query": source_query,
                "input_group": input_group,
                "input_term": input_term
            })
    return rows

def dedupe_rows(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Set[Tuple[str, Any]] = set()
    out: List[Dict[str, Any]] = []
    for r in rows:
        key = (str(r.get("name") or "").lower(), r.get("crtsh_id"))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out

# ---------------------------
# enum expansion and target logic
# ---------------------------
def enum_queries_for_target(target: str) -> List[str]:
    t = target.strip()
    if not t:
        return []
    qs: List[str] = []
    for p in ENUM_PATTERNS_PER_TARGET:
        qs.append(p.replace("{T}", t))
    for kw in ENUM_KEYWORDS:
        qs.append(f"%{kw}%.{t}%")
        qs.append(f"%.{kw}.{t}%")
    qs.append(to_lazy_like(t))
    # normalize * and wrap if needed
    return [to_lazy_like(x) for x in qs]

def parse_target_groups(target_args: List[str]) -> List[List[str]]:
    groups: List[List[str]] = []
    for raw in target_args:
        terms = [s for s in (x.strip() for x in raw.split(",")) if s]
        if terms:
            groups.append(terms)
    return groups  # OR inside each list; multiple lists are AND

def norm_name(n: str) -> str:
    return (n or "").strip().lower()

def and_across_groups(all_group_rows: List[Dict[str, Any]], group_count: int) -> List[Dict[str, Any]]:
    # jr: strict AND across groups by DNS name (case-insensitive)
    if group_count <= 1:
        return all_group_rows
    sets: List[Set[str]] = [set() for _ in range(group_count)]
    for r in all_group_rows:
        g = int(r.get("input_group") or 0) - 1
        if 0 <= g < group_count:
            sets[g].add(norm_name(r.get("name") or ""))
    if not sets:
        return []
    must_have = sets[0].copy()
    for s in sets[1:]:
        must_have &= s
    return [r for r in all_group_rows if norm_name(r.get("name") or "") in must_have]

# ---------------------------
# progress
# ---------------------------
class Progress:
    # jr: tqdm if available, else minimal ETA
    def __init__(self, total: int, enabled: bool):
        self.total = max(0, total)
        self.enabled = enabled
        self.done = 0
        self.start = time.time()
        self.last_print = 0.0
        self.pb = None
        if enabled and _HAS_TQDM and self.total > 0:
            self.pb = tqdm(total=self.total, unit="req", desc="enum", leave=False)

    def update(self, n: int = 1):
        self.done += n
        if self.pb:
            self.pb.update(n)
        elif self.enabled and self.total > 0:
            now = time.time()
            if now - self.last_print >= 0.5 or self.done == self.total:
                elapsed = now - self.start
                rate = self.done / elapsed if elapsed > 0 else 0
                remaining = self.total - self.done
                eta = int(remaining / rate) if rate > 0 else -1
                eta_s = f"{eta}s" if eta >= 0 else "?"
                print(f"\r[enum] {self.done}/{self.total} ~ {rate:.2f} r/s | ETA {eta_s}", end="", file=sys.stderr)
                self.last_print = now
                if self.done == self.total:
                    print(file=sys.stderr)

    def close(self):
        if self.pb:
            self.pb.close()

# ---------------------------
# task runner
# ---------------------------
def build_tasks(groups: List[List[str]], enum_mode: bool) -> List[Tuple[int, str, str]]:
    # returns list of (group_id, query, term)
    tasks: List[Tuple[int, str, str]] = []
    for gi, terms in enumerate(groups, start=1):
        for term in terms:
            if enum_mode:
                for q in enum_queries_for_target(term):
                    tasks.append((gi, q, term))
            else:
                tasks.append((gi, to_lazy_like(term), term))
    return tasks

def run_tasks(tasks: List[Tuple[int, str, str]], timeout: int, retries: int,
              max_workers: int, progress: Progress | None = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not tasks:
        return rows
    logging.info(f"running {len(tasks)} concurrent requests (workers={max_workers})")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(fetch_crtsh, q, timeout, retries): (gi, q, term) for (gi, q, term) in tasks}
        for fut in as_completed(futs):
            gi, q, term = futs[fut]
            try:
                data = fut.result()
                rows.extend(flatten_records(data, q, input_group=gi, input_term=term))
            except Exception as e:
                logging.error(f"task error: {q} :: {e}")
            finally:
                if progress:
                    progress.update(1)
    return rows

def run_direct_queries(queries: List[str], timeout: int, retries: int,
                       max_workers: int) -> List[Dict[str, Any]]:
    qs = [to_lazy_like(q.strip()) for q in queries if q and q.strip()]
    if not qs:
        return []
    rows: List[Dict[str, Any]] = []
    logging.info(f"running direct queries: {len(qs)}")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(fetch_crtsh, q, timeout, retries): q for q in qs}
        for fut in as_completed(futs):
            q = futs[fut]
            try:
                data = fut.result()
                rows.extend(flatten_records(data, q, input_group=0, input_term=q))
            except Exception as e:
                logging.error(f"direct query error: {q} :: {e}")
    return rows

# ---------------------------
# reports
# ---------------------------
def ensure_outdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

def safe_basename(s: str) -> str:
    return "".join(c for c in s if c.isalnum() or c in ("-","_",".")) or "report"

def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in CSV_FIELDS})

def write_json(path: Path, rows: List[Dict[str, Any]], meta: Dict[str, Any]) -> None:
    names = {norm_name(r["name"]) for r in rows}
    cert_ids = {r["crtsh_id"] for r in rows}
    nb = [r["not_before"] for r in rows if r.get("not_before")]
    na = [r["not_after"] for r in rows if r.get("not_after")]
    report = {
        "meta": meta,
        "summary": {
            "unique_dns_names": len(names),
            "unique_cert_ids": len(cert_ids),
            "earliest_not_before": min(nb) if nb else None,
            "latest_not_after": max(na) if na else None
        },
        "items": rows
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

# ---------------------------
# args / main
# ---------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crtsh-enum",
        description="crt.sh OSINT enum with AND/OR targets, logging, and progress"
    )
    p.add_argument("-e","--enum", action="store_true",
                   help="enable preset OSINT enumeration (comprehensive)")
    p.add_argument("-q","--query", action="append", default=[],
                   help="direct crt.sh query (LIKE; accepts % and *) [can repeat]")
    p.add_argument("-t","--target", action="append", default=[],
                   help="targets; commas = OR in a group; multiple -t = AND across groups")
    p.add_argument("--out-dir", default=str(DEFAULT_OUTPUT_DIR), help="output directory")
    p.add_argument("--basename", default=None, help="base filename for output files")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    p.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS)
    p.add_argument("--no-json", action="store_true", help="skip JSON report")
    p.add_argument("--no-csv", action="store_true", help="skip CSV report")
    p.add_argument("--no-expired", action="store_true", help="exclude expired certs")
    p.add_argument("--no-dedupe", action="store_true", help="do not ask server to dedupe")
    p.add_argument("--no-progress", action="store_true", help="disable enum progress bar")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    return p

def main() -> None:
    global INCLUDE_EXPIRED, DEDUPE_BY_CERT
    ap = build_arg_parser()
    args = ap.parse_args()

    INCLUDE_EXPIRED = not args.no_expired
    DEDUPE_BY_CERT = not args.no_dedupe

    out_dir = Path(args.out_dir)
    ensure_outdir(out_dir)
    base = safe_basename(args.basename or ("enum" if args.enum else "query"))
    log_path = setup_logging(out_dir, base, args.log_level)

    logging.info(f"out_dir={out_dir} base={base} log={log_path}")
    logging.info(f"expired={'include' if INCLUDE_EXPIRED else 'exclude'}, server_dedupe={DEDUPE_BY_CERT}")
    logging.info(f"timeout={args.timeout} retries={args.retries} workers={args.workers}")

    have_targets = bool(args.target)
    have_queries = bool(args.query)
    if not have_targets and not have_queries:
        logging.error("need at least one -t target or -q query")
        ap.print_help(sys.stderr)
        sys.exit(2)

    all_rows: List[Dict[str, Any]] = []

    # direct queries first (no special progress)
    if have_queries:
        dq = run_direct_queries(args.query, args.timeout, args.retries, args.workers)
        all_rows.extend(dq)
        logging.info(f"direct queries rows: {len(dq)}")

    # target mode
    if have_targets:
        groups = parse_target_groups(args.target)
        if not groups:
            logging.error("no valid targets parsed")
            sys.exit(2)

        tasks = build_tasks(groups, enum_mode=args.enum)
        progress = Progress(total=len(tasks), enabled=(args.enum and not args.no_progress))
        group_rows = run_tasks(tasks, args.timeout, args.retries, args.workers, progress=progress)
        progress.close()
        logging.info(f"target tasks rows (pre-AND): {len(group_rows)}")

        # enforce AND across groups
        and_rows = and_across_groups(group_rows, group_count=len(groups))
        logging.info(f"rows after AND across groups: {len(and_rows)}")
        all_rows.extend(and_rows)

    final_rows = dedupe_rows(all_rows)
    final_rows.sort(key=lambda r: (str(r["name"]).lower(), r.get("not_after") or "", str(r.get("crtsh_id") or "")))

    ts = dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    json_path = out_dir / f"{base}-{ts}.json"
    csv_path = out_dir / f"{base}-{ts}.csv"

    meta = {
        "generated_at": now_iso(),
        "settings": {
            "include_expired": INCLUDE_EXPIRED,
            "server_dedupe": DEDUPE_BY_CERT,
            "timeout": args.timeout,
            "retries": args.retries,
            "workers": args.workers,
            "log_file": str(log_path)
        },
        "inputs": {
            "enum_mode": args.enum,
            "targets": args.target,
            "queries": args.query
        },
        "counts": {"rows": len(final_rows)}
    }

    if not args.no_json:
        write_json(json_path, final_rows, meta)
        print(f"[+] wrote JSON  -> {json_path}")
        logging.info(f"json report: {json_path}")
    if not args.no_csv:
        write_csv(csv_path, final_rows)
        print(f"[+] wrote CSV   -> {csv_path}")
        logging.info(f"csv report: {csv_path}")

    if not final_rows:
        logging.info("no results (try broader targets or enable --enum)")
        print("[i] no results", file=sys.stderr)

if __name__ == "__main__":
    main()
