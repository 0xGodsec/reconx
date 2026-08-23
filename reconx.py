#!/usr/bin/env python3
"""
reconx - a lean, fast, accurate reconnaissance orchestrator.

An AutoRecon alternative built for OSCP methodology: it discovers ports fast,
confirms them for accuracy, runs *targeted* per-service enumeration concurrently,
then prints a RANKED "what to look at first" summary instead of drowning you in
200 files. You still do the thinking; reconx does the parallel legwork.

Design goals
------------
  speed     : rustscan (if present) or a fast async connect-scan finds ports in
              seconds; heavy enumeration runs in the background while you work.
  accuracy  : two-pass port confirmation + nmap -sCV service/version detection so
              you don't chase phantom ports.
  lean      : curated commands per service, not "run everything on everything".
  yours     : stdlib only (Python 3.8+), single file, easy to read and hack
              mid-exam. Every external tool is optional with graceful fallback.

Ethics: authorized targets only (your lab, HTB/PG/THM, or written permission).

Usage
-----
  python3 reconx.py 10.10.10.10
  python3 reconx.py 10.10.10.0/24 --ping-sweep
  python3 reconx.py target.htb -o loot/ --top-ports 2000
  python3 reconx.py 10.10.10.10 --dry-run        # print the plan, run nothing
  python3 reconx.py 10.10.10.10 --no-udp --quick

Author: built with OffSec-OS (OSCP mentor). MIT-style, hack freely.
"""

import argparse
import asyncio
import functools
import ipaddress
import itertools
import json
import os
import re
import shlex
import shutil
import signal
import sys
import time
from datetime import datetime

# --------------------------------------------------------------------------- #
#  Terminal colours
# --------------------------------------------------------------------------- #
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; CY = "\033[36m"; W = "\033[37m"; GR = "\033[90m"
    BOLD = "\033[1m"; DIM = "\033[2m"; END = "\033[0m"

    @classmethod
    def strip(cls):
        for k in list(vars(cls)):
            if not k.startswith("_") and isinstance(getattr(cls, k), str) and getattr(cls, k).startswith("\033"):
                setattr(cls, k, "")
        # module-level colour maps captured the old values at import time - reset them
        for d in (SEV_COLOR,):
            for key in d:
                d[key] = ""


def ts():
    return datetime.now().strftime("%H:%M:%S")


def info(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.B}[*]{C.END} {msg}")
def good(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.G}[+]{C.END} {msg}")
def warn(msg):  print(f"{C.GR}[{ts()}]{C.END} {C.Y}[!]{C.END} {msg}")
def bad(msg):   print(f"{C.GR}[{ts()}]{C.END} {C.R}[-]{C.END} {msg}")


# --------------------------------------------------------------------------- #
#  Severity model for the findings engine
# --------------------------------------------------------------------------- #
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
SEV_COLOR = {"CRITICAL": C.R + C.BOLD, "HIGH": C.R, "MEDIUM": C.Y, "INFO": C.CY}


class Finding:
    __slots__ = ("sev", "service", "port", "text")

    def __init__(self, sev, service, port, text):
        self.sev = sev
        self.service = service
        self.port = port
        self.text = text

    def __repr__(self):
        p = f":{self.port}" if self.port else ""
        return f"[{self.sev}] {self.service}{p} - {self.text}"


def _print_live_finding(f):
    col = SEV_COLOR.get(f.sev, "")
    p = f":{f.port}" if f.port else ""
    print(f"{C.GR}[{ts()}]{C.END} {col}[{f.sev}]{C.END} {C.DIM}{f.service}{p}{C.END}  {f.text}")


class FindingsList(list):
    """A list of Finding that prints each *new* one live as it's appended,
    instead of only ever surfacing findings in the final summary. De-duped
    on the same (sev, service, port, text) key print_summary/write_markdown
    already use, so re-registering the same job (guess pass + confirm pass)
    or a rerun rule never double-prints. Optionally persists new findings to
    a StateStore so a job that's skipped on --resume (because it already
    completed in an earlier, interrupted run) doesn't silently vanish from
    NOTES.md - findings, unlike command output, only ever live in memory
    otherwise."""

    def __init__(self, *a, state_store=None, **kw):
        super().__init__(*a, **kw)
        self._seen = set()
        self._state_store = state_store

    def append(self, finding):
        key = (finding.sev, finding.service, finding.port, finding.text)
        if key in self._seen:
            return
        super().append(finding)
        self._seen.add(key)
        _print_live_finding(finding)
        if self._state_store:
            self._state_store.record_finding(finding)

    def seed(self, finding):
        """Add a finding restored from persisted state, without a live
        reprint or re-recording it - it's already in the state file."""
        key = (finding.sev, finding.service, finding.port, finding.text)
        if key not in self._seen:
            super().append(finding)
            self._seen.add(key)


# --------------------------------------------------------------------------- #
#  Tool availability (graceful degradation)
# --------------------------------------------------------------------------- #
def which(name):
    return shutil.which(name) is not None


TOOLS = {}
def refresh_tools():
    for t in ("rustscan", "nmap", "whatweb", "feroxbuster", "gobuster", "nikto",
              "curl", "enum4linux-ng", "enum4linux", "nxc", "netexec", "crackmapexec",
              "smbclient", "rpcclient", "ldapsearch",
              "snmpwalk", "onesixtyone", "showmount", "dig",
              "redis-cli", "psql", "openssl", "ncat", "nc",
              "searchsploit",
              "impacket-GetUserSPNs", "GetUserSPNs.py",
              "impacket-GetNPUsers", "GetNPUsers.py",
              "bloodhound-python", "bloodhound-ce-python",
              "smtp-user-enum"):
        TOOLS[t] = which(t)


# --------------------------------------------------------------------------- #
#  Command runner
# --------------------------------------------------------------------------- #
class Runner:
    def __init__(self, outdir, dry_run=False, timeout=900, verbose=False, resume=False):
        self.outdir = outdir
        self.dry_run = dry_run
        self.timeout = timeout
        self.verbose = verbose
        self.resume = resume
        self.plan = []          # for --dry-run
        self.sem = None         # set once loop exists

    async def run(self, cmd, outfile=None, label=None, timeout=None, managed_outfile=False):
        """Run a shell command, tee output to a file, return (rc, stdout+stderr).

        managed_outfile=True means cmd itself writes to `outfile` (e.g.
        feroxbuster's own -o flag) rather than us capturing stdout - we only
        use `outfile` for --resume detection and to recover output if stdout
        was empty, and never overwrite what the command wrote."""
        label = label or cmd.split()[0]
        if self.dry_run:
            self.plan.append((label, cmd, outfile))
            return 0, ""
        if self.resume and outfile:
            path = os.path.join(self.outdir, outfile)
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                stale = False
                cached = None
                if not managed_outfile:
                    with open(path, errors="replace") as f:
                        cached = f.read()
                    # strip the "# cmd: ...\n\n" header we write below, if present,
                    # and use it to detect a changed command (e.g. --mode/--wordlist
                    # changed since the cached file was written) rather than
                    # blindly trusting whatever's on disk at this path.
                    if cached.startswith("# cmd:") and "\n\n" in cached:
                        header, rest = cached.split("\n\n", 1)
                        if header[len("# cmd: "):] != cmd:
                            stale = True
                        cached = rest
                else:
                    # managed-outfile tools (feroxbuster -o, ...) don't write a
                    # header themselves, so we keep a small sidecar recording
                    # the command that produced them. A missing sidecar means
                    # an older reconx wrote this file - trust the cache rather
                    # than treat pre-existing loot as stale.
                    meta_path = path + ".reconx-meta.json"
                    if os.path.isfile(meta_path):
                        try:
                            with open(meta_path) as f:
                                meta = json.load(f)
                            if meta.get("cmd") != cmd:
                                stale = True
                        except (ValueError, OSError):
                            pass
                if not stale:
                    if self.verbose:
                        info(f"resume: {C.DIM}skipping {label}, using cached {path}{C.END}")
                    if managed_outfile:
                        with open(path, errors="replace") as f:
                            cached = f.read()
                    return 0, cached
                if self.verbose:
                    info(f"resume: {C.DIM}cached {path} is from a different command, re-running {label}{C.END}")
        async with self.sem:
            if self.verbose:
                info(f"run: {C.DIM}{cmd}{C.END}")
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    preexec_fn=os.setsid,
                )
                try:
                    out, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout or self.timeout)
                except asyncio.TimeoutError:
                    # cmd runs via a shell, so proc.kill() would only kill the
                    # shell - tools that fork workers (ferox, enum4linux-ng, ...) keep
                    # running. Kill the whole process group instead.
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    warn(f"timeout ({label}) after {timeout or self.timeout}s")
                    return 124, ""
                text = out.decode(errors="replace") if out else ""
                if outfile and not managed_outfile:
                    path = os.path.join(self.outdir, outfile)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", errors="replace") as f:
                        f.write(f"# cmd: {cmd}\n\n{text}")
                elif managed_outfile:
                    path = os.path.join(self.outdir, outfile)
                    if not text and os.path.isfile(path):
                        # cmd's own -o file is the only place its results landed
                        with open(path, errors="replace") as f:
                            text = f.read()
                    if os.path.isfile(path):
                        try:
                            with open(path + ".reconx-meta.json", "w") as f:
                                json.dump({"cmd": cmd}, f)
                        except OSError:
                            pass
                return proc.returncode, text
            except FileNotFoundError:
                bad(f"command not found: {cmd.split()[0]}")
                return 127, ""


# --------------------------------------------------------------------------- #
#  Priority job queue - the scan engine
#
#  Every job is only ever registered by code that runs *after* awaiting its
#  own prerequisite (e.g. a service-enum job is added from inside the
#  coroutine that just discovered the port), so a job is always runnable the
#  instant it's added - there's no separate dependency graph to resolve.
#  Concurrency and "only run what's relevant" come from WHEN jobs get added
#  and a bounded worker pool draining a priority queue, not from every module
#  being force-started together behind one phase barrier.
# --------------------------------------------------------------------------- #
PRIO_DISCOVER, PRIO_SCAN = 0, 1
# 3-way split of the old flat PRIO_ENUM=2, so host-type-aware scheduling
# (see classify_host_type/_service_priority) can weight one enum module
# ahead of another without touching PRIO_EXPLOIT/PRIO_BACKGROUND's relative
# order - only relative order matters anywhere these are used, so this
# renumbering is safe.
PRIO_ENUM_HIGH, PRIO_ENUM, PRIO_ENUM_LOW = 2, 3, 4
PRIO_EXPLOIT, PRIO_BACKGROUND = 5, 6


class Job:
    __slots__ = ("id", "priority", "background", "coro_factory", "status", "always_reenter")

    def __init__(self, id, priority, coro_factory, background=False, always_reenter=False):
        self.id = id
        self.priority = priority
        self.coro_factory = coro_factory
        self.background = background
        self.status = "queued"
        # True for orchestrator jobs (discover/service_scan) whose coroutine
        # body has a side effect - registering follow-up jobs - beyond just
        # "did the work", so it must always be entered even when the state
        # store says "done". Their own bodies still skip the real work and
        # reuse cached ports/services; leaf enum_* jobs don't need this and
        # get the full skip-without-reentering benefit on resume.
        self.always_reenter = always_reenter


class StateStore:
    """Persists <outdir>/<host>/.reconx_state.json so an interrupted scan can
    resume without re-orchestrating every module from scratch. Only "done"/
    "failed" job statuses are ever written - a job mid-flight at crash time
    simply has no entry, so "absent -> not done -> re-run" falls out for free
    without a separate stale "running" state to worry about."""

    def __init__(self, outdir, host):
        self.path = os.path.join(outdir, host, ".reconx_state.json")
        self.data = {"target": host, "mode": None, "started_at": None,
                     "ports": [], "services": {}, "udp": {}, "jobs": {}, "findings": []}
        self._lock = asyncio.Lock()

    def load(self):
        if os.path.isfile(self.path):
            try:
                with open(self.path) as f:
                    on_disk = json.load(f)
                on_disk["services"] = {int(k): v for k, v in on_disk.get("services", {}).items()}
                self.data.update(on_disk)
            except (ValueError, OSError, TypeError) as e:
                warn(f"state file unreadable, ignoring ({e}): {self.path}")
        return self.data

    def job_status(self, job_id):
        return self.data.get("jobs", {}).get(job_id, {}).get("status")

    async def mark_job(self, job_id, status):
        async with self._lock:
            self.data["jobs"][job_id] = {
                "status": status,
                "finished_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._flush()

    def record_finding(self, finding):
        """Synchronous and lock-free by design: called from FindingsList.append(),
        which - like add_job() - never awaits, so it can't be interleaved with
        another coroutine on this single-threaded event loop."""
        entry = [finding.sev, finding.service, finding.port, finding.text]
        findings = self.data.setdefault("findings", [])
        if entry not in findings:
            findings.append(entry)
            self._flush()

    async def save_ports_services(self, ports=None, services=None, udp=None):
        async with self._lock:
            if ports is not None:
                self.data["ports"] = ports
            if services is not None:
                self.data["services"] = services
            if udp is not None:
                self.data["udp"] = udp
            self._flush()

    def _flush(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = f"{self.path}.tmp.{os.getpid()}"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        os.replace(tmp, self.path)  # atomic - no torn JSON on crash


class JobQueue:
    """Priority-ordered, bounded-worker-pool job runner.

    add_job() is synchronous (no `await` inside) so the dedup check-then-
    insert is atomic under cooperative scheduling - two coroutines racing to
    register the same job id can never both win. A job already marked "done"
    in a resumed StateStore is accepted into .jobs (for bookkeeping/back-refs)
    but never queued for execution - its coroutine is never entered at all.

    "Core" jobs (background=False) gate wait_core_done(); background jobs
    (udp/nikto/vuln-scan) run alongside everything else without
    blocking it. wait_all_done() waits for every job, core or background.
    """

    def __init__(self, workers=8, state_store=None):
        self._q = asyncio.PriorityQueue()
        self._seq = itertools.count()  # heapq tie-break: Job isn't orderable
        self.jobs = {}
        self.state_store = state_store
        self._core_inflight = 0
        self._core_done = asyncio.Event()
        self._core_done.set()
        self._nworkers = workers
        self._workers = []
        self.had_background_jobs = False

    async def __aenter__(self):
        self._workers = [asyncio.create_task(self._worker()) for _ in range(self._nworkers)]
        return self

    async def __aexit__(self, *exc):
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)

    def add_job(self, job):
        """Register a job, or - if this id is already known and still
        queued (not yet picked up by a worker) - reprioritize it: decrease-
        key via a duplicate heap entry. heapq always pops the numerically
        smallest priority first regardless of insertion order, so whichever
        entry currently matches job.priority (the single source of truth)
        wins the race; _worker() discards any other, now-stale entry for
        the same job on pop. This is what lets register_service_jobs()'s
        confirm pass (better host-type info from nmap -sCV) correct a
        still-queued job's priority from the earlier guess pass, with zero
        change needed at either call site.

        Also always refreshes coro_factory to the newest registration's
        closure while still queued - the whole point of the confirm pass is
        that it carries more accurate arguments (e.g. the real nmap-
        confirmed service name instead of a port-guessed one), and a worker
        reads job.coro_factory live at execution time, so this is enough to
        make sure a reprioritized job actually runs with fresh data instead
        of silently executing with the stale guess-pass closure."""
        existing = self.jobs.get(job.id)
        if existing is not None:
            if existing.status == "queued":
                existing.coro_factory = job.coro_factory
                if existing.priority != job.priority:
                    existing.priority = job.priority
                    self._q.put_nowait((job.priority, next(self._seq), existing))
            return False
        self.jobs[job.id] = job
        if (self.state_store and not job.always_reenter
                and self.state_store.job_status(job.id) == "done"):
            job.status = "done"  # resumed: trust it, never enter the coroutine
            return False
        if job.background:
            self.had_background_jobs = True
        else:
            self._core_inflight += 1
            self._core_done.clear()
        self._q.put_nowait((job.priority, next(self._seq), job))
        return True

    async def _worker(self):
        while True:
            priority, _, job = await self._q.get()
            if job.status != "queued" or priority != job.priority:
                # stale duplicate entry from a reprioritization, or the job
                # already started/finished via its other entry - discard.
                self._q.task_done()
                continue
            job.status = "running"
            try:
                await job.coro_factory()
                job.status = "done"
            except asyncio.CancelledError:
                raise
            except Exception as e:
                job.status = "failed"
                bad(f"job '{job.id}' failed: {e}")
            finally:
                if self.state_store and job.status in ("done", "failed"):
                    await self.state_store.mark_job(job.id, job.status)
                if not job.background:
                    self._core_inflight -= 1
                    if self._core_inflight <= 0:
                        self._core_done.set()
                self._q.task_done()

    async def wait_core_done(self):
        await self._core_done.wait()

    async def wait_all_done(self):
        await self._q.join()


# --------------------------------------------------------------------------- #
#  Port discovery
# --------------------------------------------------------------------------- #
async def tcp_connect(host, port, timeout=1.5):
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


async def async_port_scan(host, ports, concurrency=800, timeout=1.5):
    """Pure-Python fallback scanner. Fast async TCP connect sweep."""
    sem = asyncio.Semaphore(concurrency)
    found = []

    async def probe(p):
        async with sem:
            r = await tcp_connect(host, p, timeout)
            if r:
                found.append(r)

    await asyncio.gather(*(probe(p) for p in ports))
    return sorted(found)


async def discover_ports(host, runner, args):
    """Return a sorted list of open TCP ports using the fastest available method."""
    # Full range unless --quick/--top-ports narrows it.
    if args.quick:
        port_list = TOP_1000
    elif args.top_ports:
        port_list = TOP_1000[: args.top_ports] if args.top_ports <= len(TOP_1000) else range(1, 65536)
    else:
        port_list = range(1, 65536)

    if TOOLS.get("rustscan") and not args.no_rustscan:
        info(f"port discovery via rustscan ({'top 1000' if args.quick else 'full range'})")
        rng = "--top" if args.quick else "-r 1-65535"
        cmd = (f"rustscan -a {host} {rng} --ulimit 5000 -b 1500 "
               f"-t {int(args.host_timeout*1000)} -g")
        rc, out = await runner.run(cmd, outfile=f"{host}/scans/rustscan.txt",
                                   label="rustscan", timeout=args.scan_timeout)
        ports = parse_rustscan_greppable(out)
        if ports:
            return ports
        warn("rustscan returned nothing; falling back to async scanner")

    info(f"port discovery via async connect-scan ({'top 1000' if args.quick or args.top_ports else 'full 65535'})")
    ports = await async_port_scan(host, list(port_list),
                                  concurrency=args.concurrency,
                                  timeout=args.host_timeout)
    return ports


def parse_rustscan_greppable(text):
    """rustscan -g prints:  host -> [22,80,443]"""
    ports = set()
    for m in re.finditer(r"->\s*\[([0-9,\s]+)\]", text):
        for p in m.group(1).split(","):
            p = p.strip()
            if p.isdigit():
                ports.add(int(p))
    # also catch 'Open 10.0.0.1:22' style lines
    for m in re.finditer(r"Open\s+[\d.]+:(\d+)", text):
        ports.add(int(m.group(1)))
    return sorted(ports)


def parse_nmap_ports(text):
    """Parse open ports + service guesses from nmap normal output."""
    services = {}
    for line in text.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line)
        if m:
            port = int(m.group(1))
            svc = m.group(2)
            ver = m.group(3).strip()
            services[port] = {"name": svc, "version": ver}
    return services


# --------------------------------------------------------------------------- #
#  Accuracy pass: nmap -sCV service/version detection on confirmed ports
# --------------------------------------------------------------------------- #
async def service_scan(host, ports, runner, args):
    if not ports:
        return {}
    if not TOOLS.get("nmap"):
        warn("nmap not found - skipping service/version detection (accuracy reduced)")
        # best-effort banner grab so we still have *something*
        return await banner_fallback(host, ports)

    plist = ",".join(str(p) for p in ports)
    scripts = "" if args.no_scripts else "-sC"
    intensity = getattr(args, "version_intensity", None) or 6
    cmd = (f"nmap -Pn -sV {scripts} -p {plist} --version-intensity {intensity} "
           f"-oN /dev/stdout {host}")
    info(f"service/version detection on {len(ports)} port(s) via nmap -sCV")
    rc, out = await runner.run(cmd, outfile=f"{host}/scans/nmap_service.txt",
                               label="nmap-sCV", timeout=args.scan_timeout)
    if runner.dry_run:
        return {p: {"name": "?", "version": ""} for p in ports}
    services = parse_nmap_ports(out)
    # ensure every discovered port is represented even if nmap was terse
    for p in ports:
        services.setdefault(p, {"name": guess_service(p), "version": ""})
    return services


async def banner_fallback(host, ports):
    services = {}
    for p in ports:
        services[p] = {"name": guess_service(p), "version": ""}
    return services


# --------------------------------------------------------------------------- #
#  Exploit-DB lookups for detected service versions
# --------------------------------------------------------------------------- #
# words too generic/decorative to be trustworthy exploit-db search terms on
# their own (org acronyms, protocol/transport words, banner filler) - a bare
# hit on one of these is noise, not a real correlation (e.g. 'ISC 9.4.2' from
# 'ISC BIND 9.4.2' matches unrelated Cisco/Avast CVEs by version-range fluke).
_SEARCHSPLOIT_TOO_GENERIC = {
    "isc", "db", "ip", "ns", "gnu", "www", "ftp", "ssh", "http", "https",
    "dns", "tcp", "udp", "smb", "sql", "protocol", "engine", "jsp", "org", "v1",
}


def _searchsploit_terms(version):
    """Build candidate searchsploit query terms from an nmap version string,
    most specific first, e.g. 'Samba smbd 3.0.20-Debian' -> ['Samba smbd
    3.0.20', 'Samba 3.0.20']. nmap's product name doesn't always match
    exploit-db's naming (extra words like 'httpd'/'smbd' break AND-matching),
    so a clean two-word 'vendor product' name also gets tried word-by-word.
    Longer name phrases are left as just the full-phrase attempt: when nmap's
    version field puts several words between the product name and the number
    (e.g. 'Apache Tomcat/Coyote JSP engine 1.1', where 1.1 is the JSP spec
    version, not Apache's), that number likely doesn't belong to the first
    word at all, so guessing single-word fallbacks there does more harm
    (wrong product) than good."""
    m = re.match(r"^(.*?)\s+((?:\d+\.){1,3}\d+[A-Za-z0-9]*)", version or "")
    if not m:
        return []
    name_part, ver = m.group(1).strip(), m.group(2)
    words = name_part.split()
    terms = [f"{name_part} {ver}"]
    if len(words) == 2:
        for w in (words[0], words[-1]):
            w = re.sub(r"[^A-Za-z0-9]", "", w)
            if w and w.lower() not in _SEARCHSPLOIT_TOO_GENERIC:
                terms.append(f"{w} {ver}")
    return terms


async def searchsploit_lookup(host, services, runner, args, findings):
    """Best-effort exploit-db correlation for each detected service version.
    Opportunistic: a version banner that doesn't cleanly map to exploit-db's
    naming just yields no results rather than a false positive."""
    if args.no_exploit_search or not TOOLS.get("searchsploit"):
        return

    async def check(port, meta):
        for term in _searchsploit_terms(meta.get("version", "")):
            rc, out = await runner.run(f"searchsploit -j {shlex.quote(term)}",
                                       None, "searchsploit", timeout=20)
            if runner.dry_run or not out:
                continue
            try:
                data = json.loads(out)
            except ValueError:
                continue
            hits = data.get("RESULTS_EXPLOIT") or []
            if hits:
                titles = "; ".join(h.get("Title", "?") for h in hits[:3])
                more = f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""
                findings.append(Finding("MEDIUM", "exploit", port,
                    f"searchsploit hit for '{term}': {titles}{more} - verify before use"))
                return  # most-specific successful term wins; don't re-search broader terms

    await asyncio.gather(*(check(p, m) for p, m in services.items()))


async def udp_scan(host, runner, args):
    if args.no_udp or not TOOLS.get("nmap"):
        return {}
    info("top-100 UDP scan via nmap (background; slow by nature)")
    cmd = f"nmap -Pn -sU --top-ports 100 --open -oN /dev/stdout {host}"
    rc, out = await runner.run(cmd, outfile=f"{host}/scans/nmap_udp.txt",
                               label="nmap-udp", timeout=args.scan_timeout)
    if runner.dry_run:
        return {}
    udp = {}
    for line in out.splitlines():
        m = re.match(r"^(\d+)/udp\s+open\s+(\S+)", line)
        if m:
            udp[int(m.group(1))] = m.group(2)
    return udp


# --------------------------------------------------------------------------- #
#  Service classification
# --------------------------------------------------------------------------- #
COMMON = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql", 1521: "oracle", 2049: "nfs", 3128: "http-proxy",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5985: "winrm",
    5986: "winrm-ssl", 6379: "redis", 8080: "http-proxy", 8000: "http-alt",
    8443: "https-alt", 88: "kerberos-sec", 27017: "mongodb", 9200: "elasticsearch",
}

def guess_service(port):
    return COMMON.get(port, "unknown")


WEB_PORTS = {80, 443, 8080, 8000, 8443, 8888, 3128, 9200, 5000, 8081}
def is_web(port, name):
    return port in WEB_PORTS or "http" in name.lower() or name.lower() in ("ssl/http", "http-alt")


_AD_PORTS = {88, 389, 636, 3268, 3269, 464, 9389}
_LINUX_PORTS = {22, 111, 2049}

HOST_TYPE_LABELS = {
    "ad": "Active Directory host",
    "windows": "Windows host",
    "linux": "Linux host",
    "web": "web-focused host",
}


def classify_host_type(ports, services):
    """Soft, single dominant archetype from open ports + (guessed or
    confirmed) service names - drives enum priority weighting only, never
    a hard branch: an 'ad'-classified host still gets its web ports
    enumerated, just later. No extra scan needed - runs on whatever
    discover_ports()/service_scan() already produced.

    445/139 alone can't tell real Windows apart from Samba-on-Linux (any
    Linux fileserver, most CTF/Metasploitable-style boxes) - confirmed
    banner text is checked first and wins whenever it's available (i.e.
    once nmap -sCV has run), with a bare-port fallback for the earlier
    guess pass that only trusts genuinely Windows-exclusive ports."""
    ports = set(ports)
    names_blob = " ".join(
        f"{(services.get(p, {}).get('name','') or '')} {(services.get(p, {}).get('version','') or '')}"
        for p in ports).lower()

    ad_hits = len(ports & _AD_PORTS)
    if ad_hits >= 2 or (ad_hits >= 1 and (445 in ports or 139 in ports)):
        return "ad"
    if "samba" in names_blob:
        return "linux"
    if "windows" in names_blob:
        return "windows"
    if ports & {3389, 5985, 5986}:      # RDP/WinRM - essentially Windows-exclusive
        return "windows"
    if ports & _LINUX_PORTS:            # ssh/rpcbind/nfs - strong pre-banner Linux signal
        return "linux"
    if ports & {135, 139, 445}:         # SMB-only, no banner yet, no other signal - lean windows
        return "windows"
    web_ports = sum(1 for p in ports if is_web(p, (services.get(p, {}).get("name", "") or "")))
    if web_ports and (len(ports) - web_ports) <= 1:
        return "web"
    return "unknown"


# --------------------------------------------------------------------------- #
#  Credentials - authenticated enumeration & spraying
# --------------------------------------------------------------------------- #
def have_creds(args):
    return bool(getattr(args, "user", None) and (getattr(args, "password", None) is not None
                                                 or getattr(args, "hash", None)))


def _sh_quote(s):
    # single-quote for the shell; harmless for values without quotes, safe for those with
    return "'" + str(s).replace("'", "'\\''") + "'"


def nxc_auth(args):
    """Build the netexec/crackmapexec credential argument string from parsed args."""
    parts = [f"-u {_sh_quote(args.user)}"]
    if getattr(args, "hash", None):
        parts.append(f"-H {_sh_quote(args.hash)}")
    else:
        parts.append(f"-p {_sh_quote(args.password)}")
    if getattr(args, "domain", None):
        parts.append(f"-d {_sh_quote(args.domain)}")
    if getattr(args, "local_auth", False):
        parts.append("--local-auth")
    return " ".join(parts)


def nxc_bin():
    return "nxc" if TOOLS.get("nxc") else ("netexec" if TOOLS.get("netexec")
            else ("crackmapexec" if TOOLS.get("crackmapexec") else None))


def cred_label(args):
    who = args.user
    if getattr(args, "domain", None):
        who = f"{args.domain}\\{args.user}"
    secret = "<hash>" if getattr(args, "hash", None) else "<pass>"
    scope = "local" if getattr(args, "local_auth", False) else "domain"
    return f"{who}:{secret} ({scope})"


# --------------------------------------------------------------------------- #
#  Findings engine - regex rules over tool output
# --------------------------------------------------------------------------- #
FINDING_RULES = [
    # (severity, compiled_regex, service_hint, message_template)
    ("CRITICAL", re.compile(r"Anonymous( FTP)? login (allowed|successful|ok)", re.I), "ftp", "Anonymous FTP login allowed"),
    ("CRITICAL", re.compile(r"\|_?ftp-anon:.*Anonymous", re.I), "ftp", "nmap confirms anonymous FTP"),
    ("HIGH",     re.compile(r"vsftpd 2\.3\.4", re.I), "ftp", "vsftpd 2.3.4 - backdoor (CVE-2011-2523)"),
    ("CRITICAL", re.compile(r"NULL Session|Server allows session using username '', password ''", re.I), "smb", "SMB NULL session allowed"),
    ("HIGH",     re.compile(r"\bSMBv1\b|SMB1 \(enabled\)|Signing (disabled|required:\s*False)", re.I), "smb", "SMB signing disabled / SMBv1 - relay & MS17-010 candidate"),
    ("HIGH",     re.compile(r"(READ|WRITE)(,|/| )?(WRITE)? on \\\\|Mapping: OK.*Listing: OK", re.I), "smb", "Readable/writable SMB share"),
    ("MEDIUM",   re.compile(r"\[\+\] Enumerating users", re.I), "smb", "User enumeration succeeded via RID/LSA"),
    ("HIGH",     re.compile(r"MS17-010|EternalBlue", re.I), "smb", "MS17-010 (EternalBlue) likely vulnerable"),
    ("CRITICAL", re.compile(r"(anonymous|unauthenticated) bind", re.I), "ldap", "LDAP anonymous bind allowed"),
    ("HIGH",     re.compile(r"defaultNamingContext:|rootDomainNamingContext:", re.I), "ldap", "LDAP leaks naming context (domain structure)"),
    ("HIGH",     re.compile(r"(Domain Controller|DC=.*,DC=|ldap.*Kerberos)", re.I), "ad", "Host looks like a Domain Controller"),
    ("MEDIUM",   re.compile(r"Kerberos.*88/tcp open", re.I), "kerberos", "Kerberos exposed - try user enum / AS-REP roasting"),
    # requires an explicit credential-assignment keyword + ':'/'=' + a value,
    # not just two words separated by punctuation (that matched web paths
    # like "admin/config" and any "word: word" text as false positives).
    ("HIGH",     re.compile(r"(?:^|[^a-zA-Z0-9])(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)['\"]?\s*[:=]\s*['\"]?\S{3,}", re.I), "creds", "Possible default/leaked credential in output"),
    ("MEDIUM",   re.compile(r"robots\.txt", re.I), "http", "robots.txt present - inspect disallowed paths"),
    ("HIGH",     re.compile(r"(phpmyadmin|/admin|wp-login|wp-admin|/manager/html|jenkins|gitlab|/api|/backup)", re.I), "http", "Interesting web path discovered"),
    ("HIGH",     re.compile(r"(Apache Tomcat|Jenkins|GitLab|WordPress|Drupal|Joomla)[\s/]*([\d.]+)?", re.I), "http", "Notable web application detected"),
    ("MEDIUM",   re.compile(r"Server: .*(IIS|Apache|nginx)[/ ]([\d.]+)", re.I), "http", "Web server banner reveals version"),
    ("MEDIUM",   re.compile(r"(index of /|directory listing)", re.I), "http", "Directory listing enabled"),
    ("HIGH",     re.compile(r"snmp.*public|Community.*public|::public", re.I), "snmp", "SNMP community 'public' - walk it for creds/processes"),
    ("MEDIUM",   re.compile(r"showmount.*\*|/\w+ \*", re.I), "nfs", "NFS export world-readable (showmount)"),
    ("HIGH",     re.compile(r"redis.*(no password|NOAUTH|-ERR.*without)|Ready to accept", re.I), "redis", "Redis reachable without auth"),
    ("HIGH",     re.compile(r"MSSQL.*(sa|1433).*login|Login failed for user 'sa'", re.I), "mssql", "MSSQL exposed - test sa / weak creds"),
    ("MEDIUM",   re.compile(r"VRFY \d{3}|252 |250 2\.1\.5", re.I), "smtp", "SMTP VRFY/EXPN user enumeration possible"),
    ("INFO",     re.compile(r"OpenSSH ([\d.]+)", re.I), "ssh", "SSH version noted (check for user enum CVE-2018-15473)"),
    # PostgreSQL
    ("CRITICAL", re.compile(r"\[\+\].*postgres.*\(Pwn3d!\)|Login successful.*postgres|Authentication succeeded", re.I), "postgres", "PostgreSQL default/blank credentials accepted"),
    ("CRITICAL", re.compile(r"List of databases|\btemplate1\b|\btemplate0\b", re.I), "postgres", "PostgreSQL unauthenticated access - database list dumped"),
    ("HIGH",     re.compile(r"pgsql|PostgreSQL \d|psql \(", re.I), "postgres", "PostgreSQL reachable - test postgres/blank and weak creds"),
    ("MEDIUM",   re.compile(r"fe_sendauth: no password supplied|no pg_hba\.conf entry", re.I), "postgres", "PostgreSQL requires auth (note pg_hba details in output)"),
    # POP3 / IMAP
    ("HIGH",     re.compile(r"USER command used|\+OK.*USER|SASL.*(LOGIN|PLAIN)", re.I), "pop3", "POP3 supports USER/PASS or PLAIN auth - test cred reuse"),
    ("HIGH",     re.compile(r"CAPABILITY.*(LOGIN|AUTH=PLAIN|AUTH=LOGIN)|\* OK.*IMAP", re.I), "imap", "IMAP allows LOGIN/PLAIN auth - test cred reuse"),
    ("MEDIUM",   re.compile(r"STARTTLS", re.I), "mail", "STARTTLS offered - creds encrypted in transit but still testable"),
    ("INFO",     re.compile(r"Dovecot|Courier|Cyrus|UW-IMAP", re.I), "mail", "Mail server software identified (check version CVEs)"),
    # Authenticated / credentialed results (netexec style output)
    ("CRITICAL", re.compile(r"\(Pwn3d!\)", re.I), "creds", "ADMIN access with these credentials (Pwn3d!) - you can get a shell / dump SAM"),
    ("HIGH",     re.compile(r"\[\+\]\s+\S+\\\S+:\S+", re.I), "creds", "Credentials VALID on this service - reuse them across every host"),
    ("HIGH",     re.compile(r"\bSTATUS_ACCOUNT_LOCKED_OUT\b", re.I), "creds", "ACCOUNT LOCKED OUT - stop spraying this user immediately"),
    ("MEDIUM",   re.compile(r"\bSTATUS_PASSWORD_EXPIRED\b", re.I), "creds", "Password expired but valid - may be changeable via SMB/RDP"),
    ("INFO",     re.compile(r"\bSTATUS_LOGON_FAILURE\b", re.I), "creds", "Credentials rejected on this service"),
]


def scan_findings(text, default_service, port, findings):
    for sev, rx, svc_hint, msg in FINDING_RULES:
        m = rx.search(text)
        if m:
            findings.append(Finding(sev, svc_hint or default_service, port, msg))


# --------------------------------------------------------------------------- #
#  Enumeration modules - each returns nothing, appends to findings list
# --------------------------------------------------------------------------- #
def _web_target(host, port, name):
    scheme = "https" if (port in (443, 8443, 5986) or "https" in name or "ssl" in name) else "http"
    base = f"{scheme}://{host}:{port}"
    tag = f"{host}/web_{port}"
    return scheme, base, tag


async def enum_web(host, port, name, runner, args, findings):
    scheme, base, tag = _web_target(host, port, name)

    # whatweb / curl headers
    if TOOLS.get("whatweb"):
        rc, out = await runner.run(f"whatweb -a3 {base}", f"{tag}/whatweb.txt", "whatweb")
        scan_findings(out, "http", port, findings)
    elif TOOLS.get("curl"):
        rc, out = await runner.run(f"curl -skI {base}", f"{tag}/headers.txt", "curl-head")
        scan_findings(out, "http", port, findings)

    # robots.txt
    if TOOLS.get("curl"):
        rc, out = await runner.run(f"curl -sk {base}/robots.txt", f"{tag}/robots.txt", "robots")
        if out and "<html" not in out.lower() and out.strip():
            findings.append(Finding("MEDIUM", "http", port, "robots.txt present - inspect disallowed paths"))

    # directory brute force (feroxbuster preferred, gobuster fallback)
    wl = args.wordlist
    if not wl:
        pass
    elif TOOLS.get("feroxbuster"):
        recurse = "" if getattr(args, "mode", None) == "deep" else "--no-recursion"
        cmd = (f"feroxbuster -u {base} -w {wl} -t 50 -q {recurse} "
               f"-s 200,204,301,302,307,401,403 -o {os.path.join(runner.outdir, tag, 'ferox.txt')}")
        rc, out = await runner.run(cmd, f"{tag}/ferox.txt", "feroxbuster",
                                   timeout=args.enum_timeout, managed_outfile=True)
        scan_findings(out, "http", port, findings)
    elif TOOLS.get("gobuster"):
        cmd = f"gobuster dir -u {base} -w {wl} -t 50 -q -k"
        rc, out = await runner.run(cmd, f"{tag}/gobuster.txt", "gobuster", timeout=args.enum_timeout)
        scan_findings(out, "http", port, findings)
    else:
        warn(f"no feroxbuster/gobuster - skipping dirbrute on {base}")

    good(f"web enum done: {base}")


async def enum_nikto(host, port, name, runner, args, findings):
    """Runs standalone as a background job so it never delays whatweb/
    dirbrute/robots.txt findings behind its own slow scan."""
    scheme, base, tag = _web_target(host, port, name)
    if not TOOLS.get("nikto"):
        return
    rc, out = await runner.run(f"nikto -host {base} -maxtime {args.enum_timeout}s",
                               f"{tag}/nikto.txt", "nikto", timeout=args.enum_timeout + 30)
    scan_findings(out, "http", port, findings)
    good(f"nikto done: {base}")


async def enum_smb(host, runner, args, findings):
    tag = f"{host}/smb"
    nxc = nxc_bin()
    if have_creds(args):
        # authenticated: check access, admin (Pwn3d!), shares, users, and loot.
        if nxc:
            auth = nxc_auth(args)
            for sub in ("--shares", "--users", "--pass-pol", "--loggedon-users", "--sam"):
                rc, out = await runner.run(f"{nxc} smb {host} {auth} {sub}",
                                           f"{tag}/auth_nxc{sub.replace('-','')}.txt", f"{nxc} smb {sub}")
                scan_findings(out, "smb", 445, findings)
        else:
            findings.append(Finding("MEDIUM", "smb", 445,
                "Creds supplied but no netexec/nxc found - authenticated SMB untested"))
    elif nxc:
        for sub in ("--shares", "--users", "--pass-pol"):
            rc, out = await runner.run(f"{nxc} smb {host} -u '' -p '' {sub}",
                                       f"{tag}/nxc{sub.replace('-','')}.txt", f"{nxc} smb {sub}")
            scan_findings(out, "smb", 445, findings)
    if TOOLS.get("enum4linux-ng"):
        rc, out = await runner.run(f"enum4linux-ng -A {host}", f"{tag}/enum4linux-ng.txt", "enum4linux-ng",
                                   timeout=args.enum_timeout)
        scan_findings(out, "smb", 445, findings)
    elif TOOLS.get("enum4linux"):
        rc, out = await runner.run(f"enum4linux -a {host}", f"{tag}/enum4linux.txt", "enum4linux",
                                   timeout=args.enum_timeout)
        scan_findings(out, "smb", 445, findings)
    if TOOLS.get("smbclient"):
        rc, out = await runner.run(f"smbclient -N -L //{host}/", f"{tag}/smbclient_list.txt", "smbclient")
        scan_findings(out, "smb", 445, findings)
    good("smb enum done")


def _dn_to_domain(dn):
    """'DC=checkpoint,DC=htb' -> 'checkpoint.htb'"""
    parts = re.findall(r"DC=([^,]+)", dn or "", re.I)
    return ".".join(parts) if parts else None


def _impacket_bin(name):
    """Kali packages these as impacket-<Name>; some installs keep the raw
    <Name>.py script name instead - try both, skip gracefully if neither."""
    for cand in (f"impacket-{name}", f"{name}.py"):
        if TOOLS.get(cand):
            return cand
    return None


_NXC_USER_ROW_RX = re.compile(r"^\S+\s+\S+\s+\d+\s+\S+\s+(\S+)\s+(?:\d{4}-\d{2}-\d{2}|<never>)", re.M)
_KRB5TGS_RX = re.compile(r"\$krb5tgs\$\d+\$\*?([^\s*]+)")
_KRB5ASREP_RX = re.compile(r"\$krb5asrep\$\d+\$([^\s:]+)")


async def _impacket_roast_check(host, dom, runner, args, findings, tag, users_out):
    """Cross-checks nxc's --kerberoasting/--asreproast with impacket's own
    GetUserSPNs/GetNPUsers. Worth doing separately, not redundant: nxc
    auto-derives the real LDAP search base from the DC's own rootDSE no
    matter what --domain string it's given, while impacket's tools build the
    search base directly from the domain string passed in - so a wrong or
    mistyped --domain silently breaks impacket's tools with a confusing LDAP
    referral error even when nxc's own check looked completely fine. That's
    exactly the failure mode that prompted adding this cross-check, so `dom`
    should be the domain derived from rootDSE (see _dn_to_domain), not raw
    args.domain, whenever the former is available."""
    if not dom:
        return
    loot_dir = os.path.join(runner.outdir, host, "ldap", "loot")
    if not runner.dry_run:
        os.makedirs(loot_dir, exist_ok=True)

    spn_bin = _impacket_bin("GetUserSPNs")
    np_bin = _impacket_bin("GetNPUsers")
    if not spn_bin and not np_bin:
        findings.append(Finding("INFO", "ldap", None,
            "impacket's GetUserSPNs/GetNPUsers not found - Kerberoast/AS-REP cross-check skipped"))
        return

    if spn_bin:
        user = f"{dom}/{args.user}"
        if getattr(args, "hash", None):
            target, hash_flag = _sh_quote(user), f"-hashes {_sh_quote(args.hash)}"
        else:
            target, hash_flag = _sh_quote(f"{user}:{args.password}"), ""
        out_file = os.path.abspath(os.path.join(loot_dir, "kerb_impacket.txt"))
        cmd = (f"{spn_bin} {target} {hash_flag} -dc-ip {host} -request "
               f"-outputfile {_sh_quote(out_file)}").replace("  ", " ")
        rc, out = await runner.run(cmd, f"{tag}/impacket_getuserspns.txt", "GetUserSPNs",
                                   timeout=args.enum_timeout)
        hits = sorted(set(_KRB5TGS_RX.findall(out or "")))
        if hits:
            findings.append(Finding("CRITICAL", "ldap", None,
                f"Kerberoastable account(s) via GetUserSPNs: {', '.join(hits)} - "
                f"hash(es) saved to {out_file}, crack with hashcat -m 13100"))

    users = sorted(set(_NXC_USER_ROW_RX.findall(users_out or "")))
    if np_bin and users:
        users_file = os.path.join(loot_dir, "_candidate_users.txt")
        if not runner.dry_run:
            with open(users_file, "w") as f:
                f.write("\n".join(users) + "\n")
        out_file = os.path.abspath(os.path.join(loot_dir, "asrep_impacket.txt"))
        cmd = (f"{np_bin} {_sh_quote(dom + '/')} -usersfile {_sh_quote(users_file)} -no-pass "
               f"-dc-ip {host} -request -outputfile {_sh_quote(out_file)}")
        rc, out = await runner.run(cmd, f"{tag}/impacket_getnpusers.txt", "GetNPUsers",
                                   timeout=args.enum_timeout)
        hits = sorted(set(_KRB5ASREP_RX.findall(out or "")))
        if hits:
            findings.append(Finding("CRITICAL", "ldap", None,
                f"AS-REP roastable account(s) via GetNPUsers: {', '.join(hits)} - "
                f"hash(es) saved to {out_file}, crack with hashcat -m 18200"))
    good(f"{host}: impacket kerberoast/asreproast cross-check done")


def _bloodhound_bin():
    for cand in ("bloodhound-python", "bloodhound-ce-python"):
        if TOOLS.get(cand):
            return cand
    return None


async def enum_bloodhound(host, dom, runner, args, findings):
    """Background job (--bloodhound): full BloodHound collection (-c All).
    Registered from enum_ldap() once it knows the DC's real domain (see
    _dn_to_domain), not from register_service_jobs() - the domain isn't
    known until the rootDSE lookup inside enum_ldap() runs.

    Explicitly points -ns (nameserver) at the DC itself rather than relying
    on this machine's default DNS: bloodhound-python resolves every
    computer object it finds, so a wrong/absent DNS server breaks that
    silently across the whole collection - the same class of failure the
    domain-typo cross-check above exists to catch for impacket's tools."""
    bin_name = _bloodhound_bin()
    if not bin_name or not dom:
        return
    bh_dir = os.path.join(runner.outdir, host, "ldap", "bloodhound")
    if not runner.dry_run:
        os.makedirs(bh_dir, exist_ok=True)
    if getattr(args, "hash", None):
        auth = f"--hashes {_sh_quote(args.hash)}"
    else:
        auth = f"-p {_sh_quote(args.password)}"
    cmd = (f"cd {_sh_quote(bh_dir)} && {bin_name} -u {_sh_quote(args.user + '@' + dom)} {auth} "
           f"-d {_sh_quote(dom)} -ns {host} -c All --zip")
    outfile = f"{host}/ldap/bloodhound_collect.txt"
    rc, out = await runner.run(cmd, outfile, "bloodhound", timeout=args.scan_timeout)
    if rc == 0:
        findings.append(Finding("HIGH", "ad", None,
            f"BloodHound collection complete - load the .zip from {bh_dir} into BloodHound and hunt for attack paths"))
    elif not runner.dry_run:
        # surface failure as a finding too, not just a log line buried in
        # outfile - e.g. LDAP signing enforced + LDAPS unreachable/reset is
        # a real failure mode seen in testing, distinct from "just missing
        # a tool" and easy to miss if only the raw output file has it
        findings.append(Finding("MEDIUM", "ad", None,
            f"BloodHound collection failed (exit {rc}) - see {outfile} for details"))
    good(f"{host}: BloodHound collection done")


async def enum_ldap(host, port, runner, args, findings, queue):
    tag = f"{host}/ldap"
    real_domain = None
    if TOOLS.get("ldapsearch"):
        rc, out = await runner.run(
            f"ldapsearch -x -H ldap://{host}:{port} -s base -b '' namingContexts defaultNamingContext",
            f"{tag}/rootdse.txt", "ldap-rootdse")
        scan_findings(out, "ldap", port, findings)
        # try to pull naming context and dump anonymously
        m = re.search(r"(?:defaultNamingContext|namingContexts):\s*(DC=[^\n]+)", out or "", re.I)
        if m:
            base = m.group(1).strip()
            real_domain = _dn_to_domain(base)
            findings.append(Finding("HIGH", "ldap", port, f"LDAP base found: {base}"))
            rc, out2 = await runner.run(
                f"ldapsearch -x -H ldap://{host}:{port} -b '{base}'",
                f"{tag}/anon_dump.txt", "ldap-dump", timeout=args.enum_timeout)
            scan_findings(out2, "ldap", port, findings)
    # authenticated: netexec LDAP enum + kerberoast/asreproast cross-check + BloodHound hint
    if have_creds(args):
        nxc = nxc_bin()
        dom = real_domain or args.domain or "<domain>"
        if real_domain and args.domain and real_domain.lower() != args.domain.lower():
            findings.append(Finding("INFO", "ldap", port,
                f"--domain '{args.domain}' doesn't match the DC's real domain '{real_domain}' "
                f"(from rootDSE) - using '{real_domain}' for the LDAP-derived checks below"))
        users_out = ""
        if nxc:
            auth = nxc_auth(args)
            loot_dir = os.path.join(runner.outdir, host, "ldap", "loot")
            if not runner.dry_run:
                os.makedirs(loot_dir, exist_ok=True)
            asrep_out = os.path.abspath(os.path.join(loot_dir, "asrep.txt"))
            kerb_out = os.path.abspath(os.path.join(loot_dir, "kerb.txt"))
            for sub in ("--users", "--groups", f"--asreproast {_sh_quote(asrep_out)}",
                        f"--kerberoasting {_sh_quote(kerb_out)}"):
                rc, out = await runner.run(f"{nxc} ldap {host} {auth} {sub}",
                                           f"{tag}/auth_ldap_{sub.split()[0].strip('-')}.txt",
                                           f"{nxc} ldap {sub.split()[0]}")
                scan_findings(out, "ldap", port, findings)
                if sub == "--users":
                    users_out = out or ""
        real_dom = dom if dom != "<domain>" else None
        await _impacket_roast_check(host, real_dom, runner, args, findings, tag, users_out)
        if args.bloodhound and real_dom:
            queue.add_job(Job(f"{host}:bloodhound", PRIO_BACKGROUND, background=True,
                coro_factory=functools.partial(enum_bloodhound, host, real_dom, runner, args, findings)))
        else:
            findings.append(Finding("HIGH", "ad", port,
                f"Authenticated to LDAP - run BloodHound now: "
                f"bloodhound-python -u {args.user}@{dom} -p <pass> -d {dom} -ns {host} -c All"))
    good("ldap enum done")


async def enum_ftp(host, port, runner, args, findings):
    tag = f"{host}/ftp"
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script ftp-anon,ftp-syst -oN /dev/stdout {host}",
            f"{tag}/ftp_nse.txt", "nmap-ftp")
        scan_findings(out, "ftp", port, findings)
    if TOOLS.get("curl"):
        rc, out = await runner.run(f"curl -s --max-time 15 ftp://anonymous:anonymous@{host}:{port}/",
                                   f"{tag}/anon_list.txt", "ftp-anon-curl")
        if out and out.strip():
            findings.append(Finding("CRITICAL", "ftp", port, "Anonymous FTP login allowed (directory listed)"))
    good("ftp enum done")


async def enum_ssh(host, port, runner, args, findings):
    tag = f"{host}/ssh"
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey -oN /dev/stdout {host}",
            f"{tag}/ssh_nse.txt", "nmap-ssh")
        scan_findings(out, "ssh", port, findings)
    # authenticated: validate the credential over SSH via netexec (no brute; single try)
    if have_creds(args) and not getattr(args, "hash", None):
        nxc = nxc_bin()
        if nxc:
            rc, out = await runner.run(f"{nxc} ssh {host} -u {_sh_quote(args.user)} -p {_sh_quote(args.password)}",
                                       f"{tag}/auth_nxc_ssh.txt", "nxc-ssh")
            scan_findings(out, "ssh", port, findings)
            if out and ("[+]" in out or "Pwn3d" in out):
                findings.append(Finding("CRITICAL", "ssh", port,
                    f"SSH login works: ssh {args.user}@{host}  (then sudo -l, id, enumerate)"))
    good("ssh enum done")


async def enum_snmp(host, runner, args, findings):
    tag = f"{host}/snmp"
    if TOOLS.get("onesixtyone"):
        rc, out = await runner.run(f"onesixtyone {host} public private community",
                                   f"{tag}/onesixtyone.txt", "onesixtyone")
        scan_findings(out, "snmp", 161, findings)
    if TOOLS.get("snmpwalk"):
        rc, out = await runner.run(f"snmpwalk -v2c -c public -t 3 -r 1 {host}",
                                   f"{tag}/snmpwalk_public.txt", "snmpwalk", timeout=args.enum_timeout)
        if out and "Timeout" not in out and out.strip():
            findings.append(Finding("HIGH", "snmp", 161, "SNMP 'public' community responds - walk for creds/processes/users"))
            scan_findings(out, "snmp", 161, findings)
    good("snmp enum done")


# candidate username wordlists for smtp-user-enum, checked in order - nmap's
# own smtp-enum-users NSE script (run unconditionally below) only tries a
# tiny built-in list, so this dedicated pass with a real wordlist is what
# actually finds accounts on a server that supports VRFY/EXPN/RCPT TO.
_SMTP_USER_WORDLISTS = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/metasploit-framework/data/wordlists/unix_users.txt",
    "/usr/share/wordlists/metasploit/unix_users.txt",
]


def _smtp_userlist():
    for cand in _SMTP_USER_WORDLISTS:
        if os.path.isfile(cand):
            return cand
    return None


_SMTP_ENUM_USER_RX = re.compile(r":\s*(\S+)\s+exists\b", re.I)

# tried in order, most reliable/quietest first: VRFY works on most
# misconfigured servers and is a single round-trip per user; EXPN (mailing
# list expansion) and RCPT (probing MAIL/RCPT TO during a fake delivery) are
# fallbacks for servers that disable VRFY (e.g. Postfix by default) but still
# leak via one of the others.
_SMTP_ENUM_MODES = ("VRFY", "EXPN", "RCPT")


async def enum_smtp(host, port, runner, args, findings):
    tag = f"{host}/smtp"
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script smtp-commands,smtp-enum-users,smtp-open-relay -oN /dev/stdout {host}",
            f"{tag}/smtp_nse.txt", "nmap-smtp")
        scan_findings(out, "smtp", port, findings)
    if TOOLS.get("smtp-user-enum"):
        userlist = _smtp_userlist()
        if userlist:
            for mode in _SMTP_ENUM_MODES:
                cmd = f"smtp-user-enum -m {mode} -U {shlex.quote(userlist)} -h {host} -p {port}"
                if mode == "RCPT" and getattr(args, "domain", None):
                    # RCPT TO:<user> alone only works when the server does
                    # local delivery unqualified; give it user@domain too
                    # (needed for Exchange-style targets) whenever we know one.
                    cmd += f" -D {shlex.quote(args.domain)}"
                rc2, out2 = await runner.run(cmd, f"{tag}/smtp-user-enum_{mode.lower()}.txt",
                                             f"smtp-user-enum-{mode.lower()}", timeout=args.enum_timeout)
                users = sorted(set(_SMTP_ENUM_USER_RX.findall(out2 or "")))
                if users:
                    shown = ", ".join(users[:10])
                    more = f" (+{len(users) - 10} more)" if len(users) > 10 else ""
                    findings.append(Finding("HIGH", "smtp", port,
                        f"SMTP user enumeration ({mode}) confirmed account(s): {shown}{more} - "
                        f"reuse as usernames against SSH/web/mail login"))
                    break  # first successful mode wins; no need to probe weaker methods too
        else:
            findings.append(Finding("INFO", "smtp", port,
                "smtp-user-enum installed but no username wordlist found - user enum skipped"))
    good("smtp enum done")


async def enum_dns(host, port, runner, args, findings):
    """Version/PTR probe, then AXFR (zone transfer) attempts against every
    domain we can find: an explicit -d/--domain, and whatever the reverse
    PTR lookup suggests (strip the leftmost label off the PTR hostname to
    guess its zone). A misconfigured NS handing out a full zone on an
    unauthenticated AXFR is a common, high-value miss if left as a manual
    step."""
    tag = f"{host}/dns"
    if not TOOLS.get("dig"):
        return
    rc, out = await runner.run(f"dig @{host} -p {port} version.bind chaos txt +short",
                               f"{tag}/version.txt", "dig-version")
    rc2, out2 = await runner.run(f"dig @{host} -p {port} -x {host} +short",
                                 f"{tag}/ptr.txt", "dig-ptr")

    domains = []
    if getattr(args, "domain", None):
        domains.append(args.domain)
    for line in (out2 or "").splitlines():
        ptr = line.strip().rstrip(".")
        if not ptr:
            continue
        labels = ptr.split(".")
        if len(labels) > 2:
            domains.append(".".join(labels[1:]))  # strip host label -> guessed zone
        elif len(labels) == 2:
            domains.append(ptr)

    tried = set()
    for dom in domains:
        dom = dom.lower()
        if dom in tried:
            continue
        tried.add(dom)
        rc3, out3 = await runner.run(
            f"dig @{host} -p {port} {dom} axfr +time=10 +tries=1",
            f"{tag}/axfr_{dom}.txt", "dig-axfr", timeout=30)
        if out3 and "XFR size:" in out3:
            findings.append(Finding("CRITICAL", "dns", port,
                f"DNS zone transfer (AXFR) succeeded for '{dom}' - full zone dumped, "
                f"see {tag}/axfr_{dom}.txt"))

    if tried:
        good(f"dns checks done (AXFR tried against: {', '.join(sorted(tried))})")
    else:
        good("dns basic checks done (no domain known yet to try AXFR against - "
             "pass -d/--domain, or add AXFR manually once you know the domain)")


async def enum_nfs(host, runner, args, findings):
    tag = f"{host}/nfs"
    if TOOLS.get("showmount"):
        rc, out = await runner.run(f"showmount -e {host}", f"{tag}/exports.txt", "showmount")
        if out and "*" in out:
            findings.append(Finding("HIGH", "nfs", 2049, "NFS export world-readable (*) - mount it"))
        scan_findings(out, "nfs", 2049, findings)
    good("nfs enum done")


async def enum_mssql(host, port, runner, args, findings):
    nxc = nxc_bin()
    if nxc and have_creds(args):
        auth = nxc_auth(args)
        rc, out = await runner.run(f"{nxc} mssql {host} {auth} -x whoami",
                                   f"{host}/mssql/auth_nxc.txt", "nxc-mssql-auth")
        scan_findings(out, "mssql", port, findings)
        if out and ("[+]" in out or "Pwn3d" in out):
            findings.append(Finding("CRITICAL", "mssql", port,
                "MSSQL login works - enable xp_cmdshell for RCE (nxc mssql ... -x whoami / mssqlclient.py)"))
    elif nxc:
        rc, out = await runner.run(f"{nxc} mssql {host} -u sa -p '' --local-auth",
                                   f"{host}/mssql/nxc.txt", "nxc-mssql")
        scan_findings(out, "mssql", port, findings)
    findings.append(Finding("MEDIUM", "mssql", port, "MSSQL exposed - test sa/blank and weak creds (impacket mssqlclient)"))


async def enum_redis(host, port, runner, args, findings):
    if TOOLS.get("redis-cli"):
        rc, out = await runner.run(f"redis-cli -h {host} -p {port} INFO",
                                   f"{host}/redis/info.txt", "redis-info", timeout=30)
        if out and "redis_version" in out:
            findings.append(Finding("HIGH", "redis", port, "Redis reachable without auth - INFO succeeded"))


async def enum_postgres(host, port, runner, args, findings):
    tag = f"{host}/postgres"
    nxc = nxc_bin()
    # 1) nmap pgsql-brute: only as a fallback when nxc isn't around to do the
    # same job faster. It brute-forces with nmap's full default word lists,
    # so cap it with --script-timeout rather than letting it run to the enum
    # timeout - it's opportunistic, not meant to complete.
    if TOOLS.get("nmap") and not nxc:
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script pgsql-brute --script-timeout 20s -oN /dev/stdout {host}",
            f"{tag}/pgsql_nse.txt", "nmap-pgsql", timeout=45)
        scan_findings(out, "postgres", port, findings)
    # 2) netexec: use supplied creds if we have them, else default-cred sweep
    if nxc and have_creds(args):
        rc, out = await runner.run(f"{nxc} postgres {host} {nxc_auth(args)}",
                                   f"{tag}/auth_nxc.txt", f"{nxc}-postgres-auth")
        scan_findings(out, "postgres", port, findings)
    elif nxc:
        for user, pw in (("postgres", "postgres"), ("postgres", ""), ("postgres", "password")):
            rc, out = await runner.run(
                f"{nxc} postgres {host} -u {user} -p '{pw}'",
                f"{tag}/nxc_{user}_{pw or 'blank'}.txt", f"{nxc}-postgres")
            scan_findings(out, "postgres", port, findings)
    # 3) direct psql connectivity probe (no password) if the client is present
    if TOOLS.get("psql"):
        cmd = (f"PGPASSWORD='' psql 'host={host} port={port} user=postgres "
               f"dbname=postgres connect_timeout=8' -c '\\l' ")
        rc, out = await runner.run(cmd, f"{tag}/psql_list.txt", "psql-list", timeout=60)
        if out and ("List of databases" in out or "template1" in out):
            findings.append(Finding("CRITICAL", "postgres", port,
                                    "PostgreSQL blank-password login as 'postgres' works - dumped DB list"))
        scan_findings(out, "postgres", port, findings)
    if not (TOOLS.get("nxc") or TOOLS.get("netexec") or TOOLS.get("psql")):
        findings.append(Finding("MEDIUM", "postgres", port,
                                "PostgreSQL open - install netexec/psql, then test postgres:postgres & blank"))
    good("postgres enum done")


async def _mail_probe(host, port, tls, runner, tag, label):
    """Grab a mail banner + CAPABILITY. Uses openssl for TLS ports, ncat/nc otherwise."""
    if tls and TOOLS.get("openssl"):
        cmd = (f"printf 'CAPA\\r\\nQUIT\\r\\n' | timeout 15 "
               f"openssl s_client -quiet -connect {host}:{port} 2>/dev/null")
    elif TOOLS.get("ncat"):
        cmd = f"printf 'CAPA\\r\\nQUIT\\r\\n' | ncat --recv-only -w 10 {host} {port}"
    elif TOOLS.get("nc"):
        cmd = f"printf 'CAPA\\r\\nQUIT\\r\\n' | nc -w 10 {host} {port}"
    else:
        cmd = None
    if cmd:
        rc, out = await runner.run(cmd, f"{tag}/{label}_banner.txt", label, timeout=30)
        return out or ""
    return ""


async def enum_pop3(host, port, runner, args, findings):
    tag = f"{host}/pop3"
    tls = port in (995,)
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script pop3-capabilities,pop3-ntlm-info -oN /dev/stdout {host}",
            f"{tag}/pop3_nse.txt", "nmap-pop3")
        scan_findings(out, "pop3", port, findings)
    banner = await _mail_probe(host, port, tls, runner, tag, "pop3")
    # POP3 CAPA speaks USER/SASL; craft the finding from what we saw
    scan_findings(banner, "pop3", port, findings)
    if banner and ("USER" in banner.upper() or "+OK" in banner):
        findings.append(Finding("HIGH", "pop3", port,
                                "POP3 accepts USER/PASS - reuse creds harvested elsewhere (mail often = domain creds)"))
    good("pop3 enum done")


async def enum_imap(host, port, runner, args, findings):
    tag = f"{host}/imap"
    tls = port in (993,)
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script imap-capabilities,imap-ntlm-info -oN /dev/stdout {host}",
            f"{tag}/imap_nse.txt", "nmap-imap")
        scan_findings(out, "imap", port, findings)
    # IMAP CAPABILITY needs a tagged command
    if tls and TOOLS.get("openssl"):
        cmd = (f"printf 'a1 CAPABILITY\\r\\na2 LOGOUT\\r\\n' | timeout 15 "
               f"openssl s_client -quiet -connect {host}:{port} 2>/dev/null")
    elif TOOLS.get("ncat"):
        cmd = f"printf 'a1 CAPABILITY\\r\\na2 LOGOUT\\r\\n' | ncat --recv-only -w 10 {host} {port}"
    elif TOOLS.get("nc"):
        cmd = f"printf 'a1 CAPABILITY\\r\\na2 LOGOUT\\r\\n' | nc -w 10 {host} {port}"
    else:
        cmd = None
    if cmd:
        rc, out = await runner.run(cmd, f"{tag}/imap_banner.txt", "imap-capa", timeout=30)
        scan_findings(out, "imap", port, findings)
        if out and ("CAPABILITY" in out.upper() or "* OK" in out):
            findings.append(Finding("HIGH", "imap", port,
                                    "IMAP LOGIN available - reuse creds harvested elsewhere"))
    good("imap enum done")


async def enum_winrm(host, port, runner, args, findings):
    if have_creds(args):
        nxc = nxc_bin()
        if nxc:
            rc, out = await runner.run(f"{nxc} winrm {host} {nxc_auth(args)}",
                                       f"{host}/winrm/auth_nxc.txt", "nxc-winrm-auth")
            scan_findings(out, "winrm", port, findings)
            if out and ("[+]" in out or "Pwn3d" in out):
                pw = "-H <hash>" if getattr(args, "hash", None) else "-p <pass>"
                findings.append(Finding("CRITICAL", "winrm", port,
                    f"WinRM login works -> SHELL: evil-winrm -i {host} -u {args.user} {pw}"))
            else:
                findings.append(Finding("INFO", "winrm", port,
                    "WinRM open - supplied credential did not confirm a login (see auth_nxc.txt)"))
        else:
            findings.append(Finding("MEDIUM", "winrm", port,
                "WinRM open - creds supplied but netexec/nxc not found, credential untested here"))
        return
    findings.append(Finding("MEDIUM", "winrm", port,
                            "WinRM open - if you get creds, use evil-winrm for a shell"))


async def enum_rdp(host, port, runner, args, findings):
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script rdp-ntlm-info,rdp-enum-encryption -oN /dev/stdout {host}",
            f"{host}/rdp/rdp_nse.txt", "nmap-rdp")
        scan_findings(out, "rdp", port, findings)
        m = re.search(r"(DNS_Domain_Name|Target_Name|NetBIOS_Domain_Name):\s*(\S+)", out or "")
        if m:
            findings.append(Finding("MEDIUM", "rdp", port, f"RDP NTLM info leaks: {m.group(2)}"))
    if have_creds(args):
        nxc = nxc_bin()
        if nxc:
            rc, out = await runner.run(f"{nxc} rdp {host} {nxc_auth(args)}",
                                       f"{host}/rdp/auth_nxc.txt", "nxc-rdp-auth")
            scan_findings(out, "rdp", port, findings)
            if out and ("[+]" in out or "Pwn3d" in out):
                findings.append(Finding("HIGH", "rdp", port,
                    f"RDP login works: xfreerdp /u:{args.user} /p:<pass> /v:{host} /cert:ignore"))


# --------------------------------------------------------------------------- #
#  Host-type-aware enum priority
#
#  Not in this table -> "unknown" host type -> every module falls back to
#  flat PRIO_ENUM, i.e. today's behavior when classification can't say
#  anything useful. A host-type entry only needs to list what it wants to
#  pull FORWARD (PRIO_ENUM_HIGH) or push BACK (PRIO_ENUM_LOW) relative to
#  that same default - this is a soft preference, not a hard gate: a
#  LOW-priority module still runs on any worker that would otherwise sit
#  idle, it just always loses the tie-break to a HIGH one.
# --------------------------------------------------------------------------- #
_HOST_TYPE_ENUM_PRIORITY = {
    "ad": {"smb": PRIO_ENUM_HIGH, "ldap": PRIO_ENUM_HIGH, "dns": PRIO_ENUM_HIGH,
           "winrm": PRIO_ENUM_HIGH, "web": PRIO_ENUM_LOW, "ftp": PRIO_ENUM_LOW,
           "ssh": PRIO_ENUM_LOW},
    "windows": {"smb": PRIO_ENUM_HIGH, "winrm": PRIO_ENUM_HIGH, "rdp": PRIO_ENUM_HIGH,
                "web": PRIO_ENUM_LOW},
    "linux": {"ssh": PRIO_ENUM_HIGH, "web": PRIO_ENUM_LOW, "mssql": PRIO_ENUM_LOW},
    "web": {"web": PRIO_ENUM_HIGH},
}


def _service_priority(module_key, host_type):
    return _HOST_TYPE_ENUM_PRIORITY.get(host_type, {}).get(module_key, PRIO_ENUM)


# --------------------------------------------------------------------------- #
#  Dispatcher: map discovered services -> queued jobs
#
#  Pure and idempotent: called TWICE per host - once right after port
#  discovery with port-guessed service names (so enum starts within
#  seconds, not after the full nmap -sCV pass across every port), and again
#  once service_scan() confirms real versions. Job ids are deterministic, so
#  a job the guess pass already registered is a harmless dedup no-op on the
#  confirm pass (except for priority - see JobQueue.add_job's decrease-key
#  handling: the confirm pass's better host-type classification can still
#  reprioritize a job the guess pass already queued, as long as it hasn't
#  started yet); a job the guess pass missed (nmap corrects a wrong guess)
#  still fires from the confirm pass, just later, without blocking anything.
# --------------------------------------------------------------------------- #
def register_service_jobs(queue, host, services, runner, args, findings, host_profile):
    counted = host_profile.setdefault("_counted_ports", set())
    host_type = host_profile["host_type"] = classify_host_type(list(services), services)

    def prio(module_key):
        return _service_priority(module_key, host_type)

    for port, meta in sorted(services.items()):
        name = meta.get("name", guess_service(port))

        if is_web(port, name):
            queue.add_job(Job(f"{host}:web:{port}", prio("web"), background=False,
                coro_factory=functools.partial(enum_web, host, port, name, runner, args, findings)))
            if args.nikto:
                queue.add_job(Job(f"{host}:nikto:{port}", PRIO_BACKGROUND, background=True,
                    coro_factory=functools.partial(enum_nikto, host, port, name, runner, args, findings)))
        elif port in (139, 445) or "microsoft-ds" in name or "netbios" in name:
            queue.add_job(Job(f"{host}:smb", prio("smb"), background=False,
                coro_factory=functools.partial(enum_smb, host, runner, args, findings)))
        elif port in (389, 636, 3268, 3269) or "ldap" in name:
            queue.add_job(Job(f"{host}:ldap", prio("ldap"), background=False,
                coro_factory=functools.partial(enum_ldap, host, port, runner, args, findings, queue)))
        elif port == 21 or "ftp" in name:
            queue.add_job(Job(f"{host}:ftp:{port}", prio("ftp"), background=False,
                coro_factory=functools.partial(enum_ftp, host, port, runner, args, findings)))
        elif port == 22 or "ssh" in name:
            queue.add_job(Job(f"{host}:ssh:{port}", prio("ssh"), background=False,
                coro_factory=functools.partial(enum_ssh, host, port, runner, args, findings)))
        elif port == 25 or port in (465, 587) or "smtp" in name:
            queue.add_job(Job(f"{host}:smtp:{port}", prio("smtp"), background=False,
                coro_factory=functools.partial(enum_smtp, host, port, runner, args, findings)))
        elif port == 53 or "domain" in name or "dns" in name:
            queue.add_job(Job(f"{host}:dns:{port}", prio("dns"), background=False,
                coro_factory=functools.partial(enum_dns, host, port, runner, args, findings)))
        elif port == 2049 or "nfs" in name:
            queue.add_job(Job(f"{host}:nfs", prio("nfs"), background=False,
                coro_factory=functools.partial(enum_nfs, host, runner, args, findings)))
        elif port == 1433 or "ms-sql" in name or "mssql" in name:
            queue.add_job(Job(f"{host}:mssql:{port}", prio("mssql"), background=False,
                coro_factory=functools.partial(enum_mssql, host, port, runner, args, findings)))
        elif port in (6379,) or "redis" in name:
            queue.add_job(Job(f"{host}:redis:{port}", prio("redis"), background=False,
                coro_factory=functools.partial(enum_redis, host, port, runner, args, findings)))
        elif port == 5432 or "postgres" in name:
            queue.add_job(Job(f"{host}:postgres:{port}", prio("postgres"), background=False,
                coro_factory=functools.partial(enum_postgres, host, port, runner, args, findings)))
        elif port in (110, 995) or "pop3" in name:
            queue.add_job(Job(f"{host}:pop3:{port}", prio("pop3"), background=False,
                coro_factory=functools.partial(enum_pop3, host, port, runner, args, findings)))
        elif port in (143, 993) or "imap" in name:
            queue.add_job(Job(f"{host}:imap:{port}", prio("imap"), background=False,
                coro_factory=functools.partial(enum_imap, host, port, runner, args, findings)))
        elif port in (5985, 5986) or "winrm" in name:
            queue.add_job(Job(f"{host}:winrm:{port}", prio("winrm"), background=False,
                coro_factory=functools.partial(enum_winrm, host, port, runner, args, findings)))
        elif port == 3389 or "ms-wbt" in name or "rdp" in name:
            queue.add_job(Job(f"{host}:rdp:{port}", prio("rdp"), background=False,
                coro_factory=functools.partial(enum_rdp, host, port, runner, args, findings)))

        # profile hints - guarded per-port so the guess pass + confirm pass
        # (both of which see this same port) never double-count.
        if port not in counted:
            if port == 88 or "kerberos" in name:
                host_profile["dc_signals"] += 1
                findings.append(Finding("HIGH", "ad", 88, "Kerberos (88) open - strong Domain Controller signal"))
                counted.add(port)
            elif port in (389, 636) and (445 in services or 88 in services):
                host_profile["dc_signals"] += 1
                counted.add(port)


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #
def print_summary(host, services, udp, findings, host_profile, elapsed, args=None):
    print()
    print(f"{C.BOLD}{'='*70}{C.END}")
    print(f"{C.BOLD}  RECONX SUMMARY  -  {host}   ({elapsed:.1f}s){C.END}")
    print(f"{C.BOLD}{'='*70}{C.END}")

    # host profile
    if host_profile["dc_signals"] >= 2:
        print(f"  {C.M}{C.BOLD}HOST PROFILE:{C.END} likely {C.M}Active Directory Domain Controller{C.END} "
              f"- start with LDAP/Kerberos/SMB")
    else:
        label = HOST_TYPE_LABELS.get(host_profile.get("host_type"))
        if label:
            print(f"  {C.M}{C.BOLD}HOST PROFILE:{C.END} likely {C.M}{label}{C.END} - enum priority weighted accordingly")
    print()

    # open ports table
    print(f"  {C.BOLD}OPEN TCP PORTS{C.END}")
    for port in sorted(services):
        meta = services[port]
        ver = meta.get("version", "")
        print(f"    {C.G}{port:<6}{C.END} {meta.get('name',''):<16} {C.DIM}{ver}{C.END}")
    if udp:
        print(f"\n  {C.BOLD}OPEN UDP PORTS{C.END}")
        for port, name in sorted(udp.items()):
            print(f"    {C.CY}{port:<6}{C.END} {name}")
    print()

    # findings, ranked
    if findings:
        # de-dup
        seen = set(); uniq = []
        for f in findings:
            key = (f.sev, f.service, f.port, f.text)
            if key not in seen:
                seen.add(key); uniq.append(f)
        uniq.sort(key=lambda f: (SEV_ORDER.get(f.sev, 9), f.port or 0))

        print(f"  {C.BOLD}RANKED FINDINGS  (look at these first){C.END}")
        for f in uniq:
            col = SEV_COLOR.get(f.sev, "")
            p = f":{f.port}" if f.port else ""
            print(f"    {col}{f.sev:<8}{C.END} {C.DIM}{f.service}{p}{C.END}  {f.text}")
    else:
        print(f"  {C.DIM}No high-signal findings auto-detected. Enumerate the open "
              f"ports manually - the tool only flags the obvious wins.{C.END}")

    # suggested next steps
    print(f"\n  {C.BOLD}SUGGESTED NEXT STEPS{C.END}")
    for step in suggest_next(services, findings, host_profile, args):
        print(f"    {C.B}->{C.END} {step}")
    print(f"{C.BOLD}{'='*70}{C.END}\n")


def suggest_next(services, findings, host_profile, args=None):
    steps = []
    svc_present = {f.service for f in findings}
    ports = set(services)

    if args is not None and have_creds(args):
        steps.append("You have creds: SPRAY them across every host (reconx <cidr> -u .. -p .. --spray) - reuse is the fastest win.")
        if any(re.search(r"\(Pwn3d!\)|login works|SHELL", f.text) for f in findings):
            steps.append("Admin/shell confirmed above - get your shell, then dump SAM/LSASS or hunt for the next credential.")

    if host_profile["dc_signals"] >= 2:
        steps.append("AD: enumerate users via LDAP/RID, then AS-REP roast (impacket GetNPUsers) and Kerberoast.")
    if "ftp" in svc_present:
        steps.append("FTP: log in anonymously, pull every file, check for creds/config/web-root overlap.")
    if 445 in ports or 139 in ports:
        steps.append("SMB: list shares with null/guest, mount readable ones, grep for passwords & scripts.")
    if any(is_web(p, services[p].get('name','')) for p in ports):
        steps.append("Web: read the dirbrute output, hit 401/403/interesting paths, check source & default creds.")
    if 22 in ports:
        steps.append("SSH: no shell yet - only useful once you harvest a username+password/key elsewhere.")
    if "snmp" in svc_present:
        steps.append("SNMP: full walk with 'public' - extract usernames, running processes, and network info.")
    if 5432 in ports or "postgres" in svc_present:
        steps.append("PostgreSQL: try postgres:postgres/blank; if in, use COPY ... FROM PROGRAM or pg_read_file to read/exec.")
    if 110 in ports or 143 in ports or 993 in ports or 995 in ports or "pop3" in svc_present or "imap" in svc_present:
        steps.append("Mail (POP3/IMAP): try creds you've already harvested - mailbox logins often reuse domain passwords and leak more creds.")
    if not steps:
        steps.append("Re-read raw output under the loot dir; run a full -p- if you only did top-ports.")
    steps.append("Keep a full-range TCP + UDP scan running in the background while you work the above.")
    return steps


def write_markdown(host, services, udp, findings, outdir, host_profile):
    path = os.path.join(outdir, host, "NOTES.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(f"# recon notes - {host}\n\n_generated {datetime.now():%Y-%m-%d %H:%M}_\n\n")
        if host_profile["dc_signals"] >= 2:
            f.write("> **Host profile:** likely Active Directory Domain Controller.\n\n")
        else:
            label = HOST_TYPE_LABELS.get(host_profile.get("host_type"))
            if label:
                f.write(f"> **Host profile:** likely {label}.\n\n")
        f.write("## Open TCP ports\n\n| Port | Service | Version |\n|---|---|---|\n")
        for p in sorted(services):
            m = services[p]
            f.write(f"| {p} | {m.get('name','')} | {m.get('version','')} |\n")
        if udp:
            f.write("\n## Open UDP ports\n\n| Port | Service |\n|---|---|\n")
            for p in sorted(udp):
                f.write(f"| {p} | {udp[p]} |\n")
        f.write("\n## Ranked findings\n\n")
        uniq = {(x.sev, x.service, x.port, x.text) for x in findings}
        for sev, svc, port, text in sorted(uniq, key=lambda t: SEV_ORDER.get(t[0], 9)):
            f.write(f"- **{sev}** `{svc}{':'+str(port) if port else ''}` - {text}\n")
        f.write("\n## To do\n\n- [ ] \n")
    return path


# --------------------------------------------------------------------------- #
#  Host orchestration
#
#  Each job_* wrapper owns "register whatever comes next" as a side effect of
#  finishing its own await - that's the whole dependency mechanism: a job is
#  only ever added by code that runs after its prerequisite already
#  completed, so every job in the queue is runnable the instant it's added.
#  discover_ports()/service_scan()/udp_scan()/enum_*() themselves are
#  untouched pure workers.
# --------------------------------------------------------------------------- #
async def job_discover(host, runner, args, queue, findings, host_profile, host_state, state_store):
    if (args.resume and state_store
            and state_store.job_status(f"{host}:discover") == "done"
            and state_store.data.get("ports")):
        ports = state_store.data["ports"]
        info(f"resume: using {len(ports)} cached port(s) for {host}")
    else:
        ports = await discover_ports(host, runner, args)
        if runner.dry_run:
            ports = ports or [21, 22, 80, 445]  # sample so the plan shows modules
        if state_store:
            await state_store.save_ports_services(ports=ports)
    host_state["ports"] = ports

    if not ports:
        warn(f"{host}: no open TCP ports found (host down / filtered / try --no-rustscan)")
        return ports
    good(f"{host}: {len(ports)} open port(s): {', '.join(map(str, ports))}")

    # guess pass: fast opportunistic modules start now, without waiting on nmap
    guessed = {p: {"name": guess_service(p), "version": ""} for p in ports}
    register_service_jobs(queue, host, guessed, runner, args, findings, host_profile)

    queue.add_job(Job(f"{host}:service_scan", PRIO_SCAN, background=False, always_reenter=True,
        coro_factory=functools.partial(job_service_scan, host, ports, runner, args,
                                        queue, findings, host_profile, host_state, state_store)))
    queue.add_job(Job(f"{host}:udp_scan", PRIO_SCAN, background=True,
        coro_factory=functools.partial(job_udp_scan, host, runner, args, host_state, state_store)))
    if args.mode == "deep" and TOOLS.get("nmap"):
        queue.add_job(Job(f"{host}:vuln_scan", PRIO_BACKGROUND, background=True,
            coro_factory=functools.partial(job_vuln_scan, host, ports, runner, args, findings)))
    return ports


async def job_service_scan(host, ports, runner, args, queue, findings, host_profile, host_state, state_store):
    if (args.resume and state_store
            and state_store.job_status(f"{host}:service_scan") == "done"
            and state_store.data.get("services")):
        services = state_store.data["services"]
        info(f"resume: using cached service scan for {host}")
    else:
        services = await service_scan(host, ports, runner, args)
        if state_store:
            await state_store.save_ports_services(services=services)
    host_state["services"] = services

    # confirm pass: corrects anything the port-guess pass got wrong or missed
    register_service_jobs(queue, host, services, runner, args, findings, host_profile)

    if not args.no_exploit_search:
        queue.add_job(Job(f"{host}:searchsploit", PRIO_EXPLOIT, background=False,
            coro_factory=functools.partial(searchsploit_lookup, host, services, runner, args, findings)))
    return services


async def job_udp_scan(host, runner, args, host_state, state_store):
    udp = await udp_scan(host, runner, args)
    host_state["udp"] = udp
    if state_store:
        await state_store.save_ports_services(udp=udp)
    return udp


_NMAP_PORT_BLOCK_RX = re.compile(r"^(\d+)/tcp\s+open\b", re.M)


async def job_vuln_scan(host, ports, runner, args, findings):
    """--mode deep only: an extra nmap NSE vuln-category sweep, backgrounded
    since it's slow and purely opportunistic."""
    plist = ",".join(str(p) for p in ports)
    cmd = f"nmap -Pn -sV --script vuln -p {plist} -oN /dev/stdout {host}"
    rc, out = await runner.run(cmd, outfile=f"{host}/scans/nmap_vuln.txt",
                               label="nmap-vuln", timeout=args.scan_timeout)
    # Split into per-port blocks so findings get attributed to their real
    # port instead of a bare port=None duplicate of what service_scan/enum_*
    # already found (the -sV banner text that reappears in this output would
    # otherwise re-trigger the same FINDING_RULES with a different dedup key).
    blocks = list(_NMAP_PORT_BLOCK_RX.finditer(out or ""))
    if not blocks:
        scan_findings(out, "vuln", None, findings)
    else:
        for i, m in enumerate(blocks):
            end = blocks[i + 1].start() if i + 1 < len(blocks) else len(out)
            scan_findings(out[m.start():end], "vuln", int(m.group(1)), findings)
    good(f"{host}: vuln-script scan done")


async def scan_host(host, runner, args):
    t0 = time.time()
    host_profile = {"dc_signals": 0}
    host_state = {"ports": [], "services": {}, "udp": {}}
    os.makedirs(os.path.join(runner.outdir, host, "scans"), exist_ok=True)

    good(f"=== target: {host} ===")

    state_store = None if runner.dry_run else StateStore(runner.outdir, host)
    if args.resume and state_store:
        state_store.load()
    if state_store:
        state_store.data["mode"] = args.mode
        state_store.data["started_at"] = state_store.data.get("started_at") or \
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    findings = FindingsList(state_store=state_store)
    if args.resume and state_store and state_store.data.get("findings"):
        for sev, svc, port, text in state_store.data["findings"]:
            findings.seed(Finding(sev, svc, port, text))
        if findings:
            info(f"resume: restored {len(findings)} cached finding(s) for {host}")

    async with JobQueue(workers=args.workers, state_store=state_store) as queue:
        queue.add_job(Job(f"{host}:discover", PRIO_DISCOVER, background=False, always_reenter=True,
            coro_factory=functools.partial(job_discover, host, runner, args, queue,
                                            findings, host_profile, host_state, state_store)))
        await queue.wait_core_done()

        if not host_state["ports"]:
            return

        elapsed = time.time() - t0
        if not runner.dry_run:
            print_summary(host, host_state["services"], host_state["udp"], findings,
                          host_profile, elapsed, args)
            md = write_markdown(host, host_state["services"], host_state["udp"], findings,
                                runner.outdir, host_profile)
            good(f"notes written: {md}")

        if queue.had_background_jobs:
            info("background modules (udp/nikto/vuln-scan) still running - "
                 "NOTES.md will be refreshed when they finish")
        await queue.wait_all_done()
        if not runner.dry_run and queue.had_background_jobs:
            write_markdown(host, host_state["services"], host_state["udp"], findings,
                           runner.outdir, host_profile)
            good(f"{host}: background modules finished - notes updated")


# --------------------------------------------------------------------------- #
#  Targets
# --------------------------------------------------------------------------- #
def expand_targets(target):
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass
    return [target]


async def spray_credential(hosts, runner, args):
    """Test ONE credential across many hosts via SMB (and WinRM). netexec accepts
    a space-separated host list, so this is a single fast pass per protocol.
    Deliberately sprays a SINGLE credential to avoid account lockout."""
    nxc = nxc_bin()
    if not nxc:
        bad("spray needs netexec/nxc - not found.")
        return
    auth = nxc_auth(args)
    targets = " ".join(hosts)
    good(f"spraying {C.M}{cred_label(args)}{C.END} across {len(hosts)} host(s) via SMB/WinRM")
    findings = FindingsList()
    os.makedirs(os.path.join(runner.outdir, "_spray"), exist_ok=True)
    locked_out = False
    for proto in ("smb", "winrm"):
        rc, out = await runner.run(f"{nxc} {proto} {targets} {auth}",
                                   f"_spray/{proto}.txt", f"spray-{proto}",
                                   timeout=args.scan_timeout)
        # surface each valid host / admin
        for line in (out or "").splitlines():
            if "(Pwn3d!)" in line:
                findings.append(Finding("CRITICAL", proto, None, f"ADMIN: {line.strip()}"))
            elif re.search(r"\[\+\]", line):
                findings.append(Finding("HIGH", proto, None, f"valid: {line.strip()}"))
            elif "STATUS_ACCOUNT_LOCKED_OUT" in line:
                findings.append(Finding("HIGH", "creds", None, "LOCKOUT hit - stop now"))
                bad("account lockout detected - stopping spray")
                locked_out = True
                break
        if locked_out:
            break
    # report
    print(f"\n{C.BOLD}{'='*70}{C.END}")
    print(f"{C.BOLD}  SPRAY RESULTS  -  {cred_label(args)}{C.END}")
    print(f"{C.BOLD}{'='*70}{C.END}")
    if findings:
        findings.sort(key=lambda f: SEV_ORDER.get(f.sev, 9))
        for f in findings:
            print(f"    {SEV_COLOR.get(f.sev,'')}{f.sev:<8}{C.END} {C.DIM}{f.service}{C.END}  {f.text}")
        print(f"\n  {C.B}->{C.END} For any (Pwn3d!) SMB host: dump SAM / secrets. "
              f"For WinRM valid: evil-winrm -i <host> -u {args.user} ...")
    else:
        print(f"  {C.DIM}Credential not valid on any host via SMB/WinRM. Try other protocols "
              f"(mssql/rdp/ssh) or another host set.{C.END}")
    print(f"{C.BOLD}{'='*70}{C.END}\n")


async def ping_sweep(hosts, args):
    """Quick liveness check so we don't waste time on dead hosts in a /24."""
    alive = []
    sem = asyncio.Semaphore(256)

    async def check(h):
        async with sem:
            # TCP-ping common ports; ICMP needs root and is often filtered
            for p in (445, 80, 22, 443, 135):
                if await tcp_connect(h, p, timeout=1.0):
                    alive.append(h); return

    await asyncio.gather(*(check(h) for h in hosts))
    return sorted(alive, key=lambda x: tuple(int(o) for o in x.split(".")) if x.count(".")==3 and all(o.isdigit() for o in x.split(".")) else (0,))


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def build_argparser():
    p = argparse.ArgumentParser(
        prog="reconx",
        description="Lean, fast, accurate recon orchestrator (AutoRecon alternative).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Authorized targets only. Examples:\n"
               "  reconx 10.10.10.10\n"
               "  reconx 10.10.10.0/24 --ping-sweep --quick\n"
               "  reconx target.htb --nikto -o loot/\n"
               "  reconx dc01.corp.htb -u alex.turner -p 'Passw0rd!' -d corp.htb\n"
               "  reconx 10.10.10.0/24 -u svc -H <ntlm-hash> --spray\n"
               "  reconx 10.10.10.10 --dry-run",
    )
    p.add_argument("target", help="IP, hostname, or CIDR (e.g. 10.10.10.0/24)")
    p.add_argument("-o", "--outdir", default="reconx-results", help="output directory")
    # --- credentials (authorized testing only) ---
    cg = p.add_argument_group("credentials (authenticated enumeration)")
    cg.add_argument("-u", "--user", help="username for authenticated enum")
    cg.add_argument("-p", "--pass", dest="password", help="password (use --hash for NTLM)")
    cg.add_argument("-H", "--hash", help="NTLM hash for pass-the-hash (LM:NT or :NT)")
    cg.add_argument("-d", "--domain", help="AD domain (e.g. corp.htb)")
    cg.add_argument("--local-auth", action="store_true", help="treat creds as LOCAL account, not domain")
    cg.add_argument("--spray", action="store_true",
                    help="spray the ONE credential across all hosts (CIDR) via SMB/WinRM")
    p.add_argument("--mode", choices=("quick", "full", "deep"), default=None,
                   help="scan profile: quick (fast, no UDP/scripts), full (default), "
                        "deep (bigger wordlist, nikto+vuln-scripts auto-on)")
    p.add_argument("--quick", action="store_true", help="top-1000 ports only (fast); shorthand for --mode quick")
    p.add_argument("--top-ports", type=int, help="scan only the top N common ports")
    p.add_argument("--no-udp", action="store_true", help="skip UDP scan")
    p.add_argument("--no-scripts", action="store_true", help="nmap -sV only, no -sC")
    p.add_argument("--no-rustscan", action="store_true", help="force built-in async scanner")
    p.add_argument("--nikto", action="store_true", help="run nikto on web ports (noisy, backgrounded)")
    p.add_argument("--bloodhound", action="store_true",
                   help="run a full BloodHound collection (-c All) against an authenticated LDAP target (backgrounded)")
    p.add_argument("--ping-sweep", action="store_true", help="liveness-check a CIDR first")
    p.add_argument("--wordlist", default=None,
                   help="dirbrute wordlist (default: auto-detect, mode-aware)")
    p.add_argument("--concurrency", type=int, default=800, help="async scan concurrency")
    p.add_argument("--parallel", type=int, default=6, help="max concurrent external commands")
    p.add_argument("--workers", type=int, default=8,
                   help="job-queue worker pool size (how many modules run at once)")
    p.add_argument("--version-intensity", type=int, default=None,
                   help="nmap --version-intensity for -sCV (default 6, 9 in --mode deep)")
    p.add_argument("--host-timeout", type=float, default=1.5, help="per-port connect timeout (s)")
    p.add_argument("--scan-timeout", type=int, default=1800, help="port/service scan timeout (s)")
    p.add_argument("--enum-timeout", type=int, default=600, help="per-enum-module timeout (s)")
    p.add_argument("--timeout", type=int, default=900, help="default command timeout (s)")
    p.add_argument("--dry-run", action="store_true", help="print the command plan, run nothing")
    p.add_argument("--resume", action="store_true",
                   help="skip commands whose output file already exists in outdir (resume an interrupted run)")
    p.add_argument("--no-exploit-search", action="store_true",
                   help="skip searchsploit lookups for detected service versions")
    p.add_argument("-v", "--verbose", action="store_true", help="print every command as it runs")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    return p


BANNER = r"""
                              __  __
  _ __ ___  ___ ___  _ __ __ _\ \/ /   lean . fast . accurate
 | '__/ _ \/ __/ _ \| '_ \ \ / /\  /   an AutoRecon alternative
 | | |  __/ (_| (_) | | | \ V / /  \   authorized targets only
 |_|  \___|\___\___/|_| |_|_/_/  /_/\_\
"""

# candidate dirbrute wordlists, checked in order - seclists has renamed this
# file across releases (DirBuster-2007_ prefix added, then dropped again), so
# don't trust one hardcoded path. Mode-aware: quick wants something small and
# fast, deep wants the biggest list actually installed.
QUICK_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]
DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
]
DEEP_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
] + DEFAULT_WORDLISTS


def resolve_wordlist(args):
    """Fill in args.wordlist, verifying it actually exists on disk.

    feroxbuster/gobuster exit 0 even when the wordlist path is bad, so a
    silently-wrong default used to produce an empty dirbust with no warning.
    """
    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            warn(f"wordlist not found: {args.wordlist} - dirbrute will be skipped")
            args.wordlist = None
        return
    candidates = {"quick": QUICK_WORDLISTS, "deep": DEEP_WORDLISTS}.get(
        getattr(args, "mode", None), DEFAULT_WORDLISTS)
    for cand in candidates:
        if os.path.isfile(cand):
            args.wordlist = cand
            return
    warn("no default dirbrute wordlist found - pass --wordlist PATH (dirbrute will be skipped)")


# top-1000-ish common TCP ports for --quick and the async fallback
TOP_1000 = [1,3,7,9,13,17,19,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1434,1521,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3268,3269,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,5985,5986,6000,6001,6379,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9200,9999,10000,27017,32768,49152,49153,49154,49155,49156,49157]


def apply_mode_defaults(args):
    """Resolve --mode into the underlying flags. Mode defaults only ever
    strengthen a store_true flag from False->True, never the reverse -
    Python 3.8 (this tool's floor) has no reliable way to detect "the user
    explicitly passed --no-X" for a plain store_true flag, so an explicit
    flag can only ever be left alone or turned on by mode, never overridden
    off. --mode quick forcing no_udp/no_scripts True is a known, accepted
    limitation: there's no way to un-force that short of not using that mode.
    """
    if args.mode is None:
        args.mode = "quick" if args.quick else "full"
    elif args.mode == "quick":
        args.quick = True

    if args.mode == "quick":
        args.no_udp = True
        args.no_scripts = True
    elif args.mode == "deep":
        args.nikto = True
        if args.version_intensity is None:
            args.version_intensity = 9
    return args.mode


async def amain(args):
    apply_mode_defaults(args)
    refresh_tools()
    resolve_wordlist(args)
    runner = Runner(args.outdir, dry_run=args.dry_run,
                    timeout=args.timeout, verbose=args.verbose, resume=args.resume)
    runner.sem = asyncio.Semaphore(args.parallel)

    print(C.CY + BANNER + C.END)
    info(f"mode: {C.M}{args.mode}{C.END}  workers: {args.workers}  parallel: {args.parallel}")
    missing = [t for t in ("rustscan", "nmap", "feroxbuster", "gobuster", "whatweb",
                           "enum4linux-ng", "nxc", "netexec", "smtp-user-enum") if not TOOLS.get(t)]
    have = [t for t in ("rustscan", "nmap", "feroxbuster", "gobuster", "whatweb",
                        "enum4linux-ng", "nxc", "netexec", "smbclient", "ldapsearch",
                        "snmpwalk", "curl", "smtp-user-enum") if TOOLS.get(t)]
    info(f"tools available: {C.G}{', '.join(have) or 'none'}{C.END}")
    if missing:
        warn(f"missing (modules will degrade/skip): {C.DIM}{', '.join(missing)}{C.END}")

    # credential status + safety
    if have_creds(args):
        good(f"authenticated mode: {C.M}{cred_label(args)}{C.END}")
        if not nxc_bin():
            warn("no netexec/nxc found - authenticated checks need it; install netexec")
        if not args.local_auth and not args.domain:
            warn("no -d/--domain set with a domain account - some AD checks may fail; add -d, or --local-auth for local accounts")
        if args.spray and not args.local_auth:
            warn(f"{C.R}SPRAY on a DOMAIN account can trigger lockout.{C.END} "
                 f"reconx sprays ONE credential (not many) to stay safe, but confirm the lockout policy first.")
    elif args.spray:
        bad("--spray needs a credential (-u with -p or -H). Ignoring.")
        args.spray = False

    hosts = expand_targets(args.target)
    if len(hosts) > 1 and args.ping_sweep and not args.dry_run:
        info(f"ping-sweeping {len(hosts)} hosts...")
        hosts = await ping_sweep(hosts, args)
        good(f"{len(hosts)} host(s) alive")

    # spray path: one credential across many hosts, then stop (don't full-scan the /24)
    if args.spray and have_creds(args) and len(hosts) > 1:
        await spray_credential(hosts, runner, args)
        return

    if len(hosts) > 1:
        info(f"scanning {len(hosts)} host(s) sequentially (per-host modules run in parallel)")

    for h in hosts:
        try:
            await scan_host(h, runner, args)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            bad(f"{h}: error - {e}")

    if args.dry_run:
        print(f"\n{C.BOLD}=== DRY RUN: command plan ({len(runner.plan)} commands) ==={C.END}")
        for label, cmd, outfile in runner.plan:
            print(f"  {C.G}{label:<16}{C.END} {cmd}")
        print(f"\n{C.DIM}No commands were executed.{C.END}\n")


def main():
    args = build_argparser().parse_args()
    if args.no_color or not sys.stdout.isatty():
        C.strip()
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] interrupted - partial results are on disk.{C.END}")
        sys.exit(130)


if __name__ == "__main__":
    main()
