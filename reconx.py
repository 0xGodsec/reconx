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
import ipaddress
import os
import re
import shutil
import socket
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


# --------------------------------------------------------------------------- #
#  Tool availability (graceful degradation)
# --------------------------------------------------------------------------- #
def which(name):
    return shutil.which(name) is not None


TOOLS = {}
def refresh_tools():
    for t in ("rustscan", "nmap", "whatweb", "feroxbuster", "gobuster", "nikto",
              "curl", "enum4linux-ng", "enum4linux", "nxc", "netexec", "crackmapexec",
              "smbclient", "smbmap", "rpcclient", "ldapsearch", "nbtscan",
              "snmpwalk", "onesixtyone", "showmount", "dig", "nslookup",
              "hydra", "ssh", "redis-cli", "psql", "openssl", "ncat", "nc"):
        TOOLS[t] = which(t)


# --------------------------------------------------------------------------- #
#  Command runner
# --------------------------------------------------------------------------- #
class Runner:
    def __init__(self, outdir, dry_run=False, timeout=900, verbose=False):
        self.outdir = outdir
        self.dry_run = dry_run
        self.timeout = timeout
        self.verbose = verbose
        self.plan = []          # for --dry-run
        self.sem = None         # set once loop exists

    async def run(self, cmd, outfile=None, label=None, timeout=None):
        """Run a shell command, tee output to a file, return (rc, stdout+stderr)."""
        label = label or cmd.split()[0]
        if self.dry_run:
            self.plan.append((label, cmd, outfile))
            return 0, ""
        async with self.sem:
            if self.verbose:
                info(f"run: {C.DIM}{cmd}{C.END}")
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                try:
                    out, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout or self.timeout)
                except asyncio.TimeoutError:
                    proc.kill()
                    warn(f"timeout ({label}) after {timeout or self.timeout}s")
                    return 124, ""
                text = out.decode(errors="replace") if out else ""
                if outfile:
                    path = os.path.join(self.outdir, outfile)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", errors="replace") as f:
                        f.write(f"# cmd: {cmd}\n\n{text}")
                return proc.returncode, text
            except FileNotFoundError:
                bad(f"command not found: {cmd.split()[0]}")
                return 127, ""


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
        rustscan_range = "--top"
    elif args.top_ports:
        port_list = TOP_1000[: args.top_ports] if args.top_ports <= len(TOP_1000) else range(1, 65536)
        rustscan_range = None
    else:
        port_list = range(1, 65536)
        rustscan_range = None

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
    cmd = (f"nmap -Pn -sV {scripts} -p {plist} --version-intensity 6 "
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


def smbmap_auth(args):
    parts = [f"-u {_sh_quote(args.user)}"]
    if getattr(args, "hash", None):
        parts.append(f"-p {_sh_quote(args.hash)}")   # smbmap accepts LM:NT or NT hash via -p
    else:
        parts.append(f"-p {_sh_quote(args.password)}")
    if getattr(args, "domain", None):
        parts.append(f"-d {_sh_quote(args.domain)}")
    return " ".join(parts)


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
    ("HIGH",     re.compile(r"\b(admin|password|root|toor|user|guest|sa)\b\s*[:/]\s*\b\w+\b", re.I), "creds", "Possible default/leaked credential in output"),
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
async def enum_web(host, port, name, runner, args, findings):
    scheme = "https" if (port in (443, 8443, 5986) or "https" in name or "ssl" in name) else "http"
    base = f"{scheme}://{host}:{port}"
    tag = f"{host}/web_{port}"

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
    if TOOLS.get("feroxbuster"):
        cmd = (f"feroxbuster -u {base} -w {wl} -t 50 -q --no-recursion "
               f"-s 200,204,301,302,307,401,403 -o {os.path.join(runner.outdir, tag, 'ferox.txt')}")
        rc, out = await runner.run(cmd, None, "feroxbuster", timeout=args.enum_timeout)
        scan_findings(out, "http", port, findings)
    elif TOOLS.get("gobuster"):
        cmd = f"gobuster dir -u {base} -w {wl} -t 50 -q -k"
        rc, out = await runner.run(cmd, f"{tag}/gobuster.txt", "gobuster", timeout=args.enum_timeout)
        scan_findings(out, "http", port, findings)
    else:
        warn(f"no feroxbuster/gobuster - skipping dirbrute on {base}")

    # nikto (optional; noisy)
    if args.nikto and TOOLS.get("nikto"):
        rc, out = await runner.run(f"nikto -host {base} -maxtime {args.enum_timeout}s",
                                   f"{tag}/nikto.txt", "nikto", timeout=args.enum_timeout + 30)
        scan_findings(out, "http", port, findings)

    good(f"web enum done: {base}")


async def enum_smb(host, runner, args, findings):
    tag = f"{host}/smb"
    nxc = nxc_bin()
    if have_creds(args):
        # authenticated: check access, admin (Pwn3d!), shares, users, and loot.
        # nxc and smbmap are independent here - a missing nxc should not silently
        # skip the smbmap-based authenticated check (and vice versa).
        if nxc:
            auth = nxc_auth(args)
            for sub in ("--shares", "--users", "--pass-pol", "--loggedon-users", "--sam"):
                rc, out = await runner.run(f"{nxc} smb {host} {auth} {sub}",
                                           f"{tag}/auth_nxc{sub.replace('-','')}.txt", f"{nxc} smb {sub}")
                scan_findings(out, "smb", 445, findings)
        if TOOLS.get("smbmap"):
            rc, out = await runner.run(f"smbmap -H {host} {smbmap_auth(args)}",
                                       f"{tag}/auth_smbmap.txt", "smbmap-auth")
            scan_findings(out, "smb", 445, findings)
        if not nxc and not TOOLS.get("smbmap"):
            findings.append(Finding("MEDIUM", "smb", 445,
                "Creds supplied but no netexec/nxc or smbmap found - authenticated SMB untested"))
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
    if TOOLS.get("smbmap"):
        rc, out = await runner.run(f"smbmap -H {host} -u guest -p ''", f"{tag}/smbmap.txt", "smbmap")
        scan_findings(out, "smb", 445, findings)
    good("smb enum done")


async def enum_ldap(host, port, runner, args, findings):
    tag = f"{host}/ldap"
    if TOOLS.get("ldapsearch"):
        rc, out = await runner.run(
            f"ldapsearch -x -H ldap://{host}:{port} -s base -b '' namingContexts defaultNamingContext",
            f"{tag}/rootdse.txt", "ldap-rootdse")
        scan_findings(out, "ldap", port, findings)
        # try to pull naming context and dump anonymously
        m = re.search(r"(?:defaultNamingContext|namingContexts):\s*(DC=[^\n]+)", out or "", re.I)
        if m:
            base = m.group(1).strip()
            findings.append(Finding("HIGH", "ldap", port, f"LDAP base found: {base}"))
            rc, out2 = await runner.run(
                f"ldapsearch -x -H ldap://{host}:{port} -b '{base}'",
                f"{tag}/anon_dump.txt", "ldap-dump", timeout=args.enum_timeout)
            scan_findings(out2, "ldap", port, findings)
    # authenticated: netexec LDAP enum + BloodHound collection hint
    if have_creds(args):
        nxc = nxc_bin()
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
        dom = args.domain or "<domain>"
        findings.append(Finding("HIGH", "ad", port,
            f"Authenticated to LDAP - run BloodHound now: "
            f"bloodhound-python -u {args.user} -p <pass> -d {dom} -ns {host} -c all"))
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


async def enum_smtp(host, port, runner, args, findings):
    tag = f"{host}/smtp"
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script smtp-commands,smtp-enum-users,smtp-open-relay -oN /dev/stdout {host}",
            f"{tag}/smtp_nse.txt", "nmap-smtp")
        scan_findings(out, "smtp", port, findings)
    good("smtp enum done")


async def enum_dns(host, port, runner, args, findings):
    tag = f"{host}/dns"
    if TOOLS.get("dig"):
        rc, out = await runner.run(f"dig @{host} version.bind chaos txt +short",
                                   f"{tag}/version.txt", "dig-version")
        # zone transfer attempt against any domain we can guess from reverse
        rc2, out2 = await runner.run(f"dig @{host} -x {host} +short", f"{tag}/ptr.txt", "dig-ptr")
        good("dns basic checks done (add AXFR manually once you know the domain)")


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
    # 1) nmap NSE for version + brute-lite info
    if TOOLS.get("nmap"):
        rc, out = await runner.run(
            f"nmap -Pn -p {port} --script pgsql-brute -oN /dev/stdout {host}",
            f"{tag}/pgsql_nse.txt", "nmap-pgsql", timeout=args.enum_timeout)
        scan_findings(out, "postgres", port, findings)
    # 2) netexec: use supplied creds if we have them, else default-cred sweep
    nxc = nxc_bin()
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
#  Dispatcher: map services -> modules
# --------------------------------------------------------------------------- #
async def dispatch(host, services, runner, args, findings, host_profile):
    tasks = []
    smb_seen = ldap_seen = False
    for port, meta in sorted(services.items()):
        name = meta.get("name", guess_service(port))

        if is_web(port, name):
            tasks.append(enum_web(host, port, name, runner, args, findings))
        elif port in (139, 445) or "microsoft-ds" in name or "netbios" in name:
            if not smb_seen:
                tasks.append(enum_smb(host, runner, args, findings)); smb_seen = True
        elif port in (389, 636, 3268, 3269) or "ldap" in name:
            if not ldap_seen:
                tasks.append(enum_ldap(host, port, runner, args, findings)); ldap_seen = True
        elif port == 21 or "ftp" in name:
            tasks.append(enum_ftp(host, port, runner, args, findings))
        elif port == 22 or "ssh" in name:
            tasks.append(enum_ssh(host, port, runner, args, findings))
        elif port == 25 or port in (465, 587) or "smtp" in name:
            tasks.append(enum_smtp(host, port, runner, args, findings))
        elif port == 53 or "domain" in name or "dns" in name:
            tasks.append(enum_dns(host, port, runner, args, findings))
        elif port == 2049 or "nfs" in name:
            tasks.append(enum_nfs(host, runner, args, findings))
        elif port == 1433 or "ms-sql" in name or "mssql" in name:
            tasks.append(enum_mssql(host, port, runner, args, findings))
        elif port in (6379,) or "redis" in name:
            tasks.append(enum_redis(host, port, runner, args, findings))
        elif port == 5432 or "postgres" in name:
            tasks.append(enum_postgres(host, port, runner, args, findings))
        elif port in (110, 995) or "pop3" in name:
            tasks.append(enum_pop3(host, port, runner, args, findings))
        elif port in (143, 993) or "imap" in name:
            tasks.append(enum_imap(host, port, runner, args, findings))
        elif port in (5985, 5986) or "winrm" in name:
            tasks.append(enum_winrm(host, port, runner, args, findings))
        elif port == 3389 or "ms-wbt" in name or "rdp" in name:
            tasks.append(enum_rdp(host, port, runner, args, findings))

        # profile hints
        if port == 88 or "kerberos" in name:
            host_profile["dc_signals"] += 1
            findings.append(Finding("HIGH", "ad", 88, "Kerberos (88) open - strong Domain Controller signal"))
        if port in (389, 636) and (445 in services or 88 in services):
            host_profile["dc_signals"] += 1

    if tasks:
        await asyncio.gather(*tasks)


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
    sev_present = {f.sev for f in findings}
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
# --------------------------------------------------------------------------- #
async def scan_host(host, runner, args):
    t0 = time.time()
    findings = []
    host_profile = {"dc_signals": 0}
    os.makedirs(os.path.join(runner.outdir, host, "scans"), exist_ok=True)

    good(f"=== target: {host} ===")
    ports = await discover_ports(host, runner, args)
    if runner.dry_run:
        ports = ports or [21, 22, 80, 445]  # sample so the plan shows modules

    if not ports:
        warn(f"{host}: no open TCP ports found (host down / filtered / try --no-rustscan)")
        return
    good(f"{host}: {len(ports)} open port(s): {', '.join(map(str, ports))}")

    # accuracy pass + udp in parallel
    services, udp = await asyncio.gather(
        service_scan(host, ports, runner, args),
        udp_scan(host, runner, args),
    )

    # enumerate services concurrently
    await dispatch(host, services, runner, args, findings, host_profile)

    elapsed = time.time() - t0
    if not runner.dry_run:
        print_summary(host, services, udp, findings, host_profile, elapsed, args)
        md = write_markdown(host, services, udp, findings, runner.outdir, host_profile)
        good(f"notes written: {md}")


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
    findings = []
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
    p.add_argument("--quick", action="store_true", help="top-1000 ports only (fast)")
    p.add_argument("--top-ports", type=int, help="scan only the top N common ports")
    p.add_argument("--no-udp", action="store_true", help="skip UDP scan")
    p.add_argument("--no-scripts", action="store_true", help="nmap -sV only, no -sC")
    p.add_argument("--no-rustscan", action="store_true", help="force built-in async scanner")
    p.add_argument("--nikto", action="store_true", help="run nikto on web ports (noisy)")
    p.add_argument("--ping-sweep", action="store_true", help="liveness-check a CIDR first")
    p.add_argument("--wordlist", default="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                   help="dirbrute wordlist")
    p.add_argument("--concurrency", type=int, default=800, help="async scan concurrency")
    p.add_argument("--parallel", type=int, default=6, help="max concurrent external commands")
    p.add_argument("--host-timeout", type=float, default=1.5, help="per-port connect timeout (s)")
    p.add_argument("--scan-timeout", type=int, default=1800, help="port/service scan timeout (s)")
    p.add_argument("--enum-timeout", type=int, default=600, help="per-enum-module timeout (s)")
    p.add_argument("--timeout", type=int, default=900, help="default command timeout (s)")
    p.add_argument("--dry-run", action="store_true", help="print the command plan, run nothing")
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

# top-1000-ish common TCP ports for --quick and the async fallback
TOP_1000 = [1,3,7,9,13,17,19,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1434,1521,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3268,3269,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,5985,5986,6000,6001,6379,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9200,9999,10000,27017,32768,49152,49153,49154,49155,49156,49157]


async def amain(args):
    refresh_tools()
    runner = Runner(args.outdir, dry_run=args.dry_run,
                    timeout=args.timeout, verbose=args.verbose)
    runner.sem = asyncio.Semaphore(args.parallel)

    print(C.CY + BANNER + C.END)
    missing = [t for t in ("rustscan", "nmap", "feroxbuster", "gobuster", "whatweb",
                           "enum4linux-ng", "nxc", "netexec") if not TOOLS.get(t)]
    have = [t for t in ("rustscan", "nmap", "feroxbuster", "gobuster", "whatweb",
                        "enum4linux-ng", "nxc", "netexec", "smbclient", "ldapsearch",
                        "snmpwalk", "curl") if TOOLS.get(t)]
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
