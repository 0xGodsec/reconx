# reconx

A lean, fast, accurate reconnaissance orchestrator — an **AutoRecon alternative**
built around OSCP methodology. It discovers ports fast, confirms them for
accuracy, runs *targeted* per-service enumeration concurrently, then prints a
**ranked "look at this first" summary** instead of burying you in 200 files.

> Authorized targets only: your own lab, HTB / PG / THM, or written permission.

## Why this instead of AutoRecon

| Problem with heavy scanners | What reconx does |
|---|---|
| Dumps hundreds of files; you drown | Ranks findings by severity, tells you what matters |
| Slow (UDP + nikto + full wordlists on everything) | Lean curated commands per service; heavy stuff is opt-in |
| Silent failures look like "nothing there" | Flags missing tools and degrades gracefully |
| Hard to hack mid-exam | Single Python file, stdlib only, readable |

It's a **lean orchestrator**, not a full clone: fast discovery + the enumeration
you'd run anyway, in parallel — you still do the thinking.

## Requirements

- Python 3.8+ (standard library only — nothing to `pip install`)
- Optional external tools (each degrades gracefully if absent):
  `rustscan`, `nmap`, `feroxbuster`/`gobuster`, `whatweb`, `nikto`,
  `enum4linux-ng`, `nxc`/`netexec`, `smbclient`, `smbmap`, `rpcclient`,
  `ldapsearch`, `snmpwalk`, `onesixtyone`, `showmount`, `dig`, `curl`, `redis-cli`

On Kali these are mostly preinstalled. reconx prints which it found and which it's skipping.

## Usage

```bash
python3 reconx.py 10.10.10.10                 # single host, full pipeline
python3 reconx.py 10.10.10.10 --quick         # top-1000 ports, fast
python3 reconx.py 10.10.10.0/24 --ping-sweep  # sweep a subnet first
python3 reconx.py target.htb --nikto -o loot/ # add nikto, custom output dir
python3 reconx.py 10.10.10.10 --dry-run       # print the command plan, run nothing
```

Handy flags: `--no-udp`, `--no-scripts` (skip nmap `-sC`), `--no-rustscan`
(force built-in scanner), `--top-ports N`, `--wordlist PATH`, `--parallel N`,
`-v` (echo every command), `--no-color`.

## How it works

1. **Discovery** — rustscan if present, else a built-in async TCP connect sweep
   (full 65535 by default). Fast.
2. **Accuracy pass** — `nmap -sCV` on *confirmed* ports for real service/version,
   with a top-100 UDP scan in parallel.
3. **Targeted enumeration** — dispatches per-service modules concurrently:
   - **Web** (80/443/8080/…): whatweb, robots.txt, feroxbuster/gobuster, opt nikto
   - **SMB/AD** (139/445/389/88): netexec shares+users, enum4linux-ng, smbclient/smbmap, ldapsearch anon dump, DC detection
   - **Remote access** (21/22/23/3389/5985): FTP anon, SSH NSE, RDP NTLM info, WinRM note
   - **DB & misc** (1433/5432/6379/161/25/53/2049): MSSQL, **PostgreSQL** (default-cred sweep + psql probe), Redis, SNMP walk, SMTP user-enum, NFS exports, DNS
   - **Mail** (110/995 POP3, 143/993 IMAP): NSE capabilities + banner/CAPABILITY grab (TLS-aware via openssl), cred-reuse hints
4. **Findings engine** — regex rules classify output into CRITICAL / HIGH /
   MEDIUM / INFO, deduped and ranked.
5. **Output** — colored terminal summary + ranked findings + suggested next
   steps, plus a per-host `scans/` tree and a `NOTES.md` for your report.

## Output layout

```
reconx-results/
└── 10.10.10.10/
    ├── scans/        rustscan, nmap service, nmap udp
    ├── web_80/       whatweb, headers, robots, ferox/gobuster, nikto
    ├── smb/          netexec, enum4linux-ng, smbclient, smbmap
    ├── ldap/         rootdse, anon dump
    ├── ftp/ ssh/ snmp/ nfs/ ...
    └── NOTES.md      ports table + ranked findings, ready for your notes
```

## Extending it

Add a service module: write `async def enum_x(host, port, runner, args, findings)`,
run commands via `runner.run(cmd, outfile, label)`, append `Finding(...)` objects,
then wire it into `dispatch()`. Add a detection: append a `(severity, regex,
service, message)` tuple to `FINDING_RULES`. That's the whole extension surface.

## Exam-rules note

reconx only orchestrates standard enumeration tools — no automated *exploitation*,
no mass vulnerability scanning. That keeps it on the right side of the OSCP tool
policy, same category as AutoRecon. Always confirm against the current official
OSCP Exam Guide before your attempt.
```
```
