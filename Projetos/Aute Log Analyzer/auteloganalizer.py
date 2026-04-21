#!/usr/bin/env python3
"""
auth_log_analyzer.py
Análise de logs de autenticação com detecção de ataques de força bruta
e padrões suspeitos.
"""

import re
import sys
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────
# Configurações padrão
# ──────────────────────────────────────────────
DEFAULT_BRUTE_FORCE_THRESHOLD = 5      # tentativas falhas por janela de tempo
DEFAULT_TIME_WINDOW_SECONDS   = 300    # janela de 5 minutos
DEFAULT_RAPID_FIRE_THRESHOLD  = 10     # tentativas em menos de 1 segundo (spraying)
ANOMALY_HOUR_THRESHOLD        = (0, 5) # intervalo de horas suspeitas (meia-noite às 5h)


# ──────────────────────────────────────────────
# Estruturas de dados
# ──────────────────────────────────────────────
@dataclass
class LogEntry:
    timestamp: datetime
    ip: str
    user: str
    status: str          # "success" | "failure"
    raw_line: str
    extra: dict = field(default_factory=dict)


@dataclass
class Alert:
    level: str           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    category: str
    ip: str
    user: str
    description: str
    timestamp: datetime
    evidence: list = field(default_factory=list)


# ──────────────────────────────────────────────
# Parsers de formato de log
# ──────────────────────────────────────────────

# Formato SSH padrão:
# Apr 19 14:23:01 host sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
SSH_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+\S+:\s+"
    r"(?P<status>Failed|Accepted)\s+\w+\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Formato SSH "Invalid user": sshd[N]: Invalid user hacker from 10.0.0.1
SSH_INVALID_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+\S+:\s+"
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Formato genérico (CSV ou estruturado simples):
# 2024-04-19T14:23:01 192.168.1.100 admin FAILURE
GENERIC_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<status>SUCCESS|FAILURE|FAILED|OK)"
    , re.IGNORECASE
)

# Formato Apache/Nginx de autenticação:
# 192.168.1.100 - admin [19/Apr/2024:14:23:01 +0000] "POST /login HTTP/1.1" 401
APACHE_PATTERN = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+\"\S+\s+\S+\s+\S+\"\s+(?P<code>\d{3})"
)


def parse_line(line: str, year: int = None) -> Optional[LogEntry]:
    """Tenta todos os parsers e retorna o primeiro que casar."""
    year = year or datetime.now().year
    line = line.strip()
    if not line:
        return None

    # SSH Failed/Accepted
    m = SSH_PATTERN.search(line)
    if m:
        try:
            ts_str = f"{m['month']} {m['day']} {year} {m['time']}"
            ts = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S")
            status = "success" if m["status"] == "Accepted" else "failure"
            return LogEntry(ts, m["ip"], m["user"], status, line)
        except ValueError:
            pass

    # SSH Invalid user
    m = SSH_INVALID_PATTERN.search(line)
    if m:
        try:
            ts_str = f"{m['month']} {m['day']} {year} {m['time']}"
            ts = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S")
            return LogEntry(ts, m["ip"], m["user"], "failure", line)
        except ValueError:
            pass

    # Genérico
    m = GENERIC_PATTERN.search(line)
    if m:
        try:
            ts_str = m["ts"].replace("T", " ")
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            status = "success" if m["status"].upper() in ("SUCCESS", "OK") else "failure"
            return LogEntry(ts, m["ip"], m["user"], status, line)
        except ValueError:
            pass

    # Apache / Nginx
    m = APACHE_PATTERN.search(line)
    if m:
        try:
            ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
            code = int(m["code"])
            status = "success" if code < 400 else "failure"
            return LogEntry(ts, m["ip"], m["user"], status, line,
                            extra={"http_code": code})
        except ValueError:
            pass

    return None


# ──────────────────────────────────────────────
# Motor de análise
# ──────────────────────────────────────────────

class AuthLogAnalyzer:
    def __init__(
        self,
        brute_force_threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
        time_window: int = DEFAULT_TIME_WINDOW_SECONDS,
        rapid_fire_threshold: int = DEFAULT_RAPID_FIRE_THRESHOLD,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.time_window = timedelta(seconds=time_window)
        self.rapid_fire_threshold = rapid_fire_threshold

        self.entries: list[LogEntry] = []
        self.alerts: list[Alert] = []

        # Estruturas de acumulação
        self._failures_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        self._failures_by_user: dict[str, list[LogEntry]] = defaultdict(list)
        self._success_after_failures: list[tuple] = []

    # ── Ingestão ──────────────────────────────

    def load_file(self, path: str) -> int:
        count = 0
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                entry = parse_line(line)
                if entry:
                    self.entries.append(entry)
                    count += 1
        self.entries.sort(key=lambda e: e.timestamp)
        return count

    def load_lines(self, lines: list[str]) -> int:
        count = 0
        for line in lines:
            entry = parse_line(line)
            if entry:
                self.entries.append(entry)
                count += 1
        self.entries.sort(key=lambda e: e.timestamp)
        return count

    # ── Análises ──────────────────────────────

    def analyze(self):
        """Executa todos os detectores."""
        self._index_entries()
        self._detect_brute_force_by_ip()
        self._detect_brute_force_by_user()
        self._detect_credential_stuffing()
        self._detect_successful_after_failures()
        self._detect_off_hours_activity()
        self._detect_rapid_fire()
        self._detect_distributed_attack()

    def _index_entries(self):
        for e in self.entries:
            if e.status == "failure":
                self._failures_by_ip[e.ip].append(e)
                self._failures_by_user[e.user].append(e)

    def _detect_brute_force_by_ip(self):
        """Mesmo IP com muitas falhas dentro da janela de tempo."""
        for ip, events in self._failures_by_ip.items():
            # Janela deslizante
            i = 0
            while i < len(events):
                window = [events[i]]
                j = i + 1
                while j < len(events) and (events[j].timestamp - events[i].timestamp) <= self.time_window:
                    window.append(events[j])
                    j += 1
                if len(window) >= self.brute_force_threshold:
                    users = list({e.user for e in window})
                    level = "CRITICAL" if len(window) >= self.brute_force_threshold * 3 else "HIGH"
                    self.alerts.append(Alert(
                        level=level,
                        category="BRUTE_FORCE_IP",
                        ip=ip,
                        user=", ".join(users),
                        description=(
                            f"{len(window)} tentativas falhas de login de {ip} "
                            f"em {(window[-1].timestamp - window[0].timestamp).seconds}s "
                            f"contra {len(users)} usuário(s)."
                        ),
                        timestamp=window[0].timestamp,
                        evidence=[e.raw_line for e in window[:5]],
                    ))
                    i = j  # pula a janela já processada
                else:
                    i += 1

    def _detect_brute_force_by_user(self):
        """Mesmo usuário-alvo atacado de múltiplos IPs."""
        for user, events in self._failures_by_user.items():
            if user in ("-", "invalid", "unknown"):
                continue
            i = 0
            while i < len(events):
                window = [events[i]]
                j = i + 1
                while j < len(events) and (events[j].timestamp - events[i].timestamp) <= self.time_window:
                    window.append(events[j])
                    j += 1
                if len(window) >= self.brute_force_threshold:
                    ips = list({e.ip for e in window})
                    self.alerts.append(Alert(
                        level="HIGH",
                        category="BRUTE_FORCE_USER",
                        ip=", ".join(ips[:5]),
                        user=user,
                        description=(
                            f"{len(window)} falhas para o usuário '{user}' "
                            f"originadas de {len(ips)} IP(s) diferentes."
                        ),
                        timestamp=window[0].timestamp,
                        evidence=[e.raw_line for e in window[:5]],
                    ))
                    i = j
                else:
                    i += 1

    def _detect_credential_stuffing(self):
        """Um IP tenta muitos usuários diferentes."""
        for ip, events in self._failures_by_ip.items():
            unique_users = {e.user for e in events}
            if len(unique_users) >= max(5, self.brute_force_threshold):
                self.alerts.append(Alert(
                    level="HIGH",
                    category="CREDENTIAL_STUFFING",
                    ip=ip,
                    user=f"{len(unique_users)} usuários distintos",
                    description=(
                        f"Possível credential stuffing: IP {ip} tentou "
                        f"{len(unique_users)} usuários diferentes com {len(events)} requisições."
                    ),
                    timestamp=events[0].timestamp,
                    evidence=[e.raw_line for e in events[:5]],
                ))

    def _detect_successful_after_failures(self):
        """Login bem-sucedido após sequência de falhas (brute force bem-sucedido)."""
        for e in self.entries:
            if e.status != "success":
                continue
            prior_failures = [
                f for f in self._failures_by_ip.get(e.ip, [])
                if f.user == e.user and f.timestamp < e.timestamp
                and (e.timestamp - f.timestamp) <= self.time_window * 2
            ]
            if len(prior_failures) >= self.brute_force_threshold:
                self.alerts.append(Alert(
                    level="CRITICAL",
                    category="BRUTE_FORCE_SUCCESS",
                    ip=e.ip,
                    user=e.user,
                    description=(
                        f"ALERTA CRÍTICO: login bem-sucedido de {e.ip} como '{e.user}' "
                        f"após {len(prior_failures)} tentativas falhas!"
                    ),
                    timestamp=e.timestamp,
                    evidence=[f.raw_line for f in prior_failures[-3:]] + [e.raw_line],
                ))

    def _detect_off_hours_activity(self):
        """Logins fora do horário comercial."""
        h_start, h_end = ANOMALY_HOUR_THRESHOLD
        for e in self.entries:
            if h_start <= e.timestamp.hour < h_end:
                self.alerts.append(Alert(
                    level="MEDIUM",
                    category="OFF_HOURS_LOGIN",
                    ip=e.ip,
                    user=e.user,
                    description=(
                        f"Atividade de login às {e.timestamp.strftime('%H:%M')} "
                        f"(fora do horário normal) por '{e.user}' de {e.ip}."
                    ),
                    timestamp=e.timestamp,
                    evidence=[e.raw_line],
                ))

    def _detect_rapid_fire(self):
        """Múltiplas tentativas em menos de 1 segundo (automatizado)."""
        for ip, events in self._failures_by_ip.items():
            for i in range(len(events) - self.rapid_fire_threshold + 1):
                window = events[i:i + self.rapid_fire_threshold]
                delta = (window[-1].timestamp - window[0].timestamp).total_seconds()
                if delta <= 1:
                    self.alerts.append(Alert(
                        level="CRITICAL",
                        category="RAPID_FIRE_ATTACK",
                        ip=ip,
                        user=window[0].user,
                        description=(
                            f"Ataque automatizado detectado: {self.rapid_fire_threshold} "
                            f"tentativas de {ip} em ≤1 segundo."
                        ),
                        timestamp=window[0].timestamp,
                        evidence=[e.raw_line for e in window[:3]],
                    ))
                    break  # uma alerta por IP é suficiente

    def _detect_distributed_attack(self):
        """Muitos IPs diferentes atacando o mesmo usuário (DDoS de auth)."""
        for user, events in self._failures_by_user.items():
            if user in ("-", "invalid", "unknown"):
                continue
            ips = {e.ip for e in events}
            if len(ips) >= 10:
                self.alerts.append(Alert(
                    level="HIGH",
                    category="DISTRIBUTED_ATTACK",
                    ip=f"{len(ips)} IPs distintos",
                    user=user,
                    description=(
                        f"Ataque distribuído ao usuário '{user}': "
                        f"{len(ips)} IPs diferentes, {len(events)} tentativas no total."
                    ),
                    timestamp=events[0].timestamp,
                    evidence=[e.raw_line for e in events[:3]],
                ))

    # ── Relatório ─────────────────────────────

    def summary(self) -> dict:
        total = len(self.entries)
        failures = sum(1 for e in self.entries if e.status == "failure")
        successes = total - failures
        unique_ips = len({e.ip for e in self.entries})
        unique_users = len({e.user for e in self.entries})

        by_level = defaultdict(int)
        for a in self.alerts:
            by_level[a.level] += 1

        top_offenders = sorted(
            self._failures_by_ip.items(), key=lambda x: len(x[1]), reverse=True
        )[:5]

        return {
            "total_entries": total,
            "failures": failures,
            "successes": successes,
            "unique_ips": unique_ips,
            "unique_users": unique_users,
            "total_alerts": len(self.alerts),
            "alerts_by_level": dict(by_level),
            "top_offending_ips": [
                {"ip": ip, "failures": len(evts)} for ip, evts in top_offenders
            ],
        }

    def print_report(self, verbose: bool = False):
        s = self.summary()
        SEP = "=" * 65

        print(f"\n{SEP}")
        print("  AUTH LOG ANALYZER — RELATÓRIO DE SEGURANÇA")
        print(SEP)
        print(f"  Entradas analisadas : {s['total_entries']}")
        print(f"  Falhas / Sucessos   : {s['failures']} / {s['successes']}")
        print(f"  IPs únicos          : {s['unique_ips']}")
        print(f"  Usuários únicos     : {s['unique_users']}")
        print(f"  Total de alertas    : {s['total_alerts']}")

        if s["alerts_by_level"]:
            print("\n  Alertas por severidade:")
            for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                count = s["alerts_by_level"].get(lvl, 0)
                if count:
                    print(f"    [{lvl:8s}]  {count}")

        if s["top_offending_ips"]:
            print("\n  Top IPs com mais falhas:")
            for item in s["top_offending_ips"]:
                print(f"    {item['ip']:<20}  {item['failures']} falhas")

        if self.alerts:
            print(f"\n{SEP}")
            print("  ALERTAS DETECTADOS")
            print(SEP)
            # Ordena por severidade
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            for a in sorted(self.alerts, key=lambda x: order.get(x.level, 9)):
                print(f"\n  ▶ [{a.level}] {a.category}")
                print(f"    Hora    : {a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"    IP      : {a.ip}")
                print(f"    Usuário : {a.user}")
                print(f"    Detalhe : {a.description}")
                if verbose and a.evidence:
                    print("    Evidências:")
                    for line in a.evidence:
                        print(f"      > {line[:120]}")
        else:
            print("\n  ✅ Nenhum padrão suspeito detectado.")

        print(f"\n{SEP}\n")

    def export_json(self, path: str):
        data = {
            "summary": self.summary(),
            "alerts": [
                {
                    "level": a.level,
                    "category": a.category,
                    "ip": a.ip,
                    "user": a.user,
                    "description": a.description,
                    "timestamp": a.timestamp.isoformat(),
                    "evidence": a.evidence,
                }
                for a in self.alerts
            ],
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"  Relatório JSON exportado para: {path}")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_sample_log() -> list[str]:
    """Gera linhas de log de exemplo para demonstração."""
    return [
        # Ataque de força bruta de um IP
        "2024-04-19T02:10:01 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:03 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:05 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:07 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:09 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:11 10.0.0.5 admin FAILURE",
        # Brute force bem-sucedido
        "2024-04-19T02:10:15 10.0.0.5 admin SUCCESS",
        # Credential stuffing
        "2024-04-19T03:00:00 172.16.0.1 user1 FAILURE",
        "2024-04-19T03:00:05 172.16.0.1 user2 FAILURE",
        "2024-04-19T03:00:10 172.16.0.1 user3 FAILURE",
        "2024-04-19T03:00:15 172.16.0.1 user4 FAILURE",
        "2024-04-19T03:00:20 172.16.0.1 user5 FAILURE",
        "2024-04-19T03:00:25 172.16.0.1 user6 FAILURE",
        # Login fora de horário normal
        "2024-04-19T01:45:00 192.168.0.50 bob SUCCESS",
        # Ataque rápido (automatizado)
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        # Logins normais
        "2024-04-19T09:00:00 192.168.1.10 alice SUCCESS",
        "2024-04-19T09:05:00 192.168.1.11 carol SUCCESS",
    ]


def main():
    parser = argparse.ArgumentParser(
        description="Analisador de logs de autenticação — detecção de força bruta e padrões suspeitos"
    )
    parser.add_argument("logfile", nargs="?", help="Arquivo de log a analisar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar linhas de evidência")
    parser.add_argument("--threshold", type=int, default=DEFAULT_BRUTE_FORCE_THRESHOLD,
                        help=f"Tentativas falhas para disparar alerta (padrão: {DEFAULT_BRUTE_FORCE_THRESHOLD})")
    parser.add_argument("--window", type=int, default=DEFAULT_TIME_WINDOW_SECONDS,
                        help=f"Janela de tempo em segundos (padrão: {DEFAULT_TIME_WINDOW_SECONDS})")
    parser.add_argument("--json", metavar="OUTPUT.json", help="Exportar relatório em JSON")
    parser.add_argument("--demo", action="store_true", help="Executar com log de demonstração embutido")
    args = parser.parse_args()

    analyzer = AuthLogAnalyzer(
        brute_force_threshold=args.threshold,
        time_window=args.window,
    )

    if args.demo or not args.logfile:
        print("  [DEMO] Usando log de exemplo embutido...")
        count = analyzer.load_lines(build_sample_log())
    else:
        try:
            count = analyzer.load_file(args.logfile)
        except FileNotFoundError:
            print(f"Erro: arquivo '{args.logfile}' não encontrado.")
            sys.exit(1)

    print(f"  {count} entradas de log carregadas.")
    analyzer.analyze()
    analyzer.print_report(verbose=args.verbose)

    if args.json:
        analyzer.export_json(args.json)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
auth_log_analyzer.py
Análise de logs de autenticação com detecção de ataques de força bruta
e padrões suspeitos.
"""

import re
import sys
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────
# Configurações padrão
# ──────────────────────────────────────────────
DEFAULT_BRUTE_FORCE_THRESHOLD = 5      # tentativas falhas por janela de tempo
DEFAULT_TIME_WINDOW_SECONDS   = 300    # janela de 5 minutos
DEFAULT_RAPID_FIRE_THRESHOLD  = 10     # tentativas em menos de 1 segundo (spraying)
ANOMALY_HOUR_THRESHOLD        = (0, 5) # intervalo de horas suspeitas (meia-noite às 5h)


# ──────────────────────────────────────────────
# Estruturas de dados
# ──────────────────────────────────────────────
@dataclass
class LogEntry:
    timestamp: datetime
    ip: str
    user: str
    status: str          # "success" | "failure"
    raw_line: str
    extra: dict = field(default_factory=dict)


@dataclass
class Alert:
    level: str           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    category: str
    ip: str
    user: str
    description: str
    timestamp: datetime
    evidence: list = field(default_factory=list)


# ──────────────────────────────────────────────
# Parsers de formato de log
# ──────────────────────────────────────────────

# Formato SSH padrão:
# Apr 19 14:23:01 host sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
SSH_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+\S+:\s+"
    r"(?P<status>Failed|Accepted)\s+\w+\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Formato SSH "Invalid user": sshd[N]: Invalid user hacker from 10.0.0.1
SSH_INVALID_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+\S+:\s+"
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Formato genérico (CSV ou estruturado simples):
# 2024-04-19T14:23:01 192.168.1.100 admin FAILURE
GENERIC_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<status>SUCCESS|FAILURE|FAILED|OK)"
    , re.IGNORECASE
)

# Formato Apache/Nginx de autenticação:
# 192.168.1.100 - admin [19/Apr/2024:14:23:01 +0000] "POST /login HTTP/1.1" 401
APACHE_PATTERN = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+\"\S+\s+\S+\s+\S+\"\s+(?P<code>\d{3})"
)


def parse_line(line: str, year: int = None) -> Optional[LogEntry]:
    """Tenta todos os parsers e retorna o primeiro que casar."""
    year = year or datetime.now().year
    line = line.strip()
    if not line:
        return None

    # SSH Failed/Accepted
    m = SSH_PATTERN.search(line)
    if m:
        try:
            ts_str = f"{m['month']} {m['day']} {year} {m['time']}"
            ts = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S")
            status = "success" if m["status"] == "Accepted" else "failure"
            return LogEntry(ts, m["ip"], m["user"], status, line)
        except ValueError:
            pass

    # SSH Invalid user
    m = SSH_INVALID_PATTERN.search(line)
    if m:
        try:
            ts_str = f"{m['month']} {m['day']} {year} {m['time']}"
            ts = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S")
            return LogEntry(ts, m["ip"], m["user"], "failure", line)
        except ValueError:
            pass

    # Genérico
    m = GENERIC_PATTERN.search(line)
    if m:
        try:
            ts_str = m["ts"].replace("T", " ")
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            status = "success" if m["status"].upper() in ("SUCCESS", "OK") else "failure"
            return LogEntry(ts, m["ip"], m["user"], status, line)
        except ValueError:
            pass

    # Apache / Nginx
    m = APACHE_PATTERN.search(line)
    if m:
        try:
            ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
            code = int(m["code"])
            status = "success" if code < 400 else "failure"
            return LogEntry(ts, m["ip"], m["user"], status, line,
                            extra={"http_code": code})
        except ValueError:
            pass

    return None


# ──────────────────────────────────────────────
# Motor de análise
# ──────────────────────────────────────────────

class AuthLogAnalyzer:
    def __init__(
        self,
        brute_force_threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
        time_window: int = DEFAULT_TIME_WINDOW_SECONDS,
        rapid_fire_threshold: int = DEFAULT_RAPID_FIRE_THRESHOLD,
    ):
        self.brute_force_threshold = brute_force_threshold
        self.time_window = timedelta(seconds=time_window)
        self.rapid_fire_threshold = rapid_fire_threshold

        self.entries: list[LogEntry] = []
        self.alerts: list[Alert] = []

        # Estruturas de acumulação
        self._failures_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        self._failures_by_user: dict[str, list[LogEntry]] = defaultdict(list)
        self._success_after_failures: list[tuple] = []

    # ── Ingestão ──────────────────────────────

    def load_file(self, path: str) -> int:
        count = 0
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                entry = parse_line(line)
                if entry:
                    self.entries.append(entry)
                    count += 1
        self.entries.sort(key=lambda e: e.timestamp)
        return count

    def load_lines(self, lines: list[str]) -> int:
        count = 0
        for line in lines:
            entry = parse_line(line)
            if entry:
                self.entries.append(entry)
                count += 1
        self.entries.sort(key=lambda e: e.timestamp)
        return count

    # ── Análises ──────────────────────────────

    def analyze(self):
        """Executa todos os detectores."""
        self._index_entries()
        self._detect_brute_force_by_ip()
        self._detect_brute_force_by_user()
        self._detect_credential_stuffing()
        self._detect_successful_after_failures()
        self._detect_off_hours_activity()
        self._detect_rapid_fire()
        self._detect_distributed_attack()

    def _index_entries(self):
        for e in self.entries:
            if e.status == "failure":
                self._failures_by_ip[e.ip].append(e)
                self._failures_by_user[e.user].append(e)

    def _detect_brute_force_by_ip(self):
        """Mesmo IP com muitas falhas dentro da janela de tempo."""
        for ip, events in self._failures_by_ip.items():
            # Janela deslizante
            i = 0
            while i < len(events):
                window = [events[i]]
                j = i + 1
                while j < len(events) and (events[j].timestamp - events[i].timestamp) <= self.time_window:
                    window.append(events[j])
                    j += 1
                if len(window) >= self.brute_force_threshold:
                    users = list({e.user for e in window})
                    level = "CRITICAL" if len(window) >= self.brute_force_threshold * 3 else "HIGH"
                    self.alerts.append(Alert(
                        level=level,
                        category="BRUTE_FORCE_IP",
                        ip=ip,
                        user=", ".join(users),
                        description=(
                            f"{len(window)} tentativas falhas de login de {ip} "
                            f"em {(window[-1].timestamp - window[0].timestamp).seconds}s "
                            f"contra {len(users)} usuário(s)."
                        ),
                        timestamp=window[0].timestamp,
                        evidence=[e.raw_line for e in window[:5]],
                    ))
                    i = j  # pula a janela já processada
                else:
                    i += 1

    def _detect_brute_force_by_user(self):
        """Mesmo usuário-alvo atacado de múltiplos IPs."""
        for user, events in self._failures_by_user.items():
            if user in ("-", "invalid", "unknown"):
                continue
            i = 0
            while i < len(events):
                window = [events[i]]
                j = i + 1
                while j < len(events) and (events[j].timestamp - events[i].timestamp) <= self.time_window:
                    window.append(events[j])
                    j += 1
                if len(window) >= self.brute_force_threshold:
                    ips = list({e.ip for e in window})
                    self.alerts.append(Alert(
                        level="HIGH",
                        category="BRUTE_FORCE_USER",
                        ip=", ".join(ips[:5]),
                        user=user,
                        description=(
                            f"{len(window)} falhas para o usuário '{user}' "
                            f"originadas de {len(ips)} IP(s) diferentes."
                        ),
                        timestamp=window[0].timestamp,
                        evidence=[e.raw_line for e in window[:5]],
                    ))
                    i = j
                else:
                    i += 1

    def _detect_credential_stuffing(self):
        """Um IP tenta muitos usuários diferentes."""
        for ip, events in self._failures_by_ip.items():
            unique_users = {e.user for e in events}
            if len(unique_users) >= max(5, self.brute_force_threshold):
                self.alerts.append(Alert(
                    level="HIGH",
                    category="CREDENTIAL_STUFFING",
                    ip=ip,
                    user=f"{len(unique_users)} usuários distintos",
                    description=(
                        f"Possível credential stuffing: IP {ip} tentou "
                        f"{len(unique_users)} usuários diferentes com {len(events)} requisições."
                    ),
                    timestamp=events[0].timestamp,
                    evidence=[e.raw_line for e in events[:5]],
                ))

    def _detect_successful_after_failures(self):
        """Login bem-sucedido após sequência de falhas (brute force bem-sucedido)."""
        for e in self.entries:
            if e.status != "success":
                continue
            prior_failures = [
                f for f in self._failures_by_ip.get(e.ip, [])
                if f.user == e.user and f.timestamp < e.timestamp
                and (e.timestamp - f.timestamp) <= self.time_window * 2
            ]
            if len(prior_failures) >= self.brute_force_threshold:
                self.alerts.append(Alert(
                    level="CRITICAL",
                    category="BRUTE_FORCE_SUCCESS",
                    ip=e.ip,
                    user=e.user,
                    description=(
                        f"ALERTA CRÍTICO: login bem-sucedido de {e.ip} como '{e.user}' "
                        f"após {len(prior_failures)} tentativas falhas!"
                    ),
                    timestamp=e.timestamp,
                    evidence=[f.raw_line for f in prior_failures[-3:]] + [e.raw_line],
                ))

    def _detect_off_hours_activity(self):
        """Logins fora do horário comercial."""
        h_start, h_end = ANOMALY_HOUR_THRESHOLD
        for e in self.entries:
            if h_start <= e.timestamp.hour < h_end:
                self.alerts.append(Alert(
                    level="MEDIUM",
                    category="OFF_HOURS_LOGIN",
                    ip=e.ip,
                    user=e.user,
                    description=(
                        f"Atividade de login às {e.timestamp.strftime('%H:%M')} "
                        f"(fora do horário normal) por '{e.user}' de {e.ip}."
                    ),
                    timestamp=e.timestamp,
                    evidence=[e.raw_line],
                ))

    def _detect_rapid_fire(self):
        """Múltiplas tentativas em menos de 1 segundo (automatizado)."""
        for ip, events in self._failures_by_ip.items():
            for i in range(len(events) - self.rapid_fire_threshold + 1):
                window = events[i:i + self.rapid_fire_threshold]
                delta = (window[-1].timestamp - window[0].timestamp).total_seconds()
                if delta <= 1:
                    self.alerts.append(Alert(
                        level="CRITICAL",
                        category="RAPID_FIRE_ATTACK",
                        ip=ip,
                        user=window[0].user,
                        description=(
                            f"Ataque automatizado detectado: {self.rapid_fire_threshold} "
                            f"tentativas de {ip} em ≤1 segundo."
                        ),
                        timestamp=window[0].timestamp,
                        evidence=[e.raw_line for e in window[:3]],
                    ))
                    break  # uma alerta por IP é suficiente

    def _detect_distributed_attack(self):
        """Muitos IPs diferentes atacando o mesmo usuário (DDoS de auth)."""
        for user, events in self._failures_by_user.items():
            if user in ("-", "invalid", "unknown"):
                continue
            ips = {e.ip for e in events}
            if len(ips) >= 10:
                self.alerts.append(Alert(
                    level="HIGH",
                    category="DISTRIBUTED_ATTACK",
                    ip=f"{len(ips)} IPs distintos",
                    user=user,
                    description=(
                        f"Ataque distribuído ao usuário '{user}': "
                        f"{len(ips)} IPs diferentes, {len(events)} tentativas no total."
                    ),
                    timestamp=events[0].timestamp,
                    evidence=[e.raw_line for e in events[:3]],
                ))

    # ── Relatório ─────────────────────────────

    def summary(self) -> dict:
        total = len(self.entries)
        failures = sum(1 for e in self.entries if e.status == "failure")
        successes = total - failures
        unique_ips = len({e.ip for e in self.entries})
        unique_users = len({e.user for e in self.entries})

        by_level = defaultdict(int)
        for a in self.alerts:
            by_level[a.level] += 1

        top_offenders = sorted(
            self._failures_by_ip.items(), key=lambda x: len(x[1]), reverse=True
        )[:5]

        return {
            "total_entries": total,
            "failures": failures,
            "successes": successes,
            "unique_ips": unique_ips,
            "unique_users": unique_users,
            "total_alerts": len(self.alerts),
            "alerts_by_level": dict(by_level),
            "top_offending_ips": [
                {"ip": ip, "failures": len(evts)} for ip, evts in top_offenders
            ],
        }

    def print_report(self, verbose: bool = False):
        s = self.summary()
        SEP = "=" * 65

        print(f"\n{SEP}")
        print("  AUTH LOG ANALYZER — RELATÓRIO DE SEGURANÇA")
        print(SEP)
        print(f"  Entradas analisadas : {s['total_entries']}")
        print(f"  Falhas / Sucessos   : {s['failures']} / {s['successes']}")
        print(f"  IPs únicos          : {s['unique_ips']}")
        print(f"  Usuários únicos     : {s['unique_users']}")
        print(f"  Total de alertas    : {s['total_alerts']}")

        if s["alerts_by_level"]:
            print("\n  Alertas por severidade:")
            for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                count = s["alerts_by_level"].get(lvl, 0)
                if count:
                    print(f"    [{lvl:8s}]  {count}")

        if s["top_offending_ips"]:
            print("\n  Top IPs com mais falhas:")
            for item in s["top_offending_ips"]:
                print(f"    {item['ip']:<20}  {item['failures']} falhas")

        if self.alerts:
            print(f"\n{SEP}")
            print("  ALERTAS DETECTADOS")
            print(SEP)
            # Ordena por severidade
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            for a in sorted(self.alerts, key=lambda x: order.get(x.level, 9)):
                print(f"\n  ▶ [{a.level}] {a.category}")
                print(f"    Hora    : {a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"    IP      : {a.ip}")
                print(f"    Usuário : {a.user}")
                print(f"    Detalhe : {a.description}")
                if verbose and a.evidence:
                    print("    Evidências:")
                    for line in a.evidence:
                        print(f"      > {line[:120]}")
        else:
            print("\n  ✅ Nenhum padrão suspeito detectado.")

        print(f"\n{SEP}\n")

    def export_json(self, path: str):
        data = {
            "summary": self.summary(),
            "alerts": [
                {
                    "level": a.level,
                    "category": a.category,
                    "ip": a.ip,
                    "user": a.user,
                    "description": a.description,
                    "timestamp": a.timestamp.isoformat(),
                    "evidence": a.evidence,
                }
                for a in self.alerts
            ],
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"  Relatório JSON exportado para: {path}")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_sample_log() -> list[str]:
    """Gera linhas de log de exemplo para demonstração."""
    return [
        # Ataque de força bruta de um IP
        "2024-04-19T02:10:01 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:03 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:05 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:07 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:09 10.0.0.5 admin FAILURE",
        "2024-04-19T02:10:11 10.0.0.5 admin FAILURE",
        # Brute force bem-sucedido
        "2024-04-19T02:10:15 10.0.0.5 admin SUCCESS",
        # Credential stuffing
        "2024-04-19T03:00:00 172.16.0.1 user1 FAILURE",
        "2024-04-19T03:00:05 172.16.0.1 user2 FAILURE",
        "2024-04-19T03:00:10 172.16.0.1 user3 FAILURE",
        "2024-04-19T03:00:15 172.16.0.1 user4 FAILURE",
        "2024-04-19T03:00:20 172.16.0.1 user5 FAILURE",
        "2024-04-19T03:00:25 172.16.0.1 user6 FAILURE",
        # Login fora de horário normal
        "2024-04-19T01:45:00 192.168.0.50 bob SUCCESS",
        # Ataque rápido (automatizado)
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        "2024-04-19T14:00:00 203.0.113.9 root FAILURE",
        # Logins normais
        "2024-04-19T09:00:00 192.168.1.10 alice SUCCESS",
        "2024-04-19T09:05:00 192.168.1.11 carol SUCCESS",
    ]


def main():
    parser = argparse.ArgumentParser(
        description="Analisador de logs de autenticação — detecção de força bruta e padrões suspeitos"
    )
    parser.add_argument("logfile", nargs="?", help="Arquivo de log a analisar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostrar linhas de evidência")
    parser.add_argument("--threshold", type=int, default=DEFAULT_BRUTE_FORCE_THRESHOLD,
                        help=f"Tentativas falhas para disparar alerta (padrão: {DEFAULT_BRUTE_FORCE_THRESHOLD})")
    parser.add_argument("--window", type=int, default=DEFAULT_TIME_WINDOW_SECONDS,
                        help=f"Janela de tempo em segundos (padrão: {DEFAULT_TIME_WINDOW_SECONDS})")
    parser.add_argument("--json", metavar="OUTPUT.json", help="Exportar relatório em JSON")
    parser.add_argument("--demo", action="store_true", help="Executar com log de demonstração embutido")
    args = parser.parse_args()

    analyzer = AuthLogAnalyzer(
        brute_force_threshold=args.threshold,
        time_window=args.window,
    )

    if args.demo or not args.logfile:
        print("  [DEMO] Usando log de exemplo embutido...")
        count = analyzer.load_lines(build_sample_log())
    else:
        try:
            count = analyzer.load_file(args.logfile)
        except FileNotFoundError:
            print(f"Erro: arquivo '{args.logfile}' não encontrado.")
            sys.exit(1)

    print(f"  {count} entradas de log carregadas.")
    analyzer.analyze()
    analyzer.print_report(verbose=args.verbose)

    if args.json:
        analyzer.export_json(args.json)

