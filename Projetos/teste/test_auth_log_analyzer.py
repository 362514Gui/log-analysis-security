#!/usr/bin/env python3
"""
test_auth_log_analyzer.py
Suite de testes automatizados para o Auth Log Analyzer.

Execute com:
    python -m pytest test_auth_log_analyzer.py -v
    # ou diretamente:
    python test_auth_log_analyzer.py
"""

import sys
import json
import tempfile
import unittest
from datetime import datetime

from auth_log_analyzer import (
    parse_line,
    AuthLogAnalyzer,
    LogEntry,
    Alert,
)


# ══════════════════════════════════════════════════════════
# Testes de parsing de formatos de log
# ══════════════════════════════════════════════════════════

class TestParseLineGeneric(unittest.TestCase):
    """Formato genérico: 2024-04-19T14:23:01 IP USER STATUS"""

    def test_failure(self):
        line = "2024-04-19T14:23:01 192.168.1.100 admin FAILURE"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "failure")
        self.assertEqual(entry.ip, "192.168.1.100")
        self.assertEqual(entry.user, "admin")
        self.assertEqual(entry.timestamp, datetime(2024, 4, 19, 14, 23, 1))

    def test_success(self):
        line = "2024-04-19T09:00:00 10.0.0.1 alice SUCCESS"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "success")
        self.assertEqual(entry.user, "alice")

    def test_ok_maps_to_success(self):
        line = "2024-04-19T09:00:00 10.0.0.1 alice OK"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "success")

    def test_failed_maps_to_failure(self):
        line = "2024-04-19T09:00:00 10.0.0.1 bob FAILED"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "failure")

    def test_space_separator(self):
        line = "2024-04-19 14:23:01 192.168.1.1 root FAILURE"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.1")

    def test_case_insensitive(self):
        line = "2024-04-19T14:23:01 192.168.1.1 root failure"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "failure")

    def test_empty_line(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("   "))

    def test_garbage_line(self):
        self.assertIsNone(parse_line("isso não é um log válido"))


class TestParseLineSSH(unittest.TestCase):
    """Formato SSH: Apr 19 14:23:01 host sshd[1234]: ..."""

    def test_failed_password(self):
        line = "Apr 19 14:23:01 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2"
        entry = parse_line(line, year=2024)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "failure")
        self.assertEqual(entry.ip, "10.0.0.5")
        self.assertEqual(entry.user, "root")

    def test_accepted(self):
        line = "Apr 19 09:00:00 myhost sshd[5678]: Accepted password for alice from 192.168.1.1 port 22 ssh2"
        entry = parse_line(line, year=2024)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "success")
        self.assertEqual(entry.user, "alice")

    def test_invalid_user(self):
        line = "Apr 19 14:23:05 myhost sshd[9999]: Invalid user hacker from 203.0.113.1 port 22 ssh2"
        entry = parse_line(line, year=2024)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "failure")
        self.assertEqual(entry.ip, "203.0.113.1")


class TestParseLineApache(unittest.TestCase):
    """Formato Apache/Nginx: IP - user [timestamp] "METHOD /path HTTP/1.1" CODE"""

    def test_401_unauthorized(self):
        line = '192.168.1.100 - admin [19/Apr/2024:14:23:01 +0000] "POST /login HTTP/1.1" 401'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "failure")
        self.assertEqual(entry.ip, "192.168.1.100")
        self.assertEqual(entry.extra.get("http_code"), 401)

    def test_200_ok(self):
        line = '10.0.0.1 - alice [19/Apr/2024:09:00:00 +0000] "POST /login HTTP/1.1" 200'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "success")

    def test_403_forbidden(self):
        line = '10.0.0.99 - root [19/Apr/2024:03:00:00 +0000] "POST /login HTTP/1.1" 403'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, "failure")
        self.assertEqual(entry.extra.get("http_code"), 403)


# ══════════════════════════════════════════════════════════
# Testes de detecção de ataques
# ══════════════════════════════════════════════════════════

class TestBruteForceByIP(unittest.TestCase):
    """Múltiplas falhas do mesmo IP na janela de tempo."""

    def _analyzer_with_lines(self, lines, threshold=5, window=300):
        az = AuthLogAnalyzer(brute_force_threshold=threshold, time_window=window)
        az.load_lines(lines)
        az.analyze()
        return az

    def test_detects_brute_force(self):
        lines = [f"2024-04-19T02:10:{i:02d} 10.0.0.5 admin FAILURE" for i in range(6)]
        az = self._analyzer_with_lines(lines, threshold=5)
        categories = [a.category for a in az.alerts]
        self.assertIn("BRUTE_FORCE_IP", categories)

    def test_no_alert_below_threshold(self):
        lines = [f"2024-04-19T02:10:{i:02d} 10.0.0.5 admin FAILURE" for i in range(3)]
        az = self._analyzer_with_lines(lines, threshold=5)
        categories = [a.category for a in az.alerts]
        self.assertNotIn("BRUTE_FORCE_IP", categories)

    def test_critical_level_at_triple_threshold(self):
        lines = [f"2024-04-19T02:10:{i:02d} 10.0.0.5 admin FAILURE" for i in range(15)]
        az = self._analyzer_with_lines(lines, threshold=5)
        critical = [a for a in az.alerts if a.category == "BRUTE_FORCE_IP" and a.level == "CRITICAL"]
        self.assertTrue(len(critical) > 0)

    def test_outside_time_window_no_alert(self):
        # Falhas separadas por mais de a janela de tempo (10 minutos entre cada uma)
        lines = [
            "2024-04-19T02:00:00 10.0.0.5 admin FAILURE",
            "2024-04-19T02:10:01 10.0.0.5 admin FAILURE",
            "2024-04-19T02:20:02 10.0.0.5 admin FAILURE",
            "2024-04-19T02:30:03 10.0.0.5 admin FAILURE",
            "2024-04-19T02:40:04 10.0.0.5 admin FAILURE",
        ]
        az = self._analyzer_with_lines(lines, threshold=5, window=60)
        categories = [a.category for a in az.alerts]
        self.assertNotIn("BRUTE_FORCE_IP", categories)


class TestBruteForceByUser(unittest.TestCase):

    def test_detects_user_targeted_attack(self):
        lines = [
            f"2024-04-19T02:10:{i:02d} 10.0.0.{i+1} admin FAILURE"
            for i in range(6)
        ]
        az = AuthLogAnalyzer(brute_force_threshold=5)
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertIn("BRUTE_FORCE_USER", categories)


class TestCredentialStuffing(unittest.TestCase):

    def test_detects_many_users_from_one_ip(self):
        lines = [
            f"2024-04-19T03:00:{i:02d} 172.16.0.1 user{i} FAILURE"
            for i in range(7)
        ]
        az = AuthLogAnalyzer(brute_force_threshold=5)
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertIn("CREDENTIAL_STUFFING", categories)

    def test_no_stuffing_below_threshold(self):
        lines = [
            f"2024-04-19T03:00:0{i} 172.16.0.1 user{i} FAILURE"
            for i in range(3)
        ]
        az = AuthLogAnalyzer(brute_force_threshold=5)
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertNotIn("CREDENTIAL_STUFFING", categories)


class TestBruteForceSuccess(unittest.TestCase):

    def test_detects_success_after_failures(self):
        lines = [f"2024-04-19T02:10:{i:02d} 10.0.0.5 admin FAILURE" for i in range(6)]
        lines.append("2024-04-19T02:10:15 10.0.0.5 admin SUCCESS")
        az = AuthLogAnalyzer(brute_force_threshold=5)
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertIn("BRUTE_FORCE_SUCCESS", categories)
        critical = [a for a in az.alerts if a.category == "BRUTE_FORCE_SUCCESS"]
        self.assertEqual(critical[0].level, "CRITICAL")

    def test_no_alert_success_without_prior_failures(self):
        lines = ["2024-04-19T09:00:00 192.168.1.10 alice SUCCESS"]
        az = AuthLogAnalyzer(brute_force_threshold=5)
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertNotIn("BRUTE_FORCE_SUCCESS", categories)


class TestRapidFireAttack(unittest.TestCase):

    def test_detects_rapid_fire(self):
        # 10 tentativas no mesmo segundo
        lines = ["2024-04-19T14:00:00 203.0.113.9 root FAILURE"] * 10
        az = AuthLogAnalyzer(brute_force_threshold=5, rapid_fire_threshold=10)
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertIn("RAPID_FIRE_ATTACK", categories)

    def test_no_rapid_fire_below_threshold(self):
        lines = ["2024-04-19T14:00:00 203.0.113.9 root FAILURE"] * 5
        az = AuthLogAnalyzer(brute_force_threshold=5, rapid_fire_threshold=10)
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertNotIn("RAPID_FIRE_ATTACK", categories)


class TestOffHoursLogin(unittest.TestCase):

    def test_detects_off_hours(self):
        lines = ["2024-04-19T02:30:00 192.168.0.50 bob SUCCESS"]
        az = AuthLogAnalyzer()
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertIn("OFF_HOURS_LOGIN", categories)

    def test_no_alert_business_hours(self):
        lines = ["2024-04-19T10:00:00 192.168.0.50 bob SUCCESS"]
        az = AuthLogAnalyzer()
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertNotIn("OFF_HOURS_LOGIN", categories)


class TestDistributedAttack(unittest.TestCase):

    def test_detects_distributed_attack(self):
        lines = [
            f"2024-04-19T03:00:{i:02d} 10.0.0.{i+1} admin FAILURE"
            for i in range(10)
        ]
        az = AuthLogAnalyzer()
        az.load_lines(lines)
        az.analyze()
        categories = [a.category for a in az.alerts]
        self.assertIn("DISTRIBUTED_ATTACK", categories)


# ══════════════════════════════════════════════════════════
# Testes de I/O e relatório
# ══════════════════════════════════════════════════════════

class TestFileIO(unittest.TestCase):

    def test_load_file(self):
        content = (
            "2024-04-19T09:00:00 192.168.1.10 alice SUCCESS\n"
            "2024-04-19T09:05:00 192.168.1.11 bob FAILURE\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(content)
            path = f.name

        az = AuthLogAnalyzer()
        count = az.load_file(path)
        self.assertEqual(count, 2)

    def test_export_json(self):
        lines = [f"2024-04-19T02:10:{i:02d} 10.0.0.5 admin FAILURE" for i in range(6)]
        az = AuthLogAnalyzer(brute_force_threshold=5)
        az.load_lines(lines)
        az.analyze()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name

        az.export_json(path)
        with open(path) as f:
            data = json.load(f)

        self.assertIn("summary", data)
        self.assertIn("alerts", data)
        self.assertGreater(len(data["alerts"]), 0)


class TestSummary(unittest.TestCase):

    def test_summary_counts(self):
        lines = [
            "2024-04-19T09:00:00 10.0.0.1 alice SUCCESS",
            "2024-04-19T09:01:00 10.0.0.2 bob FAILURE",
            "2024-04-19T09:02:00 10.0.0.3 carol FAILURE",
        ]
        az = AuthLogAnalyzer()
        az.load_lines(lines)
        az.analyze()
        s = az.summary()
        self.assertEqual(s["total_entries"], 3)
        self.assertEqual(s["successes"], 1)
        self.assertEqual(s["failures"], 2)
        self.assertEqual(s["unique_ips"], 3)
        self.assertEqual(s["unique_users"], 3)

    def test_summary_empty(self):
        az = AuthLogAnalyzer()
        az.analyze()
        s = az.summary()
        self.assertEqual(s["total_entries"], 0)
        self.assertEqual(s["total_alerts"], 0)


# ══════════════════════════════════════════════════════════
# Runner manual (sem pytest)
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=".", pattern="test_auth_log_analyzer.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
