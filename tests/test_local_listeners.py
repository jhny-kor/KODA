from __future__ import annotations

import unittest
from unittest.mock import patch

from security_scanner.checks.host.runner import CommandResult
from security_scanner.local_listeners import collect_local_listeners, render_local_listeners_markdown


def _command_output(stdout: str) -> CommandResult:
    return CommandResult(command="inventory", ok=True, returncode=0, stdout=stdout)


class LocalListenersTests(unittest.TestCase):
    def test_macos_normalizes_wildcards_and_deduplicates_bindings(self) -> None:
        raw = """p100
f10
tIPv4
n*:4100
f11
tIPv6
n*:4100
f12
tIPv6
n*:4100
p200
f20
tIPv4
n127.0.0.1:5200
f21
tIPv6
n[fe80::1%lo0]:6200
"""
        with patch("security_scanner.local_listeners.current_platform", return_value="macos"), patch(
            "security_scanner.local_listeners.run_command", return_value=_command_output(raw)
        ) as command:
            report = collect_local_listeners()
        self.assertEqual(command.call_args.args[0], ["/usr/sbin/lsof", "-nP", "-a", "-iTCP", "-sTCP:LISTEN", "-Fftn"])
        self.assertEqual(report["status"], "completed")
        self.assertEqual(
            report["listeners"],
            [
                {"address": "0.0.0.0", "port": 4100, "family": "IPv4", "binding": "all-interfaces"},
                {"address": "::", "port": 4100, "family": "IPv6", "binding": "all-interfaces"},
                {"address": "127.0.0.1", "port": 5200, "family": "IPv4", "binding": "loopback"},
                {"address": "fe80::1%lo0", "port": 6200, "family": "IPv6", "binding": "specific-interface"},
            ],
        )
        rendered = render_local_listeners_markdown(report)
        self.assertIn("이 기기에서만", rendered)

    def test_macos_falls_back_to_socket_table_when_process_metadata_is_restricted(self) -> None:
        restricted = CommandResult(command="lsof", ok=False, returncode=1, stderr="Operation not permitted")
        table = (
            "Active Internet connections (including servers)\n"
            "tcp46      0      0  *.4100                  *.*           LISTEN\n"
            "tcp4       0      0  127.0.0.1.5200          *.*           LISTEN\n"
            "tcp4       0      0  127.0.0.1.6200          127.0.0.1.7000 ESTABLISHED\n"
        )
        with patch("security_scanner.local_listeners.current_platform", return_value="macos"), patch(
            "security_scanner.local_listeners.run_command", side_effect=[restricted, _command_output(table)]
        ) as command:
            report = collect_local_listeners()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(command.call_args.args[0], ["/usr/sbin/netstat", "-an", "-p", "tcp"])
        self.assertEqual([(row["address"], row["port"]) for row in report["listeners"]],
                         [("0.0.0.0", 4100), ("::", 4100), ("127.0.0.1", 5200)])

    def test_windows_accepts_one_listener_and_empty_inventory(self) -> None:
        for raw, count in (('[{"LocalAddress":"::1","LocalPort":4100}]', 1), ("[]", 0)):
            with (
                self.subTest(raw=raw),
                patch("security_scanner.local_listeners.current_platform", return_value="windows"),
                patch("security_scanner.local_listeners.powershell", return_value=_command_output(raw)) as command,
            ):
                report = collect_local_listeners()
                self.assertEqual(report["status"], "completed")
                self.assertEqual(len(report["listeners"]), count)
                self.assertIn("State -eq Listen", command.call_args.args[0])

    def test_bad_rows_yield_partial_inventory_and_command_error_yields_unavailable(self) -> None:
        raw = '[{"LocalAddress":"127.0.0.1","LocalPort":4100},{"LocalAddress":"::","LocalPort":true}]'
        failed = CommandResult(command="inventory", ok=False, returncode=1, error="command timed out")
        with patch("security_scanner.local_listeners.current_platform", return_value="windows"), patch(
            "security_scanner.local_listeners.powershell", return_value=_command_output(raw)
        ) as command:
            report = collect_local_listeners()
            self.assertEqual(report["status"], "partial")
            self.assertEqual(len(report["listeners"]), 1)
            command.return_value = failed
            report = collect_local_listeners()
        self.assertEqual(report["status"], "unavailable")
        self.assertEqual(report["listeners"], [])
        self.assertEqual(report["warnings"], ["command timed out"])
