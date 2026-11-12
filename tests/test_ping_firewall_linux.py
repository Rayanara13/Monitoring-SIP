import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


if sys.platform.startswith("linux"):
    from offline import ping_firewall_linux as firewall


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux file semantics")
class PingFirewallTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.directory = Path(folder.name)
        self.state = self.directory / "root-state"
        self.source = self.directory / firewall.TRUST_FILE

    def test_bootstrap_and_authoritative_snapshot(self):
        applied = []
        current = None

        def run(*args, data=None):
            nonlocal current
            if args == ("nft", "-f", "-"):
                current = data.split('comment "', 1)[1].split('"', 1)[0]
                applied.append(data)
            else:
                self.assertEqual(args, ("nft", "-c", "-f", "-"))

        with patch.multiple(firewall, STATE_DIR=self.state), \
                patch.object(firewall, "_native_nft_only"), patch.object(firewall, "_install_units"), \
                patch.object(firewall, "_current_marker", lambda: current), patch.object(firewall, "_run", run):
            firewall._install(self.directory, "10.1.2.3", dry_run=True)
            self.assertEqual(applied, [])
            self.assertFalse(self.state.exists())

            firewall._install(self.directory, "10.1.2.3", dry_run=False)
            self.assertEqual(len(applied), 1)
            self.assertIn("elements = { 10.1.2.3 }", applied[-1])
            self.assertEqual(json.loads((self.state / "settings.json").read_text()), {"path": str(self.source)})
            firewall._refresh()
            self.assertEqual(len(applied), 1)

            self.source.write_text('{"addresses":["fd00::7","10.1.2.4","10.1.2.4"]}')
            firewall._refresh()
            self.assertEqual(len(applied), 2)
            self.assertIn("elements = { 10.1.2.4 }", applied[-1])
            self.assertIn("elements = { fd00::7 }", applied[-1])
            self.assertNotIn("10.1.2.3", applied[-1])
            firewall._refresh()
            self.assertEqual(len(applied), 2)

            self.source.write_text('{"addresses":["not a host"]}')
            with self.assertRaises(firewall.TrustFileError):
                firewall._refresh()
            self.assertEqual(len(applied), 2)
            current = None  # Перезагрузка или глобальная очистка правил извне.
            with self.assertRaises(firewall.TrustFileError):
                firewall._refresh()
            self.assertEqual(applied[-2], applied[-1])

            self.source.write_text('{"addresses":[]}')
            firewall._refresh()
            self.assertNotIn("elements =", applied[-1])
            self.assertEqual(applied[-1].count('iifname != "lo"'), 2)
            self.assertEqual(applied[-1].count("type echo-request counter drop"), 2)

    def test_untrusted_source_cannot_inject_policy_or_trigger_bootstrap(self):
        with patch.object(firewall, "_native_nft_only"), patch.object(firewall, "_apply") as apply:
            for contents in ('{"addresses":["10.1.2.3; flush ruleset"]}', '{"addresses":["::%eth0"]}',
                             '{"addresses":["10.1.2.0/24"]}', '{"addresses":["224.0.0.1"]}'):
                self.source.write_text(contents)
                with self.assertRaises(firewall.TrustFileError):
                    firewall._install(self.directory, "10.1.2.3", dry_run=False)
            self.source.unlink()
            self.source.symlink_to(self.directory / "missing.json")
            with self.assertRaises(firewall.TrustFileError):
                firewall._install(self.directory, "10.1.2.3", dry_run=False)
            self.source.unlink()
            os.mkfifo(self.source)
            with self.assertRaises(firewall.TrustFileError):
                firewall._read_addresses(self.source)
            apply.assert_not_called()

    def test_install_rolls_back_units_and_previous_nft_policy(self):
        units = self.directory / "units"
        units.mkdir()
        helper = self.directory / "lib" / "helper.py"
        enabled = set()
        running = False
        fail_timer = True
        active_rules = None

        def current_marker():
            if active_rules is None:
                return None
            return active_rules.split('comment "', 1)[1].split('"', 1)[0]

        def run(*args, data=None, check=True):
            nonlocal running, active_rules
            if args == ("nft", "-f", "-"):
                active_rules = data
            elif args == ("nft", "list", "table", "inet", firewall.TABLE):
                return SimpleNamespace(stdout=active_rules.split("\n", 2)[2])
            elif args[:2] == ("systemctl", "enable"):
                enabled.add(args[-1])
                if args[-1] == firewall.TIMER:
                    running = True
                    if fail_timer:
                        raise firewall.FirewallError("timer start failed")
            elif args[:2] == ("systemctl", "stop"):
                running = False
            elif args[:2] == ("systemctl", "disable"):
                enabled.discard(args[-1])
            elif args[:2] == ("systemctl", "is-enabled"):
                return SimpleNamespace(stdout="enabled\n" if args[-1] in enabled else "disabled\n")
            elif args[:2] == ("systemctl", "is-active"):
                return SimpleNamespace(returncode=0 if running else 3)
            else:
                self.assertIn(args, [("systemctl", "daemon-reload"), ("nft", "-c", "-f", "-")])

        with patch.multiple(firewall, STATE_DIR=self.state, UNITS_DIR=units, HELPER=helper), \
                patch.object(firewall, "_native_nft_only"), patch.object(firewall, "_current_marker", current_marker), \
                patch.object(firewall, "_run", run):
            with self.assertRaisesRegex(firewall.FirewallError, "timer start failed"):
                firewall._install(self.directory, "10.1.2.3", dry_run=False)
            self.assertEqual(list(units.iterdir()), [])
            self.assertFalse(helper.exists())
            self.assertFalse((self.state / "settings.json").exists())
            self.assertFalse(enabled)
            self.assertFalse(running)
            self.assertIsNone(active_rules)

            fail_timer = False
            firewall._install(self.directory, "10.1.2.3", dry_run=False)
            prior_rules = active_rules
            self.source.write_text('{"addresses":["10.1.2.4"]}')
            real_write = firewall._atomic_write

            def fail_new_snapshot(path, content, mode=0o600):
                if path.name == "rules.nft" and "10.1.2.4" in content:
                    raise OSError("disk full")
                real_write(path, content, mode)

            with patch.object(firewall, "_atomic_write", fail_new_snapshot):
                with self.assertRaisesRegex(OSError, "disk full"):
                    firewall._install(self.directory, None, dry_run=False)
            self.assertEqual(active_rules, prior_rules)
            self.assertEqual((self.state / "rules.nft").read_text(), prior_rules)
            self.assertEqual(enabled, {firewall.TIMER, firewall.SERVICE})
            self.assertTrue(running)


if __name__ == "__main__":
    unittest.main()
