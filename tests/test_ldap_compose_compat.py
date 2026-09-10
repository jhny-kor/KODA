import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('compat', ROOT/'platforms/linux/scheduled-release/support-ldap-compose.py')
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)

class LdapCompatTests(unittest.TestCase):
    def test_reviewed_variant_preserved_and_other_changes_blocked(self):
        base = (ROOT/'platforms/linux/scheduled-release/contract/tracker/compose.yaml').read_text()
        reviewed = base.replace('    restart: unless-stopped\n\n  portal-worker:', '      - ldap-egress\n    restart: unless-stopped\n    dns:\n      - 10.95.58.206\n      - 10.95.58.207\n\n  portal-worker:', 1).replace('\nvolumes:\n', '  ldap-egress:\n    name: ${COMPOSE_PROJECT_NAME:-koda-sbom}-ldap-egress\n\nvolumes:\n', 1)
        self.assertEqual(hashlib.sha256(reviewed.encode()).hexdigest(), compat.LDAP)
        reviewed = reviewed.replace('      - 10.95', '        - 10.95').replace('  ldap-egress:\n', '\n  ldap-egress:\n').replace('-ldap-egress\n\nvolumes:', '-ldap-egress\nvolumes:')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);release=root/'release';prefix=root/'suite'
            (release/'contract/tracker').mkdir(parents=True);(prefix/'tracker').mkdir(parents=True)
            contract=release/compat.REL;contract.write_text(base)
            manifest=release/'manifest.sha256';manifest.write_text(compat.BASE+'  '+compat.REL+'\n')
            installed=prefix/'tracker/compose.yaml';installed.write_text(reviewed+'# unreviewed\n')
            with self.assertRaises(ValueError):compat.apply(release,prefix)
            self.assertEqual(contract.read_text(),base)
            installed.write_text(reviewed)
            compat.apply(release,prefix)
            compat.apply(release,prefix)
            self.assertEqual(installed.read_text(),reviewed)
            self.assertEqual(contract.read_text(),reviewed)
            self.assertEqual((release/'ldap-compat-backup/compose.yaml').read_text(),base)
            self.assertIn(hashlib.sha256(reviewed.encode()).hexdigest(),manifest.read_text())

    def test_preflight_accepts_only_exact_reviewed_variants(self):
        spec = importlib.util.spec_from_file_location('preflight', ROOT/'platforms/linux/scheduled-release/preflight.py')
        preflight = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preflight)
        baseline = ROOT/'platforms/linux/scheduled-release/contract/tracker/compose.yaml'
        accepted = preflight.ldap_variants(baseline)
        self.assertEqual(len(accepted), 4)
        with tempfile.TemporaryDirectory() as folder:
            installed = Path(folder)/'compose.yaml'
            for variant in compat.reviewed_variants(baseline.read_text()):
                installed.write_bytes(variant)
                preflight.same_file(baseline, installed, accepted=accepted)
            installed.write_bytes(variant + b'\n# unexpected')
            with self.assertRaises(preflight.PreflightError):
                preflight.same_file(baseline, installed, accepted=accepted)
