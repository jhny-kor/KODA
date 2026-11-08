import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1] / "platforms/linux/suite/handover"
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('install_new',ROOT/'install-new.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)

class FreshTests(unittest.TestCase):
    def test_refuses_existing_files_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'existing').mkdir(); (root/'existing'/'data').write_text('keep')
            (root/'link').symlink_to(root/'existing',target_is_directory=True)
            for path in [root/'existing', root/'link']:
                with self.assertRaises(n.h.Failure): n.require_empty_prefix(path)
            self.assertEqual((root/'existing'/'data').read_text(),'keep')
    def test_empty_or_absent_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            n.require_empty_prefix(Path(temp));n.require_empty_prefix(Path(temp)/'absent')
    def test_verified_release_only_then_install_without_operator_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);env=root/'production.env';env.write_text('POSTGRES_PASSWORD=fixture\n');prefix=root/'new'
            runner=mock.Mock();events=[]
            @contextlib.contextmanager
            def released(args,host):
                self.assertEqual(args.release_public_key,n.h.HERE/'release-public.pem')
                self.assertIsNone(args.archive);events.append('verified');yield root/'suite',{'POSTGRES_PASSWORD':'fixture'}
            runner.run.side_effect=lambda *a,**k:events.append('install')
            with mock.patch.object(n.sys,'platform','linux'),mock.patch.object(n.h,'source_environment',return_value=({},set())),mock.patch.object(n.h,'release',released),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(n.main(['--prefix',str(prefix),'--env-file',str(env)],runner),0)
            self.assertEqual(events,['verified','install'])
            self.assertEqual(runner.run.call_args.args[0][2],'install')
    def test_failed_verification_never_installs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);env=root/'production.env';env.write_text('X=fixture\n');runner=mock.Mock()
            with mock.patch.object(n.sys,'platform','linux'),mock.patch.object(n.h,'source_environment',return_value=({},set())),mock.patch.object(n.h,'release',side_effect=n.h.Failure('signature mismatch')),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(n.main(['--prefix',str(root/'new'),'--env-file',str(env)],runner),2)
            runner.run.assert_not_called()
    def test_refuses_configuration_inside_new_prefix(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);env=root/'production.env';env.write_text('X=fixture\n');runner=mock.Mock()
            with mock.patch.object(n.sys,'platform','linux'),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(n.main(['--prefix',str(root),'--env-file',str(env)],runner),2)
            runner.run.assert_not_called()
