"""Verify the synchronization overlay against the actual pinned dependency."""
import pathlib
import subprocess
import unittest

from core_overlay import network_started_atomic, openconnect_cancel_terminal

class NetworkLifecycleOverlay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=pathlib.Path(__file__).resolve().parents[2]
        module=pathlib.Path(subprocess.check_output(['go','list','-m','-f','{{.Dir}}','github.com/sagernet/sing-box'],cwd=root/'core/server',text=True).strip())
        cls.source=(module/'route/network.go').read_text()

    def test_actual_pinned_source_has_both_synchronized_accesses(self):
        patched=network_started_atomic(self.source)
        self.assertIn('started                  atomic.Bool',patched)
        self.assertIn('r.started.Store(true)',patched)
        self.assertIn('if !r.started.Load() {',patched)

    def test_changed_dependency_or_reapplication_requires_review(self):
        for changed in (self.source+'\n// r.started changed\n',self.source.replace('r.started = true','r.started = false'),network_started_atomic(self.source)):
            with self.assertRaisesRegex(RuntimeError,'review started synchronization'):
                network_started_atomic(changed)

class OpenConnectCancellationOverlay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=pathlib.Path(__file__).resolve().parents[2]
        module=pathlib.Path(subprocess.check_output(['go','list','-m','-f','{{.Dir}}','github.com/sagernet/sing-openconnect'],cwd=root/'core/server',text=True).strip())
        cls.source=(module/'client_supervisor.go').read_text()

    def test_actual_pinned_source_changes_only_cancellation_policy(self):
        patched=openconnect_cancel_terminal(self.source)
        self.assertEqual(patched.count('\t\tErrAuthChallengeCanceled,\n'),1)
        self.assertEqual(patched.replace('\t\tErrAuthChallengeCanceled,\n',''),self.source)

    def test_changed_dependency_or_reapplication_requires_review(self):
        for changed in (self.source.replace('\t\tErrAuthenticationFailed,\n',''),self.source.replace('func classifyClientSessionError','func renamedClassifier'),openconnect_cancel_terminal(self.source)):
            with self.assertRaisesRegex(RuntimeError,'review cancellation classification'):
                openconnect_cancel_terminal(changed)

if __name__=='__main__':unittest.main()
