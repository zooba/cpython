'''Tests for sys.audit and sys.addaudithook
'''

import os
import subprocess
import sys
import unittest
from test import support

if not hasattr(sys, 'addaudithook') or not hasattr(sys, 'audit'):
    raise unittest.SkipTest("test only relevant when sys.audit is available")

class TestHook:
    '''Used in standard hook tests to collect any logged events.

    Should be used in a with block to ensure that it has no impact
    after the test completes. Audit hooks cannot be removed, so the
    best we can do for the test run is disable it by calling close().
    '''
    def __init__(self, raise_on_events=None, exc_type=RuntimeError):
        self.raise_on_events = raise_on_events or ()
        self.exc_type = exc_type
        self.seen = []
        self.closed = False

    def __enter__(self, *a):
        sys.addaudithook(self)
        return self

    def __exit__(self, *a):
        self.close()

    def close(self):
        self.closed = True

    @property
    def seen_events(self):
        return [i[0] for i in self.seen]

    def __call__(self, event, args):
        if self.closed:
            return
        self.seen.append((event, args))
        if event in self.raise_on_events:
            raise self.exc_type('saw event ' + event)

class TestFinalizeHook:
    '''Used in the test_finalize_hooks function to ensure that hooks
    are correctly cleaned up, that they are notified about the cleanup,
    and are unable to prevent it.
    '''
    def __init__(self):
        print('Created', id(self), file=sys.stderr, flush=True)
    
    def __call__(self, event, args):
        # Avoid recursion when we call id() below
        if event == 'id':
            return

        print(event, id(self), file=sys.stderr, flush=True)

        if event == 'sys._clearaudithooks':
            raise RuntimeError('Should be ignored')
    
    def __del__(self):
        print('Finalized', id(self), file=sys.stderr, flush=True)

def run_finalize_test():
    '''Called by test_finalize_hooks in a subprocess.'''
    sys.addaudithook(TestFinalizeHook())


class AuditTest(unittest.TestCase):
    def test_basic(self):
        with TestHook() as hook:
            sys.audit('test_event', 1, 2, 3)
            self.assertEqual(hook.seen[0][0], 'test_event')
            self.assertEqual(hook.seen[0][1], (1, 2, 3))

    def test_block_add_hook(self):
        # Raising an exception should prevent a new hook from being added,
        # but will not propagate out.
        with TestHook(raise_on_events='sys.addaudithook') as hook1:
            with TestHook() as hook2:
                sys.audit('test_event')
                self.assertIn('test_event', hook1.seen_events)
                self.assertNotIn('test_event', hook2.seen_events)

    def test_block_add_hook_baseexception(self):
        # Raising BaseException will propagate out when adding a hook
        with self.assertRaises(BaseException):
            with TestHook(raise_on_events='sys.addaudithook', exc_type=BaseException) as hook1:
                # Adding this next hook should raise BaseException
                with TestHook() as hook2:
                    pass

    def test_finalize_hooks(self):
        events = []
        with subprocess.Popen([
            sys.executable, "-c", "import test.test_audit; test.test_audit.run_finalize_test()"
        ], encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            p.wait()
            for line in p.stderr:
                events.append(line.strip().partition(' '))
        firstId = events[0][2]
        self.assertSequenceEqual([
            ('Created', ' ', firstId),
            ('sys._clearaudithooks', ' ', firstId),
            ('Finalized', ' ', firstId),
        ], events)

    def test_pickle(self):
        pickle = support.import_module("pickle")
        class PicklePrint:
            def __reduce_ex__(self, p):
                return str, ("Pwned!",)
        payload_1 = pickle.dumps(PicklePrint())
        payload_2 = pickle.dumps(('a', 'b', 'c', 1, 2, 3))

        # Before we add the hook, ensure our malicious pickle loads
        self.assertEqual("Pwned!", pickle.loads(payload_1))

        with TestHook(raise_on_events='pickle.find_class') as hook:
            with self.assertRaises(RuntimeError):
                # With the hook enabled, loading globals is not allowed
                pickle.loads(payload_1)
            # pickles with no globals are okay
            pickle.loads(payload_2)

    def test_monkeypatch(self):
        class A: pass
        class B: pass
        class C(A): pass
        a = A()

        with TestHook() as hook:
            # Catch name changes
            C.__name__ = 'X'
            # Catch type changes
            C.__bases__ = B,
            # Ensure bypassing __setattr__ is still caught
            type.__dict__['__bases__'].__set__(C, (B,))
            # Catch attribute replacement
            C.__init__ = B.__init__
            # Catch attribute addition
            C.new_attr = 123
            # Catch class changes
            a.__class__ = B

        actual = [(a[0], a[1]) for e, a in hook.seen if e == 'object.__setattr__']
        self.assertSequenceEqual([
            (C, '__name__'),
            (C, '__bases__'),
            (C, '__bases__'),
            (C, '__init__'),
            (C, 'new_attr'),
            (a, '__class__'),
        ], actual);

    def test_spython(self):
        spython_executable = os.path.join(os.path.dirname(sys.executable),
            os.path.split(sys.executable)[1].replace("python", "spython"));
        if not os.path.isfile(spython_executable):
            self.skipTest("spython executable is not available at " + spython_executable)

        with support.temp_dir() as temp_path:
            spython_log = os.path.join(temp_path, "spython.log")
            env = os.environ.copy()
            env["SPYTHONLOG"] = spython_log

            with subprocess.Popen([
                spython_executable, os.path.abspath(__file__), "spython_test"
            ], env=env, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
                p.wait()
                stdout, stderr = p.stdout.read(), p.stderr.read()

            with open(spython_log, 'r', encoding='utf-8') as f:
                # For this test, we don't care about the open_for_exec messages
                spylog = [line.partition(':')[0].strip() for line in f
                          if line and line.startswith(('sys.addaudithook:', 'sys._clearaudithooks:'))]

            self.assertEqual("", stdout.strip(), "expected no stdout output")
            self.assertEqual("", stderr.strip(), "expected no stderr output")
            self.assertSequenceEqual(["sys.addaudithook",
                                      "sys._clearaudithooks"],
                                     spylog,
                                     "mismatched log output")

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "spython_test":
        # Doesn't matter what we add - it will be blocked
        sys.addaudithook(None)

        sys.exit(0)

    unittest.main()
