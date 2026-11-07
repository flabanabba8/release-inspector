"""A bounded worker timeout must stop an owned Windows child process."""
import ctypes
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('bounded_windows_test', Path(__file__).parents[1] / 'bounded.py')
bounded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded)


@unittest.skipUnless(os.name == 'nt', 'Native Windows process-tree test')
class WindowsTreeTest(unittest.TestCase):
    def test_timeout_stops_owned_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'child.txt'
            worker = ("import subprocess,sys,time\nfrom pathlib import Path\n"
                      "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)'])\n"
                      "Path(sys.argv[1]).write_text(str(p.pid))\ntime.sleep(120)\n")
            env = {k: os.environ[k] for k in ('SystemRoot', 'SYSTEMROOT', 'PATH', 'TEMP', 'TMP') if k in os.environ}
            pid = None
            active = True
            try:
                with self.assertRaisesRegex(RuntimeError, 'timed out'):
                    bounded.output([sys.executable, '-c', worker, str(marker)], env=env,
                                   timeout=4, limit=4096, label='Fixture')
                self.assertTrue(marker.exists(), 'Fixture child did not start')
                pid = int(marker.read_text())
                kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
                kernel.OpenProcess.restype = ctypes.c_void_p
                kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                for _ in range(25):
                    handle = kernel.OpenProcess(0x1000, False, pid)
                    if not handle:
                        active = False
                        break
                    code = ctypes.c_uint32()
                    ok = kernel.GetExitCodeProcess(handle, ctypes.byref(code))
                    kernel.CloseHandle(handle)
                    if ok and code.value != 259:
                        active = False
                        break
                    time.sleep(.2)
                self.assertFalse(active, 'Owned descendant remained active')
            finally:
                if pid and active:
                    exe = str(Path(os.environ['SYSTEMROOT']) / 'System32' / 'taskkill.exe')
                    subprocess.run([exe, '/PID', str(pid), '/T', '/F'], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=5, check=False)


if __name__ == '__main__':
    unittest.main()
