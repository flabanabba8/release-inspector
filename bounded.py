"""Bounded subprocess output on POSIX and Windows without exposing stderr."""
import os
import signal
import subprocess
import threading
import time


def output(command, *, env, cwd=None, stdin=subprocess.DEVNULL, timeout, limit, label):
    process = subprocess.Popen(command, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=env, cwd=cwd, start_new_session=os.name != 'nt')
    done = threading.Event(); chunks = []; state = {'size': 0, 'error': None}
    def read():
        try:
            while True:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk: break
                state['size'] += len(chunk)
                if state['size'] > limit:
                    state['error'] = 'limit'; break
                chunks.append(chunk)
        except OSError:
            state['error'] = 'read'
        finally:
            done.set()
    reader = threading.Thread(target=read, daemon=True); reader.start()
    deadline = time.monotonic() + timeout
    try:
        if not done.wait(timeout): raise RuntimeError(label + ' timed out')
        if state['error'] == 'limit': raise RuntimeError(label + ' report exceeds limit')
        if state['error']: raise RuntimeError(label + ' output could not be read')
        try: code = process.wait(timeout=max(.1, deadline-time.monotonic()))
        except subprocess.TimeoutExpired: raise RuntimeError(label + ' timed out') from None
        if code: raise RuntimeError(label + ' failed; scan is incomplete')
        return b''.join(chunks)
    finally:
        if process.poll() is None:
            try:
                if os.name == 'nt':
                    system_root = env.get('SystemRoot') or env.get('SYSTEMROOT')
                    if system_root:
                        try:
                            subprocess.run([os.path.join(system_root, 'System32', 'taskkill.exe'), '/PID', str(process.pid), '/T', '/F'],
                                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
                        except (OSError, subprocess.TimeoutExpired):
                            pass
                    if process.poll() is None: process.kill()
                else: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
        reader.join(timeout=1)
        process.stdout.close()
