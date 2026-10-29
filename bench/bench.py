"""Benchmark: one site at a time vs a parallel sweep.

usage: python bench/bench.py [N_SITES] [DELAY_MS]
Starts N local fake sites that each answer after DELAY_MS (like a slow real server), then times
`sweep.py -l sites.txt -t 1` (one site at a time, the way a one-URL checker runs) and `-t 20`.
"""
import http.server
import os
import subprocess
import sys
import tempfile
import threading
import time

n = int(sys.argv[1]) if len(sys.argv) > 1 else 50
delay = int(sys.argv[2]) if len(sys.argv) > 2 else 100
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSIONS = ['8.2.34', '8.2.35', '8.3.35', '8.4.26', '8.4.27', '8.5.11', '7.4.33', '9.0.0']


class H(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        time.sleep(delay / 1000)
        self.send_response(200)
        self.send_header('X-Powered-By', 'PHP/' + VERSIONS[int(self.path.strip('/')) % len(VERSIONS)])
        self.send_header('Content-Length', '0')
        self.end_headers()
    do_GET = do_HEAD

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
srv.daemon_threads = True
threading.Thread(target=srv.serve_forever, daemon=True).start()
with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as f:
    f.write('\n'.join('http://127.0.0.1:%d/%d' % (srv.server_address[1], i) for i in range(n)))

print('sites: %d, server delay: %d ms' % (n, delay))
for threads in (1, 20):
    t = time.perf_counter()
    subprocess.run([sys.executable, os.path.join(ROOT, 'sweep.py'), '-l', f.name, '-t', str(threads), '--json'],
                   capture_output=True)
    print('threads=%-2d  %.2f s' % (threads, time.perf_counter() - t))
os.unlink(f.name)
