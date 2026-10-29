"""Verdict vectors ported from openai/php2shell-checker (Apache-2.0) plus list-mode tests."""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import sweep  # noqa: E402


class Handler(http.server.BaseHTTPRequestHandler):
    """Path = /<mode>/<header-spec>; headers come from the server's `routes` dict."""
    def log_message(self, *a):
        pass

    def _reply(self):
        self.server.methods.append(self.command)
        route = self.server.routes.get(self.path, {})
        if route == 'drop':
            self.connection.close()
            return
        if route == 'hang':
            threading.Event().wait(1)
            return
        status = route.get(self.command + '_status', 200)
        self.send_response_only(status)
        for k, v in route.get('headers', {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', '0')
        self.end_headers()

    do_HEAD = do_GET = _reply


class Server:
    def __init__(self):
        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.httpd.routes, self.httpd.methods = {}, []
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = 'http://127.0.0.1:%d' % self.httpd.server_address[1]

    def url(self, path, route):
        self.httpd.routes[path] = route
        return self.base + path

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class VersionStatus(unittest.TestCase):
    def test_boundaries(self):
        for v in ['8.2.34', '8.3.35', '8.4.26', '8.5.11']:
            self.assertEqual(sweep.version_status(v), 'potentially_vulnerable', v)
            a, b, c = v.split('.')
            self.assertEqual(sweep.version_status('%s.%s.%d' % (a, b, int(c) + 1)), 'ok')

    def test_older_branches(self):
        for v in ['5.4.45', '5.5.38', '5.6.40', '7.0.33', '7.1.33', '7.2.34', '7.3.33', '7.4.33',
                  '8.0.30', '8.1.34', '8.1.35', '8.1.99']:
            self.assertEqual(sweep.version_status(v), 'potentially_vulnerable', v)

    def test_unknown(self):
        for v in ['8.6.0', '9.0.0', '8.4', 'not-a-version', '8.4.27RC1', '8.4.27-rc1',
                  '8.4.27~beta1', '8.1.35RC1', '8.1.35-dev', None]:
            self.assertEqual(sweep.version_status(v), 'unknown', v)

    def test_distro_suffix(self):
        self.assertEqual(sweep.version_status('8.4.26-1ubuntu1'), 'potentially_vulnerable')
        self.assertEqual(sweep.version_status('8.1.2-1ubuntu2.28'), 'potentially_vulnerable')
        self.assertEqual(sweep.version_status('8.4.27-1ubuntu1'), 'ok')
        self.assertEqual(sweep.version_status('8.4.100'), 'ok')


class CheckUrl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Server()

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def setUp(self):
        self.s.httpd.methods.clear()

    def check(self, path, route, status, version, timeout=5):
        r = sweep.check_url(self.s.url(path, route), timeout)
        self.assertEqual(r['patch_status'], status, r)
        self.assertEqual(r['php_version'], version, r)
        self.assertEqual(r['exit_code'], {'ok': 0, 'potentially_vulnerable': 1, 'unknown': 3}[status])
        return r

    def test_headers_any_case(self):
        n = 0
        for header in ['X-Powered-By', 'x-PoWeReD-bY', 'Server']:
            for v, st in [('8.4.26', 'potentially_vulnerable'), ('8.4.27', 'ok'), ('8.4.100', 'ok')]:
                n += 1
                val = 'Apache/2.4.62 (Unix) PHP/' + v if header == 'Server' else 'PHP/' + v
                self.s.httpd.methods.clear()
                self.check('/h%d' % n, {'headers': {header: val}}, st, v)
                self.assertEqual(self.s.httpd.methods, ['HEAD'])

    def test_reason_texts_match_upstream(self):
        r = self.check('/bad', {'headers': {'X-Powered-By': 'PHP/8.4.26'}}, 'potentially_vulnerable', '8.4.26')
        self.assertEqual(sweep.line(r), 'POTENTIALLY VULNERABLE: PHP 8.4.26: Potentially vulnerable. '
                         'HTTP headers cannot tell whether this version contains a backported fix.')
        r = self.check('/good', {'headers': {'X-Powered-By': 'PHP/8.4.27'}}, 'ok', '8.4.27')
        self.assertEqual(sweep.line(r), 'OK: PHP 8.4.27: advertised version meets an upstream fixed release. '
                         'Installed build not verified.')

    def test_no_php_header(self):
        r = self.check('/none', {'headers': {'Server': 'nginx', 'X-Powered-By': 'Express'}}, 'unknown', None)
        self.assertEqual(r['reason'], 'PHP version not found')

    def test_drop_and_timeout(self):
        self.assertTrue(self.check('/drop', 'drop', 'unknown', None)['reason'])
        r = self.check('/hang', 'hang', 'unknown', None, timeout=0.2)
        self.assertRegex(r['reason'], '(?i)timeout')

    def test_head_fallback(self):
        for code in (405, 501):
            self.s.httpd.methods.clear()
            self.check('/f%d' % code, {'HEAD_status': code, 'headers': {'X-Powered-By': 'PHP/8.4.27'}}, 'ok', '8.4.27')
            self.assertEqual(self.s.httpd.methods, ['HEAD', 'GET'])

    def test_no_redirect_follow(self):
        self.check('/r', {'headers': {'Location': '/elsewhere'}, 'HEAD_status': 302}, 'unknown', None)
        self.assertEqual(self.s.httpd.methods, ['HEAD'])

    def test_conflicting_headers(self):
        cases = [('8.4.26', '8.4.27', '8.4.26', 'potentially_vulnerable'),
                 ('8.4.27', '8.4.26', '8.4.26', 'potentially_vulnerable'),
                 ('8.1.35', '8.4.27', '8.1.35', 'potentially_vulnerable'),
                 ('8.4.27', '8.1.35', '8.1.35', 'potentially_vulnerable'),
                 ('9.0.0', '8.4.27', '9.0.0', 'unknown'),
                 ('8.4.27', '9.0.0', '9.0.0', 'unknown')]
        for i, (srv, pb, ver, st) in enumerate(cases):
            self.check('/c%d' % i, {'headers': {'Server': 'Apache/2.4.62 PHP/' + srv,
                                                'X-Powered-By': 'PHP/' + pb}}, st, ver)

    def test_bad_url(self):
        for u in ['ftp://x', 'http://u:p@x/', 'http://x/#f', 'http://a b/']:
            self.assertEqual(sweep.check_url(u, 1)['patch_status'], 'unknown', u)


class Sweep(unittest.TestCase):
    def test_list_mode_dedupes_and_reports_worst(self):
        s = Server()
        try:
            urls = [s.url('/a', {'headers': {'X-Powered-By': 'PHP/8.4.27'}}),
                    s.url('/b', {'headers': {'X-Powered-By': 'PHP/8.2.20'}}),
                    s.url('/c', {'headers': {'Server': 'nginx'}})]
            with tempfile.TemporaryDirectory() as d:
                hosts = os.path.join(d, 'hosts.txt')
                with open(hosts, 'w') as f:
                    f.write('# my sites\n' + '\n'.join(urls + [urls[0], '']))
                out = os.path.join(d, 'r.json')
                svg = os.path.join(d, 'r.svg')
                p = subprocess.run([sys.executable, os.path.join(ROOT, 'sweep.py'), '-l', hosts, '-o', out,
                                    '--svg', svg, '-t', '4'], capture_output=True, text=True)
                self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                with open(out, encoding='utf-8') as f:
                    rows = json.load(f)
                self.assertEqual([r['url'] for r in rows], urls)
                self.assertEqual([r['patch_status'] for r in rows], ['ok', 'potentially_vulnerable', 'unknown'])
                self.assertIn('1 potentially vulnerable', p.stdout)
                with open(svg, encoding='utf-8') as f:
                    self.assertIn('<svg', f.read())
        finally:
            s.close()

    def test_bad_args_exit_2(self):
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'sweep.py')], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)


if __name__ == '__main__':
    unittest.main()
