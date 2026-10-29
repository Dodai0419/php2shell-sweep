#!/usr/bin/env python3
"""php2shell-sweep: check many sites for the PHP2Shell warning (CVE-2026-109618/109619) at once.

Reads only the Server and X-Powered-By response headers. Sends no exploit probes.
Verdict rules follow openai/php2shell-checker (Apache-2.0); list mode follows assetnote/php2shell-scanner (MIT).
"""
import argparse
import concurrent.futures as cf
import html
import http.client
import json
import re
import socket
import sys
import urllib.parse

# Official PHP releases fixing both CVEs, published 2026-10-21.
FIXED_IN = {'8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12}
OLDER_BRANCHES = {'5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1'}
CODES = {'ok': 0, 'potentially_vulnerable': 1, 'unknown': 3}
VERSION_RE = re.compile(r'^(\d+)\.(\d+)\.(\d+)([-+~].*)?$')
PRERELEASE_RE = re.compile(r'(?:^|[-+~.])(?:dev|alpha|beta|rc)', re.I)
BANNER_RE = re.compile(r'\bPHP[ /]([^\s,;)]+)', re.I)


def version_status(version):
    m = VERSION_RE.match(version or '')
    if not m or PRERELEASE_RE.search(m.group(4) or ''):
        return 'unknown'
    branch = '%d.%d' % (int(m.group(1)), int(m.group(2)))
    if branch in OLDER_BRANCHES:
        return 'potentially_vulnerable'
    if branch not in FIXED_IN:
        return 'unknown'
    return 'potentially_vulnerable' if int(m.group(3)) < FIXED_IN[branch] else 'ok'


def fetch_headers(address, timeout):
    if re.search(r'[\x00-\x20\x7f]', address):
        raise ValueError('URL contains spaces or control characters')
    u = urllib.parse.urlsplit(address)
    if u.scheme not in ('http', 'https') or not u.hostname:
        raise ValueError('Use an http:// or https:// URL')
    if u.username or u.password or u.fragment:
        raise ValueError('URL credentials and fragments are not supported')
    conn_cls = http.client.HTTPSConnection if u.scheme == 'https' else http.client.HTTPConnection
    path = (u.path or '/') + ('?' + u.query if u.query else '')
    seen = []
    for method in ('HEAD', 'GET'):  # GET only when HEAD is refused; redirects are never followed
        conn = conn_cls(u.hostname, u.port, timeout=timeout)
        try:
            conn.request(method, path, headers={'User-Agent': 'php2shell-sweep'})
            resp = conn.getresponse()
            seen += [resp.getheader('server') or '', resp.getheader('x-powered-by') or '']
        finally:
            conn.close()
        if resp.status not in (405, 501):
            break
    return '\n'.join(seen)


def check_url(address, timeout=10):
    version, status, error = None, 'unknown', None
    try:
        for m in BANNER_RE.finditer(fetch_headers(address, timeout)):
            candidate = version_status(m.group(1))
            # Prefer warnings and unrecognized versions over a reassuring banner.
            if version is None or candidate == 'potentially_vulnerable' or status == 'ok':
                version, status = m.group(1), candidate
            if status == 'potentially_vulnerable':
                break
    except (socket.timeout, TimeoutError):
        error = 'timeout after %gs' % timeout
    except Exception as exc:  # network errors and bad URLs all mean "unknown"
        error = str(exc) or type(exc).__name__
    result = {'patch_status': 'unknown', 'reason': error or 'PHP version not found'}
    if version and not error:
        result = {'patch_status': status, 'reason': (
            'PHP %s: advertised version meets an upstream fixed release. Installed build not verified.' % version
            if status == 'ok' else
            'PHP %s: %sHTTP headers cannot tell whether this version contains a backported fix.'
            % (version, 'Potentially vulnerable. ' if status == 'potentially_vulnerable' else ''))}
    return {'url': address, **result, 'php_version': version, 'exit_code': CODES[result['patch_status']]}


def line(r):
    return r['patch_status'].replace('_', ' ').upper() + ': ' + r['reason']


def read_targets(urls, path):
    targets = list(urls)
    if path:
        with open(path, encoding='utf-8') as f:
            targets += [s.strip() for s in f if s.strip() and not s.lstrip().startswith('#')]
    return list(dict.fromkeys(targets))  # dedupe, keep order


def sweep(targets, timeout, threads):
    with cf.ThreadPoolExecutor(max(1, min(threads, len(targets)))) as pool:
        return list(pool.map(lambda t: check_url(t, timeout), targets))


def svg_report(rows):
    colors = {'ok': '#1a7f37', 'potentially_vulnerable': '#cf222e', 'unknown': '#9a6700'}
    labels = {'ok': 'OK', 'potentially_vulnerable': 'VULNERABLE?', 'unknown': 'UNKNOWN'}
    counts = {k: sum(r['patch_status'] == k for r in rows) for k in colors}
    h = 96 + 30 * len(rows)
    out = ['<svg xmlns="http://www.w3.org/2000/svg" width="760" height="%d" font-family="ui-monospace,Consolas,monospace">' % h,
           '<rect width="760" height="%d" rx="12" fill="#0d1117"/>' % h,
           '<text x="24" y="38" fill="#e6edf3" font-size="18" font-weight="bold">php2shell-sweep</text>',
           '<text x="24" y="62" fill="#8b949e" font-size="13">%d sites  |  %d ok  |  %d potentially vulnerable  |  %d unknown</text>'
           % (len(rows), counts['ok'], counts['potentially_vulnerable'], counts['unknown'])]
    for i, r in enumerate(rows):
        y = 96 + 30 * i
        c = colors[r['patch_status']]
        out += ['<rect x="24" y="%d" width="120" height="22" rx="11" fill="%s"/>' % (y - 16, c),
                '<text x="84" y="%d" fill="#fff" font-size="11" text-anchor="middle" font-weight="bold">%s</text>' % (y - 1, labels[r['patch_status']]),
                '<text x="160" y="%d" fill="#e6edf3" font-size="13">%s</text>' % (y, html.escape(r['url'][:48])),
                '<text x="736" y="%d" fill="#8b949e" font-size="13" text-anchor="end">%s</text>' % (y, html.escape('PHP ' + r['php_version'] if r['php_version'] else r['reason'][:28]))]
    return '\n'.join(out + ['</svg>\n'])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('url', nargs='*', help='http(s) URLs to check')
    ap.add_argument('-l', '--list', help='file with one URL per line (# comments allowed)')
    ap.add_argument('-t', '--threads', type=int, default=20)
    ap.add_argument('--timeout', type=float, default=10)
    ap.add_argument('--json', action='store_true', help='print one JSON object per site')
    ap.add_argument('-o', '--output', help='write all results as a JSON array')
    ap.add_argument('--svg', help='write a picture of the results')
    ap.add_argument('--demo', action='store_true', help='check a built-in local test server')
    a = ap.parse_args(argv)
    if a.demo:
        return demo(a)
    targets = read_targets(a.url, a.list)
    if not targets or not 0 < a.timeout <= 60:
        ap.print_usage(sys.stderr)
        print('error: give at least one URL (or -l FILE); --timeout must be in (0, 60]', file=sys.stderr)
        return 2
    rows = sweep(targets, a.timeout, a.threads)
    for r in rows:
        print(json.dumps(r) if a.json else '%-48s %s' % (r['url'], line(r)))
    if not a.json:
        c = {k: sum(r['patch_status'] == k for r in rows) for k in CODES}
        print('\n%d sites: %d ok, %d potentially vulnerable, %d unknown'
              % (len(rows), c['ok'], c['potentially_vulnerable'], c['unknown']))
    if a.output:
        with open(a.output, 'w', encoding='utf-8') as f:
            json.dump(rows, f, indent=2)
    if a.svg:
        with open(a.svg, 'w', encoding='utf-8') as f:
            f.write(svg_report(rows))
    return max(r['exit_code'] for r in rows if r['exit_code'] != 3) if any(r['exit_code'] != 3 for r in rows) else 3


def demo(a):
    """Serve fake sites on localhost, sweep them, and show the result. No traffic leaves this machine."""
    import http.server
    import threading
    banners = {'/shop': ('X-Powered-By', 'PHP/8.2.20'), '/blog': ('X-Powered-By', 'PHP/8.4.27'),
               '/wiki': ('Server', 'Apache/2.4.62 (Unix) PHP/7.4.33'), '/api': ('X-Powered-By', 'PHP/8.3.36'),
               '/forum': ('X-Powered-By', 'PHP/8.5.11'), '/static': ('Server', 'nginx')}

    class H(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            name, value = banners.get(self.path, ('Server', 'nginx'))
            self.send_header(name, value)
            self.end_headers()
        do_GET = do_HEAD

        def log_message(self, *args):
            pass

    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = 'http://127.0.0.1:%d' % srv.server_address[1]
    try:
        argv = [base + p for p in banners] + (['--svg', a.svg] if a.svg else []) + (['-o', a.output] if a.output else [])
        code = main(argv)
    finally:
        srv.shutdown()
    print('demo exit code would be %d (1 = at least one site needs patching)' % code)
    return 0


if __name__ == '__main__':
    sys.exit(main())
