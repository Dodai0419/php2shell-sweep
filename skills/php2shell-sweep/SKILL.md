---
name: php2shell-sweep
description: Check a list of websites for the PHP2Shell warning (CVE-2026-109618 / CVE-2026-109619) from their PHP headers, in parallel, without sending exploit probes. Use when the user asks "are my sites affected by php2shell", gives a list of domains to check, or wants a picture/JSON of the results.
---

# php2shell-sweep

Reads the `Server` and `X-Powered-By` headers of each site (HEAD, GET only if HEAD returns 405/501, no redirects) and compares the advertised PHP version with the fixed releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP 5.4-8.1 are always flagged.

## When to use
- The user owns or operates the sites and wants a quick patch-status sweep.
- Only check sites the user is responsible for. This tool never sends exploit payloads.

## Commands (run from the repo root)
```bash
python sweep.py https://example.com                 # one site
python sweep.py -l sites.txt -o results.json --svg results.svg   # many sites, JSON + picture
python sweep.py -l sites.txt --json                 # one JSON object per line
python sweep.py --demo                              # local fake sites, no network
```

## Reading the result
| Status | Exit code | Meaning |
|---|---|---|
| OK | 0 | Advertised version meets an upstream fixed release. Installed build not verified. |
| POTENTIALLY VULNERABLE | 1 | Advertised version is in an affected range. |
| UNKNOWN | 3 | No PHP header, unrecognized/prerelease version, or the request failed. |

The run exits with the worst status found (1 beats 0; 3 only when every site is unknown). Invalid arguments exit 2.

## Caveats to tell the user
- Headers cannot show distro backports (Debian/Ubuntu/RHEL). For servers you can log into, compare the package version with the vendor advisory instead.
- `UNKNOWN` is common when `expose_php = Off`; that is not proof of safety.
