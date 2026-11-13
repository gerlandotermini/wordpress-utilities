#!/usr/bin/env python3
"""
ip2ban-forensics v1.0: read-only behavioral analysis of Apache access logs.

This tool does not modify .htaccess, ban addresses, or make external API calls.
It identifies indicators for human review; it cannot prove compromise.
"""
import argparse
import collections
import datetime as dt
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qsl, unquote, urlsplit

LOG_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^]]+)\] '
    r'"((?:\\.|[^"\\])*)" (\d{3}|-) (\S+)'
    r'(?: "((?:\\.|[^"\\])*)" "((?:\\.|[^"\\])*)")?'
)

SECRET_PARAM_RE = re.compile(
    r'(?i)([?&](?:password|passwd|pass|pwd|token|access_token|refresh_token|'
    r'api[_-]?key|secret|nonce|authorization|auth|session|sessionid|code)=)[^&#\s]*'
)

SENSITIVE_FILE_RE = re.compile(
    r'(?i)(?:^|/)(?:'
    r'\.env(?:\.[^/?]*)?|'
    r'wp-config\.php(?:\.(?:bak|old|save|swp|orig|txt|zip|sql|dist))?|'
    r'\.git(?:/|$)|\.svn(?:/|$)|'
    r'id_rsa|id_ed25519|authorized_keys|'
    r'\.htpasswd|web\.config|'
    r'composer\.(?:json|lock)|package\.json|'
    r'phpinfo\.php|'
    r'(?:backup|dump|database|db|site|www|public_html)\.(?:zip|tar|tgz|gz|sql|7z|rar)'
    r')(?:$|[/?])'
)
TRAVERSAL_RE = re.compile(r'(?:\.\./|%2e%2e(?:/|%2f)|%252e%252e)', re.I)
SQLI_RE = re.compile(
    r'(?i)(?:'
    r'union(?:\s|%20|\+)+(?:all(?:\s|%20|\+)+)?select\b|'
    r'(?:select|insert|update|delete|drop|alter)\s+.{0,40}\s+from\b|'
    r'\b(?:sleep|benchmark)\s*\(|'
    r'\b(or|and)\s+[\w\'"]+\s*=\s*[\w\'"]+|'
    r' information_schema|'
    r'%27\s*(?:or|and)\b|'
    r';\s*(?:select|drop|insert|update)\b'
    r')'
)
COMMAND_INJECTION_RE = re.compile(
    r'(?i)(?:;\s*(?:cat|id|whoami|uname|curl|wget|bash|sh)\b|'
    r'\$\((?:[^)]{1,100})\)|`[^`]{1,100}`|'
    r'\|\s*(?:bash|sh|nc|curl|wget)\b|'
    r'/bin/(?:sh|bash)\b)'
)
XSS_RE = re.compile(
    r'(?i)(?:<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|'
    r'<\s*svg\b[^>]*onload|%3cscript)'
)
WP_AUTH_RE = re.compile(r'(?i)^/(?:wp-login\.php|xmlrpc\.php)(?:/|$)')
WP_USER_ENUM_RE = re.compile(r'(?i)(?:[?&]author=\d+|/wp-json/wp/v2/users(?:/|$))')
WP_ADMIN_RE = re.compile(r'(?i)^/wp-admin(?:/|$)')
SCANNER_PATH_RE = re.compile(
    r'(?i)^/(?:'
    r'phpmyadmin|pma|adminer(?:\.php)?|mysql|myadmin|'
    r'vendor/phpunit|cgi-bin|\.aws|actuator|'
    r'boaform|HNAP1|autodiscover|server-status|'
    r'wp-content/plugins/(?:wp-file-manager|revslider|revslider-old|'
    r'file-manager|duplicator|simple-file-list|'
    r'contact-form-7|woocommerce)/[^/]+\.php'
    r')(?:/|$)'
)

CRAWLER_CLAIMS = [
    ('Googlebot', re.compile(r'googlebot|google-inspectiontool', re.I)),
    ('Bingbot', re.compile(r'\bbingbot\b', re.I)),
    ('DuckDuckBot', re.compile(r'duckduckbot', re.I)),
    ('YandexBot', re.compile(r'yandex(bot|images|video|media)', re.I)),
    ('Baiduspider', re.compile(r'baiduspider', re.I)),
    ('Applebot', re.compile(r'applebot', re.I)),
    ('CCBot', re.compile(r'\bccbot\b', re.I)),
    ('GPTBot', re.compile(r'\bgptbot\b', re.I)),
    ('OAI-SearchBot', re.compile(r'\boai-searchbot\b', re.I)),
    ('ChatGPT-User', re.compile(r'\bchatgpt-user\b', re.I)),
    ('ClaudeBot', re.compile(r'\bclaudebot\b', re.I)),
    ('Claude-SearchBot', re.compile(r'\bclaude-searchbot\b', re.I)),
    ('PerplexityBot', re.compile(r'\bperplexitybot\b', re.I)),
    ('AhrefsBot', re.compile(r'ahrefsbot|ahrefssiteaudit', re.I)),
    ('SemrushBot', re.compile(r'semrushbot|siteauditbot', re.I)),
    ('MJ12bot', re.compile(r'mj12bot', re.I)),
    ('Bytespider', re.compile(r'bytespider', re.I)),
    ('PetalBot', re.compile(r'petalbot', re.I)),
    ('Amazonbot', re.compile(r'amazonbot|amzn-searchbot|amzn-user', re.I)),
    ('Feedjack', re.compile(r'feedjack', re.I)),
    ('ibou-search', re.compile(r'ibou-search', re.I)),
]


def claimed_crawlers(user_agents):
    """Return UA-declared crawler names; this is identification, not verification."""
    claims = collections.Counter()
    for user_agent, count in user_agents.items():
        for name, pattern in CRAWLER_CLAIMS:
            if pattern.search(user_agent):
                claims[name] += count
                break
    return dict(claims)

INSTALL_PATHS = {
    '/old', '/backup', '/wp', '/wp/', '/blog', '/new', '/wordpress',
    '/wordpress-2-9-beta-1', '/test', '/site', '/cms', '/portal',
    '/wp2', '/blog2', '/backup_old', '/oldsite',
}
SUSPICIOUS_METHODS = {'TRACE', 'CONNECT', 'TRACK'}
POTENTIALLY_MUTATING_METHODS = {'PUT', 'DELETE', 'PATCH'}


def load_config(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if 'logs' not in data or not isinstance(data['logs'], list) or not data['logs']:
        raise ValueError('Configuration must contain a non-empty "logs" list')
    logs = []
    for value in data['logs']:
        item = Path(value).expanduser()
        if not item.is_absolute():
            item = path.parent / item
        logs.append(item)
    return {'logs': logs, 'lookback_minutes': int(data.get('lookback_minutes', 60))}


def parse_timestamp(raw):
    return dt.datetime.strptime(raw, '%d/%b/%Y:%H:%M:%S %z').astimezone(dt.timezone.utc)


def redact_target(target):
    return SECRET_PARAM_RE.sub(r'\1[REDACTED]', target)


def normalize_target(target):
    # Decode for detection, but preserve the original URL in evidence.
    decoded = unquote(target)
    try:
        parts = urlsplit(decoded)
        path = parts.path or '/'
        query = parts.query
    except ValueError:
        path, query = decoded.split('?', 1)[0], ''
    return path, query, decoded


def event_outcome(status, sensitive=False):
    if status == '-':
        return 'unknown'
    try:
        code = int(status)
    except ValueError:
        return 'unknown'
    if 200 <= code < 300:
        return 'potentially_successful' if sensitive else 'response_2xx_needs_context'
    if 300 <= code < 400:
        return 'redirected'
    if code in (401, 403, 404, 405, 410, 429):
        return 'blocked_or_not_found'
    if code >= 500:
        return 'server_error'
    return 'inconclusive'


def add_finding(findings, category, severity, confidence, description, event,
                outcome=None):
    key = (category, severity, confidence, description)
    if key not in findings:
        findings[key] = {
            'category': category,
            'severity': severity,
            'confidence': confidence,
            'description': description,
            'count': 0,
            'outcomes': collections.Counter(),
            'evidence': [],
        }
    item = findings[key]
    item['count'] += 1
    item['outcomes'][outcome or event['outcome']] += 1
    if len(item['evidence']) < 8:
        item['evidence'].append({
            'timestamp': event['timestamp'].isoformat(),
            'method': event['method'],
            'target': redact_target(event['target']),
            'status': event['status'],
            'bytes': event['bytes'],
            'user_agent': event['user_agent'][:240],
            'referer': redact_target(event['referer'])[:500],
        })


def classify_event(event, findings):
    target = event['target']
    method = event['method']
    path, query, decoded = normalize_target(target)
    searchable = decoded.lower()
    status = event['status']

    if SENSITIVE_FILE_RE.search(path):
        add_finding(findings, 'sensitive_file_probe', 'high', 'high',
                    'Request for a commonly sensitive file or backup artifact.', event,
                    event_outcome(status, sensitive=True))
    if TRAVERSAL_RE.search(searchable):
        add_finding(findings, 'path_traversal', 'high', 'high',
                    'Path-traversal syntax detected in the request target.', event)
    if SQLI_RE.search(searchable):
        add_finding(findings, 'sql_injection', 'high', 'medium',
                    'SQL-injection-like syntax detected in the request target.', event)
    if COMMAND_INJECTION_RE.search(searchable):
        add_finding(findings, 'command_injection', 'critical', 'medium',
                    'Command-execution-like syntax detected in the request target.', event)
    if XSS_RE.search(searchable):
        add_finding(findings, 'cross_site_scripting', 'medium', 'medium',
                    'Script or event-handler injection syntax detected in the request target.', event)

    if WP_USER_ENUM_RE.search(decoded):
        add_finding(findings, 'wordpress_user_enumeration', 'medium', 'high',
                    'WordPress author or REST users enumeration pattern.', event)
    if SCANNER_PATH_RE.search(path):
        add_finding(findings, 'software_or_endpoint_probe', 'medium', 'medium',
                    'Request targets a commonly probed administrative, diagnostic, or software path.', event)
    if WP_AUTH_RE.search(path):
        severity = 'medium' if method == 'POST' else 'low'
        add_finding(findings, 'wordpress_auth_endpoint', severity, 'high',
                    'Request to WordPress login or XML-RPC endpoint; repeated POSTs are assessed separately.', event)
    if method in SUSPICIOUS_METHODS:
        add_finding(findings, 'unusual_http_method', 'high', 'high',
                    f'Unusual HTTP method {method} was used.', event)
    elif method in POTENTIALLY_MUTATING_METHODS:
        add_finding(findings, 'potentially_mutating_method', 'medium', 'high',
                    f'{method} can modify server-side resources; verify whether this is expected.', event)

    if path.rstrip('/') in {p.rstrip('/') for p in INSTALL_PATHS}:
        # This is accumulated into a sequence finding below, not scored alone.
        event['install_path_probe'] = True
    if status in ('401', '403') and (WP_ADMIN_RE.search(path) or WP_AUTH_RE.search(path)):
        add_finding(findings, 'restricted_wordpress_endpoint', 'low', 'high',
                    'Access to a WordPress administrative/authentication endpoint was denied.', event)


def summarize_counter(counter):
    return {str(key): value for key, value in sorted(counter.items(), key=lambda x: str(x[0]))}


def analyze_logs(config, minutes, ip_filter=None, network_filter=None,
                 burst_threshold=60, login_threshold=8):
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(minutes=minutes)
    selected_ip = ipaddress.ip_address(ip_filter) if ip_filter else None
    selected_network = ipaddress.ip_network(network_filter, strict=False) if network_filter else None

    per_ip = {}
    total_lines = 0
    parsed_lines = 0
    malformed_lines = 0
    for logfile in config['logs']:
        if not logfile.is_file():
            raise FileNotFoundError(f'Apache log not found: {logfile}')
        with logfile.open(encoding='utf-8', errors='replace') as stream:
            for line in stream:
                total_lines += 1
                match = LOG_RE.match(line)
                if not match:
                    malformed_lines += 1
                    continue
                raw_ip, raw_time, request, status, byte_count, referer, user_agent = match.groups()
                try:
                    address = ipaddress.ip_address(raw_ip)
                    timestamp = parse_timestamp(raw_time)
                except ValueError:
                    continue
                if not cutoff <= timestamp <= now:
                    continue
                if selected_ip and address != selected_ip:
                    continue
                if selected_network and address not in selected_network:
                    continue

                parts = request.split(' ', 2)
                method = parts[0].upper() if parts else '?'
                target = parts[1] if len(parts) > 1 else ''
                try:
                    size = int(byte_count) if byte_count.isdigit() else None
                except ValueError:
                    size = None
                try:
                    code = int(status)
                except ValueError:
                    code = None
                event = {
                    'ip': str(address),
                    'timestamp': timestamp,
                    'method': method,
                    'target': target,
                    'status': status,
                    'bytes': size,
                    'referer': referer or '',
                    'user_agent': user_agent or '',
                    'log_file': str(logfile),
                    'outcome': event_outcome(status),
                }
                entry = per_ip.setdefault(str(address), {
                    'ip': str(address),
                    'is_global': address.is_global,
                    'requests': 0,
                    'statuses': collections.Counter(),
                    'methods': collections.Counter(),
                    'user_agents': collections.Counter(),
                    'urls': collections.Counter(),
                    'minutes': collections.Counter(),
                    'events': [],
                    'findings': {},
                    'first_seen': timestamp,
                    'last_seen': timestamp,
                })
                entry['requests'] += 1
                entry['statuses'][status] += 1
                entry['methods'][method] += 1
                entry['user_agents'][user_agent or '(not logged)'] += 1
                entry['urls'][target] += 1
                entry['minutes'][timestamp.strftime('%Y-%m-%d %H:%M')] += 1
                entry['events'].append(event)
                entry['first_seen'] = min(entry['first_seen'], timestamp)
                entry['last_seen'] = max(entry['last_seen'], timestamp)
                parsed_lines += 1

    # Classify events and then assess sequences that require more than one request.
    for entry in per_ip.values():
        entry['events'].sort(key=lambda e: e['timestamp'])
        findings = entry['findings']
        for event in entry['events']:
            classify_event(event, findings)

        install_events = [e for e in entry['events'] if e.get('install_path_probe')]
        install_window = []
        left = 0
        for right, event in enumerate(install_events):
            while event['timestamp'] - install_events[left]['timestamp'] > dt.timedelta(minutes=10):
                left += 1
            candidate = install_events[left:right + 1]
            distinct_install_paths = {normalize_target(e['target'])[0].rstrip('/') for e in candidate}
            if len(distinct_install_paths) > len({normalize_target(e['target'])[0].rstrip('/') for e in install_window}):
                install_window = candidate
        install_path_count = len({normalize_target(e['target'])[0].rstrip('/') for e in install_window})
        if install_path_count >= 5:
            add_finding(findings, 'cms_installation_reconnaissance', 'medium', 'high',
                        f'{install_path_count} alternative CMS installation paths were probed within 10 minutes.',
                        install_window[0], 'sequence_detected')
            key = next(k for k in findings if k[0] == 'cms_installation_reconnaissance')
            findings[key]['count'] = install_path_count
            findings[key]['evidence'] = [{
                'timestamp': e['timestamp'].isoformat(),
                'method': e['method'],
                'target': redact_target(e['target']),
                'status': e['status'],
                'bytes': e['bytes'],
                'user_agent': e['user_agent'][:240],
                'referer': redact_target(e['referer'])[:500],
            } for e in install_window[:8]]

        login_events = [
            e for e in entry['events']
            if e['method'] == 'POST' and WP_AUTH_RE.search(normalize_target(e['target'])[0])
        ]
        login_window = []
        left = 0
        for right, event in enumerate(login_events):
            while event['timestamp'] - login_events[left]['timestamp'] > dt.timedelta(minutes=10):
                left += 1
            candidate = login_events[left:right + 1]
            if len(candidate) > len(login_window):
                login_window = candidate
        if len(login_window) >= login_threshold:
            add_finding(findings, 'repeated_authentication_posts', 'high', 'high',
                        f'{len(login_window)} POST requests to wp-login.php or xmlrpc.php within 10 minutes.',
                        login_window[0], 'repeated_attempts')
            key = next(k for k in findings if k[0] == 'repeated_authentication_posts')
            findings[key]['count'] = len(login_window)
            findings[key]['evidence'] = [{
                'timestamp': e['timestamp'].isoformat(),
                'method': e['method'],
                'target': redact_target(e['target']),
                'status': e['status'],
                'bytes': e['bytes'],
                'user_agent': e['user_agent'][:240],
                'referer': redact_target(e['referer'])[:500],
            } for e in login_window[:8]]

        peak = max(entry['minutes'].values(), default=0)
        if peak >= burst_threshold:
            minute, count = max(entry['minutes'].items(), key=lambda x: x[1])
            synthetic = next(e for e in entry['events']
                             if e['timestamp'].strftime('%Y-%m-%d %H:%M') == minute)
            add_finding(findings, 'high_request_burst', 'high', 'high',
                        f'{count} requests from this IP in one minute (configured threshold: {burst_threshold}).',
                        synthetic, 'rate_threshold_exceeded')

        # Count 4xx/5xx against unique URL diversity to identify broad path scanning.
        error_events = [e for e in entry['events'] if e['status'].startswith(('4', '5'))]
        error_paths = {normalize_target(e['target'])[0] for e in error_events}
        if len(error_paths) >= 12 and len(error_paths) / max(1, len(entry['events'])) >= 0.5:
            add_finding(findings, 'http_error_path_sweep', 'medium', 'medium',
                        f'{len(error_paths)} distinct paths returned 4xx/5xx, consistent with broad path probing.',
                        error_events[0], 'multiple_failed_paths')
            key = next(k for k in findings if k[0] == 'http_error_path_sweep')
            findings[key]['count'] = len(error_events)

    # Aggregate subnet activity without assuming every IP in a subnet has the same operator.
    subnet_map = collections.defaultdict(lambda: {'requests': 0, 'ips': set(), 'findings': collections.Counter()})
    for ip, entry in per_ip.items():
        address = ipaddress.ip_address(ip)
        prefix = 24 if address.version == 4 else 64
        network = str(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))
        item = subnet_map[network]
        item['requests'] += entry['requests']
        item['ips'].add(ip)
        for finding in entry['findings'].values():
            if finding['severity'] in ('high', 'critical'):
                item['findings'][finding['category']] += finding['count']

    ip_results = []
    for ip, entry in per_ip.items():
        findings = sorted(
            entry['findings'].values(),
            key=lambda f: (
                {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(f['severity'], 0),
                f['count']
            ),
            reverse=True
        )
        ip_results.append({
            'ip': ip,
            'is_global': entry['is_global'],
            'requests': entry['requests'],
            'first_seen': entry['first_seen'].isoformat(),
            'last_seen': entry['last_seen'].isoformat(),
            'statuses': summarize_counter(entry['statuses']),
            'methods': summarize_counter(entry['methods']),
            'user_agents': entry['user_agents'].most_common(5),
            'crawler_claims': claimed_crawlers(entry['user_agents']),
            'distinct_urls': len(entry['urls']),
            'peak_requests_per_minute': max(entry['minutes'].values(), default=0),
            'findings': [{
                **{k: v for k, v in finding.items() if k not in ('outcomes',)},
                'outcomes': summarize_counter(finding['outcomes'])
            } for finding in findings],
        })
    ip_results.sort(key=lambda item: (
        max([{'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(f['severity'], 0)
             for f in item['findings']] or [0]),
        sum(f['count'] for f in item['findings']),
        item['requests']
    ), reverse=True)

    network_results = []
    for network, item in subnet_map.items():
        if item['requests'] < 2:
            continue
        network_results.append({
            'network': network,
            'requests': item['requests'],
            'distinct_ips': len(item['ips']),
            'ips': sorted(item['ips']),
            'high_or_critical_indicators': dict(item['findings']),
        })
    network_results.sort(key=lambda item: (sum(item['high_or_critical_indicators'].values()),
                                           item['requests']), reverse=True)

    return {
        'generated_at': now.isoformat(),
        'window_minutes': minutes,
        'window_start': cutoff.isoformat(),
        'window_end': now.isoformat(),
        'logs': [str(p) for p in config['logs']],
        'input_lines': total_lines,
        'parsed_requests_in_window': parsed_lines,
        'malformed_lines': malformed_lines,
        'summary': {
            'unique_ips': len(per_ip),
            'ips_with_findings': sum(bool(item['findings']) for item in per_ip.values()),
            'critical_findings': sum(1 for item in ip_results for f in item['findings'] if f['severity'] == 'critical'),
            'high_findings': sum(1 for item in ip_results for f in item['findings'] if f['severity'] == 'high'),
            'medium_findings': sum(1 for item in ip_results for f in item['findings'] if f['severity'] == 'medium'),
        },
        'ips': ip_results,
        'networks': network_results,
    }


def print_text_report(report, top=30):
    summary = report['summary']
    print(f"\nIP forensic report — last {report['window_minutes']} minutes")
    print(f"Requests analyzed: {report['parsed_requests_in_window']} | "
          f"Unique IPs: {summary['unique_ips']} | IPs with findings: {summary['ips_with_findings']}")
    print(f"Findings: critical={summary['critical_findings']} high={summary['high_findings']} "
          f"medium={summary['medium_findings']}")
    print("Read-only analysis. Findings are indicators for review, not proof of compromise.")
    print(f"\nTop {min(top, len(report['ips']))} IP(s), ranked by forensic indicators:")
    for item in report['ips'][:top]:
        if not item['findings']:
            continue
        scope = 'public' if item['is_global'] else 'non-global'
        print(f"\n{item['ip']} [{scope}] requests={item['requests']} "
              f"URLs={item['distinct_urls']} peak/min={item['peak_requests_per_minute']}")
        print(f"  Seen: {item['first_seen']} — {item['last_seen']}")
        print(f"  Statuses: {item['statuses']}")
        print(f"  Methods: {item['methods']}")
        if item['crawler_claims']:
            print(f"  User-Agent crawler claims (NOT verified): {item['crawler_claims']}")
        for finding in item['findings']:
            print(f"  [{finding['severity'].upper()} / confidence {finding['confidence']}] "
                  f"{finding['category']} ({finding['count']}): {finding['description']}")
            print(f"    Outcome indicators: {finding['outcomes']}")
            for evidence in finding['evidence'][:3]:
                print(f"    {evidence['timestamp']} {evidence['method']} "
                      f"{evidence['target']} [{evidence['status']}]")
    if report['networks']:
        print("\nSubnet activity (aggregated request volume; not proof of common control):")
        for item in report['networks'][:min(top, 15)]:
            print(f"  {item['network']} requests={item['requests']} "
                  f"IPs={item['distinct_ips']} high/critical={item['high_or_critical_indicators']}")
    if not summary['ips_with_findings']:
        print("\nNo configured forensic indicators were detected in this time window.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).with_name('config.json'),
                        help='ip2ban JSON configuration (default: config.json beside this script)')
    window = parser.add_mutually_exclusive_group()
    window.add_argument('--minutes', type=int, help='Analysis window in minutes (default: config lookback_minutes)')
    window.add_argument('--hours', type=float, help='Analysis window in hours')
    parser.add_argument('--ip', help='Limit analysis to one IP address')
    parser.add_argument('--network', help='Limit analysis to an IP network, e.g. 188.241.38.0/24')
    parser.add_argument('--top', type=int, default=30, help='Maximum IPs and subnet groups to display (default: 30)')
    parser.add_argument('--burst-threshold', type=int, default=60,
                        help='Flag an IP reaching this many requests in one minute (default: 60)')
    parser.add_argument('--login-threshold', type=int, default=8,
                        help='Flag repeated POSTs to wp-login.php/xmlrpc.php (default: 8)')
    parser.add_argument('--json', action='store_true', help='Write machine-readable JSON to stdout instead of text')
    args = parser.parse_args()

    try:
        config_path = args.config.expanduser().resolve()
        config = load_config(config_path)
        if args.minutes is not None:
            minutes = args.minutes
        elif args.hours is not None:
            minutes = int(args.hours * 60)
        else:
            minutes = config['lookback_minutes']
        if minutes < 1:
            raise ValueError('Analysis window must be at least one minute')
        if args.top < 1 or args.burst_threshold < 1 or args.login_threshold < 1:
            raise ValueError('--top and thresholds must be positive')
        report = analyze_logs(
            config, minutes, ip_filter=args.ip, network_filter=args.network,
            burst_threshold=args.burst_threshold, login_threshold=args.login_threshold
        )
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print_text_report(report, args.top)
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
