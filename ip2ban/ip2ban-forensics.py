#!/usr/bin/env python3
"""
ip2ban-forensics v1.0: read-only behavioral analysis of Apache access logs with persistent alert deduplication.

This tool does not modify .htaccess or ban addresses. Crawler verification is
optional and may perform DNS lookups or fetch official crawler IP-range feeds.
It identifies indicators for human review; it cannot prove compromise.
"""
import argparse
import os
import collections
import datetime as dt
import ipaddress
import json
import multiprocessing
import shutil
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import unquote, urlsplit

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
    ('Bingbot', re.compile(r'bingbot', re.I)),
    ('DuckDuckBot', re.compile(r'duckduckbot', re.I)),
    ('YandexBot', re.compile(r'yandex(bot|images|video|media)', re.I)),
    ('Baiduspider', re.compile(r'baiduspider', re.I)),
    ('Applebot', re.compile(r'applebot(?!-extended)\b', re.I)),
    ('CCBot', re.compile(r'\bccbot\b', re.I)),
    ('GPTBot', re.compile(r'\bgptbot\b', re.I)),
    ('OAI-SearchBot', re.compile(r'\boai-searchbot\b', re.I)),
    ('ChatGPT-User', re.compile(r'\bchatgpt-user\b', re.I)),
    ('Claude-SearchBot', re.compile(r'\bclaude-searchbot\b', re.I)),
    ('Claude-User', re.compile(r'\bclaude-user\b', re.I)),
    ('ClaudeBot', re.compile(r'\bclaudebot\b', re.I)),
    ('Perplexity-User', re.compile(r'\bperplexity-user\b', re.I)),
    ('PerplexityBot', re.compile(r'\bperplexitybot\b', re.I)),
    ('AhrefsBot', re.compile(r'ahrefsbot', re.I)),
    ('AhrefsSiteAudit', re.compile(r'ahrefssiteaudit', re.I)),
    ('SemrushBot', re.compile(r'semrushbot|siteauditbot|splitsignalbot', re.I)),
    ('MJ12bot', re.compile(r'mj12bot', re.I)),
    ('PetalBot', re.compile(r'petalbot', re.I)),
    ('Bytespider', re.compile(r'bytespider', re.I)),
    ('Feedjack', re.compile(r'feedjack', re.I)),
    ('ibou-search', re.compile(r'ibou-search', re.I)),
    ('Amazonbot', re.compile(r'amazonbot', re.I)),
    ('Amzn-SearchBot', re.compile(r'amzn-searchbot', re.I)),
    ('Amzn-User', re.compile(r'amzn-user', re.I)),
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

    htaccess = None
    if data.get('htaccess'):
        htaccess = Path(data['htaccess']).expanduser()
        if not htaccess.is_absolute():
            htaccess = path.parent / htaccess

    return {
        'logs': logs,
        'htaccess': htaccess,
        'lookback_minutes': int(data.get('lookback_minutes', 60)),
        'mj12_ident': str(data.get('mj12_ident', '')).strip(),
    }


def load_whitelist(config):
    """Read ip2ban's whitelist, including commented entries, without modifying it."""
    path = config.get('htaccess')
    if path is None:
        return [], None
    if not path.is_file():
        raise FileNotFoundError(f'.htaccess not found for whitelist: {path}')

    lines = path.read_text(encoding='utf-8').splitlines()
    begin = [i for i, line in enumerate(lines) if 'BEGIN ip2ban-whitelist' in line]
    end = [i for i, line in enumerate(lines) if 'END ip2ban-whitelist' in line]
    if len(begin) != 1 or len(end) != 1 or begin[0] >= end[0]:
        raise ValueError(
            'Could not find exactly one valid BEGIN/END ip2ban-whitelist block in .htaccess'
        )

    networks = []
    for line in lines[begin[0] + 1:end[0]]:
        token_line = line.strip().lstrip('#').strip()
        if not token_line:
            continue
        token = token_line.split()[0]
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            print(f'Warning: invalid whitelist entry ignored: {token}', file=sys.stderr)
    return networks, str(path)


def is_whitelisted(address, networks):
    return any(address in network for network in networks)


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
    if status in ('401', '403') and WP_ADMIN_RE.search(path) and not WP_AUTH_RE.search(path):
        add_finding(findings, 'restricted_wordpress_endpoint', 'low', 'high',
                    'Access to a WordPress administrative/authentication endpoint was denied.', event)


def summarize_counter(counter):
    return {str(key): value for key, value in sorted(counter.items(), key=lambda x: str(x[0]))}


def load_ip2ban_support():
    """Load the adjacent ip2ban.py module so crawler rules stay in sync."""
    import importlib.util

    module_path = Path(__file__).with_name('ip2ban.py')
    if not module_path.is_file():
        raise FileNotFoundError(
            f'--verify-crawlers requires ip2ban.py beside this script: {module_path}'
        )
    spec = importlib.util.spec_from_file_location('ip2ban_forensics_ip2ban_support', module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f'Could not load crawler verification support from {module_path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    required = ('crawler_claim', 'verify_crawler_claim', 'crawler_range_networks')
    missing = [name for name in required if not hasattr(module, name)]
    if missing:
        raise ImportError(
            f'{module_path} lacks required v2.3 crawler functions/constants: {", ".join(missing)}'
        )
    return module


def _dns_verify_child(connection, ip, engine, user_agent, config):
    """Run a DNS-based check in an isolated process so a stuck resolver can be killed."""
    try:
        support = load_ip2ban_support()
        result = support.verify_crawler_claim(
            ip, engine, user_agent=user_agent, config=config, refresh=False, verbose=False
        )
        connection.send((result, None))
    except BaseException as exc:
        try:
            connection.send((None, f'{type(exc).__name__}: {exc}'))
        except Exception:
            pass
    finally:
        connection.close()


def bounded_dns_verify(ip, engine, user_agent, config, timeout=6.0):
    """Apply a hard wall-clock limit to FCrDNS checks (socket timeouts alone aren't reliable)."""
    try:
        context = multiprocessing.get_context('fork')
    except ValueError:
        return False, 'isolated DNS verification requires a fork-capable platform'
    parent_conn, child_conn = context.Pipe(duplex=False)
    process = context.Process(
        target=_dns_verify_child,
        args=(child_conn, ip, engine, user_agent, config),
        daemon=True,
    )
    process.start()
    child_conn.close()
    try:
        if parent_conn.poll(timeout):
            try:
                result, error = parent_conn.recv()
            except EOFError:
                return False, 'DNS verification worker exited without a result'
            process.join(0.5)
            if error:
                return False, error
            return result
        process.terminate()
        process.join(1.0)
        if process.is_alive() and hasattr(process, 'kill'):
            process.kill()
            process.join(1.0)
        return False, f'DNS verification timed out after {timeout:g}s'
    finally:
        parent_conn.close()
        if process.is_alive():
            process.terminate()
            process.join(0.5)


def verify_ip_crawler(ip, user_agents, support, cache_path, config, refresh=False, verbose=False):
    """Use ip2ban v2.3 verification, with bounded DNS and deduplicated engine checks."""
    claims = []
    checks = []
    local_claims = claimed_crawlers(user_agents)
    original_range_loader = support.crawler_range_networks

    def temporary_range_loader(engine, refresh=False, verbose=False):
        return original_range_loader(
            engine, cache_path=cache_path, refresh=refresh, verbose=verbose
        )

    support.crawler_range_networks = temporary_range_loader
    engine_claims = {}
    for user_agent, count in user_agents.items():
        engine = support.crawler_claim(user_agent)
        if engine:
            if engine not in engine_claims:
                engine_claims[engine] = [user_agent, 0]
            engine_claims[engine][1] += count

    try:
        for engine, (user_agent, count) in engine_claims.items():
            claims.append(engine)

            # Official-feed lookups already use urllib's explicit timeout. DNS
            # FCrDNS checks run in a killable child process: libc resolver calls
            # can outlive Python's socket default timeout on some hosts.
            if engine in getattr(support, 'CRAWLER_RANGE_FEEDS', {}):
                verified, evidence = support.verify_crawler_claim(
                    ip, engine, user_agent=user_agent, config=config,
                    refresh=refresh, verbose=verbose
                )
            else:
                domains = next((domains for name, _pattern, domains in support.CRAWLER_SIGNATURES
                                if name == engine), ())
                if engine == 'MJ12bot' or not domains:
                    verified, evidence = support.verify_crawler_claim(
                        ip, engine, user_agent=user_agent, config=config,
                        refresh=refresh, verbose=verbose
                    )
                else:
                    verified, evidence = bounded_dns_verify(
                        ip, engine, user_agent, config
                    )

            if verified is True:
                return {
                    'status': 'verified',
                    'crawler': engine,
                    'evidence': evidence,
                    'claim_count': count,
                }
            if verified is False and isinstance(evidence, str) and 'timed out after' in evidence:
                check_status = 'timeout'
            elif verified is False:
                check_status = 'not_verified'
            else:
                check_status = 'no_public_verification_method'
            checks.append({
                'crawler': engine,
                'status': check_status,
                'evidence': evidence,
                'claim_count': count,
            })
    finally:
        support.crawler_range_networks = original_range_loader

    all_claims = sorted(set(claims) | set(local_claims))
    return {
        'status': 'claimed_not_verified' if all_claims else 'no_crawler_claim',
        'claims': all_claims,
        'checks': checks,
    }


def analyze_logs(config, minutes, ip_filter=None, network_filter=None,
                 burst_threshold=60, login_threshold=8, verify_crawlers=False,
                 refresh_crawler_ranges=False, verbose=False, quiet=False):
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(minutes=minutes)
    selected_ip = ipaddress.ip_address(ip_filter) if ip_filter else None
    selected_network = ipaddress.ip_network(network_filter, strict=False) if network_filter else None
    whitelist, whitelist_source = load_whitelist(config)

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
                    'whitelisted': is_whitelisted(address, whitelist),
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
        if entry['whitelisted']:
            continue
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
            } for e in install_window]

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

    # Detect coordinated CMS installation-path probing across multiple IPs
    # within the same /24 (IPv4) or /64 (IPv6). Whitelisted traffic is excluded.
    subnet_probe_events = collections.defaultdict(list)
    for ip, entry in per_ip.items():
        if entry['whitelisted']:
            continue
        address = ipaddress.ip_address(ip)
        prefix = 24 if address.version == 4 else 64
        network = str(ipaddress.ip_network(f'{ip}/{prefix}', strict=False))
        for event in entry['events']:
            if event.get('install_path_probe'):
                subnet_probe_events[network].append(event)

    subnet_coordinated_findings = {}
    for network, events in subnet_probe_events.items():
        events.sort(key=lambda e: e['timestamp'])
        best_window = []
        left = 0
        for right, event in enumerate(events):
            while event['timestamp'] - events[left]['timestamp'] > dt.timedelta(minutes=10):
                left += 1
            candidate = events[left:right + 1]
            candidate_ips = {e['ip'] for e in candidate}
            candidate_paths = {
                normalize_target(e['target'])[0].rstrip('/') or '/'
                for e in candidate
            }
            best_score = (
                len({e['ip'] for e in best_window}),
                len({normalize_target(e['target'])[0].rstrip('/') or '/'
                     for e in best_window}),
                len(best_window),
            )
            score = (len(candidate_ips), len(candidate_paths), len(candidate))
            if score > best_score:
                best_window = candidate
        distinct_ips = {e['ip'] for e in best_window}
        distinct_paths = {
            normalize_target(e['target'])[0].rstrip('/') or '/'
            for e in best_window
        }
        if len(distinct_ips) >= 3 and len(distinct_paths) >= 5:
            subnet_coordinated_findings[network] = {
                'category': 'coordinated_cms_path_reconnaissance',
                'severity': 'medium',
                'confidence': 'medium',
                'description': (
                    f'{len(distinct_paths)} alternative CMS paths were probed by '
                    f'{len(distinct_ips)} IPs in this subnet within 10 minutes.'
                ),
                'distinct_ips': len(distinct_ips),
                'distinct_paths': len(distinct_paths),
                'evidence': [{
                    'ip': e['ip'],
                    'timestamp': e['timestamp'].isoformat(),
                    'method': e['method'],
                    'target': redact_target(e['target']),
                    'status': e['status'],
                    'user_agent': e['user_agent'][:240],
                } for e in best_window],
            }

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
            'whitelisted': entry['whitelisted'],
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

    if verify_crawlers:
        support = load_ip2ban_support()
        # Use the exact same crawler-name recognition as ip2ban v2.3.
        for item in ip_results:
            original_entry = per_ip[item['ip']]
            exact_claims = collections.Counter()
            for user_agent, count in original_entry['user_agents'].items():
                engine = support.crawler_claim(user_agent)
                if engine:
                    exact_claims[engine] += count
                else:
                    # Retain forensic-only labels such as ibou-search even when
                    # ip2ban v2.3 has no crawler-verification rule for them.
                    exact_claims.update({name: count for name in claimed_crawlers({user_agent: count})})
            item['crawler_claims'] = dict(exact_claims)
        # Work on a temporary copy of the crawler cache so this forensic tool
        # never changes the production cache or any other persistent file.
        with tempfile.TemporaryDirectory(prefix='ip2ban-forensics-') as temp_dir:
            temp_cache = Path(temp_dir) / 'ip2ban-crawler-ranges.json'
            existing_cache = Path(__file__).with_name('ip2ban-crawler-ranges.json')
            if existing_cache.is_file():
                shutil.copy2(existing_cache, temp_cache)
            candidates = [item for item in ip_results
                          if not item['whitelisted'] and item['crawler_claims']]
            total_candidates = len(candidates)
            if not quiet:
                print(f'Verifying crawler claims for {total_candidates} non-whitelisted IP(s)...',
                      file=sys.stderr, flush=True)
            for index, item in enumerate(candidates, 1):
                original_entry = per_ip[item['ip']]
                item['crawler_verification'] = verify_ip_crawler(
                    item['ip'], original_entry['user_agents'], support, temp_cache,
                    config, refresh=refresh_crawler_ranges, verbose=verbose
                )
                if not quiet:
                    print(f'\rCrawler verification: {index}/{total_candidates} IPs checked '
                          f'(latest: {item["ip"]}, {item["crawler_verification"]["status"]})',
                          end='', file=sys.stderr, flush=True)
            if total_candidates and not quiet:
                print(file=sys.stderr, flush=True)
            for item in ip_results:
                if item['whitelisted'] or not item['crawler_claims']:
                    item['crawler_verification'] = {
                        'status': 'not_checked' if item['crawler_claims'] else 'no_crawler_claim'
                    }
    else:
        for item in ip_results:
            item['crawler_verification'] = {
                'status': 'not_checked' if item['crawler_claims'] else 'no_crawler_claim'
            }

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
            'findings': ([subnet_coordinated_findings[network]]
                         if network in subnet_coordinated_findings else []),
        })
    network_results.sort(key=lambda item: (
        max([{'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(f['severity'], 0)
             for f in item.get('findings', [])] or [0]),
        sum(item['high_or_critical_indicators'].values()),
        len(item.get('findings', [])),
        item['requests'],
    ), reverse=True)
    subnet_findings = [finding for item in network_results for finding in item.get('findings', [])]

    return {
        'version': '1.0',
        'generated_at': now.isoformat(),
        'window_minutes': minutes,
        'window_start': cutoff.isoformat(),
        'window_end': now.isoformat(),
        'logs': [str(p) for p in config['logs']],
        'whitelist_source': whitelist_source,
        'whitelist_networks': [str(network) for network in whitelist],
        'crawler_verification_enabled': verify_crawlers,
        'input_lines': total_lines,
        'parsed_requests_in_window': parsed_lines,
        'malformed_lines': malformed_lines,
        'summary': {
            'unique_ips': len(per_ip),
            'whitelisted_ips': sum(1 for item in per_ip.values() if item['whitelisted']),
            'whitelisted_requests': sum(item['requests'] for item in per_ip.values()
                                        if item['whitelisted']),
            'ips_with_findings': sum(bool(item['findings']) for item in per_ip.values()),
            'subnets_with_findings': sum(1 for item in network_results if item.get('findings')),
            'subnet_findings': len(subnet_findings),
            'critical_findings': (
                sum(1 for item in ip_results for f in item['findings'] if f['severity'] == 'critical')
                + sum(1 for f in subnet_findings if f['severity'] == 'critical')
            ),
            'high_findings': (
                sum(1 for item in ip_results for f in item['findings'] if f['severity'] == 'high')
                + sum(1 for f in subnet_findings if f['severity'] == 'high')
            ),
            'medium_findings': (
                sum(1 for item in ip_results for f in item['findings'] if f['severity'] == 'medium')
                + sum(1 for f in subnet_findings if f['severity'] == 'medium')
            ),
        },
        'ips': ip_results,
        'whitelisted_traffic': [{
            'ip': item['ip'],
            'requests': item['requests'],
            'distinct_urls': item['distinct_urls'],
            'peak_requests_per_minute': item['peak_requests_per_minute'],
            'first_seen': item['first_seen'],
            'last_seen': item['last_seen'],
            'statuses': item['statuses'],
            'methods': item['methods'],
        } for item in ip_results if item['whitelisted']],
        'crawler_activity': [{
            'ip': item['ip'],
            'requests': item['requests'],
            'claims': item['crawler_claims'],
            'verification': item.get('crawler_verification', {}),
        } for item in ip_results if item['crawler_claims']],
        'networks': network_results,
    }


def finding_alert_key(subject_type, subject, finding):
    """Stable identity for a finding, independent of rolling-window counts/evidence."""
    return "|".join((
        subject_type,
        subject,
        str(finding.get('category', 'unknown')),
        str(finding.get('severity', 'unknown')),
    ))


def filter_previously_alerted_findings(report, state_path, cooldown_hours=24):
    """
    Return a report containing only findings not alerted within the cooldown.
    Persist emitted finding keys atomically. State is intentionally separate
    from the analysis/cache data and does not affect detection.
    """
    if cooldown_hours < 1:
        raise ValueError('--alert-cooldown-hours must be at least 1')

    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(hours=cooldown_hours)
    state_path = Path(state_path).expanduser()

    state = {'version': 1, 'alerts': {}}
    if state_path.exists():
        try:
            with state_path.open(encoding='utf-8') as stream:
                loaded = json.load(stream)
            if not isinstance(loaded, dict) or not isinstance(loaded.get('alerts'), dict):
                raise ValueError('alert state file has an unexpected structure')
            state = loaded
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f'Cannot read alert state file {state_path}: {exc}') from exc

    prior = state.get('alerts', {})
    # Discard malformed/expired records and retain recent alert timestamps.
    retained = {}
    for key, value in prior.items():
        if not isinstance(key, str) or not isinstance(value, dict):
            continue
        try:
            last_alerted = dt.datetime.fromisoformat(value['last_alerted'])
            if last_alerted.tzinfo is None:
                last_alerted = last_alerted.replace(tzinfo=dt.timezone.utc)
            if last_alerted >= cutoff:
                retained[key] = {'last_alerted': last_alerted.astimezone(dt.timezone.utc).isoformat()}
        except (KeyError, TypeError, ValueError):
            continue

    emitted = []
    filtered_ips = []
    for item in report.get('ips', []):
        if not item.get('findings'):
            continue
        kept = []
        for finding in item['findings']:
            key = finding_alert_key('ip', item['ip'], finding)
            record = retained.get(key)
            if record is None:
                kept.append(finding)
                emitted.append(key)
        if kept:
            filtered = dict(item)
            filtered['findings'] = kept
            filtered_ips.append(filtered)

    filtered_networks = []
    for item in report.get('networks', []):
        kept = []
        for finding in item.get('findings', []):
            key = finding_alert_key('network', item['network'], finding)
            if retained.get(key) is None:
                kept.append(finding)
                emitted.append(key)
        if kept:
            filtered = dict(item)
            filtered['findings'] = kept
            filtered_networks.append(filtered)

    for key in emitted:
        retained[key] = {'last_alerted': now.isoformat()}

    # Write only if there are newly emitted findings; no state churn on quiet runs.
    if emitted:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {'version': 1, 'alerts': retained}
        temp_path = state_path.with_name(state_path.name + f'.tmp.{os.getpid()}')
        try:
            with temp_path.open('w', encoding='utf-8') as stream:
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write('\n')
            os.replace(temp_path, state_path)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    filtered_report = dict(report)
    filtered_report['ips'] = filtered_ips
    filtered_report['networks'] = filtered_networks
    return filtered_report, len(emitted), len(prior)


def print_findings_only_report(report):
    """Print only actionable IP/subnet findings; print nothing when there are none."""
    ip_items = [item for item in report['ips'] if item['findings']]
    subnet_items = [
        item for item in report['networks']
        if any(finding.get('category') == 'coordinated_cms_path_reconnaissance'
               for finding in item.get('findings', []))
    ]
    if not ip_items and not subnet_items:
        return

    print(f"IP forensic findings v1.0 — last {report['window_minutes']} minutes")
    print("Read-only analysis. Findings are indicators for review, not proof of compromise.")

    for item in ip_items:
        scope = 'public' if item['is_global'] else 'non-global'
        print(f"\n{item['ip']} [{scope}] requests={item['requests']} "
              f"URLs={item['distinct_urls']} peak/min={item['peak_requests_per_minute']}")
        print(f"  Seen: {item['first_seen']} — {item['last_seen']}")
        for finding in item['findings']:
            print(f"  [{finding['severity'].upper()} / confidence {finding['confidence']}] "
                  f"{finding['category']} ({finding['count']}): {finding['description']}")
            outcomes = finding.get('outcomes', {})
            two_xx = outcomes.get('response_2xx_needs_context', 0) + outcomes.get(
                'potentially_successful', 0
            )
            if two_xx:
                print(f"    2xx responses requiring review: {two_xx} "
                      "(a 2xx response alone does not prove exposure or compromise)")
            if outcomes:
                print(f"    Outcome indicators: {outcomes}")
            for evidence in finding['evidence']:
                print(f"    {evidence['timestamp']} {evidence['method']} "
                      f"{evidence['target']} [{evidence['status']}]")

    for item in subnet_items:
        for finding in item.get('findings', []):
            print(f"\n[{finding['severity'].upper()} / confidence {finding['confidence']}] "
                  f"{item['network']} — {finding['category']}: {finding['description']}")
            for evidence in finding.get('evidence', []):
                print(f"    {evidence['timestamp']} {evidence['ip']} "
                      f"{evidence['method']} {evidence['target']} [{evidence['status']}]")


def print_text_report(report, top=30):
    summary = report['summary']
    print(f"\nIP forensic report v1.0 — last {report['window_minutes']} minutes")
    print(f"Requests analyzed: {report['parsed_requests_in_window']} | "
          f"Unique IPs: {summary['unique_ips']} | IPs with findings: {summary['ips_with_findings']}")
    print(f"Findings (IP + subnet): critical={summary['critical_findings']} "
          f"high={summary['high_findings']} medium={summary['medium_findings']}")
    if summary.get('subnets_with_findings'):
        print(f"Coordinated subnet findings: {summary['subnet_findings']} across "
              f"{summary['subnets_with_findings']} subnet(s)")
    print("Read-only analysis. Findings are indicators for review, not proof of compromise.")
    if report.get('whitelist_source'):
        print(f"Whitelist: loaded {len(report['whitelist_networks'])} network(s) from "
              f"{report['whitelist_source']}")
    else:
        print('Whitelist: not configured; no trusted IPs were excluded from findings.')
    if report.get('whitelisted_traffic'):
        print("\nWhitelisted traffic (statistics only; excluded from findings):")
        for item in report['whitelisted_traffic'][:10]:
            print(f"  {item['ip']} requests={item['requests']} URLs={item['distinct_urls']} "
                  f"peak/min={item['peak_requests_per_minute']} methods={item['methods']}")
    if report.get('crawler_activity'):
        print("\nCrawler User-Agent activity:")
        for item in report['crawler_activity'][:20]:
            verification = item['verification']
            if verification.get('status') == 'verified':
                identity = f"VERIFIED {verification['crawler']} ({verification['evidence']})"
            elif verification.get('status') == 'claimed_not_verified':
                identity = f"CLAIM NOT VERIFIED: {verification.get('claims', [])}"
            elif any(check.get('status') == 'timeout'
                     for check in verification.get('checks', [])):
                identity = f"CLAIMED; verification timed out: {item['claims']}"
            elif verification.get('status') == 'not_checked':
                identity = f"claim(s), verification not run: {item['claims']}"
            else:
                identity = f"claim(s), not verified: {item['claims']}"
            print(f"  {item['ip']} requests={item['requests']} — {identity}")
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
            verification = item.get('crawler_verification', {})
            if verification.get('status') == 'verified':
                print(f"  Crawler VERIFIED: {verification['crawler']} "
                      f"({verification['evidence']})")
            elif verification.get('status') == 'claimed_not_verified':
                print(f"  Crawler claims NOT verified: {verification.get('claims', [])}")
            elif any(check.get('status') == 'timeout'
                     for check in verification.get('checks', [])):
                print(f"  Crawler verification timed out: {item['crawler_claims']}")
            elif verification.get('status') == 'not_checked':
                print(f"  User-Agent crawler claims (not checked): {item['crawler_claims']}")
            else:
                print(f"  User-Agent crawler claims (not verified): {item['crawler_claims']}")
        for finding in item['findings']:
            print(f"  [{finding['severity'].upper()} / confidence {finding['confidence']}] "
                  f"{finding['category']} ({finding['count']}): {finding['description']}")
            print(f"    Outcome indicators: {finding['outcomes']}")
            evidence_items = finding['evidence']
            if finding['category'] not in (
                'cms_installation_reconnaissance',
                'repeated_authentication_posts',
                'http_error_path_sweep',
            ):
                evidence_items = evidence_items[:3]
            for evidence in evidence_items:
                print(f"    {evidence['timestamp']} {evidence['method']} "
                      f"{evidence['target']} [{evidence['status']}]")
    if report['networks']:
        print("\nSubnet activity (aggregated request volume; not proof of common control):")
        for item in report['networks'][:min(top, 15)]:
            print(f"  {item['network']} requests={item['requests']} "
                  f"IPs={item['distinct_ips']} high/critical={item['high_or_critical_indicators']}")
            for finding in item.get('findings', []):
                print(f"    [{finding['severity'].upper()} / confidence {finding['confidence']}] "
                      f"{finding['category']}: {finding['description']}")
                for evidence in finding['evidence']:
                    print(f"      {evidence['timestamp']} {evidence['ip']} "
                          f"{evidence['method']} {evidence['target']} [{evidence['status']}]")
    if not summary['ips_with_findings'] and not summary.get('subnet_findings'):
        print("\nNo configured IP-level or subnet-level forensic indicators were detected in this time window.")


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
    parser.add_argument('--verify-crawlers', action='store_true',
                        help='Verify crawler claims using bounded DNS checks and official IP ranges; may use the network')
    parser.add_argument('--refresh-crawler-ranges', action='store_true',
                        help='Refresh official crawler ranges during verification (requires --verify-crawlers)')
    parser.add_argument('--verbose', action='store_true',
                        help='Show crawler verification warnings and diagnostic details')
    parser.add_argument('--findings-only', action='store_true',
                        help='Print only IP/subnet findings; print nothing when there are none')
    parser.add_argument('--deduplicate-alerts', action='store_true',
                        help='With --findings-only, suppress findings already emailed within the cooldown')
    parser.add_argument('--alert-state', type=Path,
                        default=Path(__file__).with_name('ip2ban-forensics-alerts.json'),
                        help='Persistent alert state file (default: beside this script)')
    parser.add_argument('--alert-cooldown-hours', type=int, default=24,
                        help='Re-alert for the same IP/finding after this many hours (default: 24)')
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
        if args.refresh_crawler_ranges and not args.verify_crawlers:
            raise ValueError('--refresh-crawler-ranges requires --verify-crawlers')
        if args.findings_only and args.json:
            raise ValueError('--findings-only cannot be combined with --json')
        if args.deduplicate_alerts and not args.findings_only:
            raise ValueError('--deduplicate-alerts requires --findings-only')
        if args.alert_cooldown_hours < 1:
            raise ValueError('--alert-cooldown-hours must be at least 1')
        report = analyze_logs(
            config, minutes, ip_filter=args.ip, network_filter=args.network,
            burst_threshold=args.burst_threshold, login_threshold=args.login_threshold,
            verify_crawlers=args.verify_crawlers,
            refresh_crawler_ranges=args.refresh_crawler_ranges,
            verbose=args.verbose and not args.findings_only,
            quiet=args.findings_only
        )
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        elif args.findings_only:
            if args.deduplicate_alerts:
                report, new_count, _ = filter_previously_alerted_findings(
                    report, args.alert_state, args.alert_cooldown_hours
                )
            print_findings_only_report(report)
        else:
            print_text_report(report, args.top)
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
