#!/usr/bin/env python3
"""ip2ban v2.0: Apache access-log analysis and managed .htaccess bans."""
import argparse
import collections
import datetime as dt
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

BEGIN_BANS = 'BEGIN ip2ban-bans'
END_BANS = 'END ip2ban-bans'
BEGIN_WHITE = 'BEGIN ip2ban-whitelist'
END_WHITE = 'END ip2ban-whitelist'
# Supports Common Log Format and Combined Log Format. The final two quoted
# fields in Combined format are the referrer and User-Agent.
LOG_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^]]+)\] '
    r'"((?:\\.|[^"\\])*)" (\d{3}|-) (\S+)'
    r'(?: "((?:\\.|[^"\\])*)" "((?:\\.|[^"\\])*)")?'
)
BAN_DATE_RE = re.compile(r'^# (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)')
DENY_RE = re.compile(r'^\s*Deny\s+from\s+(\S+)\s*$', re.I)


def block_bounds(lines, begin, end):
    starts = [i for i, line in enumerate(lines) if begin in line]
    ends = [i for i, line in enumerate(lines) if end in line]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError(f'Expected exactly one ordered {begin} / {end} block')
    return starts[0], ends[0]


def load_config(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    required = ['htaccess', 'logs', 'keywords_file']
    for key in required:
        if key not in data:
            raise ValueError(f'Missing configuration key: {key}')
    for key in ('htaccess', 'keywords_file'):
        p = Path(data[key]).expanduser()
        data[key] = p if p.is_absolute() else path.parent / p
    data['logs'] = [Path(x).expanduser() if Path(x).expanduser().is_absolute() else path.parent / x for x in data['logs']]
    for key, default in [('threshold_errors', 30), ('threshold_keywords', 5), ('threshold_dos', 10000), ('lookback_minutes', 60), ('retention_days', 45), ('log_extract_lines', 20)]:
        data[key] = int(data.get(key, default))
        if data[key] < 1:
            raise ValueError(f'{key} must be positive')
    data['mj12_ident'] = str(data.get('mj12_ident', '')).strip()
    return data


def public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip if ip.is_global else None
    except ValueError:
        return None


def read_whitelist(lines):
    a, b = block_bounds(lines, BEGIN_WHITE, END_WHITE)
    networks = []
    for line in lines[a + 1:b]:
        line = line.strip().lstrip('#').strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            print(f'Warning: invalid whitelist entry: {token}', file=sys.stderr)
    return networks


def read_keywords(path):
    if not path.is_file():
        raise FileNotFoundError(f'Keyword file not found: {path}')
    patterns = []
    for n, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        item = line.strip()
        if item and not item.startswith('#'):
            try:
                patterns.append(re.compile(item, re.I))
            except re.error as exc:
                raise ValueError(f'Invalid keyword regex on line {n}: {exc}') from exc
    return patterns


def analyze(config, patterns, verbose=False):
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(minutes=config['lookback_minutes'])
    stats = collections.defaultdict(lambda: {
        'errors': 0,
        'keywords': 0,
        'requests': 0,
        'samples': collections.deque(maxlen=config['log_extract_lines']),
        'statuses': collections.Counter(),
        'methods': collections.Counter(),
        'urls': collections.Counter(),
        'user_agents': collections.Counter(),
        'minutes': collections.Counter(),
        'log_files': set(),
    })
    processed = 0
    for logfile in config['logs']:
        if not logfile.is_file():
            raise FileNotFoundError(f'Apache log not found: {logfile}')
        with logfile.open(encoding='utf-8', errors='replace') as stream:
            for line in stream:
                match = LOG_RE.match(line)
                if not match:
                    continue
                raw_ip, raw_time, request, status, _bytes, _referer, user_agent = match.groups()
                ip = public_ip(raw_ip)
                if ip is None:
                    continue
                try:
                    timestamp = dt.datetime.strptime(
                        raw_time, '%d/%b/%Y:%H:%M:%S %z'
                    ).astimezone(dt.timezone.utc)
                except ValueError:
                    continue
                if not cutoff <= timestamp <= now:
                    continue

                processed += 1
                parts = request.split(' ', 2)
                method = parts[0] if parts else '?'
                target = parts[1] if len(parts) > 1 else ''
                entry = stats[str(ip)]
                entry['log_files'].add(str(logfile))
                entry['requests'] += 1
                entry['methods'][method] += 1
                entry['urls'][target] += 1
                entry['user_agents'][user_agent or '(not logged)'] += 1
                entry['minutes'][timestamp.strftime('%Y-%m-%d %H:%M')] += 1
                entry['samples'].append(f'{method} {target} [{status}]')
                if status.startswith(('4', '5')):
                    entry['errors'] += 1
                    entry['statuses'][status] += 1
                if any(pattern.search(target) for pattern in patterns):
                    entry['keywords'] += 1

    candidates = {}
    for ip, item in stats.items():
        reasons = []
        if item['errors'] >= config['threshold_errors']:
            reasons.append(f'HTTP 4xx/5xx errors: {item["errors"]}')
        if item['keywords'] >= config['threshold_keywords']:
            reasons.append(f'Keyword abuse: {item["keywords"]}')
        if item['requests'] >= config['threshold_dos']:
            reasons.append(f'Request volume: {item["requests"]}')
        if reasons:
            candidates[ip] = (', '.join(reasons), list(item['samples']))
    if verbose:
        print(f'Analyzed {processed} recent requests across {len(config["logs"])} log(s); {len(candidates)} candidate IP(s)')
    return stats, candidates

# Each entry contains a display name, a User-Agent signature, and the DNS
# suffixes that can be used for forward-confirmed reverse-DNS verification.
# An empty suffix tuple means DNS verification is unavailable; some of these
# crawlers instead use an operator-published IP-range feed or site-specific ident.
# Recognition alone never grants an exemption from bans.
CRAWLER_SIGNATURES = [
    # Search engines with documented forward-confirmed reverse-DNS checks.
    ('Googlebot', re.compile(r'googlebot|google-inspectiontool', re.I),
     ('googlebot.com', 'google.com')),
    ('Bingbot', re.compile(r'bingbot', re.I), ('search.msn.com',)),
    ('DuckDuckBot', re.compile(r'duckduckbot', re.I), ('duckduckgo.com',)),
    ('YandexBot', re.compile(r'yandex(bot|images|video|media)', re.I),
     ('yandex.ru', 'yandex.net')),
    ('Baiduspider', re.compile(r'baiduspider', re.I), ('baidu.com', 'baidu.jp')),
    ('Applebot', re.compile(r'applebot(?!-extended)\b', re.I),
     ('applebot.apple.com',)),
    ('CCBot', re.compile(r'\bccbot\b', re.I), ('crawl.commoncrawl.org',)),
    # AI crawlers verified against their operators' published IP-range feeds.
    ('GPTBot', re.compile(r'\bgptbot\b', re.I), ()),
    ('OAI-SearchBot', re.compile(r'\boai-searchbot\b', re.I), ()),
    ('ChatGPT-User', re.compile(r'\bchatgpt-user\b', re.I), ()),
    ('Claude-SearchBot', re.compile(r'\bclaude-searchbot\b', re.I), ()),
    ('Claude-User', re.compile(r'\bclaude-user\b', re.I), ()),
    ('ClaudeBot', re.compile(r'\bclaudebot\b', re.I), ()),
    ('Perplexity-User', re.compile(r'\bperplexity-user\b', re.I), ()),
    ('PerplexityBot', re.compile(r'\bperplexitybot\b', re.I), ()),
    # SEO crawlers: Ahrefs supports DNS and a published IP list. Semrush and
    # Majestic require special handling; a User-Agent claim alone is not proof.
    ('AhrefsBot', re.compile(r'ahrefsbot', re.I), ('ahrefs.com', 'ahrefs.net')),
    ('AhrefsSiteAudit', re.compile(r'ahrefssiteaudit', re.I),
     ('ahrefs.com', 'ahrefs.net')),
    ('SemrushBot', re.compile(r'semrushbot|siteauditbot|splitsignalbot', re.I), ()),
    ('MJ12bot', re.compile(r'mj12bot', re.I), ()),
    ('PetalBot', re.compile(r'petalbot', re.I), ()),
    ('Bytespider', re.compile(r'bytespider', re.I), ()),
    ('Feedjack', re.compile(r'feedjack', re.I), ()),
    ('Amazonbot', re.compile(r'amazonbot', re.I), ()),
    ('Amzn-SearchBot', re.compile(r'amzn-searchbot', re.I), ()),
    ('Amzn-User', re.compile(r'amzn-user', re.I), ()),
]

# Official machine-readable crawler ranges. The cache is refreshed every 12h;
# on a temporary fetch failure, a previously cached list remains usable for up
# to 7 days. A missing/stale feed never turns an unverified UA into an exemption.
CRAWLER_RANGE_FEEDS = {
    'GPTBot': ['https://openai.com/gptbot.json'],
    'OAI-SearchBot': ['https://openai.com/searchbot.json'],
    'ChatGPT-User': ['https://openai.com/chatgpt-user.json'],
    'ClaudeBot': ['https://claude.com/crawling/bots.json'],
    'Claude-SearchBot': ['https://claude.com/crawling/bots.json'],
    'Claude-User': ['https://claude.com/crawling/bots.json'],
    'PerplexityBot': ['https://www.perplexity.ai/perplexitybot.json'],
    'Perplexity-User': ['https://www.perplexity.ai/perplexity-user.json'],
    'AhrefsBot': ['https://api.ahrefs.com/v3/public/crawler-ip-ranges'],
    'AhrefsSiteAudit': ['https://api.ahrefs.com/v3/public/crawler-ip-ranges'],
}
CRAWLER_RANGE_RUNTIME_CACHE = {}
CRAWLER_RANGE_CACHE_TTL = 12 * 60 * 60
CRAWLER_RANGE_STALE_TTL = 7 * 24 * 60 * 60


def crawler_claim(user_agent):
    """Return the first recognized crawler/client name in a User-Agent."""
    for name, signature, _domains in CRAWLER_SIGNATURES:
        if signature.search(user_agent):
            return name
    return None


def crawler_range_networks(engine, cache_path=None, refresh=False, verbose=False):
    """Return parsed official IP ranges for an engine, using a persistent cache."""
    urls = CRAWLER_RANGE_FEEDS.get(engine, [])
    if not urls:
        return []
    cache_path = cache_path or Path(__file__).with_name('ip2ban-crawler-ranges.json')
    cache = load_ip_lookup_cache(cache_path)
    now = time.time()
    networks = []
    changed = False
    for url in urls:
        if url in CRAWLER_RANGE_RUNTIME_CACHE:
            networks.extend(CRAWLER_RANGE_RUNTIME_CACHE[url])
            continue
        entry = cache.get(url, {})
        if not isinstance(entry, dict):
            entry = {}
        age = now - entry.get('cached_at', 0)
        cached_prefixes = entry.get('prefixes', [])
        if not refresh and cached_prefixes and age < CRAWLER_RANGE_CACHE_TTL:
            prefixes = cached_prefixes
        else:
            try:
                payload = http_json(url)
                raw_prefixes = []
                for item in payload.get('prefixes', []):
                    if not isinstance(item, dict):
                        continue
                    prefix = item.get('ipv4Prefix') or item.get('ipv6Prefix')
                    if prefix:
                        raw_prefixes.append(prefix)
                # Some vendor feeds may publish individual IPs instead.
                for item in payload.get('ips', []):
                    if isinstance(item, dict) and item.get('ip_address'):
                        raw_prefixes.append(item['ip_address'])
                parsed = []
                for prefix in raw_prefixes:
                    try:
                        parsed.append(str(ipaddress.ip_network(prefix, strict=False)))
                    except ValueError:
                        try:
                            parsed.append(str(ipaddress.ip_network(prefix + ('/32' if ':' not in prefix else '/128'), strict=False)))
                        except ValueError:
                            continue
                if not parsed:
                    raise ValueError('feed contained no valid IP prefixes')
                prefixes = parsed
                cache[url] = {'cached_at': now, 'prefixes': prefixes}
                changed = True
            except Exception as exc:
                if cached_prefixes and age < CRAWLER_RANGE_STALE_TTL:
                    prefixes = cached_prefixes
                    if verbose:
                        print(f'Warning: crawler range refresh failed for {engine}; using cached feed: {exc}', file=sys.stderr)
                else:
                    prefixes = []
                    if verbose:
                        print(f'Warning: crawler range lookup failed for {engine}: {exc}', file=sys.stderr)
        parsed_networks = []
        for prefix in prefixes:
            try:
                parsed_networks.append(ipaddress.ip_network(prefix, strict=False))
            except ValueError:
                continue
        CRAWLER_RANGE_RUNTIME_CACHE[url] = parsed_networks
        networks.extend(parsed_networks)
    if changed:
        try:
            temp = cache_path.with_name(cache_path.name + '.tmp')
            temp.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding='utf-8')
            os.replace(temp, cache_path)
        except OSError as exc:
            if verbose:
                print(f'Warning: could not save crawler range cache: {exc}', file=sys.stderr)
    return networks


def verify_crawler_claim(ip, engine, user_agent='', config=None, refresh=False, verbose=False):
    """Return (verified, evidence); None means no published verification method."""
    # Majestic's distributed MJ12bot has no fixed ranges or public DNS proof.
    # It can only be exempted when the site-specific CRAWLER-IDENT is configured
    # and included in the logged User-Agent string.
    if engine == 'MJ12bot':
        ident = (config or {}).get('mj12_ident', '')
        return (True, 'Majestic site ident') if ident and ident in user_agent else (None, None)

    # A User-Agent claim is never enough. Match against the operator's own
    # published IP ranges when available.
    if engine in CRAWLER_RANGE_FEEDS:
        networks = crawler_range_networks(engine, refresh=refresh, verbose=verbose)
        address = ipaddress.ip_address(ip)
        if any(address in network for network in networks):
            return True, 'official IP range'
        return False, 'outside published IP ranges'

    domains = next((domains for name, _pattern, domains in CRAWLER_SIGNATURES
                    if name == engine), None)
    if domains is None or not domains:
        return None, None

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(2.0)
    try:
        hostname = socket.gethostbyaddr(ip)[0].rstrip('.').lower()
        valid_suffix = any(
            hostname == domain or hostname.endswith('.' + domain)
            for domain in domains
        )
        if not valid_suffix:
            return False, hostname
        resolved = {
            item[4][0] for item in socket.getaddrinfo(
                hostname, None, family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM
            )
        }
        resolved_ips = {str(ipaddress.ip_address(value)) for value in resolved}
        return str(ipaddress.ip_address(ip)) in resolved_ips, hostname
    except (OSError, socket.herror, socket.gaierror, TimeoutError, ValueError):
        return False, None
    finally:
        socket.setdefaulttimeout(old_timeout)


def verified_crawler_for_ip(ip, item, config=None, refresh=False, verbose=False):
    """Return the verified crawler name/evidence for this IP, if any."""
    for user_agent, _count in item.get('user_agents', {}).items():
        engine = crawler_claim(user_agent)
        if not engine:
            continue
        verified, evidence = verify_crawler_claim(
            ip, engine, user_agent=user_agent, config=config,
            refresh=refresh, verbose=verbose
        )
        if verified:
            return engine, evidence
    return None, None



IP_LOOKUP_CACHE_TTL = 30 * 24 * 60 * 60
IP_LOOKUP_FAILURE_TTL = 6 * 60 * 60
IP_LOOKUP_TIMEOUT = 4
ASN_HOLDER_CACHE_TTL = 30 * 24 * 60 * 60
ASN_HOLDER_FAILURE_TTL = 6 * 60 * 60


def http_json(url):
    """Fetch a JSON API response with a short timeout and a descriptive UA."""
    request = Request(
        url,
        headers={
            'Accept': 'application/rdap+json, application/json',
            'User-Agent': 'ip2ban/2.0 (Apache access-log reporting)',
        },
    )
    with urlopen(request, timeout=IP_LOOKUP_TIMEOUT) as response:
        return json.loads(response.read(2 * 1024 * 1024).decode('utf-8', errors='replace'))


def rdap_entity_name(entity):
    """Extract a human-readable organization/contact name from an RDAP vCard."""
    vcard = entity.get('vcardArray')
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    values = {}
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4:
            key = str(item[0]).lower()
            value = item[3]
            if key in ('fn', 'org') and value:
                if isinstance(value, list):
                    value = ' '.join(str(part) for part in value if part)
                values.setdefault(key, str(value).strip())
    return values.get('org') or values.get('fn')


def fetch_ip_details(ip):
    """Combine PTR, RDAP registration, and RIPEstat routing/ASN information."""
    details = {
        'hostname': reverse_dns(ip),
        'network': None,
        'prefix': None,
        'country': None,
        'organization': None,
        'asns': [],
        'asn_holders': [],
    }

    # RDAP provides the registered network and its registration contacts.
    try:
        rdap = http_json('https://rdap.org/ip/' + quote(ip, safe=':'))
        details['network'] = rdap.get('name') or rdap.get('handle')
        details['country'] = rdap.get('country')
        start = rdap.get('startAddress')
        end = rdap.get('endAddress')
        if start and end:
            details['prefix'] = f'{start} - {end}'
        entities = rdap.get('entities', [])
        preferred = ('registrant', 'administrative', 'technical')
        entities = sorted(
            (entity for entity in entities if isinstance(entity, dict)),
            key=lambda entity: min(
                (preferred.index(role) for role in entity.get('roles', []) if role in preferred),
                default=len(preferred),
            ),
        )
        for entity in entities:
            if any(role in preferred for role in entity.get('roles', [])):
                name = rdap_entity_name(entity)
                if name:
                    details['organization'] = name
                    break
        if not details['organization']:
            details['organization'] = details['network']
    except (OSError, ValueError, KeyError, TypeError, HTTPError, URLError):
        pass

    # RIPEstat supplies the currently announced prefix and origin ASN(s).
    try:
        query = urlencode({'resource': ip, 'sourceapp': 'ip2ban'})
        network_info = http_json('https://stat.ripe.net/data/network-info/data.json?' + query)
        payload = network_info.get('data', {}) if network_info.get('status') == 'ok' else {}
        details['prefix'] = details['prefix'] or payload.get('prefix')
        details['asns'] = [str(value) for value in payload.get('asns', [])[:3]]
    except (OSError, ValueError, KeyError, TypeError, HTTPError, URLError):
        pass

    # ASN holder names are resolved separately and cached by ASN, not by IP.
    # This avoids repeating the same RIPEstat request for many IPs on one ISP.
    return details


def fetch_asn_holder(asn):
    """Fetch the organization name for one ASN."""
    query = urlencode({'resource': 'AS' + str(asn), 'sourceapp': 'ip2ban'})
    overview = http_json('https://stat.ripe.net/data/as-overview/data.json?' + query)
    payload = overview.get('data', {}) if overview.get('status') == 'ok' else {}
    holder = payload.get('holder')
    return str(holder) if holder else None


def lookup_asn_holders(asns, cache_path, refresh=False, verbose=False):
    """Resolve each distinct ASN once, with a persistent ASN-keyed cache."""
    cache = load_ip_lookup_cache(cache_path)
    now = time.time()
    results = {}
    pending = []
    for asn in sorted({str(value) for value in asns if str(value).isdigit()}):
        entry = cache.get(asn, {})
        if not isinstance(entry, dict):
            entry = {}
        age = now - entry.get('cached_at', 0)
        ttl = ASN_HOLDER_CACHE_TTL if entry.get('ok') else ASN_HOLDER_FAILURE_TTL
        if not refresh and age < ttl and 'holder' in entry:
            results[asn] = entry.get('holder')
        else:
            pending.append(asn)

    if pending:
        if verbose:
            print(f'ASN organization lookup: querying {len(pending)} distinct ASN(s); cache file: {cache_path}')
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {asn: executor.submit(fetch_asn_holder, asn) for asn in pending}
            for asn, future in futures.items():
                try:
                    holder = future.result()
                except Exception as exc:
                    holder = None
                    if verbose:
                        print(f'Warning: ASN lookup failed for AS{asn}: {exc}', file=sys.stderr)
                results[asn] = holder
                cache[asn] = {'cached_at': now, 'ok': bool(holder), 'holder': holder}
        try:
            temp = cache_path.with_name(cache_path.name + '.tmp')
            temp.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding='utf-8')
            os.replace(temp, cache_path)
        except OSError as exc:
            if verbose:
                print(f'Warning: could not save ASN lookup cache: {exc}', file=sys.stderr)
    return results


def load_ip_lookup_cache(path):
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def lookup_report_ips(ips, cache_path, refresh=False, verbose=False):
    """Look up displayed IPs concurrently and persist results between cron runs."""
    cache = load_ip_lookup_cache(cache_path)
    now = time.time()
    results = {}
    pending = []
    for ip in ips:
        entry = cache.get(ip, {})
        if not isinstance(entry, dict):
            entry = {}
        age = now - entry.get('cached_at', 0)
        ttl = IP_LOOKUP_CACHE_TTL if entry.get('ok') else IP_LOOKUP_FAILURE_TTL
        if not refresh and age < ttl and isinstance(entry.get('details'), dict):
            results[ip] = entry['details']
        else:
            pending.append(ip)

    if pending:
        if verbose:
            print(f'IP ownership lookup: querying {len(pending)} IP(s); cache file: {cache_path}')
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {ip: executor.submit(fetch_ip_details, ip) for ip in pending}
            for ip, future in futures.items():
                try:
                    details = future.result()
                    ok = any(details.get(key) for key in ('hostname', 'organization', 'asns', 'prefix'))
                except Exception as exc:
                    details = {}
                    ok = False
                    if verbose:
                        print(f'Warning: IP lookup failed for {ip}: {exc}', file=sys.stderr)
                results[ip] = details
                cache[ip] = {'cached_at': now, 'ok': ok, 'details': details}
        try:
            temp = cache_path.with_name(cache_path.name + '.tmp')
            temp.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding='utf-8')
            os.replace(temp, cache_path)
        except OSError as exc:
            if verbose:
                print(f'Warning: could not save IP lookup cache: {exc}', file=sys.stderr)

    # Merge ASN-holder data from a separate cache keyed by ASN. This means
    # 20 IPs from the same provider require only one holder lookup, ever per TTL.
    all_asns = [asn for details in results.values() for asn in details.get('asns', [])[:3]]
    asn_cache_path = cache_path.with_name('ip2ban-asn-cache.json')
    holders = lookup_asn_holders(all_asns, asn_cache_path, refresh, verbose)
    for details in results.values():
        details['asn_holders'] = [holders.get(str(asn)) for asn in details.get('asns', [])[:3]]
    return results


def print_ip_details(ip, details):
    """Print compact ownership/routing details beneath an IP report entry."""
    if not details:
        print('  Network lookup: unavailable')
        return
    print(f"  Hostname: {details.get('hostname') or 'not available'}")
    asns = details.get('asns') or []
    holders = details.get('asn_holders') or []
    if asns:
        asn_text = ', '.join(
            'AS' + asn + (f' ({holders[index]})' if index < len(holders) else '')
            for index, asn in enumerate(asns)
        )
        print(f'  Origin ASN: {asn_text}')
    if details.get('organization'):
        print(f"  Registered organization: {details['organization']}")
    if details.get('network'):
        print(f"  Registered network: {details['network']}")
    if details.get('prefix'):
        print(f"  Network prefix/range: {details['prefix']}")
    if details.get('country'):
        print(f"  Registry country: {details['country']}")
    if not any(details.get(key) for key in ('hostname', 'asns', 'organization', 'network', 'prefix', 'country')):
        print('  Network lookup: no public registration/routing details found')

def print_report(config, stats, candidates, limit=20, verify_crawlers=False, ip_lookup=True, refresh_ip_lookup=False, verbose=False, refresh_crawler_ranges=False):
    """Print a read-only traffic report with rates, URLs, methods and User-Agents."""
    ht_lines = config['htaccess'].read_text(encoding='utf-8').splitlines()
    whitelist = read_whitelist(ht_lines)
    a, b = block_bounds(ht_lines, BEGIN_BANS, END_BANS)
    existing = set()
    for line in ht_lines[a + 1:b]:
        match = DENY_RE.match(line)
        if match:
            try:
                existing.add(str(ipaddress.ip_address(match.group(1))))
            except ValueError:
                pass

    ranked = sorted(
        stats.items(),
        key=lambda pair: (
            pair[1]['requests'], pair[1]['errors'], pair[1]['keywords']
        ),
        reverse=True
    )
    print(f"\nIP activity report — last {config['lookback_minutes']} minutes")
    print(f"Unique public IPs: {len(stats)} | IPs meeting thresholds before crawler exemptions: {len(candidates)}")
    print(
        f"Thresholds: errors >= {config['threshold_errors']}, "
        f"keywords >= {config['threshold_keywords']}, "
        f"requests >= {config['threshold_dos']}"
    )
    if verify_crawlers:
        print("Crawler verification: forward-confirmed reverse DNS or official IP ranges where supported")
    if not ranked:
        print('No public-IP requests found in the selected time window.')
        return

    shown = ranked[:limit]
    lookup_details = {}
    if ip_lookup and shown:
        cache_path = Path(__file__).with_name('ip2ban-lookup-cache.json')
        lookup_details = lookup_report_ips([ip for ip, _item in shown], cache_path, refresh_ip_lookup, verbose)
    print(f"\nTop {len(shown)} IP(s), ranked by request volume:")
    for ip, item in shown:
        address = ipaddress.ip_address(ip)
        flags = []
        if any(address in net for net in whitelist):
            flags.append('WHITELISTED')
        if ip in existing:
            flags.append('ALREADY BANNED')
        reasons = candidates.get(ip, (None, []))[0]
        verified_crawler = None
        if verify_crawlers and reasons:
            verified_crawler = verified_crawler_for_ip(
                ip, item, config=config, refresh=refresh_crawler_ranges, verbose=verbose
            )
        if verified_crawler and verified_crawler[0]:
            flags.append(f'VERIFIED CRAWLER: {verified_crawler[0]} — BAN EXEMPT')
            reasons = None
        elif reasons:
            flags.append('THRESHOLD HIT')

        status_counts = ', '.join(
            f"{code}:{count}" for code, count in sorted(item['statuses'].items())
        ) or 'none'
        method_counts = ', '.join(
            f"{method}:{count}" for method, count in item['methods'].most_common()
        ) or 'none'
        distinct_urls = len(item['urls'])
        repeated_urls = item['urls'].most_common(3)
        peak_minute = max(item['minutes'].values(), default=0)
        avg_per_minute = item['requests'] / max(1, config['lookback_minutes'])
        error_pct = 100 * item['errors'] / item['requests'] if item['requests'] else 0

        print(
            f"\n{ip}  requests={item['requests']}  errors={item['errors']} "
            f"({error_pct:.1f}%)  keyword_hits={item['keywords']}"
        )
        if ip_lookup:
            print_ip_details(ip, lookup_details.get(ip, {}))
        print(f"  HTTP statuses: {status_counts}")
        print(f"  Methods: {method_counts}")
        print(
            f"  URL diversity: {distinct_urls} distinct URL(s); "
            f"repeated requests: {item['requests'] - distinct_urls}"
        )
        print(
            f"  Request rate: avg {avg_per_minute:.2f}/min over window; "
            f"peak {peak_minute}/min"
        )
        if repeated_urls:
            print("  Most-requested URLs:")
            for url, count in repeated_urls:
                print(f"    {count}x {url or '(empty URL)'}")

        print("  User-Agent(s):")
        for user_agent, count in item['user_agents'].most_common(3):
            clipped = user_agent if len(user_agent) <= 200 else user_agent[:197] + '...'
            engine = crawler_claim(user_agent)
            suffix = ''
            if engine:
                if verify_crawlers:
                    verified, evidence = verify_crawler_claim(ip, engine, user_agent=user_agent, config=config, refresh=refresh_crawler_ranges, verbose=verbose)
                    if verified:
                        suffix = f' — {engine}, VERIFIED ({evidence})'
                    elif verified is None:
                        suffix = f' — claims {engine}; no published verification method'
                    elif evidence:
                        suffix = f' — claims {engine}, NOT VERIFIED ({evidence})'
                    else:
                        suffix = f' — claims {engine}, DNS NOT VERIFIED'
                else:
                    suffix = f' — claims {engine}; unverified'
            print(f"    {count}x {clipped}{suffix}")

        print(f"  Assessment: {', '.join(flags) if flags else 'below thresholds'}")
        if reasons:
            print(f"  Ban reasons: {reasons}")
        print('  Recent request samples:')
        for sample in item['samples']:
            print(f"    {sample}")

    if len(ranked) > limit:
        print(f"\nShowing {limit} of {len(ranked)} IPs. Use --top {len(ranked)} to show all.")


def retain_bans(lines, retention_days):
    """Keep undated/manual entries and valid dated pairs; expire old dated pairs."""
    cutoff = dt.datetime.now().astimezone() - dt.timedelta(days=retention_days)
    output = []
    i = 0
    while i < len(lines):
        match = BAN_DATE_RE.match(lines[i])
        if match and i + 1 < len(lines) and DENY_RE.match(lines[i + 1]):
            try:
                timestamp = dt.datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S').replace(tzinfo=dt.datetime.now().astimezone().tzinfo)
                keep = timestamp >= cutoff
            except ValueError:
                keep = True
            if keep:
                output.extend(lines[i:i + 2])
            i += 2
        else:
            output.append(lines[i])
            i += 1
    return output


def reverse_dns(ip):
    """Return a reverse-DNS hostname when available, without hanging cron."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(2.0)
    try:
        return socket.gethostbyaddr(ip)[0].rstrip('.')
    except (OSError, socket.herror, socket.gaierror, TimeoutError):
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def print_ban_notification(ip, reason, item, log_files, timestamp):
    """Write a detailed new-ban notice to stdout for cron mail delivery."""
    hostname = reverse_dns(ip)
    print('\n' + '=' * 72)
    print(f'ip2ban: NEW IP BAN — {ip}')
    print(f'Time: {timestamp}')
    print(f'IP address: {ip}')
    print(f'Reverse DNS: {hostname or "(not available)"}')
    print(f'Reason: {reason}')
    print(
        f'Requests: {item["requests"]} | HTTP errors: {item["errors"]} | '
        f'Keyword matches: {item["keywords"]}'
    )

    status_counts = ', '.join(
        f'{code}: {count}' for code, count in sorted(item['statuses'].items())
    ) or 'none'
    print(f'HTTP status codes: {status_counts}')

    print('User-Agent(s):')
    for user_agent, count in item['user_agents'].most_common(5):
        engine = crawler_claim(user_agent)
        label = f' [claims {engine}]' if engine else ''
        print(f'  {count}x {user_agent}{label}')

    print('Access log source(s):')
    for logfile in sorted(log_files):
        print(f'  {logfile}')

    print('Recent request samples:')
    if item['samples']:
        for sample in item['samples']:
            print(f'  {sample}')
    else:
        print('  (no request samples available)')
    print('=' * 72)


def remove_verified_crawler_bans(lines, verified_ips):
    """Remove only dated ip2ban-managed bans for crawler IPs now verified."""
    if not verified_ips:
        return lines, 0
    output = []
    removed = 0
    i = 0
    while i < len(lines):
        dated = BAN_DATE_RE.match(lines[i])
        deny = DENY_RE.match(lines[i + 1]) if i + 1 < len(lines) else None
        if dated and deny:
            try:
                banned_ip = str(ipaddress.ip_address(deny.group(1)))
            except ValueError:
                banned_ip = None
            if banned_ip in verified_ips:
                removed += 1
                i += 2
                continue
        output.append(lines[i])
        i += 1
    return output, removed


def update(config, candidates, stats, dry_run=False, verbose=False, refresh_crawler_ranges=False):
    path = config['htaccess']
    if not path.is_file():
        raise FileNotFoundError(f'.htaccess not found: {path}')
    lockpath = path.with_name(path.name + '.ip2ban.lock')
    # Lock a separate stable file, never the atomically replaced target.
    with lockpath.open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        original = path.read_bytes()
        content = original.decode('utf-8')
        lines = content.splitlines(keepends=True)
        a, b = block_bounds(lines, BEGIN_BANS, END_BANS)
        whitelist = read_whitelist(lines)
        retained = retain_bans(lines[a + 1:b], config['retention_days'])
        existing = set()
        for line in retained:
            match = DENY_RE.match(line)
            if match:
                try:
                    existing.add(str(ipaddress.ip_address(match.group(1))))
                except ValueError:
                    pass
        additions = []
        new_bans = []
        verified_exempt_ips = set()
        verified_exempt_details = {}

        # If a previously auto-banned IP is still active and now verifies as a
        # crawler, remove its dated managed ban as well as exempting new bans.
        for ip in sorted(existing.intersection(stats)):
            crawler, evidence = verified_crawler_for_ip(
                ip, stats.get(ip, {}), config=config,
                refresh=refresh_crawler_ranges, verbose=verbose
            )
            if crawler:
                verified_exempt_ips.add(ip)
                verified_exempt_details[ip] = (crawler, evidence)
                if verbose:
                    print(f'VERIFIED CRAWLER UNBAN {ip}: {crawler} ({evidence})')

        for ip, (reason, _samples) in sorted(candidates.items()):
            crawler, evidence = verified_exempt_details.get(ip, (None, None))
            if not crawler:
                crawler, evidence = verified_crawler_for_ip(
                    ip, stats.get(ip, {}), config=config,
                    refresh=refresh_crawler_ranges, verbose=verbose
                )
            if crawler:
                verified_exempt_ips.add(ip)
                if verbose:
                    print(f'VERIFIED CRAWLER EXEMPT {ip}: {crawler} ({evidence})')
                continue
            address = ipaddress.ip_address(ip)
            if any(address in net for net in whitelist):
                if verbose:
                    print(f'WHITELISTED {ip}: {reason}')
                continue
            if ip in existing:
                if verbose:
                    print(f'ALREADY BANNED {ip}: {reason}')
                continue
            stamp = dt.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')
            additions.extend([f'# {stamp} - {reason}\n', f'Deny from {ip}\n'])
            new_bans.append((ip, reason, stamp))
            if dry_run:
                print(f'WOULD BAN {ip}: {reason}')
                if verbose:
                    for sample in stats.get(ip, {}).get('samples', []):
                        print(f'  {sample}')

        retained, removed_verified_bans = remove_verified_crawler_bans(retained, verified_exempt_ips)
        if removed_verified_bans and verbose:
            print(f'Removed {removed_verified_bans} dated ip2ban ban(s) for verified crawlers')

        # Ensure lines inserted after the marker are separated from it.
        newline = '\r\n' if b'\r\n' in original else '\n'
        additions = [line.replace('\n', newline) for line in additions]
        revised = ''.join(lines[:a + 1] + additions + retained + lines[b:]).encode('utf-8')
        if dry_run:
            if revised != original:
                print('DRY RUN: .htaccess would change; no files modified')
            return
        if revised == original:
            if verbose:
                print('No .htaccess changes required')
            return
        stat = path.stat()
        fd, tempname = tempfile.mkstemp(prefix='.ip2ban-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(revised)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), stat.st_mode & 0o7777)
                os.fchown(stream.fileno(), stat.st_uid, stat.st_gid)
            os.replace(tempname, path)
        finally:
            if os.path.exists(tempname):
                os.unlink(tempname)

        # Notify only after .htaccess has been successfully replaced. Cron can
        # email this stdout; no separate mail configuration is needed here.
        for ip, reason, stamp in new_bans:
            print_ban_notification(ip, reason, stats[ip], stats[ip]['log_files'], stamp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).with_name('config.json'))
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--check', action='store_true', help='Validate configuration, log files and .htaccess markers')
    parser.add_argument('--report', action='store_true', help='Show per-IP activity, including IPs below ban thresholds; never modify .htaccess')
    parser.add_argument('--top', type=int, default=20, help='Maximum IPs to show with --report (default: 20)')
    parser.add_argument('--verify-crawlers', action='store_true', help='Verify crawler claims using official IP ranges or forward-confirmed reverse DNS')
    parser.add_argument('--no-ip-lookup', action='store_true', help='Skip PTR, RDAP and ASN enrichment in --report')
    parser.add_argument('--refresh-ip-lookup', action='store_true', help='Refresh cached PTR, RDAP and ASN details during --report')
    parser.add_argument('--refresh-crawler-ranges', action='store_true', help='Refresh official crawler IP-range feeds during verification')
    args = parser.parse_args()
    try:
        config = load_config(args.config.resolve())
        patterns = read_keywords(config['keywords_file'])
        if not config['htaccess'].is_file():
            raise FileNotFoundError(config['htaccess'])
        lines = config['htaccess'].read_text(encoding='utf-8').splitlines(keepends=True)
        block_bounds(lines, BEGIN_BANS, END_BANS)
        read_whitelist(lines)
        for path in config['logs']:
            if not path.is_file():
                raise FileNotFoundError(path)
        if args.check:
            print(f'Configuration OK: {len(config["logs"])} log(s), {len(patterns)} keyword pattern(s)')
            return 0
        if args.top < 1:
            raise ValueError('--top must be at least 1')
        stats, candidates = analyze(config, patterns, args.verbose)
        if args.report:
            print_report(config, stats, candidates, args.top, args.verify_crawlers, not args.no_ip_lookup, args.refresh_ip_lookup, args.verbose, args.refresh_crawler_ranges)
            return 0
        update(config, candidates, stats, args.dry_run, args.verbose, args.refresh_crawler_ranges)
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
