# ip2ban-forensics v1.0

A read-only companion to `ip2ban.py` for behavioral analysis of Apache access logs. It extracts suspicious request patterns and supporting evidence so you can review activity by IP address or subnet.

## Safety and scope

- Reads the `logs` list and `lookback_minutes` value from the existing ip2ban `config.json`.
- Understands Apache Combined Log Format and Common Log Format.
- Does **not** modify `.htaccess`, ban IPs, or change ip2ban configuration.
- Makes no external network or API calls.
- Does not require an AI API key or any third-party Python packages.
- Produces a terminal report or JSON output for later review.

This is an indicator and triage tool, not an intrusion-detection guarantee. A detected pattern is not proof that the source is malicious. An HTTP 200 response is not proof that an exploit worked; WordPress rewrite rules can return a normal page for nonexistent paths.

## Installation

Copy `ip2ban-forensics-v1.0.py` into the same directory as your existing `ip2ban.py` and `config.json`. For example:

```bash
cd ~/wp-utils/ip2ban
chmod 750 ip2ban-forensics-v1.0.py
python3 ip2ban-forensics-v1.0.py --help
```

The script uses `config.json` beside itself by default. It only needs the `logs` and `lookback_minutes` settings; it ignores the `.htaccess` and keyword settings. If your config file is elsewhere, specify it with `--config /path/to/config.json`.

## Running an analysis

Run with the configured `lookback_minutes` window (currently 60 minutes):

```bash
python3 ip2ban-forensics-v1.0.py
```

Analyze the last 24 hours:

```bash
python3 ip2ban-forensics-v1.0.py --hours 24
```

Investigate one IP address:

```bash
python3 ip2ban-forensics-v1.0.py --ip 34.174.75.20
```

Investigate an entire subnet:

```bash
python3 ip2ban-forensics-v1.0.py --network 188.241.38.0/24
```

Analyze the last 7 days for one subnet:

```bash
python3 ip2ban-forensics-v1.0.py --network 188.241.38.0/24 --hours 168
```

Save a machine-readable report as JSON:

```bash
python3 ip2ban-forensics-v1.0.py --hours 24 --json > forensics-24h.json
```

Adjust the request-burst and repeated-login thresholds for a particular run:

```bash
python3 ip2ban-forensics-v1.0.py --burst-threshold 60 --login-threshold 8
```

These command-line thresholds affect forensic reporting only; they do not change ip2ban's ban thresholds.

## Detection rules in v1.0

The analyzer looks for indicators including:

- Requests for sensitive files and common backup/configuration artifacts.
- Path traversal syntax.
- SQL-injection-like request parameters.
- Command-injection-like syntax.
- Cross-site-scripting-like syntax.
- WordPress author/REST user enumeration.
- Common administrative, diagnostic, and software-probe paths.
- WordPress login and XML-RPC activity, including repeated POST requests.
- Unusual HTTP methods and potentially mutating methods.
- Multiple alternative CMS installation paths within a 10-minute window.
- Repeated login/XML-RPC POST requests within a 10-minute window.
- High per-IP request bursts within one minute.
- Broad sweeps of distinct paths returning 4xx/5xx responses.
- Aggregated request volume by IPv4 `/24` and IPv6 `/64` subnet.
- Crawler names claimed in User-Agent strings. These are reported as claims only; v1.0 does not verify crawler identity.

Subnet grouping is a traffic-aggregation convenience, not proof that the addresses share an owner or operator. The default burst threshold is 60 requests per minute; the repeated authentication POST threshold is 8 in 10 minutes. These are forensic triage defaults, not ip2ban ban thresholds.

## Interpreting the report

- **Severity** describes the type of indicator, not proof of impact.
- **Confidence** describes confidence in the pattern match, not confidence that the server was compromised.
- **Outcome indicators** help distinguish not-found/denied responses from successful HTTP status codes that deserve closer validation.
- `potentially_successful` means a sensitive-file request received a 2xx response. Check whether the requested resource actually existed and what Apache served before concluding it was exposed.
- Common secret query-parameter values (such as password, token, key, and nonce) are redacted in evidence output. The original access logs are not modified.

## Limitations

- Access logs show requests and HTTP responses, not what happened inside PHP or the database.
- The tool cannot reliably identify the person behind an IP address.
- A 200 response may be a WordPress soft-404 or rewrite fallback.
- v1.0 does not inspect Apache error logs, WordPress audit logs, filesystem changes, or database changes.
- A crawler User-Agent is not authentication. A client can spoof a Googlebot, ClaudeBot, or other crawler name; v1.0 does not verify those claims using DNS or official IP ranges.
- v1.0 uses deterministic local rules only. AI interpretation is intentionally deferred until the evidence extraction has been reviewed against real traffic.

## Suggested first run

Start with a 24-hour report and review the findings before changing any detection thresholds or taking action against an IP:

```bash
python3 ip2ban-forensics-v1.0.py --hours 24
```

You can also save the same report as JSON if you want to share or process the structured evidence:

```bash
python3 ip2ban-forensics-v1.0.py --hours 24 --json > forensics-24h.json
```
