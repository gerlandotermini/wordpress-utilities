
# ip2ban v2 — diagnostic report update

Python 3.9+ on Linux; no third-party packages. Uses Apache Common or Combined Log Format and the existing `BEGIN/END ip2ban-bans` and `BEGIN/END ip2ban-whitelist` markers in `.htaccess`.

## Diagnostic report

Run:

```bash
python3 ip2ban.py --report
```

The report is read-only and never changes `.htaccess`. It includes:

- Request counts, combined 4xx/5xx errors, error percentage, and keyword hits.
- HTTP status and method breakdowns.
- Number of distinct URLs and the most frequently requested URLs.
- Average requests per minute and the busiest observed minute.
- Most common User-Agent strings for each IP.
- Recognition of User-Agent claims for Googlebot, Bingbot, DuckDuckBot, YandexBot, Baiduspider, Applebot, AhrefsBot, AhrefsSiteAudit, PetalBot, ClaudeBot, Bytespider, Feedjack, MJ12bot, SemrushBot, Amazonbot, Amzn-SearchBot, and Amzn-User.
- Existing ban and whitelist status, plus threshold assessments.

By default, crawler labels are explicitly marked **unverified**. A User-Agent string can be forged. Crawler recognition is informational only: it never bypasses thresholds, bans, or whitelist checks.

To verify supported crawler claims using forward-confirmed reverse DNS:

```bash
python3 ip2ban.py --report --verify-crawlers
```

This performs DNS lookups only for IPs whose User-Agent claims to be a crawler with a supported reverse-DNS verification method: Googlebot, Bingbot, DuckDuckBot, YandexBot, Baiduspider, Applebot, and AhrefsBot/AhrefsSiteAudit. A crawler is marked verified only when its reverse-DNS hostname belongs to the expected provider domain and resolving that hostname forward returns the original IP. Apple documents the `applebot.apple.com` reverse-DNS suffix; Ahrefs documents `ahrefs.com` and `ahrefs.net`. Other recognized claims are reported as having no supported DNS verification method; they are not mislabeled as failed DNS checks. DNS timeouts or lookup failures are treated as **not verified**, not as proof of malicious activity. This option can make the report take longer.

Show more IPs with:

```bash
python3 ip2ban.py --report --top 50
```

## Other commands

```bash
python3 ip2ban.py --check
python3 ip2ban.py --dry-run --verbose
```

`--check` validates the configuration, required files, and `.htaccess` markers. `--dry-run` shows prospective bans without changing `.htaccess`.

## Notes

- The report uses the User-Agent and referrer fields when present in Apache Combined Log Format. If the server uses Common Log Format, User-Agent information is not available in the log and is shown as not logged. `Applebot-Extended` is intentionally not classified as a visiting crawler.
- Existing bans are preserved; dated bans expire after the configured retention period. Undated/manual entries remain.
- Thresholds trigger at **at least** the configured count. Error counts combine all 4xx and 5xx statuses.
- Keyword entries are case-insensitive regular expressions checked against the request target (path plus query string).
- Only public IPs are eligible for banning; whitelisted addresses are skipped.
- Log timestamps use the timezone offset recorded in Apache; ban timestamps use the server's local timezone.
- Apache 2.4 must support the existing `Deny from` rules (typically via `mod_access_compat`).

## Live-mode notifications

In normal live mode (without `--report` or `--dry-run`), the script writes a detailed notification to **stdout only when it successfully adds one or more new bans** to `.htaccess`. It does not send email itself. When run by cron, cron's mail delivery can send that output to the configured recipient.

Each new-ban notification includes:

- Timestamp, IP address, and reverse-DNS hostname when available (lookup timeout: 2 seconds).
- Ban reason and request/error/keyword counts.
- HTTP status-code counts.
- Up to five most common User-Agent strings, with recognized crawler claims identified as claims rather than verified identities.
- The access-log file(s) containing requests from that IP.
- Recent request samples, including HTTP status codes.

Already-banned and whitelisted IPs do not generate notifications. A notification is printed only after the `.htaccess` update succeeds. If no new ban is added, normal live mode is silent (unless verbose diagnostics are explicitly enabled). Keep `--report` on the cron command while monitoring; remove it only when you are ready to enable live bans and cron mail notifications.
