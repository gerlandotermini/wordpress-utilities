# ip2ban-forensics v1.0

Read-only Apache access-log forensics for the existing ip2ban project.

- Adds alert deduplication for `--findings-only` runs.
- A finding is identified by subject (IP or subnet), finding category, and severity. Rolling-window request counts and evidence timestamps do not change its identity.
- The same finding is suppressed for 24 hours by default. After the cooldown, it can alert again if it is still present.
- A new finding category or severity for the same IP can alert immediately.
- Alert state is stored in `ip2ban-forensics-alerts.json` beside the script by default and is written atomically.
- Alert state does not change detection, `.htaccess`, or ip2ban thresholds.
- `--alert-state` selects a different state-file path; `--alert-cooldown-hours` changes the cooldown.
- Findings-only output highlights HTTP 2xx responses for review, without treating them as proof of exposure or compromise.
- Denied `/xmlrpc.php` and `/wp-login.php` requests no longer produce duplicate overlapping findings.

## Installation

Back up your current script, then upload v1.0 as `ip2ban-forensics.py` in the same directory as `ip2ban.py` and `config.json`.

```bash
cd /home/duechiac/wp-utils/ip2ban
cp -p ip2ban-forensics.py ip2ban-forensics.py.v1.3.bak
# Upload v1.0 as ip2ban-forensics.py
chmod 755 ip2ban-forensics.py
python3 -m py_compile ip2ban-forensics.py
python3 ip2ban-forensics.py --help
```

## Test findings-only output

Preview all current findings without changing the alert state:

```bash
python3 ip2ban-forensics.py --minutes 60 --findings-only
```

The first deduplicated run reports currently active findings and creates the alert-state file:

```bash
python3 ip2ban-forensics.py --minutes 60 --findings-only --deduplicate-alerts
```

Subsequent runs suppress the same IP/category/severity or subnet/category/severity until its cooldown expires.

## Recommended hourly cron

Run at 17 minutes past every hour, analyze the previous 60 minutes, and email only newly eligible findings or script errors:

```cron
17 * * * * tmp=$(mktemp) || exit 1; /usr/bin/python3 /home/duechiac/wp-utils/ip2ban/ip2ban-forensics.py --minutes 60 --findings-only --deduplicate-alerts --alert-cooldown-hours 24 > "$tmp" 2>&1; status=$?; if [ -s "$tmp" ]; then cat "$tmp"; fi; rm -f "$tmp"; exit "$status"
```

Ensure the hosting account has a valid cron email destination configured. The alert-state JSON file is runtime data and should remain private/untracked. The existing `*.json` Git ignore rule excludes it.

## Command-line options

- `--findings-only`: print only IP/subnet findings; produce no standard output when there are none.
- `--deduplicate-alerts`: suppress findings already alerted within the cooldown. Requires `--findings-only`.
- `--alert-state PATH`: choose the persistent alert-state JSON file. Default: `ip2ban-forensics-alerts.json` beside the script.
- `--alert-cooldown-hours N`: re-alert for the same finding after N hours. Default: `24`.
- `--verify-crawlers`: manually verify crawler claims using bounded DNS checks and official IP ranges. Omitted from the hourly cron job to avoid unnecessary DNS work.

## Safety and behavior notes

- The script is read-only: it does not edit `.htaccess`, ban IPs, or change ip2ban thresholds/configuration.
- Existing whitelist behavior and detection thresholds are unchanged.
- A 2xx response is highlighted for review; it does not by itself prove that a resource was exposed or that a compromise occurred.
- Findings are indicators for review, not proof of compromise.
- The first deduplicated run may email findings already present in the selected analysis window because no alert history exists yet.
