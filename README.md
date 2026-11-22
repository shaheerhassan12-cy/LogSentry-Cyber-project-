# LogSentry 🛡️

**A SOC-style log analyzer that finds brute-force attacks, password spraying and account abuse in Linux and Windows authentication logs, and maps every alert to MITRE ATT&CK.**

![Tests](https://github.com/USERNAME/logsentry/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A Tier 1 SOC analyst spends much of the day doing exactly this: reading authentication logs, spotting attack patterns, and deciding what needs escalating. LogSentry automates that first pass. It uses only Python's standard library, so it runs anywhere without installing anything.

![LogSentry HTML report](docs/report_screenshot.png)

## What it detects

| Rule | Severity | MITRE ATT&CK | What triggers it |
|---|---|---|---|
| `success_after_failures` | Critical | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) | A successful login from an IP that already failed 5+ times |
| `brute_force` | High | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | 5+ failed logins from one IP inside 10 minutes (sliding window) |
| `password_spray` | High | [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | One IP trying 4+ different usernames |
| `admin_group_add` | High | [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) | Windows event 4732: account added to a privileged group |
| `new_account` | Medium | [T1136.001 Create Local Account](https://attack.mitre.org/techniques/T1136/001/) | `useradd` on Linux or Windows event 4720 |
| `sensitive_sudo` | Medium | [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) | sudo used on `/etc/shadow`, `useradd`, `visudo`, `authorized_keys` and similar |

All thresholds can be changed from the command line.

## Supported logs

- **Linux:** `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS). Parses sshd, sudo and useradd entries.
- **Windows:** Security events 4624, 4625, 4720 and 4732, exported to JSON with the PowerShell command below.

## Quick start

```bash
git clone https://github.com/USERNAME/logsentry.git
cd logsentry
python -m logsentry sample_logs/auth.log sample_logs/windows_security.json --year 2026 --html report.html
```

Output:

```
LogSentry: 39 events parsed, 11 alerts

[CRITICAL] 2026-11-22 03:01:02  T1078      'deploy' logged in from 203.0.113.45 after 11 failed attempts - possible account compromise
[CRITICAL] 2026-11-22 09:02:00  T1078      'administrator' logged in from 198.51.100.200 after 6 failed attempts - possible account compromise
[HIGH    ] 2026-11-22 03:01:02  T1110.001  9 failed logins from 203.0.113.45 within 10 minutes
[HIGH    ] 2026-11-22 03:05:04  T1110.003  198.51.100.77 tried 5 different usernames
...
By severity: critical=2, high=5, medium=4
```

Then open `report.html` in a browser.

## All options

| Option | Default | Meaning |
|---|---|---|
| `--threshold N` | 5 | Failed logins from one IP that count as brute force |
| `--window MIN` | 10 | Minutes those failures must fall within |
| `--spray-users N` | 4 | Distinct usernames from one IP that count as spraying |
| `--year YYYY` | current year | Year for Linux logs (syslog lines have no year) |
| `--enrich` | off | Look up external IPs on AbuseIPDB (needs `ABUSEIPDB_API_KEY`) |
| `--html / --json / --csv FILE` | none | Write the report or alerts to a file |
| `--fail-on SEVERITY` | none | Exit with code 2 if any alert is at or above this severity, for use in scripts and pipelines |

### Threat intelligence (optional)

Create a free account at [abuseipdb.com](https://www.abuseipdb.com/), copy your API key, then:

```bash
export ABUSEIPDB_API_KEY="your-key"          # Windows PowerShell: $env:ABUSEIPDB_API_KEY="your-key"
python -m logsentry /var/log/auth.log --enrich --html report.html
```

Each external IP gets an abuse score, country, ISP and report count. Internal IPs (10.x, 172.16–31.x, 192.168.x) are never sent anywhere.

### Exporting Windows Security logs

Run in PowerShell as Administrator:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4720,4732} -MaxEvents 5000 |
  ForEach-Object {
    $xml = [xml]$_.ToXml(); $d = @{}
    $xml.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeCreated = $_.TimeCreated.ToString('s'); EventID = $_.Id; Computer = $_.MachineName
      TargetUserName = $d.TargetUserName; IpAddress = $d.IpAddress
      SubjectUserName = $d.SubjectUserName; MemberName = $d.MemberName; MemberSid = $d.MemberSid
    }
  } | ConvertTo-Json | Out-File security.json -Encoding utf8
```

## Example investigation

[`docs/INVESTIGATION.md`](docs/INVESTIGATION.md) is a full incident write-up of the attack in the sample logs. It follows what a Tier 1 analyst would escalate: the timeline, indicators of compromise, MITRE mapping and recommended containment.

## Project layout

```
logsentry/
├── logsentry/
│   ├── models.py       # LogEvent and Alert data classes
│   ├── parsers.py      # Linux auth.log + Windows JSON → LogEvent
│   ├── detections.py   # detection rules (sliding window, spray, compromise...)
│   ├── enrich.py       # internal/external scope + AbuseIPDB lookups
│   ├── report.py       # console, JSON, CSV and HTML output
│   └── cli.py          # command-line options
├── sample_logs/        # simulated attack on a Linux server and a Windows workstation
├── tests/              # pytest unit tests (run in GitHub Actions on every push)
└── docs/               # sample report, screenshot and investigation write-up
```

## Run the tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

## Testing it on your own lab

Point it at a VM you own: for example, an Ubuntu VM with SSH enabled, attacked from a Kali VM with `hydra` on a host-only network. Then copy `/var/log/auth.log` off the VM and analyze it. **Only run attacks against systems you own or have written permission to test.**

## Roadmap

- [ ] Read `.evtx` files directly
- [ ] Impossible-travel detection using GeoIP
- [ ] Export alerts as Sigma rules / send to a Wazuh or Splunk instance
- [ ] Slack/Discord webhook notifications for critical alerts

## Skills demonstrated

Log analysis · Alert triage · MITRE ATT&CK mapping · Threat intelligence enrichment · Regular expressions · Python (dataclasses, argparse, sliding-window detection) · Unit testing · CI with GitHub Actions · Incident reporting

## Author

**Shaheer Hassan** · Junior Security Analyst · [shaheerhassan533@gmail.com](mailto:shaheerhassan533@gmail.com)

All IP addresses in the sample logs come from reserved documentation ranges (RFC 5737) and do not belong to anyone.
