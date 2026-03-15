# cybertek-threat-intel

Automated daily aggregation of public threat intelligence blocklists, maintained by [cybertek605](https://github.com/cybertek605).

## Lists

| File | Type | Sources |
|---|---|---|
| `lists/ip_blocklist.txt` | IPv4 addresses | Feodo Tracker, Emerging Threats |
| `lists/cidr_blocklist.txt` | CIDR ranges | Spamhaus DROP, Spamhaus EDROP |
| `lists/domain_blocklist.txt` | Hostnames | URLhaus |
| `lists/metadata.json` | Stats + last updated | All sources |

Updated daily at **02:00 UTC** via GitHub Actions.

## Sources

| Source | Feed | License |
|---|---|---|
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet C2 IPs (Emotet, TrickBot, QakBot) | Free |
| [Emerging Threats](https://rules.emergingthreats.net/) | Compromised/malicious IPs | Free |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Malicious IP ranges | Non-commercial free |
| [Spamhaus EDROP](https://www.spamhaus.org/drop/) | Hijacked netblocks | Non-commercial free |
| [URLhaus](https://urlhaus.abuse.ch/) | Malware distribution domains | Free |

> **Spamhaus note:** DROP/EDROP are free for non-commercial use. See [Spamhaus usage terms](https://www.spamhaus.org/organization/dnsblusage/) if using this in a commercial context.

## Raw URLs (for scripts)

```
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/ip_blocklist.txt
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/cidr_blocklist.txt
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/domain_blocklist.txt
https://raw.githubusercontent.com/cybertek605/cybertek-threat-intel/main/lists/metadata.json
```
